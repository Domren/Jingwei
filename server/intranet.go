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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/scanner"
)

// ---------------------------------------------------------------------------
// 内网两阶段 MVP：逻辑会话 + 隧道 + 范围审批 + 任务交接。
//
// 会话不驻留进程：每次执行都复用已登记的 webshell，cwd 由平台维护。所有能力
// 同时通过 HTTP API（无 LLM 可用）与 agent 工具（有 LLM 时）暴露，共用同一套
// 数据库表，因此人在页面上的操作与 LLM 的工具调用看到的是同一份状态。
// ---------------------------------------------------------------------------

const (
	intranetCwdMarker  = "\n__JW_CWD__"
	intranetEcMarker   = "__JW_EC__"
	intranetSizeMarker = "__JW_SIZE__"

	intranetExecTimeout   = 60 * time.Second
	intranetUploadChunk   = 24 * 1024
	intranetUploadLimit   = 4 << 20
	intranetDownloadLimit = 512 << 10
	intranetBatchLimit    = 50
	intranetTunnelTTL     = time.Hour
	intranetTunnelMaxTTL  = 24 * time.Hour
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

// parseIntranetOutput splits the cwd/exit-code markers off the command output.
func parseIntranetOutput(raw string) (output, cwd string, exitCode int) {
	exitCode = -1
	idx := strings.LastIndex(raw, intranetCwdMarker)
	if idx < 0 {
		return raw, "", exitCode
	}
	output = strings.TrimSuffix(raw[:idx], "\n")
	rest := raw[idx+len(intranetCwdMarker):]
	lines := strings.SplitN(rest, "\n", 2)
	cwd = strings.TrimSpace(lines[0])
	if len(lines) < 2 {
		return output, cwd, exitCode
	}
	ecLine := strings.TrimSpace(strings.SplitN(lines[1], "\n", 2)[0])
	if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(ecLine, intranetEcMarker))); err == nil {
		exitCode = n
	}
	return output, cwd, exitCode
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
	raw, err := scanner.RunShellCommand(cctx, client, shell.URL, payload, intranetScript(sess.Cwd, command))
	if err != nil {
		out.Output, out.IsError, out.Note = raw, true, err.Error()
		return out
	}
	output, cwd, exitCode := parseIntranetOutput(raw)
	out.Output, out.Cwd, out.ExitCode = output, cwd, exitCode
	if exitCode > 0 {
		out.IsError = true
	}
	if strings.HasPrefix(cwd, "/") && cwd != sess.Cwd {
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
	return out, nil
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

// intranetProbe collects OS/user/tool availability from the target.
func (s *Server) intranetProbe(ctx context.Context, pg *db.DB, sess *db.IntranetSession) (intranetProbeInfo, intranetExecOutcome) {
	script := `printf '__JW_HOST__%s\n' "$(hostname 2>/dev/null)"
printf '__JW_KERNEL__%s\n' "$(uname -srm 2>/dev/null)"
printf '__JW_USER__%s\n' "$(id 2>/dev/null)"
for b in socat nc ncat ssh chisel python3 python busybox; do command -v "$b" >/dev/null 2>&1 && printf '__JW_BIN__%s\n' "$b"; done
exit 0
`
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
		switch t.Kind {
		case db.IntranetTunnelKindPort, db.IntranetTunnelKindRemote:
			if t.RemoteHost == "" || t.RemotePort <= 0 || t.ListenPort <= 0 {
				return nil, info, errors.New("需要 listen_port、remote_host 与 remote_port")
			}
			if !intranetHasBin(info, "socat") {
				return nil, info, errors.New("目标上没有 socat，无法自动生成转发命令；请手动提供 deploy_command")
			}
			listen := "TCP-LISTEN:" + strconv.Itoa(t.ListenPort)
			if h := strings.TrimSpace(t.ListenHost); h != "" && h != "0.0.0.0" && h != "::" {
				listen += ",bind=" + h
			}
			listen += ",fork,reuseaddr"
			base := "socat " + listen + " TCP:" + intranetHostPort(t.RemoteHost, t.RemotePort)
			deploy = "nohup " + base + " </dev/null >/tmp/jw_tunnel_" + strconv.FormatInt(t.ID, 10) + ".log 2>&1 & echo JW_PID:$!"
		case db.IntranetTunnelKindSocks5:
			return nil, info, errors.New("SOCKS5 需要为目标手动指定 deploy_command（例如 chisel/frp/ssh -D 命令）；平台只在端口转发时自动生成命令")
		default:
			return nil, info, errors.New("不支持的隧道类型: " + t.Kind)
		}
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
	mux.HandleFunc("POST /api/intranet/sessions/batch-exec", s.batchExecIntranetSessions)

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
	writeJSON(w, 200, map[string]any{"tunnel": t})
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
	writeJSON(w, code, map[string]any{"tunnel": updated, "result": out})
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
	writeJSON(w, code, map[string]any{"tunnel": updated, "result": out})
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
	writeJSON(w, 200, map[string]any{"request": row})
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
