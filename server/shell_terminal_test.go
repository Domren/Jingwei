package server

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// markerEcho renders the wrapper trailer the way a POSIX target would print it,
// so the marker protocol can be exercised without a live webshell.
func markerEcho(output, cwd string, code int) string {
	return output + "\n" + intranetCwdMarker + cwd + "\n" + intranetEcMarker + strconv.Itoa(code) + "\n"
}

func TestShellExecCarriesCwdAndExitCode(t *testing.T) {
	var got []string
	send := func(_ context.Context, script string, _ time.Duration) (string, error) {
		got = append(got, script)
		return markerEcho("uid=33(www-data)", "/var/www/html", 0), nil
	}
	res := shellExec(context.Background(), send, "/var/www", intranetOSPosix, "", "id", time.Second)
	if res.IsError || res.ExitCode != 0 {
		t.Fatalf("clean command reported as failure: %+v", res)
	}
	if res.Output != "uid=33(www-data)" {
		t.Fatalf("output=%q", res.Output)
	}
	if res.Cwd != "/var/www/html" {
		t.Fatalf("cwd not carried back for the next turn: %q", res.Cwd)
	}
	if !strings.HasPrefix(got[0], "cd '/var/www'") {
		t.Fatalf("stored cwd not restored before the command: %q", got[0])
	}
}

func TestShellExecNonZeroExitIsError(t *testing.T) {
	send := func(_ context.Context, _ string, _ time.Duration) (string, error) {
		return markerEcho("ls: cannot access '/nope'", "/", 2), nil
	}
	res := shellExec(context.Background(), send, "/", intranetOSPosix, "", "ls /nope", time.Second)
	if !res.IsError || res.ExitCode != 2 {
		t.Fatalf("exit code 2 must surface as an error: %+v", res)
	}
	if res.TimedOut {
		t.Fatalf("a returned command is not a timeout")
	}
}

func TestShellExecWithoutTrailerIsNotSilentSuccess(t *testing.T) {
	// A 404 page or a shell that died mid-command used to look like empty
	// output; the workbench must say the trailer never ran.
	send := func(_ context.Context, _ string, _ time.Duration) (string, error) {
		return "<html>404 Not Found</html>", nil
	}
	res := shellExec(context.Background(), send, "/", intranetOSPosix, "", "id", time.Second)
	if res.MarkerOK || !res.IsError {
		t.Fatalf("unparsed echo must be an error: %+v", res)
	}
	if !strings.Contains(res.Note, "命令结束标记") {
		t.Fatalf("note does not explain the failure: %q", res.Note)
	}
}

func TestShellExecDropsRelativeCwd(t *testing.T) {
	// Restoring a relative path would cd from the web server's own directory,
	// so an answer like "html" is thrown away rather than echoed back as truth.
	send := func(_ context.Context, _ string, _ time.Duration) (string, error) {
		return markerEcho("ok", "html", 0), nil
	}
	res := shellExec(context.Background(), send, "/", intranetOSPosix, "", "pwd", time.Second)
	if res.Cwd != "" {
		t.Fatalf("relative cwd accepted: %q", res.Cwd)
	}
}

func TestShellExecClassifiesAbandonedWait(t *testing.T) {
	send := func(ctx context.Context, _ string, _ time.Duration) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	res := shellExec(context.Background(), send, "/", intranetOSPosix, "", "tail -f /dev/null", 20*time.Millisecond)
	if !res.TimedOut || !res.IsError {
		t.Fatalf("a deadline the platform gave up on must be labelled: %+v", res)
	}
	if !strings.Contains(res.Note, "仍在继续执行") {
		t.Fatalf("note must say the target may still be running: %q", res.Note)
	}
	if res.ExitCode != -1 {
		t.Fatalf("no exit code was ever reported: %d", res.ExitCode)
	}
}

// shellDeadlineError mimics the transport error a sender returns when its own
// per-request client timeout fires: net.Error with Timeout() true, wrapped in a
// *url.Error exactly like http.Client does.
type shellDeadlineError struct{}

func (shellDeadlineError) Error() string   { return "context deadline exceeded" }
func (shellDeadlineError) Timeout() bool   { return true }
func (shellDeadlineError) Temporary() bool { return true }

func TestShellExecClassifiesSenderDeadline(t *testing.T) {
	send := func(_ context.Context, _ string, _ time.Duration) (string, error) {
		return "", &url.Error{Op: "Post", URL: "http://127.0.0.1:8080/tpl.php", Err: shellDeadlineError{}}
	}
	res := shellExec(context.Background(), send, "/", intranetOSPosix, "", "tail -f /dev/null", time.Minute)
	if !res.TimedOut || !res.IsError {
		t.Fatalf("a sender-side deadline must read as an abandoned wait: %+v", res)
	}
	if !strings.Contains(res.Note, "仍在继续执行") {
		t.Fatalf("note must replace the transport wording, got %q", res.Note)
	}
}

func TestShellExecFirstCommandKeepsTargetDirectory(t *testing.T) {
	var got []string
	send := func(_ context.Context, script string, _ time.Duration) (string, error) {
		got = append(got, script)
		return markerEcho("/var/www/html/assets", "/var/www/html/assets", 0), nil
	}
	res := shellExec(context.Background(), send, "", intranetOSPosix, "", "pwd", time.Second)
	if len(got) != 1 {
		t.Fatalf("scripts=%d", len(got))
	}
	// Forcing "/" on the first turn would hide where the web server actually put
	// the process; "cd ." keeps the target's own starting directory.
	if !strings.HasPrefix(got[0], "cd '.' 2>/dev/null || cd /") {
		t.Fatalf("unknown cwd must not be forced to root: %q", got[0])
	}
	if res.Cwd != "/var/www/html/assets" {
		t.Fatalf("the target directory must come back for the next turn: %q", res.Cwd)
	}
}

func TestShellExecWindowsWrapperFromCache(t *testing.T) {
	var got []string
	// cmd.exe prints the exit code on the marker line and the directory on the
	// line after it — a different shape from the POSIX trailer.
	send := func(_ context.Context, script string, _ time.Duration) (string, error) {
		got = append(got, script)
		return "whoami\ndesktop\\admin\r\n" + intranetEcMarker + "0\r\n" +
			intranetCwdMarker + "\r\nC:\\inetpub\r\n", nil
	}
	res := shellExec(context.Background(), send, `C:\inetpub`, intranetOSWindows, "", "whoami", time.Second)
	if len(got) != 1 {
		t.Fatalf("a cached os_kind must not re-probe, scripts=%d", len(got))
	}
	if !strings.Contains(got[0], intranetWindowsCodepage) {
		t.Fatalf("cmd wrapper not used: %q", got[0])
	}
	if res.Cwd != `C:\inetpub` {
		t.Fatalf("cmd trailer cwd not parsed: %q", res.Cwd)
	}
}

func TestShellExecProbesOnceWhenFamilyUnknown(t *testing.T) {
	var scripts []string
	send := func(_ context.Context, script string, _ time.Duration) (string, error) {
		scripts = append(scripts, script)
		if strings.Contains(script, intranetOSProbe) {
			return "__JW_OS__Windows_NT", nil
		}
		return markerEcho("hi", `C:\`, 0), nil
	}
	res := shellExec(context.Background(), send, "", "", "", "whoami", time.Second)
	if len(scripts) != 2 || scripts[0] != intranetOSProbe {
		t.Fatalf("expected one probe then one command, got %q", scripts)
	}
	if res.OSKind != intranetOSWindows {
		t.Fatalf("probe result not returned for caching: %q", res.OSKind)
	}
	if !strings.Contains(scripts[1], intranetWindowsCodepage) {
		t.Fatalf("the same turn must already use the answered wrapper: %q", scripts[1])
	}
}

// A probe that never answered is not a fact about the target. Handlers persist
// whatever shellExec reports as os_kind, so reporting the POSIX fallback there
// would file a guess away — and a Windows shell that was merely unreachable during
// its first command would get POSIX wrappers for the rest of its life, with no way
// to correct it from the UI.
func TestShellOSKindOfFallsBackWithoutCachingFailure(t *testing.T) {
	probes := 0
	failing := func(_ context.Context, _ string, _ time.Duration) (string, error) {
		probes++
		return "", context.DeadlineExceeded
	}
	kind, confirmed := shellOSKindOf(context.Background(), failing, "")
	if kind != intranetOSPosix {
		t.Fatalf("fallback wrapper must be posix, got %q", kind)
	}
	if confirmed {
		t.Fatal("a failed probe must not be reported as the target's family")
	}
	if probes != 1 {
		t.Fatalf("probes=%d", probes)
	}

	cached := func(_ context.Context, _ string, _ time.Duration) (string, error) {
		probes++
		return "__JW_OS__Windows_NT", nil
	}
	if got, ok := shellOSKindOf(context.Background(), cached, intranetOSPosix); got != intranetOSPosix || !ok {
		t.Fatalf("a cached value must be reused without probing: %q confirmed=%v", got, ok)
	}
	if probes != 1 {
		t.Fatalf("cached family still triggered a probe")
	}
}

func TestShellExecReportsOnlyProbedFamily(t *testing.T) {
	// The probe fails and the command itself answers as POSIX: the turn works, but
	// nothing here proves the family, so the result must not carry one.
	silent := func(_ context.Context, script string, _ time.Duration) (string, error) {
		if strings.Contains(script, intranetOSProbe) {
			return "", context.DeadlineExceeded
		}
		return "ok\n" + intranetCwdMarker + "/var/www\n" + intranetEcMarker + "0\n", nil
	}
	res := shellExec(context.Background(), silent, "", "", "", "id", time.Second)
	if res.IsError || res.ExitCode != 0 {
		t.Fatalf("the turn itself must still succeed: %+v", res)
	}
	if res.OSKind != "" {
		t.Fatalf("an unprobed family must not be reported as known: %q", res.OSKind)
	}

	answered := func(_ context.Context, script string, _ time.Duration) (string, error) {
		if strings.Contains(script, intranetOSProbe) {
			return "__JW_OS__Windows_NT", nil
		}
		return "ok\n" + intranetCwdMarker + "C:\\inetpub\n" + intranetEcMarker + "0\n", nil
	}
	res = shellExec(context.Background(), answered, "", "", "", "whoami", time.Second)
	if res.OSKind != intranetOSWindows {
		t.Fatalf("an answered probe must be reported so the caller can cache it: %q", res.OSKind)
	}
}

// The file manager and the runtime self-report go through the same transport as
// the terminal, so a deadline must read as "we stopped waiting" there too instead
// of Go's internal error text.
func TestShellChannelErrorWordsDeadlines(t *testing.T) {
	if got := shellChannelError(nil); got != "" {
		t.Fatalf("no error must produce no message: %q", got)
	}
	deadline := &url.Error{Op: "Post", URL: "http://target/shell.php", Err: shellDeadlineError{}}
	if got := shellChannelError(deadline); !strings.Contains(got, "等待超时") {
		t.Fatalf("a client deadline must be worded as a stopped wait: %q", got)
	}
	refused := errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	if got := shellChannelError(refused); got != refused.Error() {
		t.Fatalf("a real failure must keep its own words: %q", got)
	}
}

func TestClampShellTimeout(t *testing.T) {
	if clampShellTimeout(0) != shellExecDefaultTimeout {
		t.Fatalf("unset timeout must fall back to the default")
	}
	if clampShellTimeout(-5) != shellExecDefaultTimeout {
		t.Fatalf("negative timeout must fall back to the default")
	}
	if clampShellTimeout(99999) != shellExecMaxTimeout {
		t.Fatalf("an unbounded client timeout must be clamped")
	}
	if clampShellTimeout(15) != 15*time.Second {
		t.Fatalf("in-range timeout was rewritten")
	}
}

func TestParseShellInfoSections(t *testing.T) {
	raw := "wrapper noise\n" +
		shellInfoSectionMarker + "主机与系统\nvictim-1\nLinux 6.8 x86_64\n" +
		shellInfoSectionMarker + "运行身份\nuid=33(www-data) gid=33(www-data)\n"
	sections := parseShellInfoSections(raw)
	if len(sections) != 2 {
		t.Fatalf("sections=%d %+v", len(sections), sections)
	}
	if sections[0].Label != "主机与系统" || sections[0].Output != "victim-1\nLinux 6.8 x86_64" {
		t.Fatalf("first section=%+v", sections[0])
	}
	if sections[1].Label != "运行身份" {
		t.Fatalf("second section=%+v", sections[1])
	}
}

func TestParseShellInfoSectionsCapsOversizedBlock(t *testing.T) {
	raw := shellInfoSectionMarker + "环境变量\n" + strings.Repeat("A", shellInfoSectionLimit+5000)
	sections := parseShellInfoSections(raw)
	if len(sections) != 1 {
		t.Fatalf("sections=%d", len(sections))
	}
	if len(sections[0].Output) > shellInfoSectionLimit+64 {
		t.Fatalf("section not capped: %d bytes", len(sections[0].Output))
	}
	if !strings.Contains(sections[0].Output, "输出已截断") {
		t.Fatalf("truncation must be visible to the operator")
	}
}

func TestShellInfoScriptSkipsWindowsOnlyAndPosixOnly(t *testing.T) {
	posix := shellInfoScript(intranetOSPosix)
	windows := shellInfoScript(intranetOSWindows)
	if strings.Contains(posix, "%COMPUTERNAME%") {
		t.Fatalf("POSIX script contains cmd expansion syntax")
	}
	if !strings.Contains(windows, "%COMPUTERNAME%") {
		t.Fatalf("windows script lost its probes: %q", windows)
	}
	if !strings.Contains(windows, "& (echo "+shellInfoSectionMarker) && !strings.Contains(windows, "echo "+shellInfoSectionMarker) {
		t.Fatalf("windows script lost section markers")
	}
	// cmd.exe only runs the first line of a multi-line command through PHP's
	// system(), so the windows script must be a single line.
	if strings.Contains(windows, "\n") {
		t.Fatalf("windows script spans multiple lines and will be truncated by the shell")
	}
}

func TestShellInfoProbesBoundTheirWalks(t *testing.T) {
	// One request carries all twelve sections under one 60s budget, so a walk that
	// leaves the root filesystem (find / without -xdev crossed into /mnt/c on the
	// lab host and ran for minutes) discards the whole panel, not just its section.
	posix := shellInfoScript(intranetOSPosix)
	for _, part := range strings.Split(posix, ";") {
		if strings.Contains(part, "find /") && !strings.Contains(part, "-xdev") {
			t.Fatalf("probe walks mounted filesystems: %q", strings.TrimSpace(part))
		}
	}
}

// ---------------------------------------------------------------------------
// A2 遗留：PowerShell 会话不得再落 cmd 语法脚本。宁可点名拒绝，也不静默成功。
// 这些用例只用一个假 sender，不需要测试库，验收命令可以直接跑全。
// ---------------------------------------------------------------------------

// psTrailer renders the marker trailer the PowerShell wrapper prints (exit code
// first, cwd on the following line).
func psTrailer(output, cwd string, code int) string {
	return output + "\n" + intranetEcMarker + strconv.Itoa(code) + "\n" +
		intranetCwdMarker + "\n" + cwd + "\n"
}

func TestPowerShellSessionRejectsCmdScriptsWithReason(t *testing.T) {
	// 平台生成、但仍是 cmd.exe 语法的脚本：上传存在性探测/分块/解码、
	// 下载大小探测/编码、维持部署与撤销、以及经 cmd 调 powershell.exe。
	cmdScripts := []string{
		`if exist "C:\x.txt" (echo JW_FILE_EXISTS) else (echo JW_FILE_NEW)`,
		`if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" (echo __JW_PS__1) else (echo __JW_PS__0)`,
		`echo ` + strings.Repeat("A", 64) + `>>C:\Users\lab\x.b64`,
		`certutil -decode -f "C:\x.b64" "C:\x.bin"`,
		`certutil -encode -f "C:\x.bin" "C:\x.b64"`,
		`for %I in ("C:\x.bin") do @echo %~zI`,
		`del /f /q "C:\x.b64" "C:\x.bin"`,
		`move /y "C:\x.bin" "C:\x.txt"`,
		`schtasks /create /f /tn "jw-x" /tr "cmd.exe /c whoami" /sc onlogon 2>&1 && echo JW_ARTIFACT_OK`,
		`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v jw-x /t REG_SZ /d "cmd.exe /c whoami" /f 2>&1 && echo JW_ARTIFACT_OK`,
		`sc create "jw-x" binPath= "cmd.exe /c whoami" start= auto 2>&1 & echo JW_ARTIFACT_OK`,
		`del /f /q "C:\x.txt" >nul 2>&1 & echo JW_ARTIFACT_OK & cmd /c exit 0`,
		`"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand AAAABBBB`,
		`echo __JW_CHUNK__ & "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$p='C:\x'" & echo __JW_CHUNK_END__`,
	}
	for i, cmd := range cmdScripts {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			called := false
			send := func(_ context.Context, script string, _ time.Duration) (string, error) {
				called = true
				return psTrailer("LAB-PS-OUTPUT", `C:\Users\lab`, 0), nil
			}
			res := shellExec(context.Background(), send, `C:\Users\lab`,
				intranetOSWindows, intranetShellPowerShell, cmd, time.Second)
			if called {
				t.Fatalf("cmd 语法脚本仍被投递给 PowerShell 会话: %q", cmd)
			}
			if !res.IsError || res.MarkerOK {
				t.Fatalf("拒绝必须是明确失败，不能是假成功: %+v", res)
			}
			for _, want := range []string{"PowerShell", "cmd.exe", "未静默成功", "移植"} {
				if !strings.Contains(res.Note, want) {
					t.Fatalf("拒绝原因要点名 %q，实得 %q", want, res.Note)
				}
			}
		})
	}
}

func TestPowerShellSessionStillRunsNativeCommands(t *testing.T) {
	native := []string{
		intranetProbeScriptSSHPowerShell,
		intranetReconScriptPowerShell,
		"Get-Process | Select-Object -First 5",
		"Write-Output $env:COMPUTERNAME",
		"echo hello",
	}
	for i, cmd := range native {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			var got string
			send := func(_ context.Context, script string, _ time.Duration) (string, error) {
				got = script
				return psTrailer("OK", `C:\Users\lab`, 0), nil
			}
			res := shellExec(context.Background(), send, `C:\Users\lab`,
				intranetOSWindows, intranetShellPowerShell, cmd, time.Second)
			if got == "" || res.IsError || !res.MarkerOK || res.ExitCode != 0 {
				t.Fatalf("PowerShell 原生命令被误拒: %+v (script=%q)", res, got)
			}
			if !strings.Contains(got, "$ErrorActionPreference") {
				t.Fatalf("没有用 PowerShell 包装: %q", got)
			}
		})
	}
}

func TestPowerShellCmdGuardDoesNotTouchShOrCmdSessions(t *testing.T) {
	cmdScript := `if exist "C:\x.txt" (echo JW_FILE_EXISTS) else (echo JW_FILE_NEW)`
	cases := []struct{ osKind, shell, want string }{
		{intranetOSPosix, intranetShellSh, "cd "},
		{intranetOSWindows, intranetShellCmd, "chcp 65001"},
		{intranetOSWindows, "", "chcp 65001"}, // 未探测解释器时按 OS 回落到 cmd（不回归）
	}
	for _, c := range cases {
		var got string
		send := func(_ context.Context, script string, _ time.Duration) (string, error) {
			got = script
			return markerEcho("ok", "/", 0), nil
		}
		_ = shellExec(context.Background(), send, "/", c.osKind, c.shell, cmdScript, time.Second)
		if got == "" {
			t.Fatalf("(%s,%s) 非 PowerShell 会话的 cmd 脚本不该被守卫拦下", c.osKind, c.shell)
		}
		if !strings.Contains(got, c.want) {
			t.Fatalf("(%s,%s) 包装被改坏: %q", c.osKind, c.shell, got)
		}
	}
}

func TestPowerShellWrapperAlignmentNotRegressed(t *testing.T) {
	// cwd 校验、单引号转义、控制字符拒绝、$LASTEXITCODE、退出码回收对齐
	// 现有 PowerShell 包装；守卫只拦 cmd 脚本，不动这些语义。
	s := intranetScriptPowerShell(`C:\it's`, "whoami")
	for _, want := range []string{
		`Set-Location -LiteralPath 'C:\it''s'`, "$ErrorActionPreference='Continue'",
		"$LASTEXITCODE", `Write-Output ("__JW_EC__"`, "(Get-Location).Path", "whoami",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("PowerShell 包装丢了 %q: %s", want, s)
		}
	}
	if strings.Contains(intranetScriptPowerShell("C:\\new\nline", "dir"), "Set-Location") {
		t.Fatal("控制字符路径必须拒绝，不能拼进 Set-Location")
	}
	if strings.Contains(intranetScriptPowerShell("/", "dir"), "Set-Location") {
		t.Fatal("POSIX 风格 cwd 必须忽略，不能 cd 到盘根再当成真实目录")
	}
	if !strings.Contains(intranetScriptPowerShell("", "Get-Date"), intranetEcMarker) {
		t.Fatal("纯 cmdlet 命令也必须写退出码标记，不能留空")
	}
}
