package server

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// R3 的缺口是「平台在 PowerShell 会话上生成的脚本到底是不是 PS 语法」没有夹具。
// 这组测试钉三件事：
//
//  1. 正例：PS 会话生成的每条脚本都不命中 powershellCmdScriptReason（否则会被守卫
//     拦下，等于功能不可用），且确实是 PS 语法。
//  2. 反例：cmd 会话生成的每条脚本都必然命中守卫——这既证明两族没有混写，也证明
//     「守卫拦住」和「构造出 cmd 脚本」是同一件事，不会各自漂移。
//  3. 分派：同一个入口按会话解释器分派后，**实际投递**的脚本族正确。构造对但
//     分派错了，功能照样不通。
//
// 测试只调用构造与执行路径本身，不连 SSH、不连库。
//
// 2026-11-12 补钉时这组夹具抓出两个真缺口（都已修）：
//   - 下载在 PS 会话上先跑 `if exist …` 探测 powershell.exe，被守卫拒掉后落到
//     certutil 回退（也是 cmd 语法），整条下载一次也走不通；
//   - `-EncodedCommand` 被当成 cmd 标记，把 wmi/startup/service 三个**合法 PS**
//     维持模块全数拒掉。合法用法与「经 cmd 调 powershell.exe」的包装是两件事。

// 64 字符的 base64 片段，与真实分块（4KB → 约 5.4KB base64）同量级，
// 用来让 isCmdBase64Append 生效——短串不会被识别成平台分块写入。
var r3Chunk = strings.Repeat("QUJDREVGR0g=", 5)

var r3CmdMarkers = []string{
	"if exist ", "certutil -", "move /y ", "del /f /q ",
	"for %I in (", "cmd /c exit 0", ">nul 2>&1",
}

var r3PSMarkers = []string{
	"[IO.File]::", "[Convert]::FromBase64String", "Remove-Item",
	"Write-Output", "Test-Path -LiteralPath", "Get-Item",
}

func r3CmdFamilyScripts() map[string]string {
	b64 := `C:\temp\payload.bin.jw1.b64`
	bin := `C:\temp\payload.bin.jw1.bin`
	target := `C:\temp\payload.bin`
	revoke, verify := intranetWindowsRevokeVerifyCmd(`"C:\temp\payload.bin"`)
	return map[string]string{
		"probe":        intranetCmdExistsProbeCmd(target),
		"chunk-first":  intranetCmdUploadChunkCmd(r3Chunk, b64, true),
		"chunk-append": intranetCmdUploadChunkCmd(r3Chunk, b64, false),
		"decode":       intranetCmdDecodeCmd(b64, bin),
		"move":         intranetCmdMoveCmd(bin, target),
		"cleanup":      intranetCmdCleanupCmd(b64, bin),
		"size":         intranetWindowsSizeCmd(target),
		"revoke":       revoke,
		"verify":       verify,
	}
}

func r3PSFamilyScripts() map[string]string {
	b64 := `C:\temp\payload.bin.jw1.b64`
	target := `C:\temp\payload.bin`
	revoke, verify := intranetWindowsPSRevokeVerifyCmd(target)
	return map[string]string{
		"probe":        intranetWindowsPSProbeCmd(target),
		"chunk-append": intranetPSAppendChunkCmd(b64, r3Chunk),
		"cleanup":      intranetPSRemoveCmd(b64),
		"write-plain":  intranetPSWriteDecodedCmd(target, b64),
		"write-gzip":   intranetPSWriteGzipCmd(target, b64),
		"size":         intranetWindowsPSSizeCmd(target),
		"revoke":       revoke,
		"verify":       verify,
	}
}

// 正例：PS 族脚本一条都不能命中 cmd 守卫，且必须是 PS 语法。
func TestPowerShellFamilyScriptsNeverMatchCmdGuard(t *testing.T) {
	for name, script := range r3PSFamilyScripts() {
		if reason := powershellCmdScriptReason(script); reason != "" {
			t.Errorf("PS 族 %s 命中了 cmd 守卫，说明语法混写，功能会被自己拦掉: %s", name, reason)
		}
		hasPS := false
		for _, m := range r3PSMarkers {
			if strings.Contains(script, m) {
				hasPS = true
				break
			}
		}
		if !hasPS {
			t.Errorf("PS 族 %s 不含任何 PowerShell 标记，可能退化成了别的语法: %s", name, script)
		}
	}
}

// 反例：cmd 族脚本必须逐条命中守卫，且不混入 PS 标记。
func TestCmdFamilyScriptsAreRejectedByGuard(t *testing.T) {
	for name, script := range r3CmdFamilyScripts() {
		if powershellCmdScriptReason(script) == "" {
			t.Errorf("cmd 族 %s 未被守卫识别，说明 cmd 脚本可以漏进 PowerShell 会话: %s", name, script)
		}
		for _, m := range r3PSMarkers {
			if strings.Contains(script, m) {
				t.Errorf("cmd 族 %s 混入了 PowerShell 标记 %q: %s", name, m, script)
			}
		}
	}
}

// 执行路径级证据：同一个上传入口，按会话解释器分派后实际投递的脚本族。
// 用记录型 runner 替代 SSH 传输，因此不依赖网络和数据库。
type r3ScriptRecorder struct{ cmds []string }

func (r *r3ScriptRecorder) run(command string, _ time.Duration) intranetExecOutcome {
	r.cmds = append(r.cmds, command)
	return intranetExecOutcome{ExitCode: 0}
}

func TestUploadDispatchKeepsScriptFamily(t *testing.T) {
	payload := []byte(strings.Repeat("jingwei-r3-", 8))

	cmdRec := &r3ScriptRecorder{}
	_, _, _, _ = intranetUploadWindows(cmdRec.run, intranetShellCmd, `C:\temp\payload.bin`, payload)
	if len(cmdRec.cmds) == 0 {
		t.Fatal("cmd 会话没有生成任何命令")
	}
	for _, c := range cmdRec.cmds {
		if powershellCmdScriptReason(c) == "" {
			t.Errorf("cmd 会话投递了守卫识别不出的命令（疑似 PS 语法）: %s", c)
		}
	}

	psRec := &r3ScriptRecorder{}
	_, _, _, _ = intranetUploadWindows(psRec.run, intranetShellPowerShell, `C:\temp\payload.bin`, payload)
	if len(psRec.cmds) == 0 {
		t.Fatal("PowerShell 会话没有生成任何命令")
	}
	for _, c := range psRec.cmds {
		if reason := powershellCmdScriptReason(c); reason != "" {
			t.Errorf("PowerShell 会话投递了 cmd 脚本，会被守卫拦下: %s", reason)
		}
	}
}

// r3PSHost 是一台「会真的执行」的 PowerShell 主机替身：大小探测、分块读取、
// 文件大小都按真实返回格式应答，因此能验证整条链路而不是只看第一条命令。
type r3PSHost struct {
	cmds []string
	data []byte
}

func (h *r3PSHost) run(command string, _ time.Duration) intranetExecOutcome {
	h.cmds = append(h.cmds, command)
	out := intranetExecOutcome{ExitCode: 0}
	switch {
	case strings.Contains(command, "__JW_PS__"):
		out.Output = intranetPSMarker + "1\n"
	case strings.Contains(command, ".Length"):
		out.Output = strconv.Itoa(len(h.data)) + "\n"
	case strings.Contains(command, "Test-Path"):
		out.Output = "JW_FILE_NEW\n"
	case strings.Contains(command, intranetChunkMarker):
		// 真实 PS 分块下载返回 gzip 后的 base64；用真实 gzip 才验得到解压那一步。
		out.Output = intranetChunkMarker + r3GzipBase64(h.data) + "\n" + intranetChunkEndMarker
	default:
		out.Output = "OK\n"
	}
	return out
}

func TestDownloadDispatchKeepsScriptFamily(t *testing.T) {
	payload := []byte(strings.Repeat("jingwei-r3-download-", 6))

	psHost := &r3PSHost{data: payload}
	data, total, _, _, out := intranetDownloadWindows(psHost.run, intranetShellPowerShell, `C:\temp\payload.bin`, 1<<20)
	if out.IsError {
		t.Fatalf("PS 会话的下载必须走通，实得失败: %q", out.Note)
	}
	if total != int64(len(payload)) || len(data) != len(payload) {
		t.Fatalf("PS 下载字节数不符：total=%d len=%d 期望=%d", total, len(data), len(payload))
	}
	for _, c := range psHost.cmds {
		if reason := powershellCmdScriptReason(c); reason != "" {
			t.Errorf("PS 下载投递了 cmd 脚本: %s（命令 %q）", reason, c)
		}
	}
}

// 下载的第二条缺口（2026-11-12 修）：PS 会话过去要先探测 powershell.exe 才决定
// 走 PS 分块，而那条探测是 cmd 语法、被守卫拒掉，于是永远落到 certutil 回退。
// 这条断言「PS 会话第一条命令就是 PS 语法」，退化会被直接抓住。
func TestPowerShellDownloadNeverProbesWithCmdSyntax(t *testing.T) {
	host := &r3PSHost{data: []byte("payload")}
	_, _, _, _, _ = intranetDownloadWindows(host.run, intranetShellPowerShell, `C:\temp\payload.bin`, 1<<20)
	if len(host.cmds) == 0 {
		t.Fatal("PS 会话没有投递任何命令")
	}
	if first := host.cmds[0]; strings.Contains(first, "if exist ") {
		t.Fatalf("PS 下载的第一条命令仍是 cmd 语法探测: %q", first)
	}
}

// 权限维持的 Windows 五模块，2026-11-14（R3 批 B 收口）起统一为一族：
//
//   - 全部经 intranetWindowsPSScript（-EncodedCommand）投递——schtasks/registry/service
//     从 cmd 语法（schtasks /create、reg add、sc create）翻转为 PS 原生 cmdlet
//     （Register-ScheduledTask / New-ItemProperty / New-Service）。
//   - 旧 cmd 语法在 PS 5.1 上是语法错误（无 && 管道链、>nul 不合法），PS 会话上
//     整链废——这是批 B 真机实测钉住的缺口，本次翻转把它关掉。
//   - 统一后的命令形态对 cmd 会话同样成立：-EncodedCommand 是单行外部 exe 调用，
//     cmd wrapper 的 `( ... ) &` 与 PS wrapper 的 `& { ... }` 都吃得下；
//     wmi/startup 2026-11-12 起就是这一形态（当时被守卫误判成 cmd 语法而全数拒掉）。
//
// 断言口径：五个模块的 deploy/revoke/verify 都必须被守卫放行，且都是单行
// -EncodedCommand 形态；退化回 cmd 语法会被 decode 后的 cmd 碎片断言抓住。
func TestWindowsPersistModulesScriptFamily(t *testing.T) {
	allKinds := []string{
		db.IntranetArtifactSchtasks, db.IntranetArtifactRegistry, db.IntranetArtifactService,
		db.IntranetArtifactWMI, db.IntranetArtifactStartup,
	}

	for _, kind := range allKinds {
		plan, err := buildIntranetPersistPlan(intranetPersistInput{
			Kind: kind, Command: "whoami", Schedule: "onlogon", Name: "r3",
		})
		if err != nil {
			t.Fatalf("%s 构造失败: %v", kind, err)
		}
		for label, cmd := range map[string]string{"deploy": plan.Deploy, "revoke": plan.Revoke, "verify": plan.Verify} {
			if reason := powershellCmdScriptReason(cmd); reason != "" {
				t.Errorf("%s/%s 是合法 PS 脚本却被守卫拒掉（功能不可用）: %s", kind, label, reason)
			}
			if !strings.Contains(cmd, "-EncodedCommand ") || strings.ContainsAny(cmd, "\n") {
				t.Errorf("%s/%s 必须是单行 -EncodedCommand 形态（双会话通吃）: %s", kind, label, cmd)
			}
		}
	}
}

// r3GzipBase64 把一段明文压成 PS 分块下载返回的形状：gzip + base64。
// 不接 *testing.T，因为它被主机替身的方法调用，出错时只能返回空串。
func r3GzipBase64(data []byte) string {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return ""
	}
	if _, err := zw.Write(data); err != nil {
		return ""
	}
	if err := zw.Close(); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// 信息收集：PS 会话实际投递的是 PShellCmd，9 条 Windows 脚本一条都不能被守卫拦。
func TestWindowsReconScriptsPassGuardOnPowerShell(t *testing.T) {
	checked := 0
	for _, sc := range intranetScriptCatalog {
		if sc.OS != "windows" {
			continue
		}
		deliver := sc.PShellCmd
		if strings.TrimSpace(deliver) == "" {
			deliver = sc.Command
		}
		if reason := powershellCmdScriptReason(deliver); reason != "" {
			t.Errorf("%s 在 PS 会话上会被守卫拦下: %s", sc.ID, reason)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("没有检查到任何 Windows 信息收集脚本")
	}
}
