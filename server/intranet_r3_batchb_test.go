package server

// R3 批 B（2026-11-14 Windows 本机靶机）真机实测实锤的三个实现缺口的回归夹具。
// 三条都在真机上验证过失败形态，这里钉住修复行为，防止回退：
//
//	W1  win-admins 的 GBK 中文段直插 UTF8 库 → SQLSTATE 22021 整条脚本 500
//	W2  cmd 分块 `echo chunk>>file` 块尾数字引入空格 → base64 流错位，1MB 上传全 400
//	W3  PS -EncodedCommand 的 CLIXML 进度流 `</Objs>` 无换行结尾黏住 cmd trailer
//	    → parseIntranetOutput 按行首匹配失配 → startup 等 PS 维持模块全误判
import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// ── W2：cmd 分块写入不得依赖 echo（块尾数字 + `>>` 会被 cmd 撑出空格）───────

func TestCmdUploadChunkAvoidsTrailingDigitSpace(t *testing.T) {
	b64Temp := `"C:\Users\jwlab\jw1.b64"`
	cases := map[string]struct {
		chunk string
		first bool
	}{
		"chunk-ends-digit": {chunk: strings.Repeat("QUJD", 2048) + "4", first: false},
		"chunk-first":      {chunk: strings.Repeat("QUJD", 2048) + "4", first: true},
		"chunk-ends-plus":  {chunk: strings.Repeat("QUJD", 2048) + "+", first: false},
	}
	for name, c := range cases {
		cmd := intranetCmdUploadChunkCmd(c.chunk, b64Temp, c.first)
		if strings.Contains(cmd, "echo ") {
			t.Errorf("%s: 仍用 echo 写块——块尾数字会被 cmd 的句柄解析引入空格: %s", name, cmd[:80])
		}
		if !strings.Contains(cmd, `<nul set /p="`) {
			t.Errorf("%s: 必须用 <nul set /p 无换行写入（块尾与 >> 之间要隔着引号）: %s", name, cmd[:80])
		}
		// chunk 必须被引号完整括住：尾字符之后紧贴闭引号，再接重定向。
		if !strings.Contains(cmd, c.chunk+`"`) {
			t.Errorf("%s: chunk 尾部没有被引号闭合，句柄语义仍可能触发: %s", name, cmd[:80]+"...")
		}
		// set /p 在 <nul 空输入下置 ERRORLEVEL=1，必须显式归零，否则 trailer
		// 会把每一块都误标为失败。
		if !strings.Contains(cmd, "cmd /c exit 0") {
			t.Errorf("%s: 缺少 ERRORLEVEL 归零，块写入会被 trailer 误判失败: %s", name, cmd[:80]+"...")
		}
		// chunk 是平台生成的 base64，不含引号；引号数=chunk 开+闭+b64Temp 路径开+闭=4，
		// 多出说明 chunk 或路径被破坏。
		if strings.Count(cmd, `"`) != 4 {
			t.Errorf("%s: 引号数量异常，chunk 或路径可能被破坏: %s", name, cmd[:80]+"...")
		}
	}
}

// ── W3：parseIntranetOutput 要能解析被 CLIXML 黏住的 trailer ────────────────

func TestParseIntranetOutputCLIXMLGluedTrailer(t *testing.T) {
	// 真机实拍（Win11 22631，PS 5.1 -EncodedCommand，会话 #17）：
	// `</Objs>` 无换行结尾，cmd 的 trailer 被黏在同一行。
	raw := "#< CLIXML\r\nJW_ARTIFACT_OK\r\n" +
		`<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><MS><I64 N="SourceId">1</I64><T>Completed</T></MS></Obj></Objs>` +
		"__JW_EC__0 \r\n__JW_CWD__ \r\nC:\\Users\\jwlab\r\n"
	output, cwd, code, ok := parseIntranetOutput(raw)
	if !ok {
		t.Fatalf("黏着 trailer 必须能解析（startup 等 PS 模块依赖它），raw 尾部: %q", raw[len(raw)-80:])
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if cwd != `C:\Users\jwlab` {
		t.Errorf("cwd = %q", cwd)
	}
	if !strings.Contains(output, "JW_ARTIFACT_OK") {
		t.Errorf("output 丢失部署成功标记: %q", output)
	}
	if strings.Contains(output, "<Objs") {
		t.Errorf("CLIXML 尾巴应随标记行一起被截掉: %q", output)
	}

	// 同形态但退出码非零（黏在 XML 尾部）。
	_, _, code2, ok2 := parseIntranetOutput("x</Objs>__JW_EC__2 \r\n__JW_CWD__ \r\nC:\\\r\n")
	if !ok2 || code2 != 2 {
		t.Fatalf("glued nonzero: code=%d ok=%v", code2, ok2)
	}
}

// ── W3：PS 维持模块脚本必须自带进度流关闭 ──────────────────────────────────

func TestWindowsPSScriptSuppressesProgressStream(t *testing.T) {
	script := intranetWindowsPSScript("Write-Output 'JW_ARTIFACT_OK'\n")
	const marker = `-EncodedCommand `
	i := strings.Index(script, marker)
	if i < 0 {
		t.Fatalf("不是 -EncodedCommand 形式: %s", script)
	}
	enc := strings.TrimSpace(script[i+len(marker):])
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("EncodedCommand 解码失败: %v", err)
	}
	// UTF-16LE 解回文本（前缀全 ASCII，截奇数字节即得原文；中文段截坏无妨）。
	var text strings.Builder
	for j := 0; j+1 < len(raw); j += 2 {
		text.WriteByte(raw[j])
	}
	if !strings.HasPrefix(text.String(), "$ProgressPreference='SilentlyContinue'") {
		t.Fatalf("PS 脚本未以 $ProgressPreference 开头（CLIXML 会黏住 cmd trailer）: %q", text.String()[:min(40, len(text.String()))])
	}
}

// ── W1：脚本输出的 GBK 中文段必须转码后才能入库 ─────────────────────────────

func TestIntranetValidUTF8TextMendsGBKSegments(t *testing.T) {
	// 真机形态：chcp 65001 前缀下 net localgroup 的英文段是合法 UTF-8（ASCII），
	// 中文段（命令成功完成。）按 OEM 代码页 936 输出。
	cn, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte("命令成功完成。"))
	if err != nil {
		t.Fatalf("GBK 编码失败: %v", err)
	}
	raw := "The command completed successfully." + string(cn) + "\r\njwlab\r\n"
	if utf8.ValidString(raw) {
		t.Fatal("前置条件失败：构造的输入应含无效 UTF-8 段")
	}
	got := intranetValidUTF8Text(raw)
	if !utf8.ValidString(got) {
		t.Fatalf("清洗后仍含无效 UTF-8: %q", got)
	}
	if !strings.Contains(got, "命令成功完成。") {
		t.Errorf("GBK 段未还原成中文: %q", got)
	}
	if !strings.Contains(got, "The command completed successfully.") {
		t.Errorf("合法 ASCII 段被破坏: %q", got)
	}

	// 合法 UTF-8 中文原样返回，绝不做 GBK 重解释。
	keep := "计划任务 /tmp/任务 ✓"
	if got := intranetValidUTF8Text(keep); got != keep {
		t.Fatalf("合法 UTF-8 被改写: %q -> %q", keep, got)
	}

	// UTF-8 主体夹个别坏字节：坏字节换 FFFD，合法中文必须原样保留——
	// 这种形态下整体按 GBK 转会把整段中文毁成乱码。
	good := "任务清单 task" + string([]byte{0xDC}) + "end"
	if utf8.ValidString(good) {
		t.Fatal("前置条件失败：构造的输入应含无效字节")
	}
	got2 := intranetValidUTF8Text(good)
	if !utf8.ValidString(got2) {
		t.Fatalf("清洗后仍无效: %q", got2)
	}
	if !strings.Contains(got2, "任务清单 task") || !strings.Contains(got2, "end") {
		t.Errorf("UTF-8 主体被 GBK 转码破坏: %q -> %q", good, got2)
	}

	// GBK 也解不出的纯坏字节：兜底替换，永不 500。
	bad := "ok" + string([]byte{0xDC, 0xFE}) + "end"
	if got := intranetValidUTF8Text(bad); !utf8.ValidString(got) {
		t.Fatalf("兜底后仍无效: %q", got)
	}
}
