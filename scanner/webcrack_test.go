package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractWebCrackJSON(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"pure json", `{"tool":"webcrack"}`, `{"tool":"webcrack"}`},
		{"banner then json", "欢迎使用ddddocr\n{\"tool\":\"webcrack\",\"results\":[]}", `{"tool":"webcrack","results":[]}`},
		{"noise only", "hello", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		got := extractWebCrackJSON(c.in)
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func writeStubBridge(t *testing.T, payload string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "stubbridge.py")
	body := "import sys\nprint(" + jsonStr(payload) + ")\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestRunWebCrackStub(t *testing.T) {
	result := `{"tool":"webcrack","results":[{"url":"http://127.0.0.1/login","found":true,"username":"admin","password":"123456","kind":"weak","cookie":"PHPSESSID=stub","attempts":58,"elapsed_ms":1600,"request":"POST /login HTTP/1.1\r\n\r\nusername=admin&password=123456&captcha=k76y","response":"HTTP/1.1 200 OK\r\n\r\nok","error":"","captcha":true,"captcha_retries":2,"captcha_ocr_failures":0}],"missing":false,"error":""}`
	t.Setenv("JINGWEI_WEBCRACK_BRIDGE", writeStubBridge(t, result))

	run := RunWebCrack(context.Background(), WebCrackOptions{
		URLs:          []string{"http://127.0.0.1/login"},
		PerURLSeconds: 30,
		DelayMS:       10,
		TimeoutSecond: 60,
	})
	if run.Err != nil {
		t.Fatalf("run error: %v", run.Err)
	}
	if run.Missing {
		t.Fatal("bridge reported missing")
	}
	if len(run.Results) != 1 {
		t.Fatalf("results: %d", len(run.Results))
	}
	r := run.Results[0]
	if !r.Found || r.Username != "admin" || r.Password != "123456" || r.Kind != "weak" {
		t.Fatalf("bad result: %+v", r)
	}
	if r.Cookie != "PHPSESSID=stub" {
		t.Errorf("session cookie = %q", r.Cookie)
	}
	if !strings.Contains(r.Request, "POST /login") || !strings.Contains(r.Response, "200 OK") {
		t.Fatalf("missing evidence: %+v", r)
	}
	if !strings.Contains(r.Request, "captcha=k76y") {
		t.Fatalf("captcha value missing from evidence request: %q", r.Request)
	}
	if !r.Captcha || r.CaptchaRetries != 2 || r.CaptchaOCRFails != 0 {
		t.Fatalf("captcha metadata = %+v", r)
	}
}

func TestRunWebCrackStubNoHit(t *testing.T) {
	result := `{"tool":"webcrack","results":[{"url":"http://127.0.0.1/login","found":false,"attempts":110,"error":""}],"missing":false,"error":""}`
	t.Setenv("JINGWEI_WEBCRACK_BRIDGE", writeStubBridge(t, result))

	run := RunWebCrack(context.Background(), WebCrackOptions{URLs: []string{"http://127.0.0.1/login"}})
	if run.Err != nil {
		t.Fatalf("run error: %v", run.Err)
	}
	if len(run.Results) != 1 || run.Results[0].Found {
		t.Fatalf("expected one not-found result: %+v", run.Results)
	}
}

func TestRunWebCrackNoOutput(t *testing.T) {
	t.Setenv("JINGWEI_WEBCRACK_BRIDGE", writeStubBridge(t, ""))
	run := RunWebCrack(context.Background(), WebCrackOptions{URLs: []string{"http://127.0.0.1/login"}})
	if run.Err == nil || !run.NotFound {
		t.Fatalf("expected no-output error, got %+v", run)
	}
}

func TestRunWebCrackPairModePassesProxyAndPairs(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "argbridge.py")
	body := `import sys, json
args = sys.argv[1:]
stdin = sys.stdin.read() if "--pairs-stdin" in args else ""
print(json.dumps({"tool": "webcrack", "results": [{"url": "http://127.0.0.1/login", "found": False, "error": json.dumps({"args": args, "stdin": stdin})}], "missing": False, "error": ""}))
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JINGWEI_WEBCRACK_BRIDGE", script)

	run := RunWebCrack(context.Background(), WebCrackOptions{
		URLs:  []string{"http://127.0.0.1/login"},
		Pairs: []string{"admin:p@ss:word"},
		Proxy: "socks5://127.0.0.1:1080",
	})
	if run.Err != nil {
		t.Fatalf("run error: %v", run.Err)
	}
	if len(run.Results) != 1 {
		t.Fatalf("results: %d", len(run.Results))
	}
	var captured struct {
		Args  []string `json:"args"`
		Stdin string   `json:"stdin"`
	}
	if err := json.Unmarshal([]byte(run.Results[0].Error), &captured); err != nil {
		t.Fatalf("capture decode: %v (%q)", err, run.Results[0].Error)
	}
	joined := strings.Join(captured.Args, " ")
	if !strings.Contains(joined, "--proxy socks5://127.0.0.1:1080") {
		t.Fatalf("proxy args missing: %q", joined)
	}
	if !strings.Contains(joined, "--pairs-stdin -") {
		t.Fatalf("pairs flag missing: %q", joined)
	}
	if !strings.Contains(captured.Stdin, `"user":"admin"`) || !strings.Contains(captured.Stdin, `"password":"p@ss:word"`) {
		t.Fatalf("stdin payload = %q", captured.Stdin)
	}
}

func TestRunWebCrackRejectsBadPairAndProxy(t *testing.T) {
	t.Setenv("JINGWEI_WEBCRACK_BRIDGE", writeStubBridge(t, `{"tool":"webcrack","results":[]}`))
	if run := RunWebCrack(context.Background(), WebCrackOptions{URLs: []string{"http://x/login"}, Pairs: []string{"nouser"}}); run.Err == nil {
		t.Fatal("expected pair format error")
	}
	if run := RunWebCrack(context.Background(), WebCrackOptions{URLs: []string{"http://x/login"}, Proxy: "ftp://127.0.0.1:21"}); run.Err == nil {
		t.Fatal("expected proxy scheme error")
	}
}
