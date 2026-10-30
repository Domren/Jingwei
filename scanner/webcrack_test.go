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
	result := `{"tool":"webcrack","results":[{"url":"http://127.0.0.1/login","found":true,"username":"admin","password":"123456","kind":"weak","attempts":58,"elapsed_ms":1600,"request":"POST /login HTTP/1.1\r\n\r\nusername=admin","response":"HTTP/1.1 200 OK\r\n\r\nok","error":""}],"missing":false,"error":""}`
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
	if !strings.Contains(r.Request, "POST /login") || !strings.Contains(r.Response, "200 OK") {
		t.Fatalf("missing evidence: %+v", r)
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
