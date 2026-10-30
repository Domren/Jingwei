package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The nuclei/sqlmap/dalfox wrappers build a long argument list and then parse
// the tool's own output; a regression there silently downgrades every finding
// (a run that never passes -r, a report path that is never read). These tests
// put a recording shell script on PATH so the exact argv and the produced
// output are checked without the real tools installed.

const fakeToolScript = `#!/bin/sh
set -u
log="${FAKE_ARG_LOG:-}"
if [ -n "$log" ]; then
  {
    printf 'CALL\n'
    for a in "$@"; do printf '%s\n' "$a"; done
  } >> "$log"
fi
if [ -n "${FAKE_CAPTURE_DIR:-}" ]; then
  prev=""
  for a in "$@"; do
    case "$prev" in
      -r) cp "$a" "$FAKE_CAPTURE_DIR/request.txt" 2>/dev/null ;;
      -t) cp -r "$a" "$FAKE_CAPTURE_DIR/templates" 2>/dev/null ;;
      -l) cp "$a" "$FAKE_CAPTURE_DIR/targets.txt" 2>/dev/null ;;
    esac
    prev="$a"
  done
fi
if [ -n "${FAKE_REPORT:-}" ]; then
  prev=""
  for a in "$@"; do
    if [ "$prev" = "-o" ]; then cp "$FAKE_REPORT" "$a"; fi
    prev="$a"
  done
fi
if [ "${1:-}" = "--version" ]; then
  printf '%s\n' "${FAKE_VERSION:-1.10.10#stable}"
  exit 0
fi
if [ -n "${FAKE_SLEEP:-}" ]; then exec sleep "$FAKE_SLEEP"; fi
if [ -n "${FAKE_STDOUT:-}" ]; then cat "$FAKE_STDOUT"; fi
if [ -n "${FAKE_STDERR:-}" ]; then cat "$FAKE_STDERR" >&2; fi
exit "${FAKE_EXIT:-0}"
`

func resetToolCaches() {
	sqlmapLookOnce = sync.Once{}
	sqlmapPath, sqlmapLookErr = "", nil
	sqlmapVersionOnce = sync.Once{}
	sqlmapVersionText = ""
	dalfoxLookOnce = sync.Once{}
	dalfoxPath, dalfoxLookErr = "", nil
}

// installFakeTools puts recording nuclei/sqlmap/dalfox scripts first on PATH
// and returns the call log plus a capture directory for their input files.
func installFakeTools(t *testing.T) (logPath, captureDir string) {
	t.Helper()
	binDir := t.TempDir()
	logPath = filepath.Join(binDir, "calls.log")
	captureDir = filepath.Join(binDir, "capture")
	if err := os.MkdirAll(captureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nuclei", "sqlmap", "dalfox"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(fakeToolScript), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_ARG_LOG", logPath)
	t.Setenv("FAKE_CAPTURE_DIR", captureDir)
	resetToolCaches()
	t.Cleanup(resetToolCaches)
	return logPath, captureDir
}

func readFakeCalls(t *testing.T, logPath string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("读取调用记录失败: %v", err)
	}
	var calls [][]string
	var cur []string
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case line == "CALL":
			if cur != nil {
				calls = append(calls, cur)
			}
			cur = []string{}
		case line != "" && cur != nil:
			cur = append(cur, line)
		}
	}
	if cur != nil {
		calls = append(calls, cur)
	}
	return calls
}

func argsHave(args []string, want ...string) bool {
	for i := 0; i+len(want) <= len(args); i++ {
		ok := true
		for j := range want {
			if args[i+j] != want[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestRunNucleiExecutesFakeTool(t *testing.T) {
	_, captureDir := installFakeTools(t)
	stdoutFile := filepath.Join(captureDir, "nuclei.jsonl")
	jsonl := `{"template-id":"test-poc","info":{"name":"Apache Traversal","severity":"high","tags":["apache","lfi"]},"host":"192.0.2.4","matched-at":"http://192.0.2.4/icons/.%2e/etc/passwd","type":"http","timestamp":"2026-10-29T10:00:00Z","curl-command":"curl -X GET http://192.0.2.4/icons/.%2e/etc/passwd","extracted-results":["root:x:0:0"]}` + "\n"
	if err := os.WriteFile(stdoutFile, []byte(jsonl), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_STDOUT", stdoutFile)

	tpl := `id: test-poc
info:
  name: Apache Traversal
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/icons/.%2e/etc/passwd"
    read-size: 1024
    matchers:
      - type: status
        status: [200]
`
	run := RunNuclei(context.Background(),
		[]NucleiTemplate{{ID: "test-poc", Content: tpl}},
		[]string{"http://192.0.2.4/"},
		NucleiOptions{})
	if run.Err != nil {
		t.Fatalf("run error: %v", run.Err)
	}
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(run.Results), run.Results)
	}
	got := run.Results[0]
	if got.TemplateID != "test-poc" || got.Name != "Apache Traversal" || got.Severity != "high" {
		t.Errorf("result = %+v", got)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "apache" {
		t.Errorf("tags = %v, want the info.tags array", got.Tags)
	}
	if len(got.Extracted) != 1 || got.Extracted[0] != "root:x:0:0" {
		t.Errorf("extracted = %v", got.Extracted)
	}
	if run.TemplateCount != 1 || run.TargetCount != 1 || run.Singles != 1 || run.Chains != 0 {
		t.Errorf("counts = tpl %d tgt %d singles %d chains %d", run.TemplateCount, run.TargetCount, run.Singles, run.Chains)
	}

	// The wrapper must pass the safety flags that keep a POC run local and
	// replayable; a missing -store-resp would drop multi-step evidence.
	call := readFakeCalls(t, filepath.Join(filepath.Dir(captureDir), "calls.log"))[0]
	for _, flag := range []string{"-jsonl", "-irr", "-silent", "-no-color", "-disable-update-check", "-no-interactsh", "-store-resp"} {
		if !argsHave(call, flag) {
			t.Errorf("argv缺少 %s: %v", flag, call)
		}
	}
	for _, pair := range [][2]string{{"-rate-limit", "50"}, {"-concurrency", "25"}, {"-timeout", "10"}, {"-retries", "1"}} {
		if !argsHave(call, pair[0], pair[1]) {
			t.Errorf("argv缺少 %s %s: %v", pair[0], pair[1], call)
		}
	}

	// Inputs handed to the tool: the target list and the template file, with
	// the network read-size floor already applied.
	targets, err := os.ReadFile(filepath.Join(captureDir, "targets.txt"))
	if err != nil {
		t.Fatalf("目标文件未写入: %v", err)
	}
	if strings.TrimSpace(string(targets)) != "http://192.0.2.4/" {
		t.Errorf("targets = %q", targets)
	}
	written, err := os.ReadFile(filepath.Join(captureDir, "templates", "0000-test-poc.yaml"))
	if err != nil {
		t.Fatalf("模板未写入: %v", err)
	}
	if !strings.Contains(string(written), "read-size: 16384") {
		t.Errorf("read-size 未提升到下限:\n%s", written)
	}
}

func TestRunSQLMapExecutesFakeTool(t *testing.T) {
	logPath, captureDir := installFakeTools(t)
	stdoutFile := filepath.Join(captureDir, "sqlmap.out")
	if err := os.WriteFile(stdoutFile, []byte(sqlmapRealRun), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_STDOUT", stdoutFile)

	raw := "POST /login HTTP/1.1\nHost: 192.0.2.4\nContent-Type: application/x-www-form-urlencoded\n\nuser=a&pass=b"
	run := RunSQLMap(context.Background(), "http://192.0.2.4/login", SQLMapOptions{
		RawRequest:     raw,
		Level:          2,
		Risk:           1,
		Threads:        3,
		TimeoutSeconds: 7,
		Retries:        1,
		TimeSeconds:    2,
		Techniques:     "BEU",
		DBMS:           "MySQL",
		Cookie:         "PHPSESSID=abc",
		Headers:        []string{"X-Test: 1"},
		Params:         []string{"user"},
		Proxy:          "http://127.0.0.1:8080",
		WallSeconds:    30,
	})
	if run.Err != nil || run.Missing {
		t.Fatalf("run = %+v", run)
	}
	if run.Version != "1.10.10#stable" {
		t.Errorf("version = %q", run.Version)
	}
	if len(run.Injections) != 3 || !run.Found() {
		t.Fatalf("injections = %d, want 3 from the captured run", len(run.Injections))
	}
	if run.DBMS != "MySQL >= 5.6" {
		t.Errorf("dbms = %q", run.DBMS)
	}

	calls := readFakeCalls(t, logPath)
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want --version plus one detection run: %v", len(calls), calls)
	}
	scan := calls[1]
	for _, pair := range [][2]string{
		{"--level", "2"}, {"--risk", "1"}, {"--threads", "3"}, {"--timeout", "7"},
		{"--retries", "1"}, {"--time-sec", "2"}, {"--technique", "BEU"}, {"--dbms", "MySQL"},
		{"--cookie", "PHPSESSID=abc"}, {"-H", "X-Test: 1"}, {"-p", "user"},
		{"--proxy", "http://127.0.0.1:8080"},
	} {
		if !argsHave(scan, pair[0], pair[1]) {
			t.Errorf("argv缺少 %s %s: %v", pair[0], pair[1], scan)
		}
	}
	for _, flag := range []string{"--batch", "--flush-session"} {
		if !argsHave(scan, flag) {
			t.Errorf("argv缺少 %s: %v", flag, scan)
		}
	}
	if !argsHavePrefix(scan, "-r") {
		t.Errorf("raw request not passed with -r: %v", scan)
	}
	req, err := os.ReadFile(filepath.Join(captureDir, "request.txt"))
	if err != nil {
		t.Fatalf("请求文件未写入: %v", err)
	}
	if !strings.Contains(string(req), "\r\nHost: 192.0.2.4\r\n") || !strings.Contains(string(req), "\r\n\r\nuser=a&pass=b") {
		t.Errorf("请求文件不是 CRLF 原始报文: %q", req)
	}

	// URL mode: no -r, target on the command line. The version probe is cached
	// by now, so this run makes a single tool call.
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	run = RunSQLMap(context.Background(), "http://192.0.2.4/item?id=1", SQLMapOptions{WallSeconds: 30})
	if run.Err != nil {
		t.Fatalf("url-mode run error: %v", run.Err)
	}
	urlCalls := readFakeCalls(t, logPath)
	if len(urlCalls) != 1 {
		t.Fatalf("url-mode calls = %d, want 1: %v", len(urlCalls), urlCalls)
	}
	urlCall := urlCalls[0]
	if !argsHave(urlCall, "--url", "http://192.0.2.4/item?id=1") {
		t.Errorf("argv缺少 --url: %v", urlCall)
	}
	if argsHavePrefix(urlCall, "-r") {
		t.Errorf("URL 模式不应传 -r: %v", urlCall)
	}
}

func TestRunDalfoxExecutesFakeTool(t *testing.T) {
	logPath, captureDir := installFakeTools(t)
	reportFile := filepath.Join(captureDir, "dalfox.json")
	if err := os.WriteFile(reportFile, []byte(dalfoxRealReport), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_REPORT", reportFile)

	run := RunDalfox(context.Background(), DalfoxOptions{
		Target:              "http://192.0.2.4/vul/xss/xss_reflected_get.php",
		Method:              "POST",
		Data:                "message=hi&submit=1",
		Params:              []string{"message"},
		Cookie:              "PHPSESSID=abc",
		Headers:             []string{"X-Test: 1"},
		Workers:             4,
		RateLimit:           10,
		TimeoutSeconds:      5,
		ScanTimeoutSeconds:  30,
		MaxPayloadsPerParam: 5,
		Proxy:               "http://127.0.0.1:8080",
		ScopeHost:           "192.0.2.4",
		WallSeconds:         20,
	})
	if run.Err != nil || run.Missing {
		t.Fatalf("run = %+v", run)
	}
	if len(run.Findings) != 1 || run.Vulnerable() != 1 {
		t.Fatalf("findings = %d vulnerable = %d", len(run.Findings), run.Vulnerable())
	}
	if run.Version != "3.2.4" {
		t.Errorf("version = %q", run.Version)
	}

	call := readFakeCalls(t, logPath)[0]
	for _, pair := range [][2]string{
		{"-f", "json"}, {"--workers", "4"}, {"--rate-limit", "10"},
		{"--timeout", "5"}, {"--scan-timeout", "30"}, {"--max-payloads-per-param", "5"},
		{"--only-poc", "v,r,a"}, {"-X", "POST"}, {"-d", "message=hi&submit=1"},
		{"-p", "message"}, {"--cookies", "PHPSESSID=abc"}, {"-H", "X-Test: 1"},
		{"--proxy", "http://127.0.0.1:8080"},
	} {
		if !argsHave(call, pair[0], pair[1]) {
			t.Errorf("argv缺少 %s %s: %v", pair[0], pair[1], call)
		}
	}
	if !argsHave(call, "--include-url", `^https?://192\.0\.2\.4/`) {
		t.Errorf("scope filter missing: %v", call)
	}
	for _, flag := range []string{"--skip-mining", "--include-request", "--include-response", "-S", "--no-color"} {
		if !argsHave(call, flag) {
			t.Errorf("argv缺少 %s: %v", flag, call)
		}
	}
	if !argsHavePrefix(call, "-o") {
		t.Errorf("report path not passed with -o: %v", call)
	}
}

func TestToolsMissingFromPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	resetToolCaches()
	t.Cleanup(resetToolCaches)

	if run := RunSQLMap(context.Background(), "http://192.0.2.4/", SQLMapOptions{}); !run.Missing {
		t.Errorf("sqlmap Missing = false, err = %v", run.Err)
	}
	if run := RunDalfox(context.Background(), DalfoxOptions{Target: "http://192.0.2.4/"}); !run.Missing {
		t.Errorf("dalfox Missing = false, err = %v", run.Err)
	}
	if run := RunNuclei(context.Background(), []NucleiTemplate{{ID: "x", Content: "id: x"}}, []string{"http://192.0.2.4/"}, NucleiOptions{}); run.Err == nil || !strings.Contains(run.Err.Error(), "nuclei 未安装") {
		t.Errorf("nuclei err = %v, want 未安装", run.Err)
	}
}

func TestRunNucleiRejectsEmptyInputs(t *testing.T) {
	if run := RunNuclei(context.Background(), nil, []string{"http://192.0.2.4/"}, NucleiOptions{}); run.Err == nil {
		t.Error("empty templates should error")
	}
	if run := RunNuclei(context.Background(), []NucleiTemplate{{ID: "x", Content: "id: x"}}, nil, NucleiOptions{}); run.Err == nil {
		t.Error("empty targets should error")
	}
}

// A tool that ignores its own --timeout must still be killed at WallSeconds,
// otherwise one hung point holds a deep-task worker forever.
func TestToolTimeoutKillsRun(t *testing.T) {
	installFakeTools(t)
	t.Setenv("FAKE_SLEEP", "5")

	started := time.Now()
	run := RunSQLMap(context.Background(), "http://192.0.2.4/", SQLMapOptions{WallSeconds: 1})
	if !run.TimedOut {
		t.Errorf("sqlmap TimedOut = false, err = %v", run.Err)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Errorf("sqlmap ran %v, wall clock was not enforced", elapsed)
	}

	started = time.Now()
	df := RunDalfox(context.Background(), DalfoxOptions{Target: "http://192.0.2.4/", WallSeconds: 1})
	if !df.TimedOut {
		t.Errorf("dalfox TimedOut = false, err = %v", df.Err)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Errorf("dalfox ran %v, wall clock was not enforced", elapsed)
	}
}

func argsHavePrefix(args []string, flag string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] != "" {
			return true
		}
	}
	return false
}
