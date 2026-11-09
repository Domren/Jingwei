package scanner

import (
	"context"
	"strings"
	"testing"
)

// D1：浏览器验证的纯逻辑部分。真跑 Chromium 的用例由 tools/e2e/xss-browser-check.sh
// 在镜像内执行（镜像里有 node + playwright + chromium），这里只钉输出契约与计数。

func TestBrowserXSSRunCounts(t *testing.T) {
	run := BrowserXSSRun{Results: []BrowserXSSResult{
		{URL: "http://a/1", Executed: true, Reflected: true},
		{URL: "http://a/2", Executed: false, Reflected: true},
		{URL: "http://a/3", Executed: false, Reflected: false},
	}}
	if got := run.ExecutedCount(); got != 1 {
		t.Fatalf("ExecutedCount = %d", got)
	}
	if got := run.ReflectedOnly(); got != 1 {
		t.Fatalf("ReflectedOnly = %d", got)
	}
}

func TestLastJSONLine(t *testing.T) {
	out := `(node:1) [DEP0169] DeprecationWarning: url.parse
{"version":"1.64.1","results":[{"url":"http://x","executed":true}]}`
	line := lastJSONLine(out)
	if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"executed":true`) {
		t.Fatalf("line = %s", line)
	}
}

func TestRunBrowserXSSEmptyTargets(t *testing.T) {
	run := RunBrowserXSS(context.Background(), BrowserXSSOptions{})
	if run.Err == nil {
		t.Fatal("expected an error for an empty target list")
	}
}
