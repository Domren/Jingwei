package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// R20 序 5：http_send 的 UA 收口、curl 兜底与 round-trip。

// 调用方给的 User-Agent 一律被覆盖为平台浏览器串（默认环境 BrowserUA() = 内置串）。
// 反向验证：把 forceBrowserUA 改回「调用方优先」，本用例的 curl UA 会原样穿透——
// 那正是 11-11 实机抓到的指纹残留路径。
func TestForceBrowserUAOverridesCallerHeader(t *testing.T) {
	out := forceBrowserUA(map[string]string{
		"User-Agent":   "curl/7.88.1",
		"X-Probe":      "1",
		"CONTENT-TYPE": "application/json",
	})
	ua := out["User-Agent"]
	if ua == "" || ua == "curl/7.88.1" {
		t.Fatalf("caller UA must be overridden, got %q", ua)
	}
	if strings.Contains(strings.ToLower(ua), "curl/") || strings.Contains(strings.ToLower(ua), "jingwei") {
		t.Fatalf("UA must be the platform browser string without tool fingerprints, got %q", ua)
	}
	if out["X-Probe"] != "1" || out["CONTENT-TYPE"] != "application/json" {
		t.Fatalf("other headers must pass through, got %+v", out)
	}
}

func TestCurlRCContentPinsPlatformUA(t *testing.T) {
	c := curlRCContent()
	if c == "" {
		t.Fatal("default env must produce a .curlrc")
	}
	if !strings.Contains(c, `user-agent = "`) {
		t.Fatalf(".curlrc must pin the default UA, got %q", c)
	}
	if strings.Contains(strings.ToLower(c), "curl/") || strings.Contains(strings.ToLower(c), "jingwei") {
		t.Fatalf(".curlrc must not carry tool fingerprint, got %q", c)
	}
}

// 端到端：httptest 本地服务直连（无代理），断言服务端看到的 UA 是平台浏览器串
// （调用方给的 curl UA 被覆盖）、响应回传状态码与正文。
func TestHTTPSendRoundTripForcesUA(t *testing.T) {
	var seenUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("pong-body"))
	}))
	defer srv.Close()

	ts := &ToolSet{}
	in, _ := json.Marshal(map[string]any{
		"url":     srv.URL + "/probe",
		"method":  "GET",
		"headers": map[string]string{"User-Agent": "curl/7.88.1"},
	})
	res, err := ts.runHTTPSend(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	out := res.Flatten()
	if !strings.Contains(out, `"status":200`) {
		t.Fatalf("status 200 expected in result, got %s", out)
	}
	if !strings.Contains(out, "pong-body") {
		t.Fatalf("body expected in result, got %s", out)
	}
	if seenUA == "" || seenUA == "curl/7.88.1" || strings.Contains(strings.ToLower(seenUA), "jingwei") {
		t.Fatalf("server must see the forced platform UA, got %q", seenUA)
	}
}
