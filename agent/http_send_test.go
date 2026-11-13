package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// worker 接线时 proxyCACert 传的是**文件路径**（与 CURL_CA_BUNDLE 同一口径），而
// http_send 需要 PEM 内容。11-13 实机就是因此报「代理 CA 无法解析」：工具直接不可用，
// 模型只能退回 Bash+curl（正是 R20 要收口的那条路）。这里两条都钉住：
// 路径能读成内容、端到端能信任该 CA 完成 HTTPS。
func TestHTTPSendTrustsCAFromFilePath(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tls-pong"))
	}))
	defer srv.Close()

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	dir := t.TempDir()
	caPath := filepath.Join(dir, "mitmproxy-ca-cert.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	ts := &ToolSet{}
	ts.SetHTTPProxy("", caPath) // 生产接线的形态：传路径
	if !strings.Contains(ts.httpCACert, "BEGIN CERTIFICATE") {
		t.Fatalf("路径应被读成 PEM 内容，实际 %q", ts.httpCACert[:min(40, len(ts.httpCACert))])
	}

	in, _ := json.Marshal(map[string]any{"url": srv.URL + "/tls", "method": "GET"})
	res, err := ts.runHTTPSend(context.Background(), in)
	if err != nil {
		t.Fatalf("信任该 CA 后 HTTPS 应成功：%v", err)
	}
	if out := res.Flatten(); !strings.Contains(out, "tls-pong") {
		t.Fatalf("响应正文应回传，实际 %s", out)
	}
}

// 直接传 PEM 文本的老夹具形态不能坏（http_send_test 的 httptest 用例都这么用）。
func TestLoadCACertPEMPassthrough(t *testing.T) {
	pemText := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	// 入参会被 TrimSpace（与 SetHTTPProxy 的归一一致），比较时同样去掉尾部空白。
	if got := loadCACertPEM(pemText); strings.TrimSpace(got) != strings.TrimSpace(pemText) {
		t.Fatalf("PEM 文本应原样返回，实际 %q", got)
	}
	if got := loadCACertPEM(""); got != "" {
		t.Fatalf("空值应返回空串，实际 %q", got)
	}
	if got := loadCACertPEM("/nonexistent/ca.pem"); got != "/nonexistent/ca.pem" {
		t.Fatalf("读不到的文件应原样返回（让上层报无法解析），实际 %q", got)
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
