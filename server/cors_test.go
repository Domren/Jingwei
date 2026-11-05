package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 管理 API 默认不能给任何站点发跨源许可：能读到漏洞、凭据与内网会话的接口，
// 一旦回 ACAO，同机/同网段的一个恶意页面就能借用户的会话读数据。
// 历史上那个「本机 next dev 跨端口」的例外收进 JINGWEI_DEV_CORS=1，且只对回环。
func TestCORSAllowsOnlyExplicitDevLoopback(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := cors(next)

	do := func(method, host, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://"+host+"/api/health", nil)
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 默认（未开 dev 开关）：无论来源是谁都不回跨源许可。
	for _, c := range []struct{ host, origin string }{
		{"jingwei.corp:8787", "https://evil.example"},
		{"127.0.0.1:8787", "http://127.0.0.1:3000"},
		{"127.0.0.1:8787", "http://evil.example"},
	} {
		rec := do(http.MethodGet, c.host, c.origin)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("默认不该回 ACAO：host=%s origin=%s got=%q", c.host, c.origin, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Fatalf("默认不该回 ACAC：host=%s origin=%s got=%q", c.host, c.origin, got)
		}
	}

	// 打开 dev 开关后：只对回环来源回显，并允许带凭据；外网来源依旧什么都没有。
	t.Setenv("JINGWEI_DEV_CORS", "1")
	rec := do(http.MethodGet, "127.0.0.1:8787", "http://127.0.0.1:3000")
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://127.0.0.1:3000" ||
		rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("dev 模式下回环来源应被放行：%v", rec.Header())
	}
	if rec := do(http.MethodGet, "jingwei.corp:8787", "http://127.0.0.1:3000"); rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("dev 开关只对回环 Host 生效，非回环 Host 不得放行")
	}
	if rec := do(http.MethodGet, "127.0.0.1:8787", "https://evil.example"); rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("dev 开关不该放行外部来源")
	}
	// 预检（OPTIONS）也必须守住。
	if rec := do(http.MethodOptions, "jingwei.corp:8787", "https://evil.example"); rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("evil 预检应 204 且无 ACAO，得到 %d %q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}
