package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// 欠账 R20 的回归夹具。
//
// 口径不是「我们打算发什么」，而是「靶机那侧收到了什么」——过去正是因为只看代码里
// 写的那一行，才让 "Jingwei-CredScan" / "Jingwei-DirScan" 活了两版。
//
// 三条断言：
//  1. 默认口径下，收到的是浏览器 UA，且不含任何自研品牌子串；
//  2. JINGWEI_OUTBOUND_UA=none 时，**整条 UA 头都不出现**（而不是空值）；
//  3. 自定义串时原样发出，便于对齐客户既有流量画像。

func resetOutboundUA(t *testing.T) {
	t.Helper()
	// BrowserUA 用 sync.Once 缓存，跨用例串味；用子测试时必须重置。
	outboundUAOnce = sync.Once{}
	outboundUA = ""
	t.Cleanup(func() {
		outboundUAOnce = sync.Once{}
		outboundUA = ""
	})
}

// forbiddenBrands 是任何出站报文头里都不该出现的自研标识。
var forbiddenBrands = []string{"jingwei", "Jingwei", "JINGWEI", "sentinel", "Sentinel"}

func assertNoBrandLeak(t *testing.T, ua string) {
	t.Helper()
	for _, bad := range forbiddenBrands {
		if strings.Contains(ua, bad) {
			t.Fatalf("出站 UA 含自研品牌 %q：%q", bad, ua)
		}
	}
}

func TestBrowserUADefaultHasNoBrand(t *testing.T) {
	resetOutboundUA(t)
	t.Setenv("JINGWEI_OUTBOUND_UA", "")

	ua := BrowserUA()
	if ua == "" {
		t.Fatal("默认口径下 UA 不应为空")
	}
	assertNoBrandLeak(t, ua)
	if !strings.Contains(ua, "Mozilla/5.0") {
		t.Fatalf("默认口径应为浏览器串，实际：%q", ua)
	}
	// 与 deepuse 同口径：同一平台不该同时出现两种浏览器串。
	if ua != deepUserAgent {
		t.Fatalf("默认 UA 与 deepuse 不一致：%q vs %q", ua, deepUserAgent)
	}
}

func TestBrowserUANoneEmitsNoHeader(t *testing.T) {
	resetOutboundUA(t)
	t.Setenv("JINGWEI_OUTBOUND_UA", "none")

	if ua := BrowserUA(); ua != "" {
		t.Fatalf("none 口径应返回空串，实际 %q", ua)
	}
	if line := uaHeaderLine(); line != "" {
		t.Fatalf("none 口径不应产生 UA 头行，实际 %q", line)
	}

	h := http.Header{}
	h.Set("User-Agent", "stale")
	ApplyBrowserUA(h.Set, h.Del)
	if got := h.Get("User-Agent"); got != "" {
		t.Fatalf("none 口径下应删除已有 UA，实际 %q", got)
	}
}

func TestBrowserUACustomIsVerbatim(t *testing.T) {
	resetOutboundUA(t)
	const custom = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
	t.Setenv("JINGWEI_OUTBOUND_UA", custom)

	if ua := BrowserUA(); ua != custom {
		t.Fatalf("自定义 UA 应原样使用，实际 %q", ua)
	}
}

// 非法值（含 CRLF）必须退回默认，而不是把换行带进报文头造成头注入。
func TestBrowserUARejectsCRLF(t *testing.T) {
	resetOutboundUA(t)
	t.Setenv("JINGWEI_OUTBOUND_UA", "evil\r\nX-Injected: 1")

	ua := BrowserUA()
	if strings.ContainsAny(ua, "\r\n") {
		t.Fatalf("UA 不得含换行：%q", ua)
	}
	assertNoBrandLeak(t, ua)
}

// 端到端：靶机那侧收到的请求头里不能有自研品牌。
func TestDirFetchSendsNoBrandUserAgent(t *testing.T) {
	resetOutboundUA(t)
	t.Setenv("JINGWEI_OUTBOUND_UA", "")

	var gotUA string
	var gotUAExists bool
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		vals, ok := r.Header["User-Agent"]
		gotUAExists = ok
		if len(vals) > 0 {
			gotUA = vals[0]
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	if _, _, _, _, _, err := dirFetch(t.Context(), srv.Client(), srv.URL+"/probe"); err != nil {
		t.Fatalf("dirFetch 失败：%v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !gotUAExists || gotUA == "" {
		t.Fatal("默认口径下靶机应收到 UA 头")
	}
	assertNoBrandLeak(t, gotUA)
}

// 取证副本（req 字节）必须与真实出站一致：不发 UA 时那一行不能凭空出现。
func TestDirFetchEvidenceMatchesNoUA(t *testing.T) {
	resetOutboundUA(t)
	t.Setenv("JINGWEI_OUTBOUND_UA", "none")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, _, _, reqBytes, _, err := dirFetch(t.Context(), srv.Client(), srv.URL+"/probe")
	if err != nil {
		t.Fatalf("dirFetch 失败：%v", err)
	}
	if strings.Contains(strings.ToLower(string(reqBytes)), "user-agent") {
		t.Fatalf("none 口径下取证副本不应含 UA 行，实际：\n%s", reqBytes)
	}
}

// credscan 的两条报文构造路径（HTTP 适配器与表单）同样不能带品牌。
func TestCredScanRequestsCarryNoBrand(t *testing.T) {
	resetOutboundUA(t)
	t.Setenv("JINGWEI_OUTBOUND_UA", "")

	httpReq := httpCredAdapter{protocol: "web-basic", method: "GET"}.request("/", "")
	assertNoBrandLeak(t, string(httpReq))
	if ua := uaHeaderLine(); ua != "" && !strings.Contains(string(httpReq), ua) {
		t.Fatalf("HTTP 适配器报文应包含统一 UA 行")
	}

	formReq := formRequest("POST", "/login", "example.test", nil, "user=a&pass=b")
	assertNoBrandLeak(t, string(formReq))
	if ua := uaHeaderLine(); ua != "" && !strings.Contains(string(formReq), ua) {
		t.Fatalf("表单报文应包含统一 UA 行")
	}
}
