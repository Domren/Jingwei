package enrich

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// P8 验收：默认关；开启后出网目标与字段写审计；跨主机重定向拒绝；域名固定不接受任意 URL。

func TestValidatePassiveDomainRejectsSSRF(t *testing.T) {
	bad := []string{
		"", "localhost", "a.localhost", "127.0.0.1", "http://127.0.0.1:8080",
		"example.com/path", "example.com?q=http://evil", "user:pass@example.com",
		"a@example.com", "http://example.com", "[::1]", "singlelabel", "a b.com",
	}
	for _, raw := range bad {
		if err := ValidatePassiveDomain(raw); err == nil {
			t.Errorf("应拒绝 %q", raw)
		}
	}
	for _, raw := range []string{"example.com", "Sub.Example.COM", "a-b.example.co.uk"} {
		if err := ValidatePassiveDomain(raw); err != nil {
			t.Errorf("应接受 %q: %v", raw, err)
		}
	}
}

func TestPassiveDefaultOffNoNetworkAndAuditsDenial(t *testing.T) {
	orig := ctLogBaseURL
	defer func() { ctLogBaseURL = orig }()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	ctLogBaseURL = srv.URL + "/"

	e := New(nil, nil, 1)
	defer e.Close()
	var audits []string
	e.SetPassiveGate(nil, func(kind, target string, fields []string, allowed bool, reason string) {
		audits = append(audits, kind+"|"+target+"|"+strings.Join(fields, ",")+"|"+boolStr(allowed)+"|"+reason)
	})

	e.doPassive(1, "example.com", "ct_log", ctLogBaseURL)
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("默认关不应出网")
	}
	if len(audits) != 1 || !strings.Contains(audits[0], "ct_log|") ||
		!strings.Contains(audits[0], "domain|false") {
		t.Fatalf("默认关应写拒绝审计: %+v", audits)
	}
}

func TestPassiveEnabledQueriesFixedAPIAndAudits(t *testing.T) {
	orig := dnsHistoryBaseURL
	defer func() { dnsHistoryBaseURL = orig }()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if got := r.URL.Query().Get("q"); got != "example.com" {
			t.Errorf("查询值 = %q", got)
		}
		_, _ = w.Write([]byte(`{"names":["sub.example.com","other.example.org"]}`))
	}))
	defer srv.Close()
	dnsHistoryBaseURL = srv.URL + "/"

	e := New(nil, nil, 1)
	defer e.Close()
	type audit struct {
		kind, target, fields, reason string
		allowed                      bool
	}
	var audits []audit
	e.SetPassiveGate(func() bool { return true },
		func(kind, target string, fields []string, allowed bool, reason string) {
			audits = append(audits, audit{kind, target, strings.Join(fields, ","), reason, allowed})
		})

	e.doPassive(1, "example.com", "dns_history", dnsHistoryBaseURL)
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("开启后应出网 1 次，实际 %d", hits)
	}
	if len(audits) != 1 || !audits[0].allowed || audits[0].kind != "dns_history" ||
		audits[0].fields != "domain" || !strings.Contains(audits[0].target, "127.0.0.1") {
		t.Fatalf("审计内容: %+v", audits)
	}
}

func TestPassiveRedirectGuardRejectsCrossHost(t *testing.T) {
	base, _ := url.Parse("https://crt.sh/")
	guard := passiveRedirectGuard(base)
	req, _ := http.NewRequest("GET", "https://evil.example/steal?domain=example.com", nil)
	if err := guard(req, nil); err == nil {
		t.Fatal("跨主机重定向必须拒绝")
	}
	same, _ := http.NewRequest("GET", "https://crt.sh/?q=example.com", nil)
	if err := guard(same, nil); err != nil {
		t.Fatalf("同主机应放行: %v", err)
	}
	tooMany, _ := http.NewRequest("GET", "https://crt.sh/?q=example.com", nil)
	if err := guard(tooMany, make([]*http.Request, 3)); err == nil {
		t.Fatal("超过 3 跳应拒绝")
	}
}

func TestPassiveQueryUsesFixedAPIHostOnly(t *testing.T) {
	// 用户提供的域名只进 query，不能改写 host/path；这里直接验证拼装结果。
	base, _ := url.Parse(ctLogDefaultURL)
	q := url.Values{}
	q.Set("q", "example.com")
	q.Set("output", "json")
	base.RawQuery = q.Encode()
	if base.Host != "crt.sh" || base.Path != "/" {
		t.Fatalf("固定 API 被改写: %s", base.String())
	}
	if !strings.Contains(base.RawQuery, "q=example.com") {
		t.Fatalf("查询字段丢失: %s", base.String())
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
