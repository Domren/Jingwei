package scanner

import (
	"strings"
	"testing"
)

// nuclei leaves the raw request out of many hits, so the POST body a POC
// injected with survives only in its curl command.
func TestParseCurlRequest(t *testing.T) {
	cases := []struct {
		name       string
		curl       string
		wantMethod string
		wantURL    string
		wantBody   string
		wantCookie string
		ok         bool
	}{
		{
			name:       "post form",
			curl:       `curl -X 'POST' -d 'id=1'\''&submit=1' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Host: 192.0.2.4' 'http://192.0.2.4/vul/sqli/sqli_id.php'`,
			wantMethod: "POST",
			wantURL:    "http://192.0.2.4/vul/sqli/sqli_id.php",
			wantBody:   "id=1'&submit=1",
			ok:         true,
		},
		{
			name:       "stored xss body",
			curl:       `curl -X 'POST' -d 'message=%3Cscript%3Ealert%28%27PKAJW%27%29%3C%2Fscript%3E&submit=%E6%8F%90%E4%BA%A4' -H 'Cookie: PHPSESSID=abc123' 'http://192.0.2.4/vul/xss/xss_stored.php'`,
			wantMethod: "POST",
			wantURL:    "http://192.0.2.4/vul/xss/xss_stored.php",
			wantBody:   "message=%3Cscript%3Ealert%28%27PKAJW%27%29%3C%2Fscript%3E&submit=%E6%8F%90%E4%BA%A4",
			wantCookie: "PHPSESSID=abc123",
			ok:         true,
		},
		{
			name:       "get with empty data",
			curl:       `curl -X 'GET' -d '' -H 'Host: 192.0.2.4' 'http://192.0.2.4/vul/sqli/sqli_str.php?name=kobe%27&submit=1'`,
			wantMethod: "GET",
			wantURL:    "http://192.0.2.4/vul/sqli/sqli_str.php?name=kobe%27&submit=1",
			ok:         true,
		},
		{
			name: "no url",
			curl: `curl -X 'POST' -d 'a=1'`,
			ok:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseCurlRequest(tc.curl)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if got.Method != tc.wantMethod || got.URL != tc.wantURL || got.Body != tc.wantBody {
				t.Fatalf("got %+v\nwant method=%q url=%q body=%q", got, tc.wantMethod, tc.wantURL, tc.wantBody)
			}
			if got.Cookie != tc.wantCookie {
				t.Errorf("cookie = %q, want %q", got.Cookie, tc.wantCookie)
			}
			for _, h := range got.Headers {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(h)), "cookie") ||
					strings.HasPrefix(strings.ToLower(strings.TrimSpace(h)), "host") {
					t.Errorf("session/host header should not be a plain header: %q", h)
				}
			}
		})
	}
}

func TestCurlTokensKeepsQuotedPayloads(t *testing.T) {
	got := curlTokens(`curl -H "User-Agent: sqlmap/1.10 'test'" -d a=1 --compressed 'http://h/p?x=1 y'`)
	want := []string{"-H", "User-Agent: sqlmap/1.10 'test'", "-d", "a=1", "--compressed", "http://h/p?x=1 y"}
	if len(got) != len(want) {
		t.Fatalf("tokens = %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token %d = %q, want %q (all: %q)", i, got[i], want[i], got)
		}
	}
}
