package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeDump stores one nuclei -store-resp dump file under root.
func writeDump(t *testing.T, root, name, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "http"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "http", name), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The session a login-gated POC used is the one thing a report reader and
// sqlmap/dalfox both need, and nuclei redacts it in the JSON it prints. When the
// hit's own exchange cannot be matched in the dumps, the session still has to
// come back from any other request that template sent to the same host.
func TestApplyStoredExchangesRestoresSessionFromTemplateDumps(t *testing.T) {
	root := t.TempDir()
	writeDump(t, root, "lab_xss_post.txt", `[pikachu-xss-post-reflected] Dumped HTTP request for http://lab/vul/xss/xsspost/admin_login.php

POST /vul/xss/xsspost/admin_login.php HTTP/1.1
Host: lab
Cookie: PHPSESSID=vlj14m24vbidk8vr94f0qgkbjd

username=admin&password=123456&submit=Login

[pikachu-xss-post-reflected] Dumped HTTP response http://lab/vul/xss/xsspost/admin_login.php

HTTP/1.1 302 Found
Location: /vul/xss/xsspost/xss_reflected_post.php

`)
	result := NucleiResult{
		TemplateID: "pikachu-xss-post-reflected",
		MatchedAt:  "http://lab/vul/xss/xsspost/xss_reflected_post.php",
		Request:    "POST /vul/xss/xsspost/xss_reflected_post.php HTTP/1.1\r\nCookie: ***\r\n\r\nmessage=1",
		Curl:       `curl -X 'POST' -d 'message=1' -H 'Cookie: ***' -H 'Host: lab' 'http://lab/vul/xss/xsspost/xss_reflected_post.php'`,
		Raw:        map[string]any{"curl-command": `curl -H 'Cookie: ***' 'http://lab/x'`},
	}
	results := []NucleiResult{result}
	applyStoredExchanges(results, root)
	got := results[0]
	for name, text := range map[string]string{"request": got.Request, "curl": got.Curl, "raw": asString(got.Raw["curl-command"])} {
		if strings.Contains(text, "Cookie: ***") {
			t.Errorf("%s still masked: %s", name, text)
		}
		if !strings.Contains(text, "PHPSESSID=vlj14m24vbidk8vr94f0qgkbjd") {
			t.Errorf("%s lost the session: %s", name, text)
		}
	}
	// The proof exchange is missing from the dumps, so the packet itself stays
	// as printed; only the session value is filled in.
	if !strings.HasPrefix(got.Request, "POST /vul/xss/xsspost/xss_reflected_post.php") {
		t.Errorf("proof request was replaced by the login exchange: %q", got.Request)
	}
}

func TestUnmaskAuthHeaders(t *testing.T) {
	session := map[string]string{"cookie": "sid=real; tok=9", "authorization": "Bearer jwt.token.value"}
	cases := []struct{ name, in, want string }{
		{"raw packet", "GET /a HTTP/1.1\r\nCookie: ***\r\n\r\n", "GET /a HTTP/1.1\r\nCookie: sid=real; tok=9\r\n\r\n"},
		{"curl single quote", `curl -H 'Cookie: ***' 'http://a'`, `curl -H 'Cookie: sid=real; tok=9' 'http://a'`},
		{"curl double quote", `curl -H "Authorization: ***" 'http://a'`, `curl -H "Authorization: Bearer jwt.token.value" 'http://a'`},
		{"lowercase name", "get /a HTTP/1.1\r\ncookie: ***\r\n\r\n", "get /a HTTP/1.1\r\ncookie: sid=real; tok=9\r\n\r\n"},
		{"unrelated stars", `curl 'http://a?x=***'`, `curl 'http://a?x=***'`},
	}
	for _, c := range cases {
		if out := unmaskAuthHeaders(c.in, session); out != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, out, c.want)
		}
	}
	// A session carrying a quote would split curl's single-quoted argument, so
	// the placeholder stays rather than printing a command that cannot run.
	quoted := unmaskAuthHeaders(`curl -H 'Cookie: ***' 'http://a'`, map[string]string{"cookie": "sid=it's"})
	if !strings.Contains(quoted, "Cookie: ***") {
		t.Errorf("quoted session was written into a curl argument: %q", quoted)
	}
	if got := realAuthHeaders("POST /a HTTP/1.1\r\nCookie: sid=real\r\nHost: a\r\n\r\nCookie: nope"); len(got) != 1 || got["cookie"] != "sid=real" {
		t.Errorf("realAuthHeaders = %#v", got)
	}
	if got := realAuthHeaders("GET /a HTTP/1.1\r\nCookie: ***\r\n\r\n"); len(got) != 0 {
		t.Errorf("masked value accepted as real: %#v", got)
	}
}
