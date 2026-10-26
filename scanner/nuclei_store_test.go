package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseNucleiStoreKeepsUnredactedPackets(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "http"), 0o700); err != nil {
		t.Fatal(err)
	}
	dump := `[dvwa-sqli-auth] Dumped HTTP request for http://192.0.2.4/login.php

GET /login.php HTTP/1.1
Host: 192.0.2.4
User-Agent: Mozilla/5.0

[dvwa-sqli-auth] Dumped HTTP response http://192.0.2.4/login.php

HTTP/1.1 200 OK
Set-Cookie: PHPSESSID=abc123; path=/

<html>login</html>

[dvwa-sqli-auth] Dumped HTTP request for http://192.0.2.4/vulnerabilities/sqli/?id=1%27&Submit=Submit

GET /vulnerabilities/sqli/?id=1%27&Submit=Submit HTTP/1.1
Host: 192.0.2.4
User-Agent: Mozilla/5.0
Cookie: PHPSESSID=abc123; security=low

[dvwa-sqli-auth] Dumped HTTP response http://192.0.2.4/vulnerabilities/sqli/?id=1%27&Submit=Submit

HTTP/1.1 200 OK
Content-Type: text/html

<pre>You have an error in your SQL syntax</pre>
`
	if err := os.WriteFile(filepath.Join(root, "http", "172_23_0_4_dvwa_sqli_auth.txt"), []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	store := ParseNucleiStore(root)
	if len(store.ByURL) != 2 {
		t.Fatalf("want 2 exchanges, got %d: %#v", len(store.ByURL), store.ByURL)
	}
	matched, ok := store.ByURL["dvwa-sqli-auth|http://192.0.2.4/vulnerabilities/sqli/?id=1%27&Submit=Submit"]
	if !ok {
		t.Fatalf("matched exchange missing: %#v", store.ByURL)
	}
	if !strings.Contains(matched.Request, "Cookie: PHPSESSID=abc123; security=low") {
		t.Fatalf("cookie was not preserved:\n%s", matched.Request)
	}
	if strings.Contains(matched.Request, "Cookie: ***") {
		t.Fatalf("request is still redacted:\n%s", matched.Request)
	}
	if !strings.Contains(matched.Response, "You have an error in your SQL syntax") {
		t.Fatalf("response body missing:\n%s", matched.Response)
	}
}

func TestApplyStoredExchangesReplacesRedactedJSON(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "http"), 0o700); err != nil {
		t.Fatal(err)
	}
	dump := `[tpl] Dumped HTTP request for http://lab/x

GET /x HTTP/1.1
Host: lab
Cookie: sid=real

[tpl] Dumped HTTP response http://lab/x

HTTP/1.1 200 OK
Content-Type: text/plain

proof
`
	if err := os.WriteFile(filepath.Join(root, "http", "x.txt"), []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	results := []NucleiResult{{
		TemplateID: "tpl",
		MatchedAt:  "http://lab/x",
		Request:    "GET /x HTTP/1.1\r\nCookie: ***\r\n\r\n",
		Response:   "HTTP/1.1 200 OK\r\n\r\n",
	}}
	applyStoredExchanges(results, root)
	if strings.Contains(results[0].Request, "***") || !strings.Contains(results[0].Request, "sid=real") {
		t.Fatalf("request not replaced: %q", results[0].Request)
	}
	if !strings.Contains(results[0].Response, "proof") {
		t.Fatalf("response not replaced: %q", results[0].Response)
	}
}

func TestStoredRedirectFallsBackToRequestLine(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "http"), 0o700); err != nil {
		t.Fatal(err)
	}
	dump := `[tpl] Dumped HTTP request for http://lab/login.php

POST /login.php HTTP/1.1
Host: lab
Cookie: sid=real

[tpl] Dumped HTTP response http://lab/login.php

HTTP/1.1 200 OK

login page

[tpl] Dumped HTTP response http://lab/login.php

HTTP/1.1 302 Found
Location: index.php
`
	if err := os.WriteFile(filepath.Join(root, "http", "x.txt"), []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	store := ParseNucleiStore(root)
	pair, ok := store.ByRequest["tpl|POST /login.php HTTP/1.1"]
	if !ok {
		t.Fatalf("request-line index missing: %#v", store.ByRequest)
	}
	if !strings.Contains(pair.Request, "sid=real") || !strings.Contains(pair.Response, "302 Found") {
		t.Fatalf("redirect exchange not selected: %#v", pair)
	}
	results := []NucleiResult{{
		TemplateID: "tpl",
		MatchedAt:  "http://lab/index.php",
		Request:    "POST /login.php HTTP/1.1\r\nCookie: ***\r\n\r\nusername=admin",
		Response:   "HTTP/1.1 200 OK\r\n\r\nwelcome",
	}}
	applyStoredExchanges(results, root)
	if !strings.Contains(results[0].Request, "sid=real") || strings.Contains(results[0].Request, "***") {
		t.Fatalf("fallback request not applied: %q", results[0].Request)
	}
	if !strings.Contains(results[0].Response, "302 Found") {
		t.Fatalf("fallback response not applied: %q", results[0].Response)
	}
}

func TestApplyStoredExchangesKeepsFullSequence(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "http"), 0o700); err != nil {
		t.Fatal(err)
	}
	dump := `[tpl] Dumped HTTP request for http://lab/login

GET /login HTTP/1.1
Host: lab

[tpl] Dumped HTTP response http://lab/login

HTTP/1.1 200 OK

<form>login</form>

[tpl] Dumped HTTP request for http://lab/login

POST /login HTTP/1.1
Host: lab
Cookie: sid=real

username=u&password=p

[tpl] Dumped HTTP response http://lab/login

HTTP/1.1 302 Found
Set-Cookie: sid=real

[tpl] Dumped HTTP request for http://lab/exploit

POST /exploit HTTP/1.1
Host: lab
Cookie: sid=real

payload

[tpl] Dumped HTTP response http://lab/exploit

HTTP/1.1 200 OK

queued

[tpl] Dumped HTTP request for http://lab/proof

GET /proof HTTP/1.1
Host: lab
Cookie: sid=real

[tpl] Dumped HTTP response http://lab/proof

HTTP/1.1 200 OK

secret
`
	if err := os.WriteFile(filepath.Join(root, "http", "x.txt"), []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	results := []NucleiResult{{
		TemplateID: "tpl",
		MatchedAt:  "http://lab/proof",
		Request:    "GET /proof HTTP/1.1\r\nCookie: ***\r\n\r\n",
		Response:   "HTTP/1.1 200 OK\r\n\r\nsecret",
	}}
	applyStoredExchanges(results, root)
	if len(results[0].Exchanges) != 2 {
		t.Fatalf("want exploit+proof exchanges, got %#v", results[0].Exchanges)
	}
	if !strings.Contains(results[0].Exchanges[0].Request, "POST /exploit") {
		t.Fatalf("exploit request missing: %#v", results[0].Exchanges)
	}
	if !strings.Contains(results[0].Exchanges[1].Response, "secret") {
		t.Fatalf("proof response missing: %#v", results[0].Exchanges)
	}
}

func TestApplyStoredExchangesKeepsMatchedLoginProof(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "http"), 0o700); err != nil {
		t.Fatal(err)
	}
	dump := `[tpl] Dumped HTTP request for http://lab/login

POST /login HTTP/1.1
Host: lab

username=admin'--

[tpl] Dumped HTTP response http://lab/login

HTTP/1.1 200 OK

Welcome admin

[tpl] Dumped HTTP request for http://lab/exploit

POST /exploit HTTP/1.1
Host: lab

payload

[tpl] Dumped HTTP response http://lab/exploit

HTTP/1.1 200 OK

queued
`
	if err := os.WriteFile(filepath.Join(root, "http", "x.txt"), []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	results := []NucleiResult{{
		TemplateID: "tpl",
		MatchedAt:  "http://lab/login",
		Request:    "POST /login HTTP/1.1\r\n\r\nusername=admin'--",
		Response:   "HTTP/1.1 200 OK\r\n\r\nWelcome admin",
	}}
	applyStoredExchanges(results, root)
	if len(results[0].Exchanges) != 2 {
		t.Fatalf("matched login proof must survive filtering, got %#v", results[0].Exchanges)
	}
	foundProof := false
	for _, ex := range results[0].Exchanges {
		if strings.Contains(ex.Response, "Welcome admin") {
			foundProof = true
		}
	}
	if !foundProof {
		t.Fatalf("proof exchange missing: %#v", results[0].Exchanges)
	}
}
