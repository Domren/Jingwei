package server

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/scanner"
)

func TestIntranetScriptQuotesCwd(t *testing.T) {
	script := intranetScript("/tmp/a b'c", "id")
	if !strings.Contains(script, `cd '/tmp/a b'\''c'`) {
		t.Fatalf("cwd not single-quoted: %q", script)
	}
	if !strings.Contains(script, "__JW_CWD__") || !strings.Contains(script, "__JW_EC__") {
		t.Fatalf("markers missing: %q", script)
	}
}

func TestIntranetWrapCommandPHP(t *testing.T) {
	wrapped := scanner.WrapShellCommand("php", intranetScript("/", "id"))
	const prefix = "@system(base64_decode('"
	if !strings.HasPrefix(wrapped, prefix) || !strings.HasSuffix(wrapped, "'));") {
		t.Fatalf("unexpected php wrapper: %q", wrapped)
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(wrapped, prefix), "'));")
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("payload is not base64: %v", err)
	}
	if !strings.Contains(string(decoded), "id\n__jw_ec=$?") {
		t.Fatalf("decoded script does not run the command: %q", decoded)
	}
}

func TestParseIntranetOutput(t *testing.T) {
	output, cwd, code := parseIntranetOutput("hello\nworld\n__JW_CWD__/var/www\n__JW_EC__0\n")
	if output != "hello\nworld" || cwd != "/var/www" || code != 0 {
		t.Fatalf("got output=%q cwd=%q code=%d", output, cwd, code)
	}

	output, cwd, code = parseIntranetOutput("ls: nope\n__JW_CWD__/root\n__JW_EC__2\n")
	if output != "ls: nope" || cwd != "/root" || code != 2 {
		t.Fatalf("nonzero exit: output=%q cwd=%q code=%d", output, cwd, code)
	}

	output, cwd, code = parseIntranetOutput("plain output")
	if output != "plain output" || cwd != "" || code != -1 {
		t.Fatalf("unmarked output: output=%q cwd=%q code=%d", output, cwd, code)
	}

	// A command that itself prints the marker must not confuse the parser: the
	// wrapper's marker is the last one.
	output, cwd, code = parseIntranetOutput("x __JW_CWD__/fake\ny\n__JW_CWD__/real\n__JW_EC__0\n")
	if strings.Contains(output, "/real") || cwd != "/real" || code != 0 {
		t.Fatalf("last marker not used: output=%q cwd=%q code=%d", output, cwd, code)
	}
}

func TestIntranetHostNormalization(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM:8443/a/b": "example.com",
		"10.0.0.1:22":                  "10.0.0.1",
		"::1":                          "::1",
		"[2001:db8::1]:443":            "2001:db8::1",
		"  host.Example.  ":            "host.example",
		"":                             "",
	}
	for raw, want := range cases {
		if got := intranetHost(raw); got != want {
			t.Errorf("intranetHost(%q)=%q want %q", raw, got, want)
		}
	}
	if got := intranetHostPort("2001:db8::1", 8080); got != "[2001:db8::1]:8080" {
		t.Errorf("ipv6 host:port = %q", got)
	}
	if got := intranetHostPort("10.0.0.1", 80); got != "10.0.0.1:80" {
		t.Errorf("ipv4 host:port = %q", got)
	}
}

func TestIntranetVerifyCommandUsesPort(t *testing.T) {
	cmd := intranetVerifyCommand(18080)
	if !strings.Contains(cmd, "[:.]18080[[:space:]]") || !strings.Contains(cmd, "JW_TUNNEL_OK") {
		t.Fatalf("verify command = %q", cmd)
	}
	if got := intranetKillCommand(0); got != "" {
		t.Fatalf("zero pid should have no kill command, got %q", got)
	}
}
