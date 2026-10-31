package server

import (
	"encoding/base64"
	"os/exec"
	"runtime"
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
	output, cwd, code, ok := parseIntranetOutput("hello\nworld\n__JW_CWD__/var/www\n__JW_EC__0\n")
	if !ok || output != "hello\nworld" || cwd != "/var/www" || code != 0 {
		t.Fatalf("got output=%q cwd=%q code=%d ok=%v", output, cwd, code, ok)
	}

	output, cwd, code, ok = parseIntranetOutput("ls: nope\n__JW_CWD__/root\n__JW_EC__2\n")
	if !ok || output != "ls: nope" || cwd != "/root" || code != 2 {
		t.Fatalf("nonzero exit: output=%q cwd=%q code=%d ok=%v", output, cwd, code, ok)
	}

	output, cwd, code, ok = parseIntranetOutput("plain output")
	if ok || output != "plain output" || cwd != "" || code != -1 {
		t.Fatalf("unmarked output: output=%q cwd=%q code=%d ok=%v", output, cwd, code, ok)
	}

	// A command that itself prints the marker must not confuse the parser: the
	// wrapper's marker is the last one.
	output, cwd, code, ok = parseIntranetOutput("x __JW_CWD__/fake\ny\n__JW_CWD__/real\n__JW_EC__0\n")
	if !ok || strings.Contains(output, "/real") || cwd != "/real" || code != 0 {
		t.Fatalf("last marker not used: output=%q cwd=%q code=%d ok=%v", output, cwd, code, ok)
	}
}

func TestParseIntranetOutputWindows(t *testing.T) {
	raw := "win-55ook7lana1\\test\r\n__JW_EC__0 \r\n__JW_CWD__ \r\nC:\\phpStudy\\WWW\r\n"
	output, cwd, code, ok := parseIntranetOutput(raw)
	if !ok || output != "win-55ook7lana1\\test" || cwd != `C:\phpStudy\WWW` || code != 0 {
		t.Fatalf("windows trailer: output=%q cwd=%q code=%d ok=%v", output, cwd, code, ok)
	}

	output, cwd, code, ok = parseIntranetOutput("Access is denied.\r\n__JW_EC__1 \r\n__JW_CWD__ \r\nC:\\\r\n")
	if !ok || output != "Access is denied." || cwd != `C:\` || code != 1 {
		t.Fatalf("windows failure: output=%q cwd=%q code=%d ok=%v", output, cwd, code, ok)
	}

	// Trailer missing: the command killed the shell or the wrapper never ran.
	if _, _, _, ok := parseIntranetOutput("only output"); ok {
		t.Fatal("missing trailer must not be reported as success")
	}
}

func TestIntranetScriptWindows(t *testing.T) {
	script := intranetScriptWindows(`C:\phpStudy\WWW`, "ipconfig /all")
	want := intranetWindowsCodepage + `cd /d "C:\phpStudy\WWW" & (ipconfig /all) & call echo __JW_EC__%^ERRORLEVEL% & echo __JW_CWD__ & cd`
	if script != want {
		t.Fatalf("windows wrapper = %q", script)
	}
	if !strings.HasPrefix(script, "chcp 65001 >nul & ") {
		t.Fatalf("windows wrapper must switch the console to UTF-8: %q", script)
	}
	if root := intranetScriptWindows(`C:\`, "whoami"); !strings.HasPrefix(root, intranetWindowsCodepage+`cd /d C:\ & (whoami)`) {
		t.Fatalf("root cwd must be unquoted: %q", root)
	}
	if bare := intranetScriptWindows("/", "whoami"); strings.Contains(bare, "cd /d") {
		t.Fatalf("posix cwd must not be spliced into cmd: %q", bare)
	}
	if evil := intranetScriptWindows(`C:\a"&calc`, "whoami"); strings.Contains(evil, "calc") {
		t.Fatalf("unsafe cwd must be rejected: %q", evil)
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

func TestIntranetWindowsPath(t *testing.T) {
	cases := []struct {
		in, quoted, normalized string
		ok                     bool
	}{
		{`C:\phpStudy\WWW\a b.txt`, `"C:\phpStudy\WWW\a b.txt"`, `C:\phpStudy\WWW\a b.txt`, true},
		{`D:/tools/x.exe`, `"D:\tools\x.exe"`, `D:\tools\x.exe`, true},
		{`rel\path`, "", "", false},
		{`C:\Windows\%TEMP%\x`, "", "", false},
		{`C:\a"b`, "", "", false},
		{`C:\a&b`, "", "", false},
		{`C:\a*b`, "", "", false},
		{`\\server\share\a`, "", "", false},
	}
	for _, c := range cases {
		quoted, normalized, ok := intranetWindowsPath(c.in)
		if ok != c.ok || quoted != c.quoted || normalized != c.normalized {
			t.Errorf("intranetWindowsPath(%q) = %q/%q/%v want %q/%q/%v",
				c.in, quoted, normalized, ok, c.quoted, c.normalized, c.ok)
		}
	}
}

func TestIntranetWindowsSizeCmd(t *testing.T) {
	got := intranetWindowsSizeCmd(`"C:\a b\f.txt"`)
	want := `for %I in ("C:\a b\f.txt") do @echo %~zI`
	if got != want {
		t.Fatalf("size command = %q want %q", got, want)
	}
}

func TestParseCertutilBase64(t *testing.T) {
	raw := "输入长度 = 11\r\n输出长度 = 16\r\nCertUtil: -encode 成功完成。\r\n" +
		"-----BEGIN CERTIFICATE-----\r\naGVsbG8t\r\nd29ybGQ=\r\n-----END CERTIFICATE-----\r\n" +
		"CertUtil: -encode 命令成功完成。\r\n"
	data, err := parseCertutilBase64(raw)
	if err != nil || string(data) != "hello-world" {
		t.Fatalf("decoded = %q err=%v", data, err)
	}
	if _, err := parseCertutilBase64("no markers"); err == nil {
		t.Fatal("missing markers must fail")
	}
}

func TestIntranetInternalScriptsReachTrailer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix wrapper test")
	}
	cases := map[string]string{
		"probe": intranetProbeScript,
		"recon": intranetReconScript,
	}
	for name, script := range cases {
		raw, err := exec.Command("/bin/sh", "-c", intranetScript("/", script)).CombinedOutput()
		if err != nil {
			t.Fatalf("%s script failed: %v\n%s", name, err, raw)
		}
		if _, _, code, ok := parseIntranetOutput(string(raw)); !ok || code != 0 {
			t.Fatalf("%s wrapper trailer missing (ok=%v code=%d); an `exit` in the script kills it:\n%s",
				name, ok, code, raw)
		}
	}
}
