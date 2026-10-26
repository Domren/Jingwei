package guard

import (
	"encoding/json"
	"testing"
)

func TestExtractTargetsCommand(t *testing.T) {
	cmd := `curl -sS -H 'X-Test: 1' https://API.Example.com:8443/path?q=1 | tee out.txt; ssh -p 2222 root@10.1.2.3; ping 192.168.1.9`
	_, hosts := ExtractTargets("Bash", json.RawMessage(`{"command":`+strconvQuote(cmd)+`}`), cmd)
	want := map[string]bool{"api.example.com": true, "10.1.2.3": true, "192.168.1.9": true}
	for _, h := range hosts {
		delete(want, h)
	}
	if len(want) != 0 {
		t.Fatalf("missing hosts %v in %v", want, hosts)
	}
	urls, _ := ExtractTargets("Bash", nil, cmd)
	if len(urls) != 1 || urls[0] != "https://API.Example.com:8443/path?q=1" {
		t.Fatalf("urls = %v", urls)
	}
}

func TestExtractTargetsJSON(t *testing.T) {
	input := json.RawMessage(`{
		"target": "https://shop.example.com/a",
		"upload_url": "http://10.0.0.5:8080/upload",
		"nested": {"callback_url": ["evil.test", "https://api.other.io/x"]},
		"note": "curl https://not-a-target.com"
	}`)
	urls, hosts := ExtractTargets("inject_webshell", input, "")
	if len(urls) != 3 {
		t.Fatalf("urls = %v", urls)
	}
	want := map[string]bool{"shop.example.com": true, "10.0.0.5": true, "evil.test": true, "api.other.io": true}
	for _, h := range hosts {
		delete(want, h)
	}
	if len(want) != 0 {
		t.Fatalf("missing hosts %v in %v (note text must not be parsed)", want, hosts)
	}
	if len(hosts) != 4 {
		t.Fatalf("should extract exactly the four target hosts, got %v", hosts)
	}
	for _, h := range hosts {
		if h == "not-a-target.com" {
			t.Fatal("free-text notes must not be parsed for targets")
		}
	}
}

func TestExtractTargetsExemptLocalTools(t *testing.T) {
	input := json.RawMessage(`{"assets":[{"domain":"out-of-scope.test","url":"https://out-of-scope.test/x"}]}`)
	_, hosts := ExtractTargets("insert_assets", input, "")
	if len(hosts) != 0 {
		t.Fatalf("insert_assets must not be scope-checked, got %v", hosts)
	}
}

func TestExtractTargetsSingleLabelURLHost(t *testing.T) {
	_, hosts := ExtractTargets("WebFetch", json.RawMessage(`{"url":"http://jumpserver:8080/api"}`), "")
	if len(hosts) != 1 || hosts[0] != "jumpserver" {
		t.Fatalf("hosts = %v", hosts)
	}
}

func TestExtractTargetsNoFalseHostFromFile(t *testing.T) {
	cmd := `cat notes.txt && nmap -p 80 -oN scan.txt 10.9.8.7`
	_, hosts := ExtractTargets("Bash", nil, cmd)
	if len(hosts) != 1 || hosts[0] != "10.9.8.7" {
		t.Fatalf("hosts = %v", hosts)
	}
}

func TestExtractTargetsFlagValueDoesNotSwallowOption(t *testing.T) {
	cmd := `curl -s -i -c cookies.txt http://192.0.2.4/login.php`
	_, hosts := ExtractTargets("Bash", nil, cmd)
	if len(hosts) != 1 || hosts[0] != "192.0.2.4" {
		t.Fatalf("hosts = %v", hosts)
	}
}

func TestExtractTargetsHeaderValueIsNotTarget(t *testing.T) {
	cmd := `curl -s -H 'Host: evil.example' -H "X-Forwarded-For: 10.9.9.9" http://192.0.2.4:8080/WebGoat/login`
	_, hosts := ExtractTargets("Bash", nil, cmd)
	if len(hosts) != 1 || hosts[0] != "192.0.2.4" {
		t.Fatalf("header values must not be targets, got hosts = %v", hosts)
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
