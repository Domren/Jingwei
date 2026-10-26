package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scanner"
)

func TestScanTargetBlockReason(t *testing.T) {
	rules := []db.AssetInterceptRule{
		{Kind: "fuzzy_domain", Pattern: ".gov.cn", Enabled: true, Note: "政府站点"},
		{Kind: "cidr", Pattern: "10.0.0.0/8", Enabled: true},
		{Kind: "exact_ip", Pattern: "192.0.2.10", Enabled: false},
	}
	targets, err := scanner.ParseTargets([]string{"https://www.example.gov.cn/"})
	if err != nil {
		t.Fatal(err)
	}
	reason, blocked := scanTargetBlockReason(rules, targets)
	if !blocked || !strings.Contains(reason, ".gov.cn") {
		t.Fatalf("domain should be blocked: %q %v", reason, blocked)
	}

	targets, _ = scanner.ParseTargets([]string{"10.1.2.3"})
	if reason, blocked := scanTargetBlockReason(rules, targets); !blocked || !strings.Contains(reason, "10.0.0.0/8") {
		t.Fatalf("ip should be blocked: %q %v", reason, blocked)
	}

	targets, _ = scanner.ParseTargets([]string{"10.1.2.0/24"})
	if reason, blocked := scanTargetBlockReason(rules, targets); !blocked {
		t.Fatalf("cidr should be blocked: %q %v", reason, blocked)
	}

	targets, _ = scanner.ParseTargets([]string{"192.0.2.10"})
	if reason, blocked := scanTargetBlockReason(rules, targets); blocked {
		t.Fatalf("disabled rule must not block: %q", reason)
	}

	targets, _ = scanner.ParseTargets([]string{"203.0.113.5", "example.com"})
	if reason, blocked := scanTargetBlockReason(rules, targets); blocked {
		t.Fatalf("unrelated targets blocked: %q", reason)
	}
}

func TestCIDRIPs(t *testing.T) {
	ips, err := cidrIPs("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 256 || ips[0] != "192.0.2.0" || ips[255] != "192.0.2.255" {
		t.Fatalf("cidr expansion: len=%d first=%s last=%s", len(ips), ips[0], ips[len(ips)-1])
	}
	if _, err := cidrIPs("2001:db8::/64"); err == nil {
		t.Fatal("IPv6 CIDR should be rejected")
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank("") != 0 || severityRank("low") != 2 || severityRank("critical") != 5 {
		t.Fatal("severity ranks changed")
	}
	if severityRank("nope") != -1 {
		t.Fatal("invalid severity should be -1")
	}
}

func TestPrioritizeAutoTemplates(t *testing.T) {
	ids := []int64{10, 11, 12, 13, 14}
	ranks := map[int64]int{10: 1, 11: 5, 12: 0, 13: 5, 14: 3}
	prioritizeAutoTemplates(ids, ranks)
	want := []int64{11, 13, 14, 10, 12}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("priority order = %v, want %v", ids, want)
		}
	}
}

func TestSanitizeNucleiRaw(t *testing.T) {
	raw := map[string]any{
		"template":         "t",
		"template-encoded": "e",
		"request":          "req",
		"response":         "resp",
		"matched-at":       "http://127.0.0.1/",
	}
	out := sanitizeNucleiRaw(raw)
	if len(out) != 1 || out["matched-at"] == nil {
		t.Fatalf("unexpected sanitized raw: %+v", out)
	}
}

func TestFormatScanEvidenceUsesPacketsAndProvenCredential(t *testing.T) {
	ev := formatScanEvidence(scanner.NucleiResult{
		TemplateID: "dvwa-default-login",
		Name:       "DVWA Default Login",
		Severity:   "critical",
		Host:       "192.0.2.4",
		MatchedAt:  "http://192.0.2.4/index.php",
		Type:       "http",
		Curl:       "curl -X POST 'http://192.0.2.4/login.php'",
		Request:    "POST /login.php HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\nusername=admin&password=password",
		Response:   "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nWelcome",
		Raw: map[string]any{"meta": map[string]any{
			"username": "admin", "password": "password",
		}},
	})
	for _, want := range []string{"admin / password", "POST /login.php HTTP/1.1", "HTTP/1.1 200 OK", "原始 HTTP 请求/响应报文已保存"} {
		if !strings.Contains(ev, want) {
			t.Fatalf("evidence missing %q:\n%s", want, ev)
		}
	}
	if strings.Contains(ev, "curl") || strings.Contains(ev, "复现命令") {
		t.Fatalf("evidence must not contain curl instructions:\n%s", ev)
	}
}

func TestFormatScanEvidenceRawProtocolUsesDataNotHTTP(t *testing.T) {
	ev := formatScanEvidence(scanner.NucleiResult{
		TemplateID: "redis-unauthorized",
		Name:       "Redis Unauthorized Access",
		Severity:   "critical",
		Host:       "192.0.2.1",
		MatchedAt:  "192.0.2.1:6379",
		Type:       "tcp",
		Request:    "PING\r\n",
		Response:   "$2714\r\nRedis\r\n",
	})
	for _, want := range []string{"请求数据: PING", "响应数据: $2714", "原始 TCP 请求/响应数据已保存"} {
		if !strings.Contains(ev, want) {
			t.Fatalf("evidence missing %q:\n%s", want, ev)
		}
	}
	for _, bad := range []string{"请求报文", "响应报文", "原始 HTTP", "HTTP/1.1", "Host:"} {
		if strings.Contains(ev, bad) {
			t.Fatalf("TCP evidence must not contain HTTP wording %q:\n%s", bad, ev)
		}
	}
}

func TestCleanPacketTextKeepsRawProtocolTerminators(t *testing.T) {
	if got := cleanPacketText("info\r\nquit\r\n", 0, true); got != "info\r\nquit\r\n" {
		t.Fatalf("raw packet bytes must survive untouched, got %q", got)
	}
	if got := cleanPacketText("  GET / HTTP/1.1\r\n\r\n  ", 0, false); got != "GET / HTTP/1.1" {
		t.Fatalf("HTTP text is still trimmed, got %q", got)
	}
}
