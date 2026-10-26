package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTargets(t *testing.T) {
	targets, err := ParseTargets([]string{
		"https://Example.com/a?b=1",
		"10.0.0.1",
		"10.0.0.0/24",
		"example.org",
		"example.org",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 4 {
		t.Fatalf("want 4 targets, got %d: %+v", len(targets), targets)
	}
	if targets[0].Kind != KindURL || !strings.EqualFold(targets[0].Host, "example.com") {
		t.Fatalf("url target parsed wrong: %+v", targets[0])
	}
	if targets[2].Kind != KindCIDR || targets[2].Host != "10.0.0.0/24" {
		t.Fatalf("cidr target parsed wrong: %+v", targets[2])
	}
	for _, raw := range []string{"", "ftp://x/", "10.0.0.0/16", "300.1.1.1", "http://", "bad host"} {
		if _, err := ParseTarget(raw); err == nil {
			t.Fatalf("expected error for %q", raw)
		}
	}
	if _, err := ParseTargets([]string{"  ", ""}); err == nil {
		t.Fatal("expected error for empty target list")
	}
}

func TestParsePortSpec(t *testing.T) {
	web, err := ParsePortSpec("web")
	if err != nil || len(web) == 0 {
		t.Fatalf("web preset: %v %v", web, err)
	}
	for _, p := range []int{80, 443} {
		if !containsInt(web, p) {
			t.Fatalf("web preset missing %d", p)
		}
	}
	top, err := ParsePortSpec("top100")
	if err != nil || len(top) != 100 {
		t.Fatalf("top100: len=%d err=%v", len(top), err)
	}
	custom, err := ParsePortSpec("80,443,8000-8002")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(custom) != "[80 443 8000 8001 8002]" {
		t.Fatalf("custom ports: %v", custom)
	}
	if top, err := ParsePortSpec(""); err != nil || len(top) != len(top1000Ports) {
		t.Fatalf("empty spec should fall back to top1000: len=%d err=%v", len(top), err)
	}
	for _, bad := range []string{"abc", "0", "70000", "8002-8000"} {
		if _, err := ParsePortSpec(bad); err == nil {
			t.Fatalf("expected error for ports %q", bad)
		}
	}
}

func TestDetectTechnologies(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.25.3")
	body := `<html><head><title>x</title><link href="/wp-content/x.css"></head><body></body></html>`
	techs := DetectTechnologies(h, body)
	if !containsFold(techs, "nginx") || !containsFold(techs, "wordpress") {
		t.Fatalf("techs: %v", techs)
	}
	springHeader := http.Header{}
	springHeader.Set("X-Application-Context", "application:8080")
	if got := DetectTechnologies(springHeader, ""); !containsFold(got, "spring boot") {
		t.Fatalf("spring header detection: %v", got)
	}
	whitelabel := DetectTechnologies(http.Header{}, `<html><body><h1>Whitelabel Error Page</h1></body></html>`)
	if !containsFold(whitelabel, "spring boot") {
		t.Fatalf("spring whitelabel detection: %v", whitelabel)
	}
	kube := DetectTechnologies(http.Header{}, `{"major":"1","minor":"28"}`)
	if containsFold(kube, "kubernetes") {
		t.Fatalf("false positive kubernetes: %v", kube)
	}
	if got := TechnologyAliases("Spring Boot"); !containsFold(got, "spring") {
		t.Fatalf("spring aliases: %v", got)
	}
}

func TestMatchTemplates(t *testing.T) {
	metas := []TemplateMeta{
		{ID: 1, TemplateID: "CVE-2021-44228", Name: "Apache Log4j RCE", Tags: []string{"log4j", "rce"}},
		{ID: 2, TemplateID: "springboot-actuator", Name: "Spring Boot Actuator", Tags: []string{"spring"}},
		{ID: 3, TemplateID: "wordpress-x", Name: "WordPress XSS", Tags: []string{"wordpress", "xss"}},
	}
	ids := MatchTemplates([]string{"Nginx", "Spring Boot"}, metas)
	if fmt.Sprint(ids) != "[2]" {
		t.Fatalf("matched ids: %v", ids)
	}
	ids = MatchTemplates([]string{"Log4j"}, metas)
	if fmt.Sprint(ids) != "[1]" {
		t.Fatalf("log4j matched ids: %v", ids)
	}
	if ids := MatchTemplates(nil, metas); len(ids) != 0 {
		t.Fatalf("empty techs should match nothing: %v", ids)
	}
}

func TestParseNucleiJSONL(t *testing.T) {
	raw := strings.Join([]string{
		`{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical"},"host":"http://a:8080","matched-at":"http://a:8080/x","type":"http","extracted-results":["jndi:ldap://x"],"curl-command":"curl -v http://a/x","request":"secret","response":"secret"}`,
		`not json`,
		`{"template-id":"weak","info":{"name":"Weak TLS","severity":"low"},"host":"a:443","matched-at":"a:443","type":"ssl"}`,
	}, "\n")
	results := ParseNucleiJSONL(raw)
	if len(results) != 2 {
		t.Fatalf("results: %d %+v", len(results), results)
	}
	if results[0].TemplateID != "CVE-2021-44228" || results[0].Severity != "critical" {
		t.Fatalf("first result: %+v", results[0])
	}
	if len(results[0].Extracted) != 1 || results[0].Curl == "" {
		t.Fatalf("extracted/curl missing: %+v", results[0])
	}
	if results[0].Request != "secret" || results[0].Response != "secret" {
		t.Fatalf("raw HTTP pair missing: %+v", results[0])
	}
	if results[0].Raw["request"] != "secret" {
		t.Fatalf("raw missing: %+v", results[0].Raw)
	}
	if results[1].Extracted == nil {
		t.Fatal("extracted should be an empty slice, not nil")
	}
}

func TestProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>Hello &amp; World</title></head><body><script src="/wp-includes/x.js"></script></body></html>`))
	}))
	defer srv.Close()
	p := NewProber(3 * time.Second)
	svc, err := p.Probe(context.Background(), srv.URL, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if svc.Title != "Hello & World" {
		t.Fatalf("title: %q", svc.Title)
	}
	if svc.StatusCode != 200 || svc.Server != "nginx" {
		t.Fatalf("service: %+v", svc)
	}
	if !containsFold(svc.Technologies, "wordpress") {
		t.Fatalf("techs: %v", svc.Technologies)
	}
}

func TestScanPortsFindsLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	open, err := ScanPorts(context.Background(), []string{"127.0.0.1"}, []int{port}, 4, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].Port != port {
		t.Fatalf("open: %+v", open)
	}
}

func TestResolveCIDRLimit(t *testing.T) {
	targets, err := ParseTargets([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Resolve(context.Background(), targets, 100)
	if err == nil {
		t.Fatalf("expected maxHosts error, got %d ips", len(res.IPs))
	}
	res, err = Resolve(context.Background(), targets, 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.IPs) != 254 {
		t.Fatalf("cidr expansion: %d", len(res.IPs))
	}
}

func TestDiscoverPortCheckLimit(t *testing.T) {
	targets, err := ParseTargets([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Discover(context.Background(), targets, DiscoverOptions{
		Ports:         "80,443",
		MaxPortChecks: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "端口扫描量过大") {
		t.Fatalf("expected port check limit error, got %v", err)
	}
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestRaiseNetworkReadSizeLiftsSmallCapsOnly(t *testing.T) {
	redis := "tcp:\n  - inputs:\n      - data: \"info\\r\\nquit\\r\\n\"\n    read-size: 2048\n"
	got := raiseNetworkReadSize(redis, minNetworkReadSize)
	if !strings.Contains(got, "read-size: 16384") {
		t.Fatalf("small cap must be lifted, got:\n%s", got)
	}
	if !strings.Contains(got, `data: "info\r\nquit\r\n"`) {
		t.Fatalf("payload must survive the rewrite, got:\n%s", got)
	}
	big := "    read-size: 65536\n"
	if raiseNetworkReadSize(big, minNetworkReadSize) != big {
		t.Fatal("larger caps must not be reduced")
	}
	httpOnly := "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/x'\n"
	if raiseNetworkReadSize(httpOnly, minNetworkReadSize) != httpOnly {
		t.Fatal("templates without read-size must be untouched")
	}
}
