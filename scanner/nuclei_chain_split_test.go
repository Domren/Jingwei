package scanner

import (
	"reflect"
	"testing"
)

func TestAnalyzeTemplate(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		stateful bool
		rawOK    bool
	}{
		{"single request", "http:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n        Host: {{Hostname}}\n", false, false},
		{"two raw requests", "http:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n      - |\n        GET /b HTTP/1.1\n", true, false},
		{"cookie reuse", "http:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n    cookie-reuse: true\n", true, false},
		{"req condition", "http:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n    req-condition: true\n", true, false},
		{"redirect follow", "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/a\"\n    redirects: true\n", true, false},
		{"two paths", "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/a\"\n      - \"{{BaseURL}}/b\"\n", true, false},
		{"one path", "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/a\"\n", false, false},
		{"network chain", "network:\n  - host:\n      - \"{{Host}}:6379\"\n    inputs:\n      - data:\n          - \"PING\\r\\n\"\n      - data:\n          - \"INFO\\r\\n\"\n", true, true},
		{"network single", "network:\n  - host:\n      - \"{{Host}}:6379\"\n    inputs:\n      - data:\n          - \"PING\\r\\n\"\n", false, true},
		{"tcp single (exposed-redis shape)", "tcp:\n  - inputs:\n      - data: \"info\\r\\nquit\\r\\n\"\n    host:\n      - \"{{Hostname}}\"\n    port: 6379,6380\n", false, true},
		{"tcp chain", "tcp:\n  - inputs:\n      - data: \"AUTH x\\r\\n\"\n      - data: \"INFO\\r\\n\"\n", true, true},
		{"javascript single", "javascript:\n  - code: |\n      const net = require('nuclei/net');\n", false, true},
		{"ssl single", "ssl:\n  - address: \"{{Hostname}}:443\"\n", false, true},
		{"code template", "code:\n  - engine: python\n    code: print(1)\n", false, false},
		{"headless template", "headless:\n  - steps:\n      - action: navigate\n", false, false},
		{"malformed raw tcp", "id: x\ntcp:\n  - inputs:\n       - data: \"PING\\r\\n\"\n   bad indent here\n", false, true},
		{"malformed raw http", "id: x\nhttp:\n  - raw:\n       - |\n         GET / HTTP/1.1\n   bad indent here\n", false, false},
	}
	for _, c := range cases {
		got := analyzeTemplate(c.content)
		if got.stateful != c.stateful || got.rawOK != c.rawOK {
			t.Errorf("%s: got (stateful=%v rawOK=%v) want (%v, %v)",
				c.name, got.stateful, got.rawOK, c.stateful, c.rawOK)
		}
	}
}

func TestSplitNucleiTargets(t *testing.T) {
	targets := []string{
		"http://1.2.3.4/",
		"https://example.com:8443",
		"1.2.3.4:6379",
		"1.2.3.4:8080",
		"example.com",
		"[::1]:6379",
	}
	web, raw := splitNucleiTargets(targets)
	wantWeb := []string{"http://1.2.3.4/", "https://example.com:8443", "1.2.3.4:8080"}
	wantRaw := []string{"1.2.3.4:6379", "example.com", "[::1]:6379"}
	if !reflect.DeepEqual(web, wantWeb) {
		t.Errorf("web = %v, want %v", web, wantWeb)
	}
	if !reflect.DeepEqual(raw, wantRaw) {
		t.Errorf("raw = %v, want %v", raw, wantRaw)
	}
}

func TestBuildNucleiGroups(t *testing.T) {
	const redisSingle = "tcp:\n  - inputs:\n      - data: \"info\\r\\nquit\\r\\n\"\n    port: 6379,6380\n"
	const redisChain = "tcp:\n  - inputs:\n      - data: \"AUTH x\\r\\n\"\n      - data: \"INFO\\r\\n\"\n"
	const httpSingle = "http:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n"
	const httpChain = "http:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n      - |\n        GET /b HTTP/1.1\n"
	templates := []NucleiTemplate{
		{ID: "redis-single", Content: redisSingle},
		{ID: "redis-chain", Content: redisChain},
		{ID: "http-single", Content: httpSingle},
		{ID: "http-chain", Content: httpChain},
	}
	groups := buildNucleiGroups(templates, []string{"1.2.3.4:6379", "http://1.2.3.4/"}, 25, 50)

	var gotDirs []string
	byDir := map[string]nucleiGroup{}
	for _, g := range groups {
		gotDirs = append(gotDirs, g.dir)
		byDir[g.dir] = g
	}
	wantDirs := []string{"chains", "single", "raw-chains", "raw-single"}
	if !reflect.DeepEqual(gotDirs, wantDirs) {
		t.Fatalf("dirs = %v, want %v", gotDirs, wantDirs)
	}
	if got := byDir["chains"].templates; len(got) != 2 || got[0].ID != "redis-chain" || got[1].ID != "http-chain" {
		t.Errorf("chains = %v", ids(got))
	}
	if got := byDir["single"].templates; len(got) != 2 || got[0].ID != "redis-single" || got[1].ID != "http-single" {
		t.Errorf("single = %v", ids(got))
	}
	if got := byDir["raw-chains"].templates; len(got) != 1 || got[0].ID != "redis-chain" {
		t.Errorf("raw-chains = %v", ids(got))
	}
	if got := byDir["raw-single"].templates; len(got) != 1 || got[0].ID != "redis-single" {
		t.Errorf("raw-single = %v", ids(got))
	}
	for _, d := range []string{"chains", "single"} {
		if !reflect.DeepEqual(byDir[d].targets, []string{"http://1.2.3.4/"}) {
			t.Errorf("%s targets = %v", d, byDir[d].targets)
		}
	}
	for _, d := range []string{"raw-chains", "raw-single"} {
		if !reflect.DeepEqual(byDir[d].targets, []string{"1.2.3.4:6379"}) {
			t.Errorf("%s targets = %v", d, byDir[d].targets)
		}
		if !byDir[d].raw {
			t.Errorf("%s must be marked raw", d)
		}
	}
	if byDir["chains"].concurrency != 4 || byDir["raw-chains"].concurrency != 4 {
		t.Errorf("chain concurrency = %d/%d, want 4/4", byDir["chains"].concurrency, byDir["raw-chains"].concurrency)
	}
	if byDir["chains"].rateLimit != 8 || byDir["raw-chains"].rateLimit != 8 {
		t.Errorf("chain rate = %d/%d, want 8/8", byDir["chains"].rateLimit, byDir["raw-chains"].rateLimit)
	}
	if byDir["single"].concurrency != 25 || byDir["raw-single"].concurrency != 25 {
		t.Errorf("single concurrency = %d/%d, want 25/25", byDir["single"].concurrency, byDir["raw-single"].concurrency)
	}

	// No web targets -> no web groups even though HTTP templates exist.
	groups = buildNucleiGroups(templates, []string{"1.2.3.4:6379"}, 25, 50)
	for _, g := range groups {
		if g.dir == "chains" || g.dir == "single" {
			t.Errorf("unexpected web group %s for raw-only targets", g.dir)
		}
	}
	// No raw-capable templates -> no raw groups even though raw targets exist.
	groups = buildNucleiGroups([]NucleiTemplate{{ID: "http-single", Content: httpSingle}},
		[]string{"1.2.3.4:6379"}, 25, 50)
	if len(groups) != 0 {
		t.Errorf("groups = %v, want none (HTTP POC must not wrap a raw port)", dirs(groups))
	}
}

func ids(tpls []NucleiTemplate) []string {
	out := make([]string, 0, len(tpls))
	for _, tpl := range tpls {
		out = append(out, tpl.ID)
	}
	return out
}

func dirs(groups []nucleiGroup) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.dir)
	}
	return out
}
