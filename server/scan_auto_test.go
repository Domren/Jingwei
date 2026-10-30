package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/scanner"
)

func TestGroupAutoResults(t *testing.T) {
	results := []scanner.NucleiResult{
		{
			TemplateID: "CVE-2024-0001",
			Severity:   "high",
			Host:       "https://app.example.com:8443",
			MatchedAt:  "https://app.example.com:8443/api/query?name=x",
		},
		{
			TemplateID: "tech-detect",
			Severity:   "low",
			Host:       "https://app.example.com:8443",
			MatchedAt:  "https://app.example.com:8443/",
		},
		{
			TemplateID: "CVE-2024-0002",
			Severity:   "critical",
			Host:       "https://app.example.com:8443",
			MatchedAt:  "https://app.example.com:8443/login",
		},
		{
			TemplateID: "CVE-2024-0001",
			Severity:   "high",
			Host:       "https://app.example.com:8443",
			MatchedAt:  "https://app.example.com:8443/api/query?name=y",
		},
		{
			TemplateID: "CVE-2024-0003",
			Severity:   "medium",
			Host:       "http://other.example.com",
			MatchedAt:  "http://other.example.com/",
		},
		{
			TemplateID: "raw-socket",
			Severity:   "high",
			Host:       "10.0.0.1:6379",
			MatchedAt:  "10.0.0.1:6379",
		},
	}

	findingIDs := map[string]int64{
		"CVE-2024-0001|https://app.example.com:8443/api/query?name=x": 101,
		"CVE-2024-0001|https://app.example.com:8443/api/query?name=y": 102,
		"CVE-2024-0002|https://app.example.com:8443/login":            103,
	}
	groups, skipped := groupAutoResults(results, findingIDs)
	if skipped != 2 {
		t.Fatalf("skipped = %d, want 2 (low + non-http)", skipped)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}

	first := groups[0]
	if first.target != "https://app.example.com:8443" {
		t.Fatalf("target = %q", first.target)
	}
	if first.wafPath != "/api/query" || first.wafParam != "name" {
		t.Fatalf("waf probe = %q %q", first.wafPath, first.wafParam)
	}
	if len(first.templates) != 2 || first.templates[0] != "CVE-2024-0001" || first.templates[1] != "CVE-2024-0002" {
		t.Fatalf("templates = %v", first.templates)
	}
	if first.maxRank != severityRank("critical") {
		t.Fatalf("maxRank = %d", first.maxRank)
	}
	if got := first.findings["CVE-2024-0001"]; len(got) != 2 || got[0] != 101 || got[1] != 102 {
		t.Fatalf("CVE-2024-0001 findings = %v", got)
	}
	if got := first.findings["CVE-2024-0002"]; len(got) != 1 || got[0] != 103 {
		t.Fatalf("CVE-2024-0002 findings = %v", got)
	}

	if groups[1].target != "http://other.example.com" || len(groups[1].templates) != 1 {
		t.Fatalf("second group = %+v", groups[1])
	}
}

func TestAutoResultTargetPrefersOrigin(t *testing.T) {
	cases := []struct {
		name string
		res  scanner.NucleiResult
		want string
	}{
		{
			name: "host origin",
			res:  scanner.NucleiResult{Host: "https://a.example.com/base/", MatchedAt: "https://a.example.com/x?q=1"},
			want: "https://a.example.com/base",
		},
		{
			name: "fallback to matched URL",
			res:  scanner.NucleiResult{Host: "a.example.com", MatchedAt: "http://a.example.com:8080/p?q=1"},
			want: "http://a.example.com:8080",
		},
		{
			name: "no web url",
			res:  scanner.NucleiResult{Host: "10.0.0.1:6379", MatchedAt: "10.0.0.1:6379"},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := autoResultTarget(tc.res); got != tc.want {
				t.Fatalf("autoResultTarget = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJoinHostPath(t *testing.T) {
	if got := joinHostPath("https://a.example.com:8443/base", "/upload.jsp"); got != "https://a.example.com:8443/upload.jsp" {
		t.Fatalf("joinHostPath = %q", got)
	}
	if got := joinHostPath("https://a.example.com", "https://b.example.com/x"); got != "https://b.example.com/x" {
		t.Fatalf("absolute path = %q", got)
	}
	if got := joinHostPath("not-a-url", "/x"); got != "" {
		t.Fatalf("invalid base = %q", got)
	}
}

// SQLi and XSS hits are routed to sqlmap / dalfox instead of a POC replay, so
// the grouping must keep the injection point (including POST bodies) and drop
// points no web tool can reach.
func TestGroupAutoResultsRoutesInjectionsToTools(t *testing.T) {
	results := []scanner.NucleiResult{
		{
			TemplateID: "pikachu-sqli-get",
			Name:       "Pikachu SQL Injection",
			Severity:   "high",
			Tags:       []string{"php", "sqli"},
			Host:       "http://127.0.0.1:18080",
			MatchedAt:  "http://127.0.0.1:18080/vul/sqli/sqli_str.php?name=1&submit=%E6%9F%A5%E8%AF%A2",
		},
		{
			TemplateID: "pikachu-xss",
			Name:       "Reflected XSS",
			Severity:   "medium",
			Tags:       []string{"php", "xss"},
			Host:       "http://127.0.0.1:18080",
			MatchedAt:  "http://127.0.0.1:18080/vul/xss/xss_reflected_get.php?message=test&submit=submit",
		},
		{
			TemplateID: "pikachu-sqli-post",
			Name:       "SQL Injection in POST parameter",
			Severity:   "high",
			Host:       "http://127.0.0.1:18080",
			MatchedAt:  "http://127.0.0.1:18080/vul/sqli/sqli_search.php",
			Request:    "POST /vul/sqli/sqli_search.php HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=1'&submit=%E6%9F%A5%E8%AF%A2",
		},
		{
			// A duplicated hit must not queue the same point twice.
			TemplateID: "pikachu-sqli-get",
			Name:       "Pikachu SQL Injection",
			Severity:   "high",
			Tags:       []string{"sqli"},
			Host:       "http://127.0.0.1:18080",
			MatchedAt:  "http://127.0.0.1:18080/vul/sqli/sqli_str.php?name=1&submit=%E6%9F%A5%E8%AF%A2",
		},
		{
			// sqlmap only speaks HTTP: a tcp match keeps its POC verdict.
			TemplateID: "mysql-blind-sql-injection",
			Name:       "MySQL Blind SQL Injection",
			Severity:   "high",
			Host:       "10.0.0.1:3306",
			MatchedAt:  "tcp://10.0.0.1:3306",
		},
		{
			// nuclei printed no raw request here; the method, body and session
			// live only in the curl command.
			TemplateID: "pikachu-sqli-iu-reg",
			Name:       "Pikachu - SQL Injection in Registration INSERT (sqli_reg)",
			Severity:   "high",
			Tags:       []string{"pikachu", "sqli"},
			Host:       "http://127.0.0.1:18080",
			MatchedAt:  "http://127.0.0.1:18080/vul/sqli/sqli_iu/sqli_reg.php",
			Curl:       `curl -X 'POST' -d 'username=x%27%20and%20updatexml(1,concat(0x7e,database(),0x7e),1)%20and%20%27&submit=Submit' -H 'Cookie: PHPSESSID=abc123' -H 'Content-Type: application/x-www-form-urlencoded' 'http://127.0.0.1:18080/vul/sqli/sqli_iu/sqli_reg.php'`,
		},
		{
			// A CSRF check that happens to live on a sqli_* page: the tool has
			// nothing to say about it, so it must not be probed at all.
			TemplateID: "pikachu-sqli-iu-edit",
			Name:       "Pikachu - Profile Update Without Anti-CSRF Token (sqli_edit)",
			Severity:   "medium",
			Tags:       []string{"pikachu", "csrf"},
			Host:       "http://127.0.0.1:18080",
			MatchedAt:  "http://127.0.0.1:18080/vul/sqli/sqli_iu/sqli_edit.php",
		},
	}
	// The persisted finding index is keyed by template|matched-at, so the
	// duplicate hit resolves to the same row.
	findingIDs := map[string]int64{
		scanResultKey(results[0]): 11,
		scanResultKey(results[1]): 12,
		scanResultKey(results[2]): 13,
		scanResultKey(results[3]): 11,
	}

	groups, skipped := groupAutoResults(results, findingIDs)
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (non-web target)", skipped)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	g := groups[0]
	if g.target != "http://127.0.0.1:18080" {
		t.Fatalf("target = %q", g.target)
	}
	if len(g.templates) != 5 {
		t.Fatalf("templates = %v", g.templates)
	}
	sqli, xss := g.injections[scanner.InjectionSQLi], g.injections[scanner.InjectionXSS]
	if len(sqli) != 3 {
		t.Fatalf("sqli points = %d, want 3 (duplicate deduped): %+v", len(sqli), sqli)
	}
	if len(xss) != 1 {
		t.Fatalf("xss points = %d, want 1", len(xss))
	}
	if sqli[0].URL != results[0].MatchedAt || sqli[0].Method != "GET" {
		t.Errorf("GET point = %+v", sqli[0])
	}
	if got := sqli[0].FindingIDs; len(got) != 1 || got[0] != 11 {
		t.Errorf("GET point findings = %v", got)
	}
	if xss[0].TemplateID != "pikachu-xss" {
		t.Errorf("xss template = %q", xss[0].TemplateID)
	}
	if sqli[1].Method != "POST" || !strings.Contains(sqli[1].Body, "id=1'") {
		t.Errorf("POST point lost its body: %+v", sqli[1])
	}
	if sqli[1].URL != "http://127.0.0.1:18080/vul/sqli/sqli_search.php" {
		t.Errorf("POST point url = %q", sqli[1].URL)
	}
	if sqli[2].TemplateID != "pikachu-sqli-iu-reg" || sqli[2].Method != "POST" ||
		!strings.Contains(sqli[2].Body, "updatexml") {
		t.Errorf("curl-only hit lost its request: %+v", sqli[2])
	}
	if sqli[2].Cookie != "PHPSESSID=abc123" {
		t.Errorf("point cookie = %q, want the session the POC used", sqli[2].Cookie)
	}
	for _, p := range append(append([]probePoint{}, sqli...), xss...) {
		if p.TemplateID == "pikachu-sqli-iu-edit" {
			t.Fatalf("a CSRF template was routed to an injection tool: %+v", p)
		}
	}

	params := autoProbeParams(sqli)
	if len(params) != 3 {
		t.Fatalf("params = %d", len(params))
	}
	point, ok := params[1].(map[string]any)
	if !ok {
		t.Fatalf("param entry type %T", params[1])
	}
	if stringFromMap(point, "method") != "POST" || stringFromMap(point, "data") != sqli[1].Body {
		t.Errorf("encoded POST point = %v", point)
	}
	if ids := idsFromAny(point["finding_ids"]); len(ids) != 1 || ids[0] != 13 {
		t.Errorf("encoded finding ids = %v", ids)
	}
}

func TestAutoProbePointIgnoresNonWebURL(t *testing.T) {
	res := scanner.NucleiResult{
		TemplateID: "x",
		Host:       "http://127.0.0.1:18080",
		MatchedAt:  "file:///etc/passwd",
	}
	if got := autoProbePoint(res, nil); got.URL != "" {
		t.Fatalf("non-http point kept: %+v", got)
	}
}

func TestAutoProbePointDropsRedactedSession(t *testing.T) {
	matched := "http://127.0.0.1:18080/vul/xss/xsspost/xss_reflected_post.php"
	fromCurl := scanner.NucleiResult{
		TemplateID: "pikachu-xss-post-reflected", Name: "Pikachu Reflected XSS (POST)",
		Severity: "medium", Tags: []string{"pikachu", "xss"},
		Host: "http://127.0.0.1:18080", MatchedAt: matched,
		Curl: `curl -X 'POST' -d 'message=1&submit=Submit' -H 'Cookie: ***' '` + matched + `'`,
	}
	fromPacket := scanner.NucleiResult{
		TemplateID: "pikachu-xss-blind-admin", Name: "Pikachu Blind XSS (admin)",
		Severity: "medium", Tags: []string{"pikachu", "xss"},
		Host: "http://127.0.0.1:18080", MatchedAt: matched,
		Request: "GET /vul/xss/xssblind/admin.php HTTP/1.1\r\nCookie: ***\r\n\r\n",
	}
	for name, res := range map[string]scanner.NucleiResult{"curl": fromCurl, "packet": fromPacket} {
		point := autoProbePoint(res, nil)
		if point.Cookie != "" {
			t.Errorf("%s: placeholder session forwarded to the tool: %q", name, point.Cookie)
		}
		if point.URL == "" {
			t.Errorf("%s: point dropped", name)
		}
	}
	if got := autoProbePoint(fromCurl, nil); got.Method != "POST" || got.Body != "message=1&submit=Submit" {
		t.Errorf("POST request lost while dropping the session: %+v", got)
	}
	if got := usableSession("PHPSESSID=real; sec=low"); got != "PHPSESSID=real; sec=low" {
		t.Errorf("real session dropped: %q", got)
	}
}

func TestContainsProbePointDistinguishesBody(t *testing.T) {
	base := probePoint{URL: "http://h/p", Method: "POST", Body: "a=1", TemplateID: "t"}
	other := base
	other.Body = "a=2"
	if containsProbePoint([]probePoint{base}, base) != true {
		t.Fatal("duplicate not detected")
	}
	if containsProbePoint([]probePoint{base}, other) {
		t.Fatal("different body treated as duplicate")
	}
}

func TestAutoProbeWallFitsTaskDeadline(t *testing.T) {
	cases := []struct {
		name   string
		budget int
		points int
		want   int
	}{
		{"sqli four points", autoSQLiBudgetSec, 4, 180},
		{"sqli single point caps", autoSQLiBudgetSec, 1, autoProbeMaxSec},
		{"xss eight points", autoXSSBudgetSec, 8, 82},
		{"many points keep a floor", autoXSSBudgetSec, 80, autoProbeMinSec},
		{"zero points still bounded", autoXSSBudgetSec, 0, autoProbeMaxSec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := autoProbeWall(tc.budget, tc.points); got != tc.want {
				t.Fatalf("autoProbeWall(%d,%d) = %d, want %d", tc.budget, tc.points, got, tc.want)
			}
		})
	}
	if maxAutoSQLiPoints*autoProbeWall(autoSQLiBudgetSec, maxAutoSQLiPoints) >= 900 {
		t.Fatal("sqli run can outlive the deep task deadline")
	}
	if maxAutoXSSPoints*autoProbeWall(autoXSSBudgetSec, maxAutoXSSPoints) >= 900 {
		t.Fatal("xss run can outlive the deep task deadline")
	}
}

// Points past one task's cap are not dropped: they start a second task of the
// same class, so a whole lab module gets every point decided by the tool while no
// single task can outlive the deep executor's deadline.
func TestPlanAutoProbeClassBatchesEveryInjectionPoint(t *testing.T) {
	pts := make([]probePoint, 0, 10)
	for i := 10; i > 0; i-- {
		pts = append(pts, probePoint{
			URL:        fmt.Sprintf("http://lab.example.com/sqli_%02d.php?id=1", i),
			TemplateID: fmt.Sprintf("pikachu-sqli-%02d", i),
		})
	}
	batches, owned := planAutoProbeClass(pts, maxAutoSQLiPoints)
	if len(batches) != 2 || len(batches[0]) != maxAutoSQLiPoints || len(batches[1]) != 2 {
		t.Fatalf("batches = %v, want 2 batches of %d and 2", lengthsOf(batches), maxAutoSQLiPoints)
	}
	// Ordered before cutting, so the same points land in the same batch every
	// round instead of following whatever order nuclei emitted.
	if batches[0][0].TemplateID != "pikachu-sqli-01" || batches[1][0].TemplateID != "pikachu-sqli-09" {
		t.Fatalf("batch order = %q then %q", batches[0][0].TemplateID, batches[1][0].TemplateID)
	}
	total := 0
	for i, batch := range batches {
		total += len(batch)
		wall := autoProbeWall(autoSQLiBudgetSec, len(batch))
		if len(batch)*wall+len(batch)*20 >= 900 {
			t.Fatalf("batch %d can outlive the deep task deadline: %d points x %d s", i, len(batch), wall)
		}
	}
	if total != 10 {
		t.Fatalf("batched points = %d, want all 10 verified", total)
	}
	if len(owned) != 10 || !owned["pikachu-sqli-10"] {
		t.Fatalf("owned = %d templates, want all 10 (a batched point must not keep its POC verdict)", len(owned))
	}

	one, owned := planAutoProbeClass([]probePoint{{URL: "http://lab.example.com/x", TemplateID: "t"}}, maxAutoXSSPoints)
	if len(one) != 1 || len(one[0]) != 1 || len(owned) != 1 {
		t.Fatalf("single point plan = %d batches, %#v", len(one), owned)
	}
	if wall := autoProbeWall(autoXSSBudgetSec, len(one[0])); wall != autoProbeMaxSec {
		t.Fatalf("single point wall = %d, want %d", wall, autoProbeMaxSec)
	}
}

func lengthsOf(batches [][]probePoint) []int {
	out := make([]int, 0, len(batches))
	for _, b := range batches {
		out = append(out, len(b))
	}
	return out
}
