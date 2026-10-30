package server

import (
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/scanner"
)

func TestWeakPassScore(t *testing.T) {
	cases := []struct {
		path, title string
		want        int
	}{
		{"/login", "用户中心", 100},
		{"/user/login.php", "Member", 100},
		{"/portal", "后台登录", 80},
		{"/", "Login · ACME", 80},
		{"/admin/console", "Dashboard", 60},
		{"/", "管理面板", 50},
		{"/docs", "Documentation", 10},
	}
	for _, c := range cases {
		if got := weakPassScore(c.path, c.title); got != c.want {
			t.Errorf("weakPassScore(%q,%q)=%d want %d", c.path, c.title, got, c.want)
		}
	}
}

func TestWeakPassCandidatesRanksAndCaps(t *testing.T) {
	services := []scanner.WebService{
		{URL: "http://10.0.0.1:80/", Title: "Welcome"},
	}
	apps := make([]scanner.AppSystem, 0, maxWeakPassTargets+4)
	for i := 0; i < maxWeakPassTargets+3; i++ {
		apps = append(apps, scanner.AppSystem{
			URL:   "http://10.0.0.1:80/docs" + string(rune('a'+i)),
			Path:  "/docs" + string(rune('a'+i)),
			Title: "Docs",
		})
	}
	apps = append(apps,
		scanner.AppSystem{URL: "http://10.0.0.1:80/login", Path: "/login", Title: "系统登录"},
		scanner.AppSystem{URL: "http://10.0.0.1:80/admin", Path: "/admin", Title: "管理后台"},
		// duplicate of the service root: must not consume a slot twice
		scanner.AppSystem{URL: "http://10.0.0.1:80/", Path: "/", Title: "Welcome"},
	)

	got := weakPassCandidates(services, apps)
	if len(got) != maxWeakPassTargets {
		t.Fatalf("candidate count: %d want %d", len(got), maxWeakPassTargets)
	}
	if got[0].URL != "http://10.0.0.1:80/login" || got[0].Score != 100 {
		t.Fatalf("first candidate should be the login page: %+v", got[0])
	}
	// /admin (score 60) must outrank the score-10 docs pages, even though it
	// was appended after them.
	for i, c := range got {
		if c.URL == "http://10.0.0.1:80/admin" && i > 1 {
			t.Fatalf("admin console ranked too low at %d: %+v", i, got)
		}
	}
	seen := map[string]bool{}
	for _, c := range got {
		if seen[c.URL] {
			t.Fatalf("duplicate candidate %s", c.URL)
		}
		seen[c.URL] = true
	}
	// scores must be non-increasing
	for i := 1; i < len(got); i++ {
		if got[i].Score > got[i-1].Score {
			t.Fatalf("candidates not sorted by score: %+v", got)
		}
	}
}

func TestProbeLocationKeyIgnoresValues(t *testing.T) {
	poc := probeLocationKey("GET", "http://h:80/vul/sqli/sqli_str.php?name=%27&submit=Query", "")
	page := probeLocationKey("get", "http://h:80/vul/sqli/sqli_str.php?name=1&submit=1", "")
	if poc != page {
		t.Fatalf("same endpoint with different values must share a location: %q vs %q", poc, page)
	}
	other := probeLocationKey("POST", "http://h:80/vul/sqli/sqli_str.php", "name=1&submit=1")
	if other == poc {
		t.Fatalf("a POST body location differs from the GET one: %q", other)
	}
	if probeLocationKey("GET", "/relative/path?id=1", "") != "" {
		t.Fatal("a hostless URL has no location key")
	}
	// Order of the parameters must not create a second location for one spot.
	a := probeLocationKey("POST", "http://h/x.php", "b=2&a=1")
	b := probeLocationKey("POST", "http://h/x.php", "a=9&b=8")
	if a != b {
		t.Fatalf("parameter order leaked into the key: %q vs %q", a, b)
	}
}

func TestBaselineSeedsCoversServicesAndApps(t *testing.T) {
	services := []scanner.WebService{
		{URL: "http://10.0.0.1:8080/"},
		{URL: "  "},
		{URL: "ftp://10.0.0.1:21/"},
		{URL: "http://10.0.0.1:8080/"},
	}
	apps := make([]scanner.AppSystem, 0, maxBaselineSeeds+5)
	for i := 0; i < maxBaselineSeeds+5; i++ {
		apps = append(apps, scanner.AppSystem{URL: "http://10.0.0.1:8080/p" + strconv.Itoa(i)})
	}
	apps = append(apps, scanner.AppSystem{URL: "http://10.0.0.2:8080/login"})

	got := baselineSeeds(services, apps)
	if len(got) != maxBaselineSeeds {
		t.Fatalf("seed count %d want %d", len(got), maxBaselineSeeds)
	}
	if got[0] != "http://10.0.0.1:8080/" {
		t.Fatalf("service root should lead: %v", got)
	}
	for _, u := range got {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			t.Fatalf("non-http seed: %s", u)
		}
	}
	if len(baselineSeeds(nil, nil)) != 0 {
		t.Fatal("no assets must yield no seeds")
	}
}

func TestCapProbePointsAndOrigin(t *testing.T) {
	pts := []probePoint{{URL: "http://h/a?id=1"}, {URL: "http://h/b?id=1"}, {URL: "http://h/c?id=1"}}
	if got := capProbePoints(pts, 2); len(got) != 2 || got[1].URL != "http://h/b?id=1" {
		t.Fatalf("cap lost the leading order: %+v", got)
	}
	if got := capProbePoints(pts, 0); len(got) != 1 {
		t.Fatalf("cap below 1 must keep one point: %+v", got)
	}
	if got := capProbePoints(pts, 9); len(got) != 3 {
		t.Fatalf("cap above the count must keep everything: %+v", got)
	}
	for raw, want := range map[string]string{
		"http://h:8080/a/b.php?id=1": "http://h:8080",
		"https://h/x":                "https://h",
		"/a/b.php":                   "",
		"ftp://h/x":                  "",
		"http://h/a/b.php#frag":      "http://h",
	} {
		if got := probeOrigin(raw); got != want {
			t.Errorf("probeOrigin(%q)=%q want %q", raw, got, want)
		}
	}
	for _, tc := range [][2]int{{0, 1}, {1, 1}, {4, 4}, {50, 6}} {
		if got := baselineConcurrency(tc[0]); got != tc[1] {
			t.Errorf("baselineConcurrency(%d)=%d want %d", tc[0], got, tc[1])
		}
	}
}
