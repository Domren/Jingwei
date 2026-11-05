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
	apps := make([]scanner.AppSystem, 0, maxWeakPassTargets+6)
	// 一堆不像登录页的子系统：旧口径会把它们塞满候选位，新口径一个都不收。
	for i := 0; i < maxWeakPassTargets+3; i++ {
		apps = append(apps, scanner.AppSystem{
			URL:   "http://10.0.0.1:80/docs" + string(rune('a'+i)),
			Path:  "/docs" + string(rune('a'+i)),
			Title: "Docs",
		})
	}
	for i := 0; i < 8; i++ { // 与 login/admin/根 合计超过上限，逼出截断
		apps = append(apps, scanner.AppSystem{
			URL:   "http://10.0.0.1:80/signin" + string(rune('a'+i)),
			Path:  "/signin" + string(rune('a'+i)),
			Title: "登录",
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
		t.Fatalf("candidate count: %d want %d（%+v）", len(got), maxWeakPassTargets, got)
	}
	for _, c := range got {
		if strings.Contains(c.URL, "/docs") {
			t.Fatalf("低分页面不该进兜底候选：%+v", got)
		}
		if c.Score < weakPassMinScore && c.URL != "http://10.0.0.1:80/" {
			t.Fatalf("除服务根外不该有低于门槛的候选：%+v", got)
		}
	}
	if got[0].URL != "http://10.0.0.1:80/login" || got[0].Score != 100 {
		t.Fatalf("first candidate should be the login page: %+v", got[0])
	}
	seen := map[string]bool{}
	for _, c := range got {
		if seen[c.URL] {
			t.Fatalf("duplicate candidate %s", c.URL)
		}
		seen[c.URL] = true
	}
	for i := 1; i < len(got); i++ {
		if got[i].Score > got[i-1].Score {
			t.Fatalf("candidates not sorted by score: %+v", got)
		}
	}
	if got[0].Score < weakPassMinScore {
		t.Fatalf("截断后首位不该是低分候选：%+v", got[0])
	}
}

// 纯前端站：每个路由都返回同一份 HTML 壳，路径名也各不相同。旧口径交出
// maxWeakPassTargets 个「登录页候选」，等于对着一堆同一份页面反复发认证尝试。
func TestWeakPassCandidatesSkipsUnrelatedPages(t *testing.T) {
	services := []scanner.WebService{{URL: "http://10.0.0.1:3006/", Title: "Jingwei"}}
	apps := []scanner.AppSystem{
		{URL: "http://10.0.0.1:3006/home", Path: "/home", Title: "首页"},
		{URL: "http://10.0.0.1:3006/function/scans", Path: "/function/scans", Title: "自动化漏扫"},
		{URL: "http://10.0.0.1:3006/help", Path: "/help", Title: "通知设置"},
	}
	got := weakPassCandidates(services, apps)
	if len(got) != 1 || got[0].URL != "http://10.0.0.1:3006/" {
		t.Fatalf("SPA 上只该留下服务根一个候选，得到：%+v", got)
	}
	if basis := weakPassBasis(got); !strings.Contains(basis, "服务根 1") {
		t.Fatalf("依据统计没体现服务根：%q", basis)
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
