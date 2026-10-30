package server

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

func TestPrescanNucleiTargetsKeepsServiceURLsAndNonWebPorts(t *testing.T) {
	res := &scanner.DiscoverResult{
		Resolved: &scanner.Resolved{IPs: []string{"10.0.0.5"}},
		Services: []scanner.WebService{
			{URL: "http://10.0.0.5:8080", IP: "10.0.0.5", Port: 8080},
			{URL: "https://10.0.0.5:8443", IP: "10.0.0.5", Port: 8443},
			{URL: "http://10.0.0.5:8080", IP: "10.0.0.5", Port: 8080},
		},
		Ports: []scanner.PortFinding{
			{IP: "10.0.0.5", Port: 22, Service: "ssh"},
			{IP: "10.0.0.5", Port: 8080, Service: "http"},
			{IP: "10.0.0.6", Port: 3306, Service: "mysql"},
		},
	}
	got := prescanNucleiTargets(res, nil, nil)
	want := []string{"http://10.0.0.5:8080", "https://10.0.0.5:8443", "10.0.0.5:22", "10.0.0.6:3306"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
}

func TestPrescanNucleiTargetsFallsBackToRawTargets(t *testing.T) {
	raw := []scanner.Target{
		{Raw: "http://lab.example:8080", Kind: scanner.KindURL, Host: "lab.example", URL: "http://lab.example:8080"},
		{Raw: "lab.example", Kind: scanner.KindDomain, Host: "lab.example"},
		{Raw: "10.0.0.0/24", Kind: scanner.KindCIDR, Host: "10.0.0.0/24"},
	}
	got := prescanNucleiTargets(&scanner.DiscoverResult{Resolved: &scanner.Resolved{}}, raw, nil)
	want := []string{"http://lab.example:8080", "lab.example"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("fallback targets = %v, want %v (CIDR must not be probed host-by-host)", got, want)
	}
}

func TestAppsToServicesCarriesFingerprint(t *testing.T) {
	apps := []scanner.AppSystem{{
		URL: "http://10.0.0.5:8080/admin", Path: "/admin",
		Host: "10.0.0.5", IP: "10.0.0.5", Port: 8080, Scheme: "http",
		StatusCode: 200, Title: "Admin", Server: "nginx",
		Technologies: []string{"php", "nginx"}, ContentLength: 4096,
	}}
	got := appsToServices(apps)
	if len(got) != 1 {
		t.Fatalf("services = %d, want 1", len(got))
	}
	svc := got[0]
	if svc.URL != apps[0].URL || svc.Host != "10.0.0.5" || svc.IP != "10.0.0.5" ||
		svc.Port != 8080 || svc.Scheme != "http" || svc.StatusCode != 200 ||
		svc.Title != "Admin" || svc.Server != "nginx" || svc.ContentLength != 4096 ||
		len(svc.Technologies) != 2 || svc.Technologies[0] != "php" {
		t.Fatalf("service lost fields: %+v", svc)
	}
}

func prescanTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test postgres not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return pg
}

func TestPrescanPersistWritesAssetsAndScope(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("prescan fixture", "http://prescan.example.com", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)

	res := &scanner.DiscoverResult{
		Resolved: &scanner.Resolved{IPs: []string{"10.0.0.5"}},
		Ports: []scanner.PortFinding{
			{IP: "10.0.0.5", Port: 22, Service: "ssh"},
			{IP: "10.0.0.5", Port: 8080, Service: "http"},
		},
		Services: []scanner.WebService{{
			URL: "http://10.0.0.5:8080", Host: "10.0.0.5", IP: "10.0.0.5", Port: 8080,
			Scheme: "http", StatusCode: 200, Title: "Fixture", Server: "nginx",
			Technologies: []string{"nginx"}, ContentLength: 1234,
		}},
	}
	apps := []scanner.AppSystem{{
		URL: "http://10.0.0.5:8080/admin", Path: "/admin", Host: "10.0.0.5", IP: "10.0.0.5",
		Port: 8080, Scheme: "http", StatusCode: 200, Title: "Admin",
		Technologies: []string{"php"}, ContentLength: 88,
	}}
	summary := prescanPersist(nil, pg.Assets(), task.ID, "prescan.example.com", res, apps)
	if summary["resolved_ips"] != 1 || summary["open_ports"] != 2 ||
		summary["services"] != 1 || summary["app_systems"] != 1 {
		t.Fatalf("summary = %+v", summary)
	}

	var links int
	if err := pg.QueryRow(`SELECT count(*) FROM task_asset_links WHERE task_id=$1`, task.ID).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if links != 3 {
		t.Fatalf("asset links = %d, want 3 (1 ip + 1 service + 1 app)", links)
	}

	rows, err := pg.Query(`SELECT kind, COALESCE(domain,''), COALESCE(net::text,'') FROM task_scope WHERE task_id=$1 ORDER BY kind`, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var scopes []string
	for rows.Next() {
		var kind, domain, network string
		if err := rows.Scan(&kind, &domain, &network); err != nil {
			t.Fatal(err)
		}
		scopes = append(scopes, kind+"|"+domain+"|"+network)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"ip||10.0.0.5/32", "subdomain|prescan.example.com|"}
	if strings.Join(scopes, ",") != strings.Join(want, ",") {
		t.Fatalf("task scope = %v, want %v", scopes, want)
	}
}

func TestPrescanPersistHitsRecordsFindings(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("prescan hits fixture", "http://prescan.example.com", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)

	pt := &Task{ID: strconv.FormatInt(task.ID, 10), ExpID: task.ExplorationID, Store: pg.Exploration(task.ExplorationID)}
	n := prescanPersistHits(context.Background(), pt, task.ID, nil, nil, []scanner.NucleiResult{{
		TemplateID: "CVE-TEST-1", Name: "Fixture POC", Severity: "HIGH",
		Host: "http://prescan.example.com", MatchedAt: "http://prescan.example.com/x",
		Request:  "GET /x HTTP/1.1\r\nHost: prescan.example.com\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\n\r\nfixture",
	}})
	if n != 1 {
		t.Fatalf("persisted hits = %d, want 1", n)
	}

	var vulnclass, name, severity, summary, evidence string
	if err := pg.QueryRow(`SELECT vulnclass, name, severity, summary, evidence FROM findings WHERE task_id=$1`, task.ID).
		Scan(&vulnclass, &name, &severity, &summary, &evidence); err != nil {
		t.Fatal(err)
	}
	if vulnclass != "nuclei-CVE-TEST-1" || name != "Fixture POC" || severity != "high" {
		t.Fatalf("finding = %q/%q/%q", vulnclass, name, severity)
	}
	if !strings.Contains(summary, "CVE-TEST-1") || evidence == "" {
		t.Fatalf("summary/evidence = %q/%q", summary, evidence)
	}
}

func TestPrescanTaskToleratesNilInputs(t *testing.T) {
	s := &Server{}
	s.prescanTask(context.Background(), nil)
}

func TestPrescanPortSpecHonorsExplicitPort(t *testing.T) {
	cases := map[int]string{
		0: "web", 80: "web", 443: "web",
		10800: "10800", 8080: "8080", 22: "22",
	}
	for port, want := range cases {
		if got := prescanPortSpec(port); got != want {
			t.Fatalf("prescanPortSpec(%d) = %q, want %q", port, got, want)
		}
	}
}
