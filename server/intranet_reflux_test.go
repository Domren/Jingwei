package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// 隧道把内网服务映射到平台自己的监听口上。扫描与范围审批看到的因此是
// 127.0.0.1:<port>，不归位就会把平台登记成一台内网主机：资产列表、报告与下一轮
// 扫描都会顺着这条资产打回 Jingwei 自己。

func refluxFixtureTask(t *testing.T, pg *db.DB, name string) int64 {
	t.Helper()
	task, err := pg.CreateTask(name, "127.0.0.1", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM intranet_session_events WHERE session_id IN (SELECT id FROM intranet_sessions WHERE task_id=$1)`, task.ID)
		_, _ = pg.Exec(`DELETE FROM intranet_artifacts WHERE session_id IN (SELECT id FROM intranet_sessions WHERE task_id=$1)`, task.ID)
		_, _ = pg.Exec(`DELETE FROM intranet_sessions WHERE task_id=$1`, task.ID)
		_, _ = pg.Exec(`DELETE FROM intranet_tunnels WHERE task_id=$1`, task.ID)
		_, _ = pg.Exec(`DELETE FROM intranet_scope_requests WHERE task_id=$1`, task.ID)
		_, _ = pg.Exec(`DELETE FROM assets WHERE $1 = ANY(task_ids) AND (ip LIKE '10.253.77.%' OR ip='127.0.0.1')`, task.ID)
	})
	return task.ID
}

func makeTunnel(t *testing.T, pg *db.DB, taskID int64, listenHost string, listenPort int, remoteHost string, remotePort int, status string) *db.IntranetTunnel {
	t.Helper()
	tunnel, err := pg.CreateIntranetTunnel(db.IntranetTunnelInput{
		Name: "reflux tunnel " + strconv.Itoa(listenPort), TaskID: taskID,
		Kind: db.IntranetTunnelKindPort, ListenHost: listenHost, ListenPort: listenPort,
		ListenSide: db.IntranetListenSidePivot, RemoteHost: remoteHost, RemotePort: remotePort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != "" {
		if _, err := pg.SetIntranetTunnelStatus(tunnel.ID, status, 0, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	return tunnel
}

func TestLiveIntranetTunnelByListen(t *testing.T) {
	pg := prescanTestDB(t)
	taskID := refluxFixtureTask(t, pg, "tunnel listen lookup fixture")
	dedicated := makeTunnel(t, pg, taskID, "127.0.0.1", 41301, "10.253.77.1", 8080, db.IntranetTunnelDeployed)
	wide := makeTunnel(t, pg, taskID, "0.0.0.0", 41302, "10.253.77.2", 3306, db.IntranetTunnelVerified)
	makeTunnel(t, pg, taskID, "127.0.0.1", 41303, "10.253.77.3", 22, db.IntranetTunnelStopped)

	got, err := pg.LiveIntranetTunnelByListen("127.0.0.1", 41301)
	if err != nil || got == nil || got.ID != dedicated.ID || got.RemoteHost != "10.253.77.1" {
		t.Fatalf("dedicated listener = %+v err=%v", got, err)
	}
	// The caller may spell the same address "localhost": it is the same socket.
	if g2, err := pg.LiveIntranetTunnelByListen("localhost", 41301); err != nil || g2 == nil || g2.ID != dedicated.ID {
		t.Fatalf("localhost lookup = %+v err=%v", g2, err)
	}
	if g3, err := pg.LiveIntranetTunnelByListen("127.0.0.1", 41302); err != nil || g3 == nil || g3.ID != wide.ID {
		t.Fatalf("wildcard listener should match any local address: %+v err=%v", g3, err)
	}
	if _, err := pg.LiveIntranetTunnelByListen("127.0.0.1", 41303); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("a stopped tunnel must not vouch for a listener, got %v", err)
	}
	if _, err := pg.LiveIntranetTunnelByListen("127.0.0.1", 0); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("port 0 must not match a tunnel, got %v", err)
	}
	if _, err := pg.LiveIntranetTunnelByListen("10.253.77.9", 41301); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("a remote address must not match, got %v", err)
	}
}

func TestIntranetTunnelIdentity(t *testing.T) {
	pg := prescanTestDB(t)
	taskID := refluxFixtureTask(t, pg, "tunnel identity fixture")
	makeTunnel(t, pg, taskID, "127.0.0.1", 41310, "10.253.77.10", 3306, db.IntranetTunnelDeployed)

	// A non-local endpoint is its own identity: a plain lab scan of 127.0.0.1
	// targets must not be rewritten.
	if host, port, ok := intranetTunnelIdentity(pg, "10.99.0.20", 22); !ok || host != "10.99.0.20" || port != 22 {
		t.Fatalf("passthrough = %s:%d ok=%v", host, port, ok)
	}
	if host, port, ok := intranetTunnelIdentity(pg, "127.0.0.1", 41310); !ok || host != "10.253.77.10" || port != 3306 {
		t.Fatalf("tunnelled identity = %s:%d ok=%v", host, port, ok)
	}
	if _, _, ok := intranetTunnelIdentity(pg, "127.0.0.1", 41311); ok {
		t.Fatal("an unexplained local port must be dropped")
	}
	if _, _, ok := intranetTunnelIdentity(pg, "127.0.0.1", 0); ok {
		t.Fatal("a local address without a port carries no service identity")
	}
	if _, _, ok := intranetTunnelIdentity(pg, "localhost", 41310); !ok {
		t.Fatal("localhost must resolve through the same tunnel")
	}
}

// TestRewriteScanURL: the internal identity replaces the listener, and everything
// else about the discovered endpoint — scheme, path, query — stays as probed.
func TestRewriteScanURL(t *testing.T) {
	cases := []struct {
		raw, host string
		port      int
		want      string
	}{
		{"http://127.0.0.1:41310/login.php?u=1", "10.253.77.10", 8080, "http://10.253.77.10:8080/login.php?u=1"},
		{"https://127.0.0.1:41311/", "10.253.77.11", 443, "https://10.253.77.11/"},
		{"http://127.0.0.1:41312", "10.253.77.12", 80, "http://10.253.77.12"},
		{"http://127.0.0.1:41313/admin", "10.253.77.13", 8443, "http://10.253.77.13:8443/admin"},
		{"http://127.0.0.1:41314", "", 0, "http://127.0.0.1:41314"},
		{"not a url", "10.253.77.14", 80, "not a url"},
	}
	for _, c := range cases {
		if got := rewriteScanURL(c.raw, c.host, c.port); got != c.want {
			t.Fatalf("rewriteScanURL(%q,%q,%d) = %q, want %q", c.raw, c.host, c.port, got, c.want)
		}
	}
}

func approveScopeRequest(t *testing.T, s *Server, pg *db.DB, reqID int64) (map[string]any, []string, int) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/intranet/scope-requests/"+strconv.FormatInt(reqID, 10)+"/approve",
		strings.NewReader(`{"note":"fixture"}`))
	r.SetPathValue("id", strconv.FormatInt(reqID, 10))
	s.approveIntranetScopeRequest(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Request  db.IntranetScopeRequest `json:"request"`
		Assets   map[string]any          `json:"assets"`
		Warnings []string                `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Assets, resp.Warnings, w.Code
}

// TestApproveIntranetScopeRequestRefusesPlatformSelf: approving a loopback request
// authorises the range but must never mint an asset for the platform itself.
func TestApproveIntranetScopeRequestRefusesPlatformSelf(t *testing.T) {
	pg := prescanTestDB(t)
	taskID := refluxFixtureTask(t, pg, "scope self reflux fixture")
	s := &Server{m: &Manager{pg: pg}}

	for _, host := range []string{"127.0.0.1", "localhost"} {
		req, _, err := pg.CreateIntranetScopeRequest(db.IntranetScopeRequestInput{
			TaskID: taskID, Host: host, Port: 8443, Reason: "fixture",
		})
		if err != nil {
			t.Fatal(err)
		}
		assets, warnings, _ := approveScopeRequest(t, s, pg, req.ID)
		if assets["registered"] != false {
			t.Fatalf("host %s must not register an asset: %+v", host, assets)
		}
		joined := strings.Join(warnings, "|")
		if !strings.Contains(joined, "平台自身") {
			t.Fatalf("host %s should warn about self-targeting: %v", host, warnings)
		}
		var count int
		if err := pg.QueryRow(`SELECT count(*) FROM assets WHERE ip=$1 AND $2 = ANY(task_ids)`, host, taskID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("host %s leaked %d assets into the ledger", host, count)
		}
		// The range itself is still approved: the guard checks the dial, and a
		// later tunnel may legitimately carry this listener. An IP lands in
		// task_scope.net, a name in task_scope.domain.
		var scoped int
		if err := pg.QueryRow(`SELECT count(*) FROM task_scope
WHERE task_id=$1 AND (net::text=$2 OR lower(domain)=$3)`,
			taskID, host+"/32", strings.ToLower(host)).Scan(&scoped); err != nil {
			t.Fatal(err)
		}
		if scoped == 0 {
			t.Fatalf("approving must still authorize the range for %s", host)
		}
	}
}

func TestApproveIntranetScopeRequestReattributesTunnelListener(t *testing.T) {
	pg := prescanTestDB(t)
	taskID := refluxFixtureTask(t, pg, "scope tunnel reflux fixture")
	const internal = "10.253.77.20"
	makeTunnel(t, pg, taskID, "127.0.0.1", 41320, internal, 3306, db.IntranetTunnelVerified)
	s := &Server{m: &Manager{pg: pg}}

	req, _, err := pg.CreateIntranetScopeRequest(db.IntranetScopeRequestInput{
		TaskID: taskID, Host: "127.0.0.1", Port: 41320, Reason: "mysql through tunnel",
	})
	if err != nil {
		t.Fatal(err)
	}
	assets, warnings, _ := approveScopeRequest(t, s, pg, req.ID)
	if assets["registered"] != true {
		t.Fatalf("tunnel-mapped listener must register the internal host: %+v", assets)
	}
	if assets["host"] != internal {
		t.Fatalf("asset host = %v, want %s", assets["host"], internal)
	}
	if id, _ := assets["ip_id"].(float64); id <= 0 {
		t.Fatalf("no ip asset id: %+v", assets)
	}
	if id, _ := assets["service_id"].(float64); id <= 0 {
		t.Fatalf("no service asset id: %+v", assets)
	}
	if joined := strings.Join(warnings, "|"); !strings.Contains(joined, "按隧道映射") || !strings.Contains(joined, internal) {
		t.Fatalf("warnings should explain the re-attribution: %v", warnings)
	}

	var ipCount, svcPort int
	if err := pg.QueryRow(`SELECT count(*) FROM assets WHERE type='ip' AND ip=$1`, internal).Scan(&ipCount); err != nil {
		t.Fatal(err)
	}
	if ipCount == 0 {
		t.Fatalf("internal ip asset missing for %s", internal)
	}
	if err := pg.QueryRow(`SELECT port FROM assets WHERE type='service' AND ip=$1 ORDER BY id DESC LIMIT 1`, internal).Scan(&svcPort); err != nil {
		t.Fatalf("service asset for the internal host missing: %v", err)
	}
	if svcPort != 3306 {
		t.Fatalf("service port = %d, want the real internal port 3306", svcPort)
	}
	var selfAssets int
	if err := pg.QueryRow(`SELECT count(*) FROM assets WHERE ip='127.0.0.1' AND $1 = ANY(task_ids)`, taskID).Scan(&selfAssets); err != nil {
		t.Fatal(err)
	}
	if selfAssets != 0 {
		t.Fatalf("the listener must not become an asset: %d rows", selfAssets)
	}
}

func TestRemapTunnelledDiscoveryRewritesListeners(t *testing.T) {
	pg := prescanTestDB(t)
	taskID := refluxFixtureTask(t, pg, "tunnelled discovery fixture")
	makeTunnel(t, pg, taskID, "127.0.0.1", 41330, "10.253.77.30", 22, db.IntranetTunnelDeployed)
	makeTunnel(t, pg, taskID, "127.0.0.1", 41331, "10.253.77.31", 80, db.IntranetTunnelVerified)

	scan, err := pg.CreateScanTask(db.ScanTaskInput{
		Name: "tunnelled discovery fixture", Targets: []string{"10.253.77.0/24"},
		Proxy: "socks5://127.0.0.1:41329",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM scan_tasks WHERE id=$1`, scan.ID) })
	r := &scanRun{pg: pg, task: scan, ctx: context.Background(), progress: map[string]any{}}

	res := &scanner.DiscoverResult{
		Resolved: &scanner.Resolved{IPs: []string{"127.0.0.1", "10.253.77.40"}, Domains: []string{"lab.example"}},
		PortList: []int{22, 80},
		Ports: []scanner.PortFinding{
			{IP: "127.0.0.1", Port: 41330, Service: "ssh"},
			{IP: "127.0.0.1", Port: 41399, Service: "unknown"},
			{IP: "10.253.77.40", Port: 445, Service: "smb"},
		},
		Services: []scanner.WebService{
			{URL: "http://127.0.0.1:41331/", Host: "127.0.0.1", IP: "127.0.0.1", Port: 41331, Scheme: "http", StatusCode: 200},
			{URL: "http://10.253.77.40/", Host: "10.253.77.40", IP: "10.253.77.40", Port: 80, Scheme: "http", StatusCode: 200},
		},
	}
	out, aliases := r.remapTunnelledDiscovery(res)
	if out == res {
		t.Fatal("a proxied scan must produce a rewritten result")
	}
	if len(out.Ports) != 2 {
		t.Fatalf("ports = %+v, want the tunnelled one and the direct one", out.Ports)
	}
	if out.Ports[0].IP != "10.253.77.30" || out.Ports[0].Port != 22 {
		t.Fatalf("ssh port not re-attributed: %+v", out.Ports[0])
	}
	if len(out.Services) != 2 || out.Services[0].URL != "http://10.253.77.31/" {
		t.Fatalf("services = %+v", out.Services)
	}
	if out.Services[0].Host != "10.253.77.31:80" || out.Services[0].IP != "10.253.77.31" || out.Services[0].Port != 80 {
		t.Fatalf("service identity not rewritten: %+v", out.Services[0])
	}
	for _, ip := range out.Resolved.IPs {
		if ip == "127.0.0.1" {
			t.Fatalf("loopback must not survive as a discovered ip: %+v", out.Resolved.IPs)
		}
	}
	ips := append([]string{}, out.Resolved.IPs...)
	sort.Strings(ips)
	if strings.Join(ips, ",") != "10.253.77.30,10.253.77.31,10.253.77.40" {
		t.Fatalf("ips = %v", out.Resolved.IPs)
	}
	if len(out.Resolved.Domains) != 1 || out.Resolved.Domains[0] != "lab.example" {
		t.Fatalf("domains lost: %v", out.Resolved.Domains)
	}
	// Aliases keep findings recorded against the listener attached to the asset
	// stored under the internal identity.
	if aliases[hostPortKey("127.0.0.1", 41330)] != hostPortKey("10.253.77.30", 22) {
		t.Fatalf("port alias = %v", aliases)
	}
	if aliases[normalizeScanURL("http://127.0.0.1:41331/")] != normalizeScanURL("http://10.253.77.31") {
		t.Fatalf("service alias = %v", aliases)
	}
}

func TestRemapTunnelledDiscoveryLeavesPlainScansAlone(t *testing.T) {
	pg := prescanTestDB(t)
	refluxFixtureTask(t, pg, "plain discovery fixture")
	scan, err := pg.CreateScanTask(db.ScanTaskInput{
		Name: "plain discovery fixture", Targets: []string{"http://127.0.0.1:8080"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM scan_tasks WHERE id=$1`, scan.ID) })
	r := &scanRun{pg: pg, task: scan, ctx: context.Background(), progress: map[string]any{}}

	// Local lab targets (Pikachu/DVWA on 127.0.0.1) are scanned without a proxy:
	// they must keep being registered exactly as probed.
	res := &scanner.DiscoverResult{
		Resolved: &scanner.Resolved{IPs: []string{"127.0.0.1"}},
		Ports:    []scanner.PortFinding{{IP: "127.0.0.1", Port: 8080, Service: "http"}},
	}
	out, aliases := r.remapTunnelledDiscovery(res)
	if out != res {
		t.Fatal("a scan without a proxy must not be rewritten")
	}
	if aliases != nil {
		t.Fatalf("aliases = %v, want none", aliases)
	}
	if out.Ports[0].IP != "127.0.0.1" || out.Ports[0].Port != 8080 {
		t.Fatalf("ports rewritten without a tunnel: %+v", out.Ports)
	}

	// A proxied scan that resolved nothing is left untouched rather than rewritten
	// into an empty result.
	scan.Proxy = "socks5://127.0.0.1:1080"
	if got, _ := r.remapTunnelledDiscovery(&scanner.DiscoverResult{}); got.Resolved != nil {
		t.Fatalf("nil Resolved must stay nil: %+v", got.Resolved)
	}
}
