package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

const intranetReconFixture = `__JW_RECON__addr
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0
1: lo    inet 127.0.0.1/8 scope host lo
3: eth1    inet 172.16.8.2/16 brd 172.16.255.255 scope global eth1
2: eth0    inet6 fe80::1/64 scope link
2: eth0    inet6 fd00::5/64 scope global
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.7 netmask 255.255.255.0  broadcast 10.0.0.255
__JW_RECON__route
default via 10.0.0.1 dev eth0
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5
local 10.0.0.5 dev eth0 table local scope host src 10.0.0.5
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.0.0.254      0.0.0.0         UG    0      0        0 eth0
192.168.3.0     0.0.0.0         255.255.255.0   U     0      0        0 eth1
__JW_RECON__hosts
127.0.0.1 localhost
10.0.0.20 db.internal db
# 10.0.0.21 commented.internal
fd00::20 v6.internal
__JW_RECON__neigh
10.0.0.9 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
10.0.0.10 dev eth0 lladdr 11:22:33:44:55:66 STALE
10.0.0.99 dev eth0  FAILED
? (10.0.0.30) at aa:bb:cc:dd:ee:01 [ether] on eth0
? (10.0.0.31) at <incomplete> on eth0
__JW_RECON__listen
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
LISTEN 0      128             [::]:22           [::]:*
LISTEN 0      128        127.0.0.1:3306      0.0.0.0:*
LISTEN 0      128         10.0.0.5:8080        0.0.0.0:*
tcp        0      0 192.168.3.5:443         0.0.0.0:*               LISTEN
__JW_RECON__end
`

func TestParseIntranetRecon(t *testing.T) {
	info := parseIntranetRecon(intranetReconFixture)

	ips := strings.Join(info.IPs, ",")
	for _, want := range []string{"10.0.0.5", "172.16.8.2", "10.0.0.7", "fd00::5"} {
		if !strings.Contains(ips, want) {
			t.Fatalf("ips %v missing %s", info.IPs, want)
		}
	}
	for _, bad := range []string{"127.0.0.1", "fe80::1"} {
		if strings.Contains(ips, bad) {
			t.Fatalf("ips %v should not contain %s", info.IPs, bad)
		}
	}

	if len(info.Routes) != 4 {
		t.Fatalf("routes = %+v, want 4 (ip route x2 + netstat x2)", info.Routes)
	}
	var defaultRoute *intranetRoute
	for i := range info.Routes {
		if info.Routes[i].Destination == "default" && info.Routes[i].Gateway == "10.0.0.1" {
			defaultRoute = &info.Routes[i]
		}
	}
	if defaultRoute == nil || defaultRoute.Iface != "eth0" {
		t.Fatalf("default route not parsed: %+v", info.Routes)
	}

	if len(info.Hosts) != 2 || info.Hosts[0].IP != "10.0.0.20" || len(info.Hosts[0].Names) != 2 {
		t.Fatalf("hosts = %+v", info.Hosts)
	}
	if info.Hosts[1].IP != "fd00::20" || info.Hosts[1].Names[0] != "v6.internal" {
		t.Fatalf("ipv6 host entry = %+v", info.Hosts[1])
	}

	if len(info.Neighbors) != 3 {
		t.Fatalf("neighbors = %+v, want 3 (FAILED/incomplete dropped)", info.Neighbors)
	}
	byIP := map[string]intranetNeighbor{}
	for _, n := range info.Neighbors {
		byIP[n.IP] = n
	}
	if n := byIP["10.0.0.9"]; n.MAC != "aa:bb:cc:dd:ee:ff" || n.Iface != "eth0" || n.State != "REACHABLE" {
		t.Fatalf("ip neigh entry = %+v", n)
	}
	if n := byIP["10.0.0.30"]; n.MAC != "aa:bb:cc:dd:ee:01" || n.Iface != "eth0" {
		t.Fatalf("arp -an entry = %+v", n)
	}

	scopes := map[string]string{}
	for _, l := range info.Listeners {
		scopes[l.Address+":"+strconv.Itoa(l.Port)] = l.Scope
	}
	if scopes["0.0.0.0:22"] != "all" || scopes[":::22"] != "all" {
		t.Fatalf("wildcard listener scopes = %+v", scopes)
	}
	if scopes["127.0.0.1:3306"] != "local" {
		t.Fatalf("loopback listener scope = %+v", scopes)
	}
	if scopes["10.0.0.5:8080"] != "interface" || scopes["192.168.3.5:443"] != "interface" {
		t.Fatalf("interface listener scopes = %+v", scopes)
	}
}

const intranetReconWindowsFixture = `__JW_RECON__addr
Windows IP Configuration

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.1.2.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.1.2.1
__JW_RECON__route

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         10.1.2.1       10.1.2.100     25
        10.1.2.0    255.255.255.0         On-link        10.1.2.100    281
        10.1.3.0    255.255.255.0         在链路上        10.1.2.100    281
===========================================================================
__JW_RECON__hosts
10.1.2.20 db.internal db
__JW_RECON__neigh
Interface: 10.1.2.100 --- 0xb
  Internet Address      Physical Address      Type
  10.1.2.1              00-11-22-33-44-55     dynamic
  10.1.2.30             aa-bb-cc-dd-ee-01     dynamic
__JW_RECON__listen
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING       4321
  TCP    10.1.2.100:8080        0.0.0.0:0              LISTENING       5678
  TCP    10.1.2.100:50212       10.1.2.20:445          ESTABLISHED     9012
  UDP    0.0.0.0:123            *:*                                    1111
__JW_RECON__end
`

func TestParseIntranetReconWindows(t *testing.T) {
	info := parseIntranetRecon(intranetReconWindowsFixture)

	ips := strings.Join(info.IPs, ",")
	if !strings.Contains(ips, "10.1.2.100") {
		t.Fatalf("windows ips = %v", info.IPs)
	}
	var def *intranetRoute
	onlink := 0
	for i := range info.Routes {
		if info.Routes[i].Destination == "default" {
			def = &info.Routes[i]
		}
		if (info.Routes[i].Destination == "10.1.2.0" || info.Routes[i].Destination == "10.1.3.0") &&
			info.Routes[i].Gateway == "" && info.Routes[i].Iface == "10.1.2.100" {
			onlink++
		}
	}
	if def == nil || def.Gateway != "10.1.2.1" || def.Iface != "10.1.2.100" {
		t.Fatalf("windows default route = %+v", info.Routes)
	}
	if onlink != 2 {
		t.Fatalf("localized/English on-link routes not parsed: %+v", info.Routes)
	}
	if len(info.Hosts) != 1 || info.Hosts[0].IP != "10.1.2.20" {
		t.Fatalf("windows hosts = %+v", info.Hosts)
	}
	neigh := map[string]intranetNeighbor{}
	for _, n := range info.Neighbors {
		neigh[n.IP] = n
	}
	if len(neigh) != 2 || neigh["10.1.2.1"].MAC != "00-11-22-33-44-55" || neigh["10.1.2.1"].State != "dynamic" {
		t.Fatalf("windows arp entries = %+v", info.Neighbors)
	}
	scopes := map[string]string{}
	for _, l := range info.Listeners {
		scopes[l.Address+":"+strconv.Itoa(l.Port)] = l.Scope
	}
	if len(info.Listeners) != 3 || scopes["0.0.0.0:135"] != "all" || scopes["127.0.0.1:3306"] != "local" || scopes["10.1.2.100:8080"] != "interface" {
		t.Fatalf("windows listeners = %+v scopes=%+v", info.Listeners, scopes)
	}
	cands := strings.Join(intranetReconScopeCandidates(info), ",")
	if !strings.Contains(cands, "10.1.2.1") || !strings.Contains(cands, "10.1.2.30") {
		t.Fatalf("windows candidates = %v", cands)
	}
	if strings.Contains(cands, "10.1.2.100") {
		t.Fatalf("own address must not be a candidate: %v", cands)
	}
}

func TestIntranetReconScopeCandidatesSkipsBroadcast(t *testing.T) {
	info := intranetReconInfo{
		IPs: []string{"10.0.0.5"},
		Neighbors: []intranetNeighbor{
			{IP: "10.0.0.255", MAC: "FF-FF-FF-FF-FF-FF", State: "dynamic"},
			{IP: "10.0.0.9", MAC: "AA-BB-CC-DD-EE-01", State: "dynamic"},
		},
	}
	joined := strings.Join(intranetReconScopeCandidates(info), ",")
	if strings.Contains(joined, "10.0.0.255") {
		t.Fatalf("broadcast neighbor must be skipped: %v", joined)
	}
	if !strings.Contains(joined, "10.0.0.9") {
		t.Fatalf("real neighbor missing: %v", joined)
	}
}

func TestIntranetReconScopeCandidates(t *testing.T) {
	info := parseIntranetRecon(intranetReconFixture)
	cands := intranetReconScopeCandidates(info)
	joined := strings.Join(cands, ",")
	for _, want := range []string{"10.0.0.9", "10.0.0.10", "10.0.0.30", "10.0.0.20", "fd00::20", "192.168.3.5", "10.0.0.1", "10.0.0.254"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("candidates %v missing %s", cands, want)
		}
	}
	for _, bad := range []string{"10.0.0.5", "172.16.8.2", "127.0.0.1", "10.0.0.99"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("candidates %v should not contain %s", cands, bad)
		}
	}
	if len(cands) > intranetReconMaxHosts {
		t.Fatalf("candidates = %d, cap %d", len(cands), intranetReconMaxHosts)
	}
}

func TestIntranetPivotServer(t *testing.T) {
	t.Setenv("JINGWEI_PIVOT_SERVER", "")
	if _, _, err := intranetPivotServer(); err == nil {
		t.Fatal("expected error when JINGWEI_PIVOT_SERVER is empty")
	}
	t.Setenv("JINGWEI_PIVOT_SERVER", "pivot.example.com")
	if host, port, err := intranetPivotServer(); err != nil || host != "pivot.example.com" || port != 8788 {
		t.Fatalf("pivot = %s:%d err=%v", host, port, err)
	}
	t.Setenv("JINGWEI_PIVOT_SERVER", "https://10.9.9.9:9443")
	if host, port, err := intranetPivotServer(); err != nil || host != "10.9.9.9" || port != 9443 {
		t.Fatalf("pivot with url = %s:%d err=%v", host, port, err)
	}
	t.Setenv("JINGWEI_PIVOT_SERVER", "10.9.9.9:notaport")
	if _, _, err := intranetPivotServer(); err == nil {
		t.Fatal("expected error for non-numeric port")
	}
}

func TestAutoSelectTunnelUsesPivotServer(t *testing.T) {
	t.Setenv("JINGWEI_PIVOT_SERVER", "10.9.9.9:8788")
	tr := &db.IntranetTunnel{ID: 7, Kind: db.IntranetTunnelKindSocks5, ListenHost: "0.0.0.0", ListenPort: 1080}
	deploy, reason := autoSelectTunnelCommand(tr.Kind, intranetProbeInfo{Bins: []string{"chisel"}}, tr)
	if deploy == "" {
		t.Fatalf("chisel socks5 deploy empty: %s", reason)
	}
	if !strings.Contains(deploy, "10.9.9.9:8788") || !strings.Contains(deploy, "1080:socks") {
		t.Fatalf("deploy = %s", deploy)
	}
	if strings.Contains(deploy, "YOUR_C2") {
		t.Fatalf("placeholder leaked: %s", deploy)
	}

	t.Setenv("JINGWEI_PIVOT_SERVER", "")
	deploy, reason = autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, intranetProbeInfo{Bins: []string{"chisel"}}, tr)
	if deploy != "" || !strings.Contains(reason, "JINGWEI_PIVOT_SERVER") {
		t.Fatalf("expected clear pivot error, deploy=%q reason=%q", deploy, reason)
	}

	// socat needs no pivot endpoint.
	fwd := &db.IntranetTunnel{ID: 8, Kind: db.IntranetTunnelKindPort, ListenHost: "0.0.0.0", ListenPort: 8080, RemoteHost: "10.0.0.8", RemotePort: 80}
	deploy, reason = autoSelectTunnelCommand(fwd.Kind, intranetProbeInfo{Bins: []string{"socat"}}, fwd)
	if deploy == "" || !strings.Contains(deploy, "socat") || reason == "" {
		t.Fatalf("socat deploy = %q reason=%q", deploy, reason)
	}
}

func TestIntranetTunnelAccessHints(t *testing.T) {
	s := &Server{}
	socks := &db.IntranetTunnel{
		Kind: db.IntranetTunnelKindSocks5, Status: db.IntranetTunnelVerified,
		ListenHost: "10.0.0.5", ListenPort: 1080,
	}
	access := s.intranetTunnelAccess(nil, socks)
	if access["proxy"] != "socks5://10.0.0.5:1080" {
		t.Fatalf("socks access = %+v", access)
	}
	loop := &db.IntranetTunnel{
		Kind: db.IntranetTunnelKindSocks5, Status: db.IntranetTunnelDeployed,
		ListenHost: "127.0.0.1", ListenPort: 1080,
	}
	if access := s.intranetTunnelAccess(nil, loop); access["loopback_only"] != true {
		t.Fatalf("loopback access = %+v", access)
	}
	planned := &db.IntranetTunnel{
		Kind: db.IntranetTunnelKindSocks5, Status: db.IntranetTunnelPlanned,
		ListenHost: "0.0.0.0", ListenPort: 1080,
	}
	if access := s.intranetTunnelAccess(nil, planned); access != nil {
		t.Fatalf("planned tunnel should have no access hint: %+v", access)
	}
}

func TestIntranetCredentialURLAndParts(t *testing.T) {
	cred := &db.IntranetCredential{Host: "10.0.0.5", Port: 8080, Protocol: "http"}
	if got := intranetCredentialURL(cred); got != "http://10.0.0.5:8080" {
		t.Fatalf("derived url = %s", got)
	}
	cred.URL = "http://10.0.0.5/login.php"
	if got := intranetCredentialURL(cred); got != cred.URL {
		t.Fatalf("stored url = %s", got)
	}
	host, port, scheme := intranetTargetParts("https://Example.COM:8443/login")
	if host != "example.com" || port != 8443 || scheme != "https" {
		t.Fatalf("parts = %s/%d/%s", host, port, scheme)
	}
	if got := normalizeIntranetReuseURL("10.0.0.5/login"); got != "http://10.0.0.5/login" {
		t.Fatalf("normalized = %s", got)
	}
}

func writeFakeWebCrackBridge(t *testing.T, found bool) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake_webcrack.py")
	pyFound := "False"
	if found {
		pyFound = "True"
	}
	body := fmt.Sprintf(`import json, sys
sys.stdin.read()
urls = []
args = sys.argv[1:]
for i, a in enumerate(args):
    if a == "--url" and i + 1 < len(args):
        urls.append(args[i + 1])
results = []
for u in urls:
    results.append({"url": u, "found": %s, "username": "admin", "password": "s3cret",
                    "kind": "weak", "cookie": "sid=1", "attempts": 1, "elapsed_ms": 3,
                    "request": "POST /login HTTP/1.1\r\nHost: target\r\n\r\n",
                    "response": "HTTP/1.1 200 OK\r\n\r\nwelcome", "error": "", "log": []})
print(json.dumps({"tool": "webcrack", "results": results, "missing": False, "error": ""}))
`, pyFound)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIntranetReuseCredentialMarksValidAndRegisters(t *testing.T) {
	pg := prescanTestDB(t)
	t.Setenv("JINGWEI_WEBCRACK_BRIDGE", writeFakeWebCrackBridge(t, true))
	if !scanner.WebCrackAvailable() {
		t.Skip("python3 unavailable for fake WebCrack bridge")
	}
	const credHost, targetHost = "10.250.77.9", "10.250.77.10"
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM intranet_credentials WHERE host = ANY($1::text[])`, []string{credHost, targetHost})
	})
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: credHost, Port: 80, Protocol: "http", URL: "http://" + credHost + "/login.php",
		Username: "admin", Password: "s3cret", Source: "weakpass",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	res, err := s.intranetReuseCredential(context.Background(), pg, intranetReuseInput{
		CredentialID: cred.ID,
		URLs:         []string{"http://" + targetHost + "/login.php"},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := res["targets"].([]intranetReuseTarget)
	if !ok || len(targets) != 1 {
		t.Fatalf("targets = %#v", res["targets"])
	}
	if targets[0].Status != "valid" || targets[0].Host != targetHost {
		t.Fatalf("target = %+v", targets[0])
	}
	if targets[0].Request == "" || targets[0].Response == "" {
		t.Fatalf("raw evidence missing: %+v", targets[0])
	}
	updated, err := pg.GetIntranetCredential(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != db.IntranetCredValid || updated.LastUsedAt == nil {
		t.Fatalf("credential status = %+v", updated)
	}
	rows, err := pg.ListIntranetCredentials(db.IntranetCredentialFilter{Host: targetHost})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Source != "reuse" {
		t.Fatalf("reuse rows = %+v", rows)
	}
}

func TestIntranetReuseCredentialRejectsUnparseableTargets(t *testing.T) {
	pg := prescanTestDB(t)
	t.Setenv("JINGWEI_WEBCRACK_BRIDGE", writeFakeWebCrackBridge(t, true))
	if !scanner.WebCrackAvailable() {
		t.Skip("python3 unavailable for fake WebCrack bridge")
	}
	const host = "10.250.77.11"
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_credentials WHERE host=$1`, host) })
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: host, Username: "admin", Password: "s3cret", Source: "weakpass",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	_, err = s.intranetReuseCredential(context.Background(), pg, intranetReuseInput{
		CredentialID: cred.ID, URLs: []string{"not a url"},
	})
	if err == nil || !strings.Contains(err.Error(), "无法解析") {
		t.Fatalf("expected unparseable urls error, got %v", err)
	}
	if rows, _ := pg.ListIntranetCredentials(db.IntranetCredentialFilter{Host: host}); len(rows) != 1 || rows[0].Status != db.IntranetCredUntested {
		t.Fatalf("credential should stay untested: %+v", rows)
	}
	if _, err := s.intranetReuseCredential(context.Background(), pg, intranetReuseInput{CredentialID: 99999999}); err == nil {
		t.Fatal("expected error for missing credential")
	}
}

func TestIntranetReuseCredentialRejectionSemantics(t *testing.T) {
	pg := prescanTestDB(t)
	t.Setenv("JINGWEI_WEBCRACK_BRIDGE", writeFakeWebCrackBridge(t, false))
	if !scanner.WebCrackAvailable() {
		t.Skip("python3 unavailable for fake WebCrack bridge")
	}
	const credHost, targetHost = "10.250.77.12", "10.250.77.13"
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM intranet_credentials WHERE host = ANY($1::text[])`, []string{credHost, targetHost})
	})
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: credHost, Port: 80, Protocol: "http", URL: "http://" + credHost + "/login.php",
		Username: "admin", Password: "s3cret", Source: "weakpass",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}

	// A rejection on another host says nothing about the original credential.
	res, err := s.intranetReuseCredential(context.Background(), pg, intranetReuseInput{
		CredentialID: cred.ID, URLs: []string{"http://" + targetHost + "/login.php"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if note, ok := res["note"].(string); !ok || !strings.Contains(note, "状态保持不变") {
		t.Fatalf("expected retention note, res = %#v", res)
	}
	updated, err := pg.GetIntranetCredential(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != db.IntranetCredUntested {
		t.Fatalf("cross-host rejection must keep status untested, got %+v", updated)
	}

	// A rejection on the credential's own host marks it invalid.
	if _, err := s.intranetReuseCredential(context.Background(), pg, intranetReuseInput{
		CredentialID: cred.ID, URLs: []string{"http://" + credHost + "/login.php"},
	}); err != nil {
		t.Fatal(err)
	}
	updated, err = pg.GetIntranetCredential(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != db.IntranetCredInvalid {
		t.Fatalf("own-host rejection must mark invalid, got %+v", updated)
	}
	if updated.Evidence == "" {
		t.Fatalf("invalid credential should carry evidence: %+v", updated)
	}
}

func TestApproveIntranetScopeRequestRefluxesAssets(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet scope reflux fixture", "reflux fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	const host = "10.251.13.7"
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM intranet_scope_requests WHERE task_id=$1`, task.ID)
		_, _ = pg.Exec(`DELETE FROM assets WHERE type='service' AND service_type='other' AND ip=$1 AND port=8443`, host)
		_, _ = pg.Exec(`DELETE FROM assets WHERE type='ip' AND ip=$1`, host)
	})
	req, _, err := pg.CreateIntranetScopeRequest(db.IntranetScopeRequestInput{
		TaskID: task.ID, Host: host, Port: 8443, Reason: "fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{pg: pg}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/intranet/scope-requests/"+strconv.FormatInt(req.ID, 10)+"/approve", strings.NewReader(`{"note":"ok"}`))
	r.SetPathValue("id", strconv.FormatInt(req.ID, 10))
	s.approveIntranetScopeRequest(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Request db.IntranetScopeRequest `json:"request"`
		Assets  struct {
			Registered bool  `json:"registered"`
			IPID       int64 `json:"ip_id"`
			ServiceID  int64 `json:"service_id"`
		} `json:"assets"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Request.Status != db.IntranetScopeApproved {
		t.Fatalf("request = %+v", resp.Request)
	}
	if !resp.Assets.Registered || resp.Assets.IPID <= 0 || resp.Assets.ServiceID <= 0 {
		t.Fatalf("assets = %+v warnings=%v", resp.Assets, resp.Warnings)
	}
}

func TestIntranetTaskScopeNets(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet scope nets fixture", "scope fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.252.0.0/24", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	inScope, err := intranetTaskScopeNets(pg, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !inScope("10.252.0.9") {
		t.Fatal("10.252.0.9 should be inside 10.252.0.0/24")
	}
	if inScope("10.253.0.9") {
		t.Fatal("10.253.0.9 should be out of scope")
	}
}
