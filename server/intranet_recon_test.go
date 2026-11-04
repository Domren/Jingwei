package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	deploy, reason, side := autoSelectTunnelCommand(tr.Kind, intranetProbeInfo{Bins: []string{"chisel"}}, tr)
	if deploy == "" {
		t.Fatalf("chisel socks5 deploy empty: %s", reason)
	}
	if !strings.Contains(deploy, "10.9.9.9:8788") || !strings.Contains(deploy, "1080:socks") {
		t.Fatalf("deploy = %s", deploy)
	}
	if strings.Contains(deploy, "YOUR_C2") {
		t.Fatalf("placeholder leaked: %s", deploy)
	}
	// chisel client 不带 R: 时监听开在控制端：记成 target 会让 verify 在目标上查一个
	// 从来不存在端口，把好隧道判死。
	if side != db.IntranetListenSidePivot {
		t.Fatalf("chisel socks5 listen side = %q, want %q", side, db.IntranetListenSidePivot)
	}
	if !strings.Contains(deploy, "echo $p >/tmp/jw_tunnel_7.pid") || !strings.Contains(deploy, "JW_PID:$p") {
		t.Fatalf("chisel deploy must record the pid on the target too: %s", deploy)
	}

	// ssh -D 在目标上开监听，选型不能把监听侧写成 pivot。
	sshSide, _, side := autoSelectTunnelCommand(tr.Kind, intranetProbeInfo{Bins: []string{"ssh"}}, tr)
	if side != db.IntranetListenSideTarget {
		t.Fatalf("ssh -D listen side = %q, want target", side)
	}
	if !strings.Contains(sshSide, "ssh -N -D 0.0.0.0:1080") || !strings.Contains(sshSide, "BatchMode=yes") {
		t.Fatalf("ssh -D deploy = %s", sshSide)
	}

	t.Setenv("JINGWEI_PIVOT_SERVER", "")
	deploy, reason, side = autoSelectTunnelCommand(db.IntranetTunnelKindSocks5, intranetProbeInfo{Bins: []string{"chisel"}}, tr)
	if deploy != "" || !strings.Contains(reason, "JINGWEI_PIVOT_SERVER") {
		t.Fatalf("expected clear pivot error, deploy=%q reason=%q", deploy, reason)
	}

	// socat needs no pivot endpoint.
	fwd := &db.IntranetTunnel{ID: 8, Kind: db.IntranetTunnelKindPort, ListenHost: "0.0.0.0", ListenPort: 8080, RemoteHost: "10.0.0.8", RemotePort: 80}
	deploy, reason, side = autoSelectTunnelCommand(fwd.Kind, intranetProbeInfo{Bins: []string{"socat"}}, fwd)
	if deploy == "" || !strings.Contains(deploy, "socat") || reason == "" {
		t.Fatalf("socat deploy = %q reason=%q", deploy, reason)
	}
	if side != db.IntranetListenSideTarget {
		t.Fatalf("socat listen side = %q, want target", side)
	}
	// chisel 的 R: 把监听开在**控制端**（chisel server 一侧），拨号目的地由目标发起——
	// 2026-11-05 真机实测：`R:18474:10.99.0.10:8000` 的监听进程是控制端的 chisel server，
	// 经它取到仅内网服务 200；不带 R: 的形态才是目标监听、控制端拨号。
	rev := &db.IntranetTunnel{ID: 9, Kind: db.IntranetTunnelKindRemote, ListenHost: "0.0.0.0", ListenPort: 8888, RemoteHost: "127.0.0.1", RemotePort: 3000}
	t.Setenv("JINGWEI_PIVOT_SERVER", "10.9.9.9:8788")
	deploy, _, side = autoSelectTunnelCommand(rev.Kind, intranetProbeInfo{Bins: []string{"chisel"}}, rev)
	if side != db.IntranetListenSidePivot || !strings.Contains(deploy, "R:0.0.0.0:8888:127.0.0.1:3000") {
		t.Fatalf("chisel R: tunnel = %q side=%q", deploy, side)
	}
	// port_forward（目标监听且由目标拨号）这个方向 chisel 表达不了，必须拒绝而不是给反向命令。
	pf := &db.IntranetTunnel{ID: 10, Kind: db.IntranetTunnelKindPort, ListenHost: "0.0.0.0", ListenPort: 8080, RemoteHost: "10.0.0.8", RemotePort: 80}
	deploy, reason, _ = autoSelectTunnelCommand(pf.Kind, intranetProbeInfo{Bins: []string{"chisel"}}, pf)
	if deploy != "" || !strings.Contains(reason, "socat") {
		t.Fatalf("chisel 对 port_forward 应当拒绝并指向 socat: deploy=%q reason=%q", deploy, reason)
	}
}

func TestIntranetTunnelTeardownCoversLostPID(t *testing.T) {
	if got := intranetTunnelTeardown(0, 0); got != "" {
		t.Fatalf("no pid and no tunnel id must yield no teardown: %q", got)
	}
	withPID := intranetTunnelTeardown(4321, 7)
	if !strings.Contains(withPID, "kill 4321") || !strings.Contains(withPID, "kill -9 4321") {
		t.Fatalf("teardown must kill the captured pid: %q", withPID)
	}
	// 部署输出被壳吃掉时只剩 pid 文件：拆除仍要能收回那个 chisel/ssh 客户端。
	if !strings.Contains(withPID, `p=$(cat /tmp/jw_tunnel_7.pid 2>/dev/null)`) {
		t.Fatalf("teardown must fall back to the on-target pid file: %q", withPID)
	}
	onlyFile := intranetTunnelTeardown(0, 7)
	if !strings.Contains(onlyFile, "/tmp/jw_tunnel_7.pid") || strings.Contains(onlyFile, "kill 0") {
		t.Fatalf("pid-less teardown = %q", onlyFile)
	}
	if !strings.Contains(onlyFile, "rm -f /tmp/jw_tunnel_7.pid /tmp/jw_tunnel_7.log") {
		t.Fatalf("teardown must remove its own residue: %q", onlyFile)
	}
}

func TestIntranetPivotListenerChecks(t *testing.T) {
	if !intranetHostIsLocal("127.0.0.1") || !intranetHostIsLocal("localhost") {
		t.Fatal("loopback must count as this host")
	}
	if intranetHostIsLocal("") || intranetHostIsLocal("203.0.113.9") {
		t.Fatal("empty/external addresses must not count as this host")
	}
	if got := intranetPivotMarkerPort("pivot:tcp:18080"); got != 18080 {
		t.Fatalf("marker port = %d", got)
	}
	if got := intranetPivotMarkerPort("ss -lnt"); got != 0 {
		t.Fatalf("non-marker must yield 0, got %d", got)
	}
	// 占住一个端口再检查：控制端即本机时读监听表，不能把在听的端口说成没在听。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen locally: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if ok, detail := intranetPivotListenerState("127.0.0.1", port); !ok {
		t.Fatalf("listener on this host reported down: %s", detail)
	}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot reserve a free port: %v", err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	free.Close()
	if ok, detail := intranetPivotListenerState("127.0.0.1", freePort); ok || !strings.Contains(detail, "没有") {
		t.Fatalf("absent port must report down with a reason: ok=%v detail=%q", ok, detail)
	}
	if ok, detail := intranetPivotListenerState("", port); ok || !strings.Contains(detail, "JINGWEI_PIVOT_SERVER") {
		t.Fatalf("missing pivot host must be an honest failure: ok=%v detail=%q", ok, detail)
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
	if access["listen_side"] != db.IntranetListenSideTarget {
		t.Fatalf("target-side hint = %+v", access)
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
	// 监听侧是 pivot 时，即便 listen_host 记着目标的 127.0.0.1，也必须给出控制端地址：
	// 按目标回环处理会让操作员以为隧道只能从目标内部用，而它其实已经能直连。
	t.Setenv("JINGWEI_PIVOT_SERVER", "10.9.9.9:8788")
	pivoted := &db.IntranetTunnel{
		Kind: db.IntranetTunnelKindSocks5, Status: db.IntranetTunnelVerified,
		ListenHost: "127.0.0.1", ListenPort: 1080, ListenSide: db.IntranetListenSidePivot,
	}
	access = s.intranetTunnelAccess(nil, pivoted)
	if access["listen_side"] != db.IntranetListenSidePivot || access["proxy"] != "socks5://10.9.9.9:1080" {
		t.Fatalf("pivot-side access = %+v", access)
	}
	if access["loopback_only"] == true {
		t.Fatalf("pivot-side tunnel must not be reported as target-loopback only: %+v", access)
	}
	// 反向转发（R:）的监听在目标上，控制端一侧只有 chisel server 端口。
	rev := &db.IntranetTunnel{
		Kind: db.IntranetTunnelKindRemote, Status: db.IntranetTunnelVerified,
		ListenHost: "10.0.0.5", ListenPort: 8888, RemoteHost: "127.0.0.1", RemotePort: 3000,
	}
	access = s.intranetTunnelAccess(nil, rev)
	if access["endpoint"] != "10.0.0.5:8888" {
		t.Fatalf("reverse forward endpoint must stay on the target: %+v", access)
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
