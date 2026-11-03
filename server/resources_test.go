package server

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

func TestParseProcAddr(t *testing.T) {
	cases := []struct {
		raw  string
		ip   string
		port int
		ok   bool
	}{
		{"0100007F:1F90", "127.0.0.1", 8080, true},
		{"00000000:0050", "0.0.0.0", 80, true},
		{"0A00000A:22B8", "10.0.0.10", 8888, true},
		{"00000000000000000000000001000000:0050", "::1", 80, true},
		{"00000000000000000000000000000000:01BB", "::", 443, true},
		{"bad", "", 0, false},
	}
	for _, tc := range cases {
		ip, port, ok := parseProcAddr(tc.raw)
		if ok != tc.ok {
			t.Fatalf("%s ok = %v, want %v", tc.raw, ok, tc.ok)
		}
		if !ok {
			continue
		}
		if ip.String() != tc.ip || port != tc.port {
			t.Fatalf("%s = %s:%d, want %s:%d", tc.raw, ip.String(), port, tc.ip, tc.port)
		}
	}
}

func TestListenerScope(t *testing.T) {
	if got := listenerScope(net.ParseIP("127.0.0.1")); got != "loopback" {
		t.Fatalf("loopback = %q", got)
	}
	if got := listenerScope(net.ParseIP("::1")); got != "loopback" {
		t.Fatalf("ipv6 loopback = %q", got)
	}
	if got := listenerScope(net.ParseIP("0.0.0.0")); got != "wildcard" {
		t.Fatalf("wildcard = %q", got)
	}
	if got := listenerScope(net.ParseIP("10.1.2.3")); got != "interface" {
		t.Fatalf("interface = %q", got)
	}
}

func TestEndpointPort(t *testing.T) {
	cases := []struct {
		endpoint string
		want     int
	}{
		{"1.2.3.4:1389", 1389},
		{"ldap://1.2.3.4:1389/path", 1389},
		{"https://a.example.com/x", 443},
		{"http://a.example.com", 80},
		{"not-a-port", 0},
		{"", 0},
	}
	for _, tc := range cases {
		if got := endpointPort(tc.endpoint); got != tc.want {
			t.Fatalf("endpointPort(%q) = %d, want %d", tc.endpoint, got, tc.want)
		}
	}
}

func TestAuditLocalPortsRuns(t *testing.T) {
	// The dev container always has listeners; the result must be usable even when
	// /proc is unavailable (empty lists, no panic).
	res := (&Server{}).auditLocalPorts(t.Context())
	if res.CheckedAt.IsZero() {
		t.Fatal("checked_at not set")
	}
	if res.Listeners == nil || res.Unmanaged == nil {
		t.Fatal("nil slices")
	}
	for _, l := range res.Unmanaged {
		if l.Managed || l.Platform || l.Scope == "loopback" {
			t.Fatalf("unmanaged listener has wrong flags: %+v", l)
		}
	}
}

func TestMetadataInt64(t *testing.T) {
	// JSON 数字回到 Go 里是 float64，写回再读出时可能是字符串，两种都要认。
	var fromJSON map[string]any
	if err := json.Unmarshal([]byte(`{"tunnel_id":3,"pid":"26427"}`), &fromJSON); err != nil {
		t.Fatal(err)
	}
	if got := metadataInt64(fromJSON, "tunnel_id"); got != 3 {
		t.Fatalf("float64 tunnel_id = %d", got)
	}
	if got := metadataInt64(fromJSON, "pid"); got != 26427 {
		t.Fatalf("string pid = %d", got)
	}
	if got := metadataInt64(map[string]any{"x": int64(7)}, "x"); got != 7 {
		t.Fatalf("int64 = %d", got)
	}
	for _, md := range []map[string]any{nil, {}, {"tunnel_id": "abc"}, {"tunnel_id": nil}} {
		if got := metadataInt64(md, "tunnel_id"); got != 0 {
			t.Fatalf("bad metadata %#v = %d, want 0", md, got)
		}
	}
}

func TestRunCleanupRebuildsTunnelTeardown(t *testing.T) {
	m := &resourceManager{s: &Server{m: &Manager{}}}
	var ran int
	m.runCleanup(t.Context(), &db.ManagedResource{ID: 1, Kind: db.ManagedKindTunnel}, func(context.Context) { ran++ })
	if ran != 1 {
		t.Fatal("in-process cleanup closure must still win when it exists")
	}
	// 回调丢失（平台重启）时不能再静默跳过：隧道行的 metadata 里有 tunnel_id，
	// 按台账补做拆除。pg 为空时 intranetStopTunnel 直接返回，这里只要求不 panic。
	m.runCleanup(t.Context(), &db.ManagedResource{
		ID: 2, Kind: db.ManagedKindTunnel, Metadata: map[string]any{"tunnel_id": float64(9)},
	}, nil)
	for _, kind := range []string{db.ManagedKindWebshell, db.ManagedKindCallback} {
		m.runCleanup(t.Context(), &db.ManagedResource{ID: 3, Kind: kind}, nil)
	}
}
