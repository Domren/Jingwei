package server

import (
	"net"
	"testing"
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
