package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestParsePortSpecTop1000Default(t *testing.T) {
	def, err := ParsePortSpec("")
	if err != nil {
		t.Fatal(err)
	}
	if len(def) < 1000 {
		t.Fatalf("default preset should cover 1-1024 plus service ports, got %d", len(def))
	}
	seen := map[int]bool{}
	for _, p := range def {
		seen[p] = true
	}
	for _, want := range []int{22, 80, 443, 445, 1433, 3306, 5432, 6379, 8085, 9200, 27017} {
		if !seen[want] {
			t.Errorf("top1000 preset missing port %d", want)
		}
	}
	explicit, err := ParsePortSpec("top1000")
	if err != nil {
		t.Fatal(err)
	}
	if len(explicit) != len(def) {
		t.Fatalf("top1000 alias mismatch: %d vs %d", len(explicit), len(def))
	}
	top100, err := ParsePortSpec("top100")
	if err != nil {
		t.Fatal(err)
	}
	if len(top100) >= len(def) {
		t.Fatalf("top100 should be smaller than top1000")
	}
}

func TestPortLabelCoversServices(t *testing.T) {
	cases := map[int]string{
		22: "ssh", 445: "smb", 1433: "mssql", 3306: "mysql", 6379: "redis",
		9200: "elasticsearch", 27017: "mongodb", 2375: "docker",
	}
	for port, want := range cases {
		if got := PortLabel(port); got != want {
			t.Errorf("PortLabel(%d)=%q want %q", port, got, want)
		}
	}
	if got := PortLabel(65000); got != "" {
		t.Errorf("unknown port should have no label, got %q", got)
	}
}

func TestClassifyBanner(t *testing.T) {
	cases := []struct {
		banner string
		want   string
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n", "ssh"},
		{"220 (vsFTPd 3.0.5)\r\n", "ftp"},
		{"220 mail.example.com ESMTP Postfix\r\n", "smtp"},
		{"+OK Dovecot ready.\r\n", "pop3"},
		{"* OK [CAPABILITY IMAP4rev1] ready\r\n", "imap"},
		{"RFB 003.008\n", "vnc"},
		{"HTTP/1.1 400 Bad Request\r\n", "http"},
		{"AMQP\x00\x00\x09\x01", "amqp"},
		{"\xff\xfd\x18\xff\xfd\x20", "telnet"},
		{"random-bytes", ""},
	}
	for _, c := range cases {
		if got := classifyBanner(c.banner); got != c.want {
			t.Errorf("classifyBanner(%q)=%q want %q", c.banner, got, c.want)
		}
	}
	// MySQL handshake packets are binary but contain auth plugin names.
	mysql := "\x4a\x00\x00\x00\x0a" + strings.Repeat("x", 20) + "mysql_native_password\x00"
	if got := classifyBanner(mysql); got != "mysql" {
		t.Errorf("classifyBanner(mysql)=%q want mysql", got)
	}
}

func TestFingerprintOneSSH(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_ = conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	fp := fingerprintOne(context.Background(), PortFinding{IP: "127.0.0.1", Port: port})
	if fp.Service != "ssh" {
		t.Fatalf("service=%q, want ssh (banner=%q)", fp.Service, fp.Banner)
	}
	if !strings.Contains(fp.Banner, "OpenSSH_9.6") {
		t.Fatalf("banner not captured: %q", fp.Banner)
	}
	if fp.TLS {
		t.Fatalf("ssh banner should skip TLS probe")
	}
	if !definitelyNotHTTP(fp.Service) {
		t.Fatalf("ssh should not get an HTTP probe")
	}
}

func TestFingerprintOneTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	fp := fingerprintOne(context.Background(), PortFinding{IP: "127.0.0.1", Port: port})
	if !fp.TLS {
		t.Fatalf("expected TLS handshake to succeed, got %+v", fp)
	}
	if fp.CertCN == "" {
		t.Fatalf("expected certificate CN, got %+v", fp)
	}
	if fp.TLSVersion == "" {
		t.Fatalf("expected TLS version, got %+v", fp)
	}
	if definitelyNotHTTP(fp.Service) {
		t.Fatalf("TLS service %q should still be HTTP-probed", fp.Service)
	}
}

func TestProbeExtraPortsFindsHTTPOnOddPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "werkzeug/2.0")
		_, _ = w.Write([]byte("<html><title>odd port app</title></html>"))
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	res := &Resolved{IPs: []string{host}, DomainsByIP: map[string][]string{}}
	open := []PortFinding{{IP: host, Port: port}}
	fps := map[string]ServiceFingerprint{
		fingerprintKey(host, port): {IP: host, Port: port},
	}
	got := probeExtraPorts(context.Background(), res, open, fps, nil, 10, func(string, ...any) {})
	if len(got) != 1 {
		t.Fatalf("want 1 service on odd port, got %d: %+v", len(got), got)
	}
	if !strings.Contains(got[0].URL, ":"+portStr+"/") {
		t.Fatalf("unexpected service URL: %s", got[0].URL)
	}
	if !strings.Contains(got[0].Title, "odd port app") {
		t.Fatalf("title not extracted: %+v", got[0])
	}
}

func TestCoveredServicePortsMapsDomainToIP(t *testing.T) {
	services := []WebService{{URL: "http://app.example.test:8080/", IP: "10.0.0.5", Port: 8080}}
	covered := CoveredServicePorts(services, map[string][]string{"10.0.0.5": {"app.example.test"}})
	for _, key := range []string{"10.0.0.5|8080", "app.example.test|8080"} {
		if !covered[key] {
			t.Errorf("expected %s covered: %+v", key, covered)
		}
	}
	if covered["10.0.0.5|22"] {
		t.Errorf("port 22 should not be covered")
	}
}

func TestProbeExtraPortsSkipsIdentifiedProtocols(t *testing.T) {
	if !definitelyNotHTTP("redis") || !definitelyNotHTTP("mysql") {
		t.Fatal("redis/mysql must be skipped by the HTTP extra pass")
	}
	if definitelyNotHTTP("") || definitelyNotHTTP("tls") || definitelyNotHTTP("elasticsearch") {
		t.Fatal("empty/tls/http-capable labels must remain HTTP-probe candidates")
	}
}
