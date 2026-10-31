package scanner

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeProxyURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"  socks5://127.0.0.1:1080 ", "socks5://127.0.0.1:1080", false},
		{"http://user:pass@10.0.0.2:8080", "http://user:pass@10.0.0.2:8080", false},
		{"https://proxy.corp:8443", "https://proxy.corp:8443", false},
		{"ftp://127.0.0.1:21", "", true},
		{"socks5://", "", true},
		{"socks5://127.0.0.1:0", "", true},
		{"://bad", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeProxyURL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: got %q want %q", c.in, got, c.want)
		}
	}
}

// TestProxyDialFuncHTTPConnect exercises the CONNECT path against a local stub
// proxy: the dialer must send the requested authority and then pass bytes.
func TestProxyDialFuncHTTPConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	denied := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
				}
				if !strings.HasPrefix(line, "CONNECT internal.example:8080 ") {
					denied <- struct{}{}
					_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				_, _ = io.Copy(c, br)
			}(conn)
		}
	}()

	dial, err := ProxyDialFunc("http://"+ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial(context.Background(), "tcp", "internal.example:8080")
	if err != nil {
		t.Fatalf("dial through CONNECT: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
	select {
	case <-denied:
		t.Fatal("proxy saw a different CONNECT authority")
	default:
	}
}

func TestProxyDialFuncRejectsUnsupportedScheme(t *testing.T) {
	if _, err := ProxyDialFunc("ftp://127.0.0.1:21", time.Second); err == nil {
		t.Fatal("expected error")
	}
}

func TestScanPortsWithDialRoutesEveryConnect(t *testing.T) {
	var calls int32
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt32(&calls, 1)
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	open, err := scanPortsWithDial(context.Background(), []string{"10.0.0.5", "10.0.0.6"}, []int{22, 443}, 2, time.Second, dial, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Fatalf("dial calls = %d, want 4", got)
	}
	if len(open) != 4 {
		t.Fatalf("open = %d, want 4", len(open))
	}
}

func TestDiscoverRejectsBadProxy(t *testing.T) {
	targets, err := ParseTargets([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(context.Background(), targets, DiscoverOptions{Ports: "web", Proxy: "ftp://127.0.0.1:21"}); err == nil {
		t.Fatal("expected proxy scheme error")
	}
}
