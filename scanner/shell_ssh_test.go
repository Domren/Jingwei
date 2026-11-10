package scanner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshTestServer is a minimal in-process SSH server: enough to accept a password
// login, run one exec command and report an exit status, so the SSH transport can
// be exercised without an external host.
type sshTestServer struct {
	listener net.Listener
	user     string
	password string
	execute  func(cmd string) (string, int)
	delay    time.Duration
	hostKey  ssh.Signer
	stall    chan struct{}

	mu   sync.Mutex
	seen []string
}

func newSSHTestServer(t *testing.T, user, password string, execute func(string) (string, int)) *sshTestServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &sshTestServer{
		listener: ln, user: user, password: password,
		execute: execute, hostKey: signer, stall: make(chan struct{}),
	}
	go srv.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

func (srv *sshTestServer) commands() []string {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return append([]string{}, srv.seen...)
}

func (srv *sshTestServer) serve() {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if meta.User() != srv.user || string(pass) != srv.password {
				return nil, errors.New("password rejected")
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(srv.hostKey)
	for {
		conn, err := srv.listener.Accept()
		if err != nil {
			return
		}
		go srv.handle(conn, cfg)
	}
}

func (srv *sshTestServer) handle(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, requests, err := newChan.Accept()
		if err != nil {
			return
		}
		go srv.handleSession(channel, requests)
	}
}

func (srv *sshTestServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for req := range requests {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var payload struct {
			Command string
		}
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		srv.mu.Lock()
		srv.seen = append(srv.seen, payload.Command)
		srv.mu.Unlock()
		_ = req.Reply(true, nil)

		out, code := "", 0
		if srv.execute != nil {
			out, code = srv.execute(payload.Command)
		}
		if srv.delay > 0 {
			select {
			case <-time.After(srv.delay):
			case <-srv.stall:
				return
			}
		}
		_, _ = io.WriteString(channel, out)
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ ExitStatus uint32 }{ExitStatus: uint32(code)}))
		return
	}
}

func (srv *sshTestServer) target(timeout time.Duration) SSHCommandTarget {
	return SSHCommandTarget{
		Addr: srv.listener.Addr().String(), User: srv.user, Password: srv.password, Timeout: timeout,
	}
}

func TestRunSSHCommandReturnsOutputAndMarkers(t *testing.T) {
	srv := newSSHTestServer(t, "root", "hunter2", func(string) (string, int) {
		return "hello from target\n__JW_CWD__/tmp\n__JW_EC__0\n", 0
	})
	out, err := RunSSHCommand(context.Background(), srv.target(5*time.Second), "echo hi")
	if err != nil {
		t.Fatalf("run failed: %v (out=%q)", err, out)
	}
	if !strings.Contains(out, "hello from target") || !strings.Contains(out, "__JW_EC__0") {
		t.Fatalf("unexpected output: %q", out)
	}
	got := srv.commands()
	if len(got) != 1 || got[0] != "echo hi" {
		t.Fatalf("server saw %q", got)
	}
}

func TestRunSSHCommandNonZeroExitIsNotTransportError(t *testing.T) {
	srv := newSSHTestServer(t, "u", "p", func(string) (string, int) { return "boom\n", 7 })
	out, err := RunSSHCommand(context.Background(), srv.target(5*time.Second), "false")
	if err != nil {
		t.Fatalf("a non-zero exit must stay a real result: %v", err)
	}
	if !strings.Contains(out, "boom") {
		t.Fatalf("output lost: %q", out)
	}
}

func TestRunSSHCommandAuthFailure(t *testing.T) {
	srv := newSSHTestServer(t, "u", "right", nil)
	target := srv.target(5 * time.Second)
	target.Password = "wrong"
	_, err := RunSSHCommand(context.Background(), target, "id")
	if err == nil {
		t.Fatal("expected an authentication error")
	}
	if !strings.Contains(err.Error(), "认证失败") {
		t.Fatalf("error should say the credential was rejected: %v", err)
	}
}

func TestRunSSHCommandTimeout(t *testing.T) {
	srv := newSSHTestServer(t, "u", "p", func(string) (string, int) { return "late\n", 0 })
	srv.delay = 3 * time.Second
	started := time.Now()
	_, err := RunSSHCommand(context.Background(), srv.target(300*time.Millisecond), "sleep 10")
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("the timeout did not cut the connection: %v", elapsed)
	}
}

func TestRunSSHCommandUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	_, err = RunSSHCommand(context.Background(), SSHCommandTarget{
		Addr: addr, User: "u", Password: "p", Timeout: 2 * time.Second,
	}, "id")
	if err == nil || !strings.Contains(err.Error(), "拒绝连接") {
		t.Fatalf("expected a refused-connection error, got %v", err)
	}
}

func TestSSHAddrDefaultsTo22(t *testing.T) {
	if got := SSHAddr("10.99.0.20", 0); got != "10.99.0.20:22" {
		t.Fatalf("addr = %q", got)
	}
	if got := SSHAddr("fd00::1", 2222); got != "[fd00::1]:2222" {
		t.Fatalf("ipv6 addr = %q", got)
	}
}
