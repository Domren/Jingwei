package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// 进程内 SSH 靶机：够用来验密码登录、exec 通道与退出码，让 SSH 承载的会话不必
// 依赖真实主机就能跑完整链路。
// ---------------------------------------------------------------------------

type labSSHServer struct {
	listener net.Listener
	user     string
	password string
	execute  func(script string) (string, int)
	hostKey  ssh.Signer

	mu   sync.Mutex
	seen []string
}

func newLabSSHServer(t *testing.T, user, password string, execute func(string) (string, int)) *labSSHServer {
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
	srv := &labSSHServer{listener: ln, user: user, password: password, execute: execute, hostKey: signer}
	go srv.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

func (srv *labSSHServer) port() int {
	_, portPart, err := net.SplitHostPort(srv.listener.Addr().String())
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(portPart)
	return port
}

func (srv *labSSHServer) addr() string {
	return srv.listener.Addr().String()
}

func (srv *labSSHServer) commands() []string {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return append([]string{}, srv.seen...)
}

func (srv *labSSHServer) serve() {
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

func (srv *labSSHServer) handle(conn net.Conn, cfg *ssh.ServerConfig) {
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

func (srv *labSSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
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
		_, _ = io.WriteString(channel, out)
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ ExitStatus uint32 }{uint32(code)}))
		return
	}
}

// labPOSIXShell answers the marker protocol the platform speaks. It tracks a
// working directory, so the test can prove the cwd handed to one command is the
// one the next command resumes with.
type labPOSIXShell struct {
	mu         sync.Mutex
	pwd        string
	wrapperCwd string
	commands   []string
	// hang is how long a "lab-hang" command stays unanswered, for tests that need
	// the operator's wait to end before the target's does.
	hang time.Duration
}

var (
	labWrapperCwdRe = regexp.MustCompile(`(?m)^cd '([^']*)' 2>/dev/null`)
	labBodyCwdRe    = regexp.MustCompile(`(?m)^[ \t]*cd (/[^ \t&]+)`)
)

func (h *labPOSIXShell) exec(script string) (string, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.commands = append(h.commands, script)
	// The OS probe goes out unwrapped: it must answer with its own marker only.
	if strings.Contains(script, "__JW_OS__") && !strings.Contains(script, intranetCwdMarker) {
		return "__JW_OS__Linux\n", 0
	}
	if strings.Contains(script, "lab-hang") {
		time.Sleep(h.hang)
		return "", 0
	}
	if m := labWrapperCwdRe.FindStringSubmatch(script); m != nil {
		h.wrapperCwd = m[1]
	}
	if m := labBodyCwdRe.FindStringSubmatch(script); m != nil {
		h.pwd = m[1]
	}
	out := "uid=1000(labuser) gid=1000(labuser) groups=1000(labuser)\n"
	if strings.Contains(script, "__JW_HOST__") {
		out = "__JW_HOST__lab-ssh-3\n__JW_KERNEL__Linux 6.18.0 x86_64\n" +
			"__JW_USER__uid=1000(labuser) gid=1000(labuser)\n__JW_BIN__python3\n__JW_BIN__socat\n"
	}
	return out + "\n" + intranetCwdMarker + h.pwd + "\n" + intranetEcMarker + "0\n", 0
}

func (h *labPOSIXShell) state() (pwd, wrapperCwd string, count int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pwd, h.wrapperCwd, len(h.commands)
}

func (h *labPOSIXShell) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string{}, h.commands...)
}

func sshFixtureCleanup(t *testing.T, pg *db.DB, taskID int64) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM intranet_session_events WHERE session_id IN (SELECT id FROM intranet_sessions WHERE task_id=$1)`, taskID)
		_, _ = pg.Exec(`DELETE FROM intranet_artifacts WHERE session_id IN (SELECT id FROM intranet_sessions WHERE task_id=$1)`, taskID)
		_, _ = pg.Exec(`DELETE FROM intranet_tunnels WHERE task_id=$1`, taskID)
		_, _ = pg.Exec(`DELETE FROM intranet_sessions WHERE task_id=$1`, taskID)
		_, _ = pg.Exec(`DELETE FROM intranet_credentials WHERE task_id=$1`, taskID)
		_, _ = pg.Exec(`DELETE FROM intranet_scope_requests WHERE task_id=$1`, taskID)
	})
}

func labSSHSessionRequest(taskID, credID int64, dialPort int) intranetSSHSessionRequest {
	return intranetSSHSessionRequest{
		Name: "lab ssh session", TaskID: taskID,
		Host: "10.99.0.20", Port: 22, CredentialID: credID,
		DialHost: "127.0.0.1", DialPort: dialPort,
	}
}

// TestIntranetOpenSSHSessionRunsCommandsOverSSH is the positive path: an internal
// host with no web service at all becomes a managed session, speaks the same
// marker protocol as a webshell, keeps its cwd, records events and proves the
// credential it logged in with.
func TestIntranetOpenSSHSessionRunsCommandsOverSSH(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet ssh session fixture", "10.99.0.20", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	sshFixtureCleanup(t, pg, task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.99.0.0/24", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "10.99.0.20", Port: 22, Protocol: "ssh",
		Username: "labuser", Password: "lab-pass-1", Source: "weakpass", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	shell := &labPOSIXShell{pwd: "/home/labuser"}
	srv := newLabSSHServer(t, "labuser", "lab-pass-1", shell.exec)
	s := &Server{m: &Manager{pg: pg}}

	sess, info, err := s.intranetOpenSSHSession(context.Background(), pg, labSSHSessionRequest(task.ID, cred.ID, srv.port()))
	if err != nil {
		t.Fatalf("open ssh session: %v", err)
	}
	if sess.Transport != db.IntranetTransportSSH {
		t.Fatalf("transport = %q, want ssh", sess.Transport)
	}
	if sess.WebshellID != nil {
		t.Fatalf("an ssh session must not bind a webshell: %+v", sess.WebshellID)
	}
	if sess.Host != "10.99.0.20" || sess.SSHPort != 22 || sess.SSHUser != "labuser" || sess.SSHCredentialID != cred.ID {
		t.Fatalf("session lost its ssh identity: %+v", sess)
	}
	// The ledger keeps the internal identity; only the dial points at the local
	// listener. Reversing that is exactly how the platform ends up as its own asset.
	if sess.SSHDialHost != "127.0.0.1" || sess.SSHDialPort != srv.port() {
		t.Fatalf("session lost its dial endpoint: %+v", sess)
	}
	if got := sess.SSHDialAddr(); got != net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.port())) {
		t.Fatalf("dial addr = %q, want %s", got, srv.addr())
	}
	if info.Host != "lab-ssh-3" || !strings.Contains(info.User, "labuser") || !intranetHasBin(info, "socat") {
		t.Fatalf("probe info not parsed over ssh: %+v", info)
	}
	if sess.Cwd != "/home/labuser" {
		t.Fatalf("cwd = %q, want the target's own home", sess.Cwd)
	}
	if sess.Metadata["os"] != intranetOSPosix {
		t.Fatalf("os cache = %#v", sess.Metadata["os"])
	}
	if dial, _ := sess.Metadata["ssh_dial"].(string); !strings.Contains(dial, "127.0.0.1") {
		t.Fatalf("metadata should record the overridden dial: %#v", sess.Metadata)
	}

	afterProbe, err := pg.GetIntranetCredential(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterProbe.Status != db.IntranetCredValid || !strings.Contains(afterProbe.Evidence, "SSH 登录 10.99.0.20:22 成功") {
		t.Fatalf("a successful ssh login must prove the credential: %+v", afterProbe)
	}

	out := s.intranetRun(context.Background(), pg, sess, "cd /tmp && id", 20*time.Second)
	if out.IsError || out.ExitCode != 0 {
		t.Fatalf("exec failed: %+v", out)
	}
	if !strings.Contains(out.Output, "uid=1000(labuser)") {
		t.Fatalf("output lost: %q", out.Output)
	}
	if out.Cwd != "/tmp" || sess.Cwd != "/tmp" {
		t.Fatalf("cwd = %q (session %q), want /tmp", out.Cwd, sess.Cwd)
	}
	stored, err := pg.GetIntranetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Cwd != "/tmp" {
		t.Fatalf("stored cwd = %q", stored.Cwd)
	}
	// The next command must resume where the last one landed, not the home dir.
	next := s.intranetRun(context.Background(), pg, sess, "id", 20*time.Second)
	if next.IsError {
		t.Fatalf("follow-up exec failed: %+v", next)
	}
	if _, wrapperCwd, _ := shell.state(); wrapperCwd != "/tmp" {
		t.Fatalf("the follow-up command did not resume the tracked cwd: %q", wrapperCwd)
	}

	// The OS family is probed once and cached: a probe per command would double the
	// round-trips of every exec, upload and persistence step.
	osProbes := 0
	for _, cmd := range shell.all() {
		if strings.Contains(cmd, "__JW_OS__") {
			osProbes++
		}
	}
	if osProbes != 1 {
		t.Fatalf("os probe ran %d times, want 1", osProbes)
	}

	out = s.intranetExec(context.Background(), pg, sess, "whoami", 20*time.Second)
	if out.IsError {
		t.Fatalf("exec error: %+v", out)
	}
	events, err := pg.ListIntranetSessionEvents(sess.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, ev := range events {
		kinds[ev.Kind] = ev.Command
	}
	if _, ok := kinds["probe"]; !ok {
		t.Fatalf("probe event missing: %+v", kinds)
	}
	if kinds["exec"] != "whoami" {
		t.Fatalf("exec event missing: %+v", kinds)
	}
}

// An SSH session has to report an abandoned wait the same way a landed webshell
// does — the terminal component and the worker both read timed_out to tell "this
// command never returns" from "this channel is dead" — and it must not advance
// last_seen for a command that never came back, or the stale-session scan would
// treat a hung target as a healthy one.
func TestIntranetSSHExecReportsAbandonedWait(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet ssh timeout fixture", "10.99.0.20", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	sshFixtureCleanup(t, pg, task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.99.0.0/24", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "10.99.0.20", Port: 22, Protocol: "ssh",
		Username: "labuser", Password: "lab-pass-2", Source: "weakpass", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	shell := &labPOSIXShell{pwd: "/home/labuser", hang: 3 * time.Second}
	srv := newLabSSHServer(t, "labuser", "lab-pass-2", shell.exec)
	s := &Server{m: &Manager{pg: pg}}

	sess, _, err := s.intranetOpenSSHSession(context.Background(), pg, labSSHSessionRequest(task.ID, cred.ID, srv.port()))
	if err != nil {
		t.Fatalf("open ssh session: %v", err)
	}
	before, err := pg.GetIntranetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}

	out := s.intranetRun(context.Background(), pg, sess, "lab-hang", time.Second)
	if !out.TimedOut || !out.IsError {
		t.Fatalf("abandoned wait misreported: %+v", out)
	}
	if !strings.Contains(out.Note, "仍在继续执行") {
		t.Fatalf("note should say the target may still be working: %q", out.Note)
	}
	if out.DurationMS < 900 {
		t.Fatalf("duration not measured for the turn: %d ms", out.DurationMS)
	}

	after, err := pg.GetIntranetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	sameSeen := (before.LastSeen == nil) == (after.LastSeen == nil)
	if before.LastSeen != nil && after.LastSeen != nil {
		sameSeen = before.LastSeen.Equal(*after.LastSeen)
	}
	if !sameSeen {
		t.Fatalf("a command that never returned advanced last_seen: %v -> %v", before.LastSeen, after.LastSeen)
	}
}

// TestIntranetOpenSSHSessionClosesWhenLoginFails keeps a misconfigured credential
// from leaving an "active" session that every later command fails on.
func TestIntranetOpenSSHSessionClosesWhenLoginFails(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet ssh failure fixture", "10.99.0.20", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	sshFixtureCleanup(t, pg, task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.99.0.0/24", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "10.99.0.20", Port: 22, Protocol: "ssh",
		Username: "labuser", Password: "wrong-password", Source: "weakpass", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	shell := &labPOSIXShell{pwd: "/root"}
	srv := newLabSSHServer(t, "labuser", "lab-pass-1", shell.exec)
	s := &Server{m: &Manager{pg: pg}}

	sess, _, err := s.intranetOpenSSHSession(context.Background(), pg, labSSHSessionRequest(task.ID, cred.ID, srv.port()))
	if err == nil {
		t.Fatal("a rejected login must fail the session")
	}
	if sess == nil {
		t.Fatal("the failed session must still be reported")
	}
	if sess.Status != db.IntranetSessionClosed {
		t.Fatalf("status = %q, want closed", sess.Status)
	}
	if !strings.Contains(err.Error(), "认证失败") {
		t.Fatalf("error should name the auth failure: %v", err)
	}
	unchanged, err := pg.GetIntranetCredential(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Status == db.IntranetCredValid {
		t.Fatal("a failed login must not mark the credential valid")
	}

	// The handler returns the closed session rather than a bare 400, so what was
	// attempted stays auditable.
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"name":"lab ssh handler","task_id":%d,"transport":"ssh","host":"10.99.0.20","port":22,`+
		`"credential_id":%d,"dial_host":"127.0.0.1","dial_port":%d}`, task.ID, cred.ID, srv.port())
	r := httptest.NewRequest("POST", "/api/intranet/sessions", strings.NewReader(body))
	s.createIntranetSession(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Session    db.IntranetSession `json:"session"`
		ProbeError string             `json:"probe_error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Session.Transport != db.IntranetTransportSSH || resp.Session.Status != db.IntranetSessionClosed {
		t.Fatalf("session = %+v", resp.Session)
	}
	if !strings.Contains(resp.ProbeError, "认证失败") {
		t.Fatalf("probe_error = %q", resp.ProbeError)
	}
}

// TestIntranetOpenSSHSessionWithoutMarkersCloses: a target that answers with
// something other than the expected shell family must not stay active.
func TestIntranetOpenSSHSessionWithoutMarkersCloses(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet ssh no-marker fixture", "10.99.0.20", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	sshFixtureCleanup(t, pg, task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.99.0.0/24", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "10.99.0.20", Port: 22, Protocol: "ssh", Username: "banner",
		Password: "p", Source: "manual", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := newLabSSHServer(t, "banner", "p", func(string) (string, int) {
		return "SSH-2.0-openring banner only\n", 0
	})
	s := &Server{m: &Manager{pg: pg}}
	sess, _, err := s.intranetOpenSSHSession(context.Background(), pg, labSSHSessionRequest(task.ID, cred.ID, srv.port()))
	if err == nil || sess == nil {
		t.Fatalf("a reply with no trailer must fail the session: sess=%+v err=%v", sess, err)
	}
	if sess.Status != db.IntranetSessionClosed {
		t.Fatalf("status = %q, want closed", sess.Status)
	}
	if !strings.Contains(err.Error(), "未解析到命令结束标记") {
		t.Fatalf("error should explain the missing trailer: %v", err)
	}
}

// TestIntranetSSHSessionRefusesPlatformSelf: the dial guard is what stops the
// platform from SSH-ing into itself and booking the result as an intranet host.
func TestIntranetSSHSessionRefusesPlatformSelf(t *testing.T) {
	pg := prescanTestDB(t)
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "127.0.0.1", Port: 22, Protocol: "ssh", Username: "root", Password: "p", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM intranet_session_events WHERE session_id IN (SELECT id FROM intranet_sessions WHERE webshell_id IS NULL AND host='127.0.0.1')`)
		_, _ = pg.Exec(`DELETE FROM intranet_sessions WHERE webshell_id IS NULL AND host='127.0.0.1'`)
		_, _ = pg.Exec(`DELETE FROM intranet_credentials WHERE id=$1`, cred.ID)
	})
	srv := newLabSSHServer(t, "root", "p", nil)
	s := &Server{m: &Manager{pg: pg}}
	if _, _, err := s.intranetOpenSSHSession(context.Background(), pg, intranetSSHSessionRequest{
		Name: "self", Host: "127.0.0.1", Port: 22, CredentialID: cred.ID,
	}); err == nil || !strings.Contains(err.Error(), "拒绝把平台自身作为 SSH 目标") {
		t.Fatalf("self-target must be refused, got %v", err)
	}
	if _, _, err := s.intranetOpenSSHSession(context.Background(), pg, intranetSSHSessionRequest{
		Name: "self", Host: "localhost", Port: 22, CredentialID: cred.ID,
		DialHost: "127.0.0.1", DialPort: srv.port(),
	}); err == nil || !strings.Contains(err.Error(), "拒绝把平台自身") {
		t.Fatalf("an explicit loopback dial of a local identity must be refused, got %v", err)
	}
}

func TestIntranetLocalDialResolvesTunnelledEndpoint(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet ssh dial fixture", "10.99.0.20", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	sshFixtureCleanup(t, pg, task.ID)
	tunnel, err := pg.CreateIntranetTunnel(db.IntranetTunnelInput{
		Name: "ssh forward", TaskID: task.ID, Kind: db.IntranetTunnelKindPort,
		ListenHost: "127.0.0.1", ListenPort: 41234, ListenSide: db.IntranetListenSidePivot,
		RemoteHost: "10.99.0.20", RemotePort: 22,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Status != db.IntranetTunnelPlanned {
		t.Fatalf("a fresh tunnel should stay planned, got %q", tunnel.Status)
	}
	// A planned tunnel has no listener on the machine yet, so it cannot vouch for
	// the port: the dial is still allowed (the identity is a real internal host)
	// but it is called out as unregistered.
	if _, _, note, err := intranetLocalDial(pg, "10.99.0.20", "127.0.0.1", 41234); err != nil ||
		!strings.Contains(note, "没有登记在隧道台账里") {
		t.Fatalf("a planned tunnel must not authorise the dial, got note=%q err=%v", note, err)
	}
	if _, err := pg.SetIntranetTunnelStatus(tunnel.ID, db.IntranetTunnelDeployed, 0, "", ""); err != nil {
		t.Fatalf("cannot mark tunnel deployed: %v", err)
	}

	host, port, note, err := intranetLocalDial(pg, "10.99.0.20", "127.0.0.1", 41234)
	if err != nil {
		t.Fatalf("tunnel-mapped dial must be accepted: %v", err)
	}
	if host != "127.0.0.1" || port != 41234 {
		t.Fatalf("dial = %s:%d", host, port)
	}
	if !strings.Contains(note, "隧道 #"+strconv.FormatInt(tunnel.ID, 10)) {
		t.Fatalf("note should credit the tunnel: %q", note)
	}
	if _, _, _, err := intranetLocalDial(pg, "10.99.0.21", "127.0.0.1", 41234); err == nil ||
		!strings.Contains(err.Error(), "与会话身份") {
		t.Fatalf("a mismatched identity must be refused, got %v", err)
	}
	if _, _, note, err := intranetLocalDial(pg, "10.99.0.30", "127.0.0.1", 41299); err != nil {
		t.Fatalf("an unregistered listener with a non-local identity is the lab case: %v", err)
	} else if !strings.Contains(note, "没有登记在隧道台账里") {
		t.Fatalf("note = %q", note)
	}
	if _, _, _, err := intranetLocalDial(pg, "10.99.0.30", "10.99.0.30", 22); err != nil {
		t.Fatalf("a directly reachable host needs no note: %v", err)
	}
}

// TestIntranetSSHAuthResolvesCredentialEachUse: the password lives in the ledger
// only, so deleting it must surface as an explicit message rather than a failed
// webshell lookup or a silent hang.
func TestIntranetSSHAuthResolvesCredentialEachUse(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet ssh auth fixture", "10.99.0.20", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	sshFixtureCleanup(t, pg, task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.99.0.0/24", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "10.99.0.20", Port: 22, Protocol: "ssh", Username: "labuser",
		Password: "lab-pass-2", Source: "weakpass", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	shell := &labPOSIXShell{pwd: "/srv"}
	srv := newLabSSHServer(t, "labuser", "lab-pass-2", shell.exec)
	s := &Server{m: &Manager{pg: pg}}
	sess, _, err := s.intranetOpenSSHSession(context.Background(), pg, labSSHSessionRequest(task.ID, cred.ID, srv.port()))
	if err != nil {
		t.Fatal(err)
	}
	if target, terr := s.intranetSSHAuth(pg, sess); terr != nil || target.User != "labuser" || target.Password != "lab-pass-2" {
		t.Fatalf("ssh auth = %+v err=%v", target, terr)
	}
	if _, err := pg.Exec(`DELETE FROM intranet_credentials WHERE id=$1`, cred.ID); err != nil {
		t.Fatal(err)
	}
	out := s.intranetRun(context.Background(), pg, sess, "id", 10*time.Second)
	if !out.IsError || !strings.Contains(out.Note, "已不存在") {
		t.Fatalf("a session whose credential is gone must say so: %+v", out)
	}
	if err := s.intranetTransportCheck(pg, sess); err == nil || !strings.Contains(err.Error(), "凭据") {
		t.Fatalf("transport check must fail fast: %v", err)
	}
}

func TestIntranetSSHSessionFailoverIsRejected(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet ssh failover fixture", "10.99.0.20", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	sshFixtureCleanup(t, pg, task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.99.0.0/24", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "10.99.0.20", Port: 22, Protocol: "ssh", Username: "labuser",
		Password: "lab-pass-3", Source: "weakpass", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	shell := &labPOSIXShell{pwd: "/home/labuser"}
	srv := newLabSSHServer(t, "labuser", "lab-pass-3", shell.exec)
	s := &Server{m: &Manager{pg: pg}}
	sess, _, err := s.intranetOpenSSHSession(context.Background(), pg, labSSHSessionRequest(task.ID, cred.ID, srv.port()))
	if err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(sess.ID, 10)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/intranet/sessions/"+id+"/failover", strings.NewReader(`{"webshell_id":1}`))
	r.SetPathValue("id", id)
	s.failoverIntranetSession(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "SSH 会话不走 webshell") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestNormalizeIntranetTransport(t *testing.T) {
	if got := db.NormalizeIntranetTransport("SSH"); got != db.IntranetTransportSSH {
		t.Fatalf("ssh = %q", got)
	}
	for _, v := range []string{"", "webshell", "php", "cmd"} {
		if got := db.NormalizeIntranetTransport(v); got != db.IntranetTransportWebshell {
			t.Fatalf("NormalizeIntranetTransport(%q) = %q", v, got)
		}
	}
}

func TestIntranetSessionSSHDefaults(t *testing.T) {
	sess := &db.IntranetSession{Host: "10.99.0.20"}
	if got := sess.SSHDialAddr(); got != "10.99.0.20:22" {
		t.Fatalf("default ssh addr = %q", got)
	}
	sess.SSHDialHost = "127.0.0.1"
	sess.SSHDialPort = 41234
	if got := sess.SSHDialAddr(); got != "127.0.0.1:41234" {
		t.Fatalf("overridden dial = %q", got)
	}
	if got := (&db.IntranetSession{}).SSHDialAddr(); got != "" {
		t.Fatalf("a session without any host must report no address, got %q", got)
	}
}

// A command the operator is still waiting on must not be mistaken for a dead
// session: the heartbeat skips the turn instead of recording a failure, or a long
// transfer would age a healthy host into "lost" and retire the session nobody
// asked to retire.
func TestIntranetHeartbeatSkipsBusySession(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet heartbeat busy fixture", "10.99.0.20", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	sshFixtureCleanup(t, pg, task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.99.0.0/24", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "10.99.0.20", Port: 22, Protocol: "ssh",
		Username: "labuser", Password: "lab-pass-3", Source: "weakpass", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	shell := &labPOSIXShell{pwd: "/home/labuser", hang: 3 * time.Second}
	srv := newLabSSHServer(t, "labuser", "lab-pass-3", shell.exec)
	s := &Server{m: &Manager{pg: pg}}
	sess, _, err := s.intranetOpenSSHSession(context.Background(), pg, labSSHSessionRequest(task.ID, cred.ID, srv.port()))
	if err != nil {
		t.Fatalf("open ssh session: %v", err)
	}
	_, failuresBefore := intranetSessionHealth(sess)

	_, _, scriptsBefore := shell.state()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.intranetRun(context.Background(), pg, sess, "lab-hang", 5*time.Second)
	}()
	// Wait until the hung turn has actually been delivered, or the heartbeat wins
	// the lock first and the test proves nothing.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, count := shell.state(); count > scriptsBefore {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// 「脚本已被 shell 收到」不等于「那一轮已经持住会话锁」。机器忙的时候心跳会
	// 抢在持锁之前跑完，于是测到的是探测失败而不是跳过——用例在负载下就是红在这里。
	// 挂起的命令跑满 3 秒，等锁就位是快的；等不到就是前提不成立，直说。
	busy := false
	for time.Now().Before(deadline) {
		mu := intranetTurnLock(sess.ID)
		if !mu.TryLock() {
			busy = true
			break
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	if !busy {
		t.Fatal("没等到「上一条命令仍在执行」的锁位，用例前提不成立")
	}

	alive, out, _ := s.intranetHeartbeatCheck(context.Background(), pg, sess, false)
	if alive {
		t.Fatal("a busy session must not report a successful probe")
	}
	if !strings.Contains(out.Note, "未探测") {
		t.Fatalf("the heartbeat must say it skipped, not that the target failed: %q", out.Note)
	}

	current, err := pg.GetIntranetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, failuresAfter := intranetSessionHealth(current); failuresAfter != failuresBefore {
		t.Fatalf("a busy session must not advance the failure counter: %d -> %d", failuresBefore, failuresAfter)
	}
	<-done
}
