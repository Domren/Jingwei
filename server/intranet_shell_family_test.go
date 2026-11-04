package server

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// ---------------------------------------------------------------------------
// A2：SSH 承载会话必须认得出 cmd.exe 之外的解释器。Windows OpenSSH 的默认 shell
// 可配，越来越多机器给的是 PowerShell；chained 探针（带 `&`）在 PowerShell 里是语法
// 错误，什么回显都没有，于是过去这台机器被判成「不是预期的 shell」，会话在建好的
// 那一刻就 closed —— 明明凭据是真的、机器是能打的。
// ---------------------------------------------------------------------------

// labPSCwdRe picks the cwd a PowerShell wrapper was told to cd into (the first
// Set-Location, which is the one the wrapper emits before the command body).
var labPSCwdRe = regexp.MustCompile(`Set-Location -LiteralPath '([^']*)'`)

// labPowerShellShell answers like Windows PowerShell: the chained probe is a
// parse error (no output at all), the unchained one echoes %OS% literally, and
// only a PowerShell-shaped script gets the marker trailer.
type labPowerShellShell struct {
	mu       sync.Mutex
	commands []string
	pwd      string
	exitCode int
}

func (h *labPowerShellShell) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string{}, h.commands...)
}

func (h *labPowerShellShell) exec(script string) (string, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.commands = append(h.commands, script)
	wrapped := strings.Contains(script, "$ErrorActionPreference='Continue'")
	envProbe := strings.Contains(script, "__JW_HOST__")
	trailer := ""
	if wrapped {
		// The wrapper's own cwd statement is what moves the target's directory.
		if m := labPSCwdRe.FindStringSubmatch(script); len(m) > 1 {
			h.pwd = strings.ReplaceAll(m[1], "''", "'")
		}
		trailer = intranetEcMarker + strconv.Itoa(h.exitCode) + "\n" + intranetCwdMarker + "\n" + h.pwd + "\n"
	}
	switch {
	// `echo a & uname` is a ParserError in PowerShell 5.1: nothing runs.
	case strings.Contains(script, " & uname"):
		return "", 0
	case strings.Contains(script, intranetOSMark) && !wrapped:
		return intranetOSMark + "%OS%\n", 0
	case envProbe:
		if !strings.Contains(script, "$env:COMPUTERNAME") {
			// A POSIX/cmd env probe reaching PowerShell echoes its own markers
			// literally — that must not be mistaken for an answer.
			return "", 0
		}
		body := "__JW_HOST__LAB-WIN-7\n__JW_KERNEL__Windows_NT\n__JW_USER__LAB-WIN-7\\labuser\n__JW_BIN__powershell\n__JW_BIN__curl\n"
		if wrapped {
			return body + "LAB-PS-OUTPUT\n" + trailer, 0
		}
		return body, 0
	case wrapped:
		return "LAB-PS-OUTPUT\n" + trailer, 0
	}
	// Not a PowerShell-shaped script: the caller would be running sh/cmd syntax here.
	return "", 0
}

// labLoginShell answers nothing but its own message: the account can log in, but
// its shell is a placeholder that never executes commands.
type labLoginShell struct {
	mu     sync.Mutex
	notice string
	seen   int
}

func (h *labLoginShell) exec(string) (string, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seen++
	return h.notice + "\n", 1
}

func TestIntranetScriptPowerShellSpeaksMarkers(t *testing.T) {
	script := intranetScriptPowerShell(`C:\inetpub\www root`, "whoami")
	for _, want := range []string{"$ErrorActionPreference='Continue'", "Set-Location -LiteralPath", "__JW_EC__", "__JW_CWD__", "(Get-Location).Path", "whoami"} {
		if !strings.Contains(script, want) {
			t.Fatalf("PowerShell wrapper lost %q: %s", want, script)
		}
	}
	// A PowerShell single-quoted literal doubles its quotes; the space inside the
	// path must survive without turning into a second argument.
	if !strings.Contains(script, `'C:\inetpub\www root'`) {
		t.Fatalf("cwd must be a quoted literal: %s", script)
	}
	esc := intranetScriptPowerShell(`C:\it's`, "dir")
	if !strings.Contains(esc, `'C:\it''s'`) {
		t.Fatalf("single quote must be doubled: %s", esc)
	}
	// Backtick path: PowerShell single quotes take it literally, so it is safe to
	// quote — but a control character in the path would end the statement.
	ctrl := intranetScriptPowerShell("C:\\new\nline", "dir")
	if strings.Contains(ctrl, "Set-Location") {
		t.Fatalf("a path with a control character must not be spliced in: %q", ctrl)
	}
	// A session row defaults its cwd to "/", which under PowerShell would cd to the
	// current drive's root and then report *that* as the working directory.
	rooty := intranetScriptPowerShell("/", "dir")
	if strings.Contains(rooty, "Set-Location") {
		t.Fatalf("a POSIX-looking cwd must be ignored, not cd-ed into: %s", rooty)
	}
}

func TestShellWrapperPicksByInterpreter(t *testing.T) {
	cases := []struct {
		osKind, shell string
		want          string
	}{
		{intranetOSPosix, intranetShellSh, "trap"},
		{intranetOSWindows, intranetShellCmd, "chcp 65001"},
		{intranetOSWindows, intranetShellPowerShell, "$ErrorActionPreference"},
		// An unknown interpreter on a Windows box keeps the historical cmd choice:
		// webshell channels report an OS, not a shell.
		{intranetOSWindows, "", "chcp 65001"},
		{intranetOSPosix, "", "trap"},
	}
	for _, c := range cases {
		got := shellWrapper(c.osKind, c.shell, "/tmp", "id")
		if !strings.Contains(got, c.want) {
			t.Fatalf("wrapper(%q,%q) = %q, want it to contain %q", c.osKind, c.shell, got, c.want)
		}
	}
}

func TestShellFamilyProbeCascadesPastTheChainedSyntax(t *testing.T) {
	powershell := func(ctx context.Context, script string, _ time.Duration) (string, error) {
		if strings.Contains(script, " & uname") {
			return "", nil // parse error: PowerShell answers nothing
		}
		return intranetOSMark + "%OS%\n", nil
	}
	osKind, shell, ok := shellFamilyProbe(context.Background(), powershell)
	if !ok || osKind != intranetOSWindows || shell != intranetShellPowerShell {
		t.Fatalf("PowerShell host = (%q,%q,ok=%v), want windows/powershell", osKind, shell, ok)
	}

	chained := func(ctx context.Context, script string, _ time.Duration) (string, error) {
		return intranetOSMark + "Linux\n", nil
	}
	if osKind, shell, ok := shellFamilyProbe(context.Background(), chained); !ok || osKind != intranetOSPosix || shell != intranetShellSh {
		t.Fatalf("posix host = (%q,%q,ok=%v)", osKind, shell, ok)
	}

	cmdHost := func(ctx context.Context, script string, _ time.Duration) (string, error) {
		return intranetOSMark + intranetWindowsOSValue + "\n", nil
	}
	if osKind, shell, ok := shellFamilyProbe(context.Background(), cmdHost); !ok || osKind != intranetOSWindows || shell != intranetShellCmd {
		t.Fatalf("cmd host = (%q,%q,ok=%v)", osKind, shell, ok)
	}

	silent := func(ctx context.Context, script string, _ time.Duration) (string, error) { return "", nil }
	if _, _, ok := shellFamilyProbe(context.Background(), silent); ok {
		t.Fatal("a target that answers neither syntax must stay unconfirmed")
	}
}

func TestIntranetNotAShellReasonNamesTheCause(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"This account is currently not available.", "nologin"},
		{"forced command only", "ForceCommand"},
		{"", "毫无回应"},
		{"totally unexpected banner", "三种语法"},
	}
	for _, c := range cases {
		if got := intranetNotAShellReason(c.raw); !strings.Contains(got, c.want) {
			t.Fatalf("reason(%q) = %q, want it to mention %q", c.raw, got, c.want)
		}
	}
}

// TestIntranetOpenSSHSessionDrivesPowerShellHost is the positive path A2 exists
// for: a Windows host whose default shell is PowerShell becomes a managed
// session, keeps its cwd and reports an exit code.
func TestIntranetOpenSSHSessionDrivesPowerShellHost(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("intranet powershell session fixture", "10.99.0.30", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	sshFixtureCleanup(t, pg, task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.99.0.0/24", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "10.99.0.30", Port: 22, Protocol: "ssh",
		Username: "labuser", Password: "lab-pass-ps", Source: "weakpass", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	shell := &labPowerShellShell{pwd: `C:\Users\labuser`, exitCode: 0}
	srv := newLabSSHServer(t, "labuser", "lab-pass-ps", shell.exec)
	s := &Server{m: &Manager{pg: pg}}

	sess, info, err := s.intranetOpenSSHSession(context.Background(), pg, intranetSSHSessionRequest{
		Name: "ps lab", TaskID: task.ID, Host: "10.99.0.30", Port: 22,
		CredentialID: cred.ID, DialHost: "127.0.0.1", DialPort: srv.port(),
	})
	if err != nil {
		t.Fatalf("a PowerShell host must become a session, not a closed row: %v", err)
	}
	if sess.Status != db.IntranetSessionActive {
		t.Fatalf("session status = %q, want active", sess.Status)
	}
	if sess.Metadata["os"] != intranetOSWindows || sess.Metadata["shell"] != intranetShellPowerShell {
		t.Fatalf("family cache = %#v, want os=windows shell=powershell", sess.Metadata)
	}
	if info.Host != "LAB-WIN-7" || !strings.Contains(info.User, "labuser") {
		t.Fatalf("probe not parsed from the PowerShell script: %+v", info)
	}
	if !intranetHasBin(info, "powershell") {
		t.Fatalf("bins lost: %+v", info.Bins)
	}
	if sess.Cwd != `C:\Users\labuser` {
		t.Fatalf("cwd = %q", sess.Cwd)
	}

	out := s.intranetRun(context.Background(), pg, sess, "ipconfig /all", 20*time.Second)
	if out.IsError || out.ExitCode != 0 || !out.MarkerOK {
		t.Fatalf("powershell exec failed: %+v", out)
	}
	if !strings.Contains(out.Output, "LAB-PS-OUTPUT") {
		t.Fatalf("output lost: %q", out.Output)
	}
	sent := shell.all()
	if len(sent) < 3 {
		t.Fatalf("target saw too few commands: %d", len(sent))
	}
	// The first two sends are the probes themselves — the chained one is *supposed*
	// to be unparseable, that is how PowerShell gets identified. Everything after
	// the family is known must speak PowerShell: one sh/cmd line slipping through is
	// the exact bug this test exists for.
	for i, sc := range sent {
		if strings.Contains(sc, "__JW_HOST__") && !strings.Contains(sc, "$env:COMPUTERNAME") {
			t.Fatalf("sent a non-PowerShell env probe at step %d: %s", i, sc)
		}
		if strings.Contains(sc, "ipconfig /all") && !strings.Contains(sc, "$ErrorActionPreference") {
			t.Fatalf("sent a non-PowerShell command wrapper at step %d: %s", i, sc)
		}
	}

	// The exit code must reach the ledger as the target's, not as "marker missing".
	shell.mu.Lock()
	shell.exitCode = 3
	shell.mu.Unlock()
	out2 := s.intranetRun(context.Background(), pg, sess, "net user", 20*time.Second)
	if out2.ExitCode != 3 || !out2.IsError {
		t.Fatalf("exit code not carried: %+v", out2)
	}

	beforeRecon := len(shell.all())
	// Recon must be collected in PowerShell syntax too: the cmd form is one long
	// `&` chain and a PowerShell host would answer nothing at all.
	s.intranetRecon(context.Background(), pg, sess, false)
	after := shell.all()
	if len(after) <= beforeRecon {
		t.Fatal("recon never reached the target")
	}
	reconSent := strings.Join(after[beforeRecon:], "\n")
	if strings.Contains(reconSent, "chcp 65001") || !strings.Contains(reconSent, "Get-Content") {
		t.Fatalf("recon used cmd syntax on a PowerShell host: %s", reconSent)
	}
	if stored, err := pg.GetIntranetSession(sess.ID); err == nil {
		if stored.Metadata["shell"] != intranetShellPowerShell {
			t.Fatalf("shell family not persisted: %#v", stored.Metadata)
		}
	}
	if len(shell.all()) < 3 {
		t.Fatalf("target saw too few commands: %d", len(shell.all()))
	}
}

// TestIntranetOpenSSHSessionNamesNonShellAccounts is the honest failure: an
// account that logs in but runs nothing must be closed with the reason, not left
// active and not reported as a working session.
func TestIntranetOpenSSHSessionNamesNonShellAccounts(t *testing.T) {
	cases := []struct {
		name   string
		notice string
		want   string
	}{
		{"nologin", "This account is currently not available.", "nologin"},
		{"forced", "warning: forced command only, no shell", "ForceCommand"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pg := prescanTestDB(t)
			task, err := pg.CreateTask("intranet noshell fixture "+c.name, "10.99.0.40", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			purgeTaskFixture(t, pg, task.ID)
			sshFixtureCleanup(t, pg, task.ID)
			if _, err := pg.Assets().AddAgentScope(task.ID, "ip", "10.99.0.0/24", "fixture", "manual"); err != nil {
				t.Fatal(err)
			}
			cred, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
				Host: "10.99.0.40", Port: 22, Protocol: "ssh",
				Username: "svc", Password: "lab-pass-noshell", Source: "manual", TaskID: task.ID,
			})
			if err != nil {
				t.Fatal(err)
			}
			h := &labLoginShell{notice: c.notice}
			srv := newLabSSHServer(t, "svc", "lab-pass-noshell", h.exec)
			s := &Server{m: &Manager{pg: pg}}
			sess, _, err := s.intranetOpenSSHSession(context.Background(), pg, intranetSSHSessionRequest{
				Name: c.name, TaskID: task.ID, Host: "10.99.0.40", Port: 22,
				CredentialID: cred.ID, DialHost: "127.0.0.1", DialPort: srv.port(),
			})
			if err == nil {
				t.Fatalf("a non-executing account must not yield a live session: %+v", sess)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error must name the cause %q, got: %v", c.want, err)
			}
			if sess == nil || sess.Status != db.IntranetSessionClosed {
				t.Fatalf("session must be closed, got %+v", sess)
			}
			// The credential is still true — login worked. Saying so keeps the
			// lateral-movement ledger from discarding a password that does work.
			if stored, serr := pg.GetIntranetCredential(cred.ID); serr == nil {
				if stored.Status != db.IntranetCredValid {
					t.Fatalf("a login that succeeded must keep the credential valid: %+v", stored)
				}
			}
		})
	}
}
