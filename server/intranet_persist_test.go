package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

func TestNormalizeCronSchedule(t *testing.T) {
	ok := map[string]string{
		"*/5 * * * *":     "*/5 * * * *",
		" 0  2\t* * 1-5 ": "0 2 * * 1-5",
		"@reboot":         "@reboot",
		"@daily":          "@daily",
	}
	for raw, want := range ok {
		got, err := normalizeCronSchedule(raw)
		if err != nil || got != want {
			t.Errorf("normalizeCronSchedule(%q)=%q err=%v want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "* * * *", "* * * * * *", "@sometimes", "*/5 * * * *\nreboot"} {
		if _, err := normalizeCronSchedule(raw); err == nil {
			t.Errorf("schedule %q should be rejected", raw)
		}
	}
}

func TestBuildCronPersistPlan(t *testing.T) {
	plan, err := buildCronPersistPlan(intranetPersistInput{
		Schedule: "*/5 * * * *", Command: "date +%s", Name: "beacon",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != db.IntranetArtifactCron || plan.Name != "beacon" || !strings.HasPrefix(plan.Path, "crontab:") {
		t.Fatalf("plan = %+v", plan)
	}
	marker, _ := plan.Metadata["marker"].(string)
	if marker == "" && plan.Metadata["token"] != nil {
		marker = "# jw:" + plan.Metadata["token"].(string)
	}
	if marker == "" {
		t.Fatalf("metadata = %+v", plan.Metadata)
	}
	for name, cmd := range map[string]string{"deploy": plan.Deploy, "revoke": plan.Revoke, "verify": plan.Verify} {
		if !strings.Contains(cmd, marker) {
			t.Errorf("%s command lacks marker: %q", name, cmd)
		}
	}
	if !strings.Contains(plan.Deploy, `date +\%s`) {
		t.Errorf("cron %% not escaped: %q", plan.Deploy)
	}
	if !strings.Contains(plan.Deploy, "crontab -") || !strings.Contains(plan.Revoke, "grep -vF") {
		t.Errorf("cron commands = %q / %q", plan.Deploy, plan.Revoke)
	}
	if _, err := buildCronPersistPlan(intranetPersistInput{Schedule: "* * * * *", Command: "id\nreboot"}); err == nil {
		t.Fatal("multi-line cron command must be rejected")
	}
}

func TestBuildSystemdPersistPlan(t *testing.T) {
	plan, err := buildSystemdPersistPlan(intranetPersistInput{Command: "sleep 1000", Name: "keeper"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != db.IntranetArtifactSystemd || !strings.HasPrefix(plan.Path, "/etc/systemd/system/jingwei-") ||
		!strings.HasSuffix(plan.Path, ".service") {
		t.Fatalf("plan = %+v", plan)
	}
	for name, cmd := range map[string]string{"deploy": plan.Deploy, "revoke": plan.Revoke, "verify": plan.Verify} {
		if !strings.Contains(cmd, plan.Path) {
			t.Errorf("%s command lacks unit path: %q", name, cmd)
		}
	}
	if !strings.Contains(plan.Deploy, "systemctl enable --now") || !strings.Contains(plan.Deploy, "base64 -d") {
		t.Errorf("deploy = %q", plan.Deploy)
	}
	scriptPath, _ := plan.Metadata["script_path"].(string)
	if scriptPath == "" || !strings.Contains(plan.Revoke, scriptPath) {
		t.Fatalf("script path = %q metadata=%+v revoke=%q", scriptPath, plan.Metadata, plan.Revoke)
	}
	if _, err := buildSystemdPersistPlan(intranetPersistInput{}); err == nil {
		t.Fatal("missing command must be rejected")
	}
}

func TestBuildSSHKeyPersistPlan(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl tester@example"
	plan, err := buildSSHKeyPersistPlan(intranetPersistInput{PublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != db.IntranetArtifactSSHKey || !strings.HasPrefix(plan.Path, "authorized_keys:current:") {
		t.Fatalf("plan = %+v", plan)
	}
	marker, _ := plan.Metadata["marker"].(string)
	if marker == "" || !strings.Contains(plan.Deploy, marker) || !strings.Contains(plan.Revoke, marker) || !strings.Contains(plan.Verify, marker) {
		t.Fatalf("marker %q missing: %+v", marker, plan)
	}
	if strings.Contains(plan.Deploy, "tester@example") {
		t.Errorf("original key comment must be dropped: %q", plan.Deploy)
	}
	if strings.Contains(plan.Deploy, "mkdir -p") == false || strings.Contains(plan.Revoke, "grep -vF") == false {
		t.Errorf("deploy/revoke = %q / %q", plan.Deploy, plan.Revoke)
	}

	if _, err := buildSSHKeyPersistPlan(intranetPersistInput{PublicKey: key + "\nreboot"}); err == nil {
		t.Fatal("multi-line public key must be rejected")
	}
	if _, err := buildSSHKeyPersistPlan(intranetPersistInput{PublicKey: "not-a-key AAAA"}); err == nil {
		t.Fatal("unknown key type must be rejected")
	}
	if _, err := buildSSHKeyPersistPlan(intranetPersistInput{PublicKey: key, User: "bad user"}); err == nil {
		t.Fatal("invalid user must be rejected")
	}

	named, err := buildSSHKeyPersistPlan(intranetPersistInput{PublicKey: key, User: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(named.Deploy, "getent passwd 'deploy'") {
		t.Errorf("named user home not resolved: %q", named.Deploy)
	}
}

func TestBuildSchtasksPersistPlan(t *testing.T) {
	plan, err := buildSchtasksPersistPlan(intranetPersistInput{Command: "echo jw-beacon", Name: "beacon"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != db.IntranetArtifactSchtasks || !strings.HasPrefix(plan.Path, "schtasks:beacon-") {
		t.Fatalf("plan = %+v", plan)
	}
	task, _ := plan.Metadata["task_name"].(string)
	if task == "" || !strings.Contains(plan.Deploy, winQuote(task)) || !strings.Contains(plan.Verify, winQuote(task)) || !strings.Contains(plan.Revoke, winQuote(task)) {
		t.Fatalf("task %q missing from commands: %+v", task, plan)
	}
	for name, cmd := range map[string]string{"deploy": plan.Deploy, "revoke": plan.Revoke, "verify": plan.Verify} {
		wantPart := map[string]string{"deploy": "schtasks /create /f /tn", "revoke": "schtasks /delete /f /tn", "verify": "schtasks /query /tn"}[name]
		if !strings.Contains(cmd, wantPart) {
			t.Errorf("%s command = %q", name, cmd)
		}
	}
	if !strings.Contains(plan.Deploy, "/sc onlogon") || !strings.Contains(plan.Deploy, "cmd.exe /c echo jw-beacon") {
		t.Errorf("deploy = %q", plan.Deploy)
	}
	if !strings.Contains(plan.Deploy, intranetArtifactOK) || !strings.Contains(plan.Verify, intranetArtifactPresent) || !strings.Contains(plan.Verify, intranetArtifactGone) {
		t.Errorf("artifact markers missing: %+v", plan)
	}
	if !strings.HasSuffix(plan.Revoke, "cmd /c exit 0") || !strings.HasSuffix(plan.Verify, "cmd /c exit 0") {
		t.Errorf("windows revoke/verify must reset ERRORLEVEL: %q / %q", plan.Revoke, plan.Verify)
	}

	minute, err := buildSchtasksPersistPlan(intranetPersistInput{Command: "echo hi", Schedule: "minute:15"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(minute.Deploy, "/sc minute /mo 15") {
		t.Errorf("minute deploy = %q", minute.Deploy)
	}
	if _, err := buildSchtasksPersistPlan(intranetPersistInput{Command: "echo hi", Schedule: "everyday"}); err == nil {
		t.Fatal("invalid schedule must be rejected")
	}
	if _, err := buildSchtasksPersistPlan(intranetPersistInput{Command: "echo hi", Schedule: "minute:0"}); err == nil {
		t.Fatal("minute:0 must be rejected")
	}
	for _, bad := range []string{"", "echo \"x\"", "echo 100%", "echo a\necho b"} {
		if _, err := buildSchtasksPersistPlan(intranetPersistInput{Command: bad}); err == nil {
			t.Fatalf("command %q must be rejected", bad)
		}
	}
	if _, err := buildSchtasksPersistPlan(intranetPersistInput{Command: "echo hi", Name: "bad name"}); err == nil {
		t.Fatal("invalid name must be rejected")
	}
}

func TestBuildRegistryPersistPlan(t *testing.T) {
	plan, err := buildRegistryPersistPlan(intranetPersistInput{Command: "echo jw-run", Name: "runkey"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != db.IntranetArtifactRegistry || !strings.HasPrefix(plan.Path, intranetWindowsRunKey+`\runkey-`) {
		t.Fatalf("plan = %+v", plan)
	}
	value, _ := plan.Metadata["value"].(string)
	if value == "" || !strings.Contains(plan.Deploy, winQuote(value)) || !strings.Contains(plan.Verify, winQuote(value)) || !strings.Contains(plan.Revoke, winQuote(value)) {
		t.Fatalf("value %q missing from commands: %+v", value, plan)
	}
	if !strings.Contains(plan.Deploy, "reg add "+winQuote(intranetWindowsRunKey)) ||
		!strings.Contains(plan.Deploy, "/t REG_SZ") || !strings.Contains(plan.Deploy, "cmd.exe /c echo jw-run") {
		t.Errorf("deploy = %q", plan.Deploy)
	}
	if !strings.Contains(plan.Verify, "reg query "+winQuote(intranetWindowsRunKey)) ||
		!strings.Contains(plan.Revoke, "reg delete "+winQuote(intranetWindowsRunKey)) {
		t.Errorf("verify/revoke = %q / %q", plan.Verify, plan.Revoke)
	}
	if !strings.HasSuffix(plan.Revoke, "cmd /c exit 0") || !strings.HasSuffix(plan.Verify, "cmd /c exit 0") {
		t.Errorf("windows revoke/verify must reset ERRORLEVEL: %q / %q", plan.Revoke, plan.Verify)
	}
	if _, err := buildRegistryPersistPlan(intranetPersistInput{Command: "echo hi", Name: "bad/name"}); err == nil {
		t.Fatal("invalid name must be rejected")
	}
}

func TestBuildIntranetPersistPlanKindValidation(t *testing.T) {
	if _, err := buildIntranetPersistPlan(intranetPersistInput{Kind: "file"}); err == nil {
		t.Fatal("file is not a standard persistence module")
	}
	if _, err := buildIntranetPersistPlan(intranetPersistInput{Kind: db.IntranetArtifactSchtasks, Command: "echo hi"}); err != nil {
		t.Fatalf("schtasks dispatch: %v", err)
	}
	if _, err := buildIntranetPersistPlan(intranetPersistInput{Kind: db.IntranetArtifactRegistry, Command: "echo hi"}); err != nil {
		t.Fatalf("registry dispatch: %v", err)
	}
}

func TestIntranetPersistKindForOS(t *testing.T) {
	for _, kind := range []string{db.IntranetArtifactCron, db.IntranetArtifactSystemd, db.IntranetArtifactSSHKey} {
		if err := intranetPersistKindForOS(kind, intranetOSPosix); err != nil {
			t.Errorf("posix kind %s rejected: %v", kind, err)
		}
		if err := intranetPersistKindForOS(kind, intranetOSWindows); err == nil {
			t.Errorf("posix kind %s must be rejected on Windows", kind)
		}
	}
	for _, kind := range []string{db.IntranetArtifactSchtasks, db.IntranetArtifactRegistry} {
		if err := intranetPersistKindForOS(kind, intranetOSWindows); err != nil {
			t.Errorf("windows kind %s rejected: %v", kind, err)
		}
		if err := intranetPersistKindForOS(kind, intranetOSPosix); err == nil {
			t.Errorf("windows kind %s must be rejected on POSIX", kind)
		}
	}
	if err := intranetPersistKindForOS("file", intranetOSPosix); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
}

// newIntranetPersistFixture wires a fake PHP webshell that runs the delivered
// script locally under a temp HOME and a stub crontab. It lets the generated
// deploy/revoke commands execute for real without touching the host.
func newIntranetPersistFixture(t *testing.T, pg *db.DB) (*Server, *db.IntranetSession, string) {
	t.Helper()
	home := t.TempDir()
	binDir := t.TempDir()
	crontabStub := `#!/bin/sh
f="$HOME/.crontab"
case "$1" in
  -l) [ -f "$f" ] && cat "$f" || exit 1 ;;
  -) cat > "$f" ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(binDir, "crontab"), []byte(crontabStub), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		raw := r.FormValue("jingwei")
		const prefix = "@system(base64_decode('"
		const suffix = "'));"
		if !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, suffix) {
			_, _ = w.Write([]byte("usage"))
			return
		}
		script, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(raw, prefix), suffix))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cmd := exec.Command("/bin/sh", "-c", string(script))
		cmd.Dir = home
		cmd.Env = append(os.Environ(), "HOME="+home, "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
		out, _ := cmd.CombinedOutput()
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)

	ws, err := pg.CreateWebshell(db.WebshellInput{
		Name: "persist-fixture", URL: srv.URL, ShellType: "php", Password: "jingwei",
		Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := pg.CreateIntranetSession(db.IntranetSessionInput{
		Name: "persist-fixture", WebshellID: ws.ID, Host: "10.250.88.5", Cwd: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM intranet_artifacts WHERE session_id=$1`, sess.ID)
		_, _ = pg.Exec(`DELETE FROM intranet_sessions WHERE id=$1`, sess.ID)
		_, _ = pg.Exec(`DELETE FROM webshells WHERE id=$1`, ws.ID)
	})
	return &Server{m: &Manager{pg: pg}}, sess, home
}

func TestIntranetPersistCronDeployAndRevoke(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, home := newIntranetPersistFixture(t, pg)

	art, out, verify, err := s.intranetPersist(context.Background(), pg, intranetPersistInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactCron,
		Schedule: "*/5 * * * *", Command: "echo jw-beacon", Name: "t-cron",
	})
	if err != nil {
		t.Fatalf("persist failed: %v out=%+v verify=%+v", err, out, verify)
	}
	if art == nil || art.Status != db.IntranetArtifactActive || art.Host != "10.250.88.5" {
		t.Fatalf("artifact = %+v", art)
	}
	if art.TaskID != nil {
		t.Fatalf("session without task should not invent one: %+v", art.TaskID)
	}
	crontab, err := os.ReadFile(filepath.Join(home, ".crontab"))
	if err != nil {
		t.Fatalf("stub crontab not written: %v", err)
	}
	if !strings.Contains(string(crontab), "echo jw-beacon") || !strings.Contains(string(crontab), "# jw:") {
		t.Fatalf("crontab = %q", crontab)
	}

	revoked, _, vout, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0)
	if err != nil || !ok {
		t.Fatalf("revoke ok=%v err=%v verify=%+v", ok, err, vout)
	}
	if revoked.Status != db.IntranetArtifactRevoked || revoked.RevokedAt == nil {
		t.Fatalf("revoked artifact = %+v", revoked)
	}
	crontab, _ = os.ReadFile(filepath.Join(home, ".crontab"))
	if strings.Contains(string(crontab), "jw-beacon") {
		t.Fatalf("crontab entry survived revoke: %q", crontab)
	}

	again, _, _, revokedAgain, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0)
	if err != nil || !revokedAgain || again.Status != db.IntranetArtifactRevoked {
		t.Fatalf("second revoke should be a no-op: %+v ok=%v err=%v", again, revokedAgain, err)
	}
}

func TestIntranetPersistSSHKeyDeployAndRevoke(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, home := newIntranetPersistFixture(t, pg)
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl tester@example"

	art, out, verify, err := s.intranetPersist(context.Background(), pg, intranetPersistInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactSSHKey, PublicKey: key,
	})
	if err != nil {
		t.Fatalf("persist failed: %v out=%+v verify=%+v", err, out, verify)
	}
	authFile := filepath.Join(home, ".ssh", "authorized_keys")
	data, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("authorized_keys missing: %v", err)
	}
	if !strings.Contains(string(data), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl jw:") {
		t.Fatalf("authorized_keys = %q", data)
	}
	if strings.Contains(string(data), "tester@example") {
		t.Fatalf("original comment leaked into authorized_keys: %q", data)
	}

	if _, _, vout, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0); err != nil || !ok {
		t.Fatalf("revoke ok=%v err=%v verify=%+v", ok, err, vout)
	}
	data, err = os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("authorized_keys removed by revoke: %v", err)
	}
	if strings.Contains(string(data), "jw:") {
		t.Fatalf("key survived revoke: %q", data)
	}
}

func TestIntranetRevokeTrustsGoneVerifyOverExitCode(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, _ := newIntranetPersistFixture(t, pg)

	art, err := s.intranetRegisterArtifact(pg, intranetArtifactRegisterInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactOther, Name: "already-gone",
		RevokeCommand: "false",
		VerifyCommand: "echo " + intranetArtifactGone,
	})
	if err != nil {
		t.Fatal(err)
	}
	revoked, revokeOut, verifyOut, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0)
	if err != nil || !ok {
		t.Fatalf("verify GONE should be enough: ok=%v err=%v revoke=%+v verify=%+v", ok, err, revokeOut, verifyOut)
	}
	if revoked.Status != db.IntranetArtifactRevoked {
		t.Fatalf("artifact = %+v", revoked)
	}
}

func TestIntranetUploadRegistersRevocableArtifact(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, home := newIntranetPersistFixture(t, pg)
	target := filepath.Join(home, "tool.sh")

	out, err := s.intranetUpload(context.Background(), pg, sess, target, []byte("#!/bin/sh\necho hi\n"))
	if err != nil {
		t.Fatalf("upload failed: %v out=%+v", err, out)
	}
	if !strings.Contains(out.Note, "落地物") {
		t.Fatalf("upload note = %q", out.Note)
	}
	rows, total, err := pg.ListIntranetArtifacts(db.IntranetArtifactFilter{SessionID: sess.ID, Kind: db.IntranetArtifactFile})
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("artifacts total=%d rows=%+v err=%v", total, rows, err)
	}
	art := rows[0]
	if art.Path != target || art.Status != db.IntranetArtifactActive || art.Name != "tool.sh" {
		t.Fatalf("artifact = %+v", art)
	}

	if _, _, vout, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0); err != nil || !ok {
		t.Fatalf("revoke ok=%v err=%v verify=%+v", ok, err, vout)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("uploaded file survived revoke: err=%v", err)
	}
}

func TestIntranetUploadSkipsLedgerForExistingFile(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, home := newIntranetPersistFixture(t, pg)
	target := filepath.Join(home, "existing.conf")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.intranetUpload(context.Background(), pg, sess, target, []byte("replaced")); err != nil {
		t.Fatal(err)
	}
	rows, total, err := pg.ListIntranetArtifacts(db.IntranetArtifactFilter{SessionID: sess.ID})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("overwritten file must not enter the ledger: total=%d rows=%+v err=%v", total, rows, err)
	}
}

func TestIntranetRegisterArtifactValidation(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, _ := newIntranetPersistFixture(t, pg)

	if _, err := s.intranetRegisterArtifact(pg, intranetArtifactRegisterInput{SessionID: sess.ID}); err == nil {
		t.Fatal("manual registration without revoke command must be rejected")
	}
	art, err := s.intranetRegisterArtifact(pg, intranetArtifactRegisterInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactOther, Name: "manual",
		Path: "/tmp/manual", RevokeCommand: "rm -f /tmp/manual",
		VerifyCommand: "test -e /tmp/manual && echo JW_ARTIFACT_PRESENT || echo JW_ARTIFACT_GONE",
	})
	if err != nil {
		t.Fatal(err)
	}
	if art.Host != "10.250.88.5" || art.SessionID == nil || *art.SessionID != sess.ID {
		t.Fatalf("artifact = %+v", art)
	}
	revoked, _, _, ok, err := s.intranetRevokeArtifact(context.Background(), pg, art.ID, 0)
	if err != nil || !ok || revoked.Status != db.IntranetArtifactRevoked {
		t.Fatalf("revoke = %+v ok=%v err=%v", revoked, ok, err)
	}
}
