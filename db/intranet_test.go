package db

import (
	"testing"
	"time"
)

func TestListWebshellsByIntranetTask(t *testing.T) {
	d, _, _ := testSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateTask("webshell ownership", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	other, err := d.CreateTask("other webshell ownership", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(other.ID) })

	mkShell := func(name string) *Webshell {
		t.Helper()
		ws, err := d.CreateWebshell(WebshellInput{
			Name: name, URL: "http://127.0.0.1:9/" + name + ".php", ShellType: "php",
			Password: "test", Target: "127.0.0.1", Source: "manual",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM webshells WHERE id=$1`, ws.ID) })
		return ws
	}
	ws1, ws2, foreign := mkShell("owned-a"), mkShell("owned-b"), mkShell("foreign")

	mkSession := func(taskID int64, shellID int64) *IntranetSession {
		t.Helper()
		sess, err := d.CreateIntranetSession(IntranetSessionInput{
			Name: "ws-owner", WebshellID: shellID, TaskID: taskID, Host: "127.0.0.1", Cwd: "/",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intranet_sessions WHERE id=$1`, sess.ID) })
		return sess
	}
	mkSession(task.ID, ws1.ID)
	mkSession(task.ID, ws2.ID)
	mkSession(task.ID, ws1.ID) // duplicate binding must not duplicate the result
	mkSession(other.ID, foreign.ID)

	shells, err := d.ListWebshellsByIntranetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(shells) != 2 || shells[0].ID != ws2.ID || shells[1].ID != ws1.ID {
		t.Fatalf("shells = %+v", shells)
	}
	for _, ws := range shells {
		if ws.ID == foreign.ID {
			t.Fatalf("foreign shell leaked into task list: %+v", ws)
		}
	}
	if shells, err := d.ListWebshellsByIntranetTask(0); err != nil || shells != nil {
		t.Fatalf("invalid task id = %+v, %v", shells, err)
	}
}

func TestIntranetSessionStore(t *testing.T) {
	d, _, _ := testSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	ws, err := d.CreateWebshell(WebshellInput{
		Name: "intranet-test-shell", URL: "http://127.0.0.1:9/intranet-test.php",
		ShellType: "php", Password: "test", Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM webshells WHERE id=$1`, ws.ID)

	sess, err := d.CreateIntranetSession(IntranetSessionInput{
		Name: "test-session", WebshellID: ws.ID, Host: "127.0.0.1", Cwd: "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM intranet_sessions WHERE id=$1`, sess.ID)
	if sess.Cwd != "/tmp" || sess.Status != IntranetSessionActive {
		t.Fatalf("created session = %+v", sess)
	}

	got, err := d.GetIntranetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WebshellName != ws.Name || got.WebshellURL != ws.URL || got.ShellType != "php" {
		t.Fatalf("joined webshell fields missing: %+v", got)
	}

	updated, err := d.UpdateIntranetSessionState(sess.ID, "/var/www", "", "note")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Cwd != "/var/www" || updated.Note != "note" || updated.LastSeen == nil {
		t.Fatalf("updated session = %+v", updated)
	}

	if err := d.AddIntranetSessionEvent(sess.ID, "exec", "id", "uid=0", false); err != nil {
		t.Fatal(err)
	}
	events, err := d.ListIntranetSessionEvents(sess.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Command != "id" || events[0].Output != "uid=0" {
		t.Fatalf("events = %+v", events)
	}

	list, total, err := d.ListIntranetSessions("", 0, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range list {
		if s.ID == sess.ID {
			found = true
		}
	}
	if !found || total < 1 {
		t.Fatalf("session missing from list (total=%d)", total)
	}

	if ok, err := d.DeleteIntranetSession(sess.ID); err != nil || !ok {
		t.Fatalf("delete session ok=%v err=%v", ok, err)
	}
	if _, err := d.GetIntranetSession(sess.ID); err == nil {
		t.Fatal("deleted session still readable")
	}
}

func TestIntranetSessionHealthAndFailoverStore(t *testing.T) {
	d, _, _ := testSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	ws1, err := d.CreateWebshell(WebshellInput{
		Name: "health-shell-1", URL: "http://127.0.0.1:9/health1.php",
		ShellType: "php", Password: "test", Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM webshells WHERE id=$1`, ws1.ID)
	ws2, err := d.CreateWebshell(WebshellInput{
		Name: "health-shell-2", URL: "http://127.0.0.1:9/health2.php",
		ShellType: "php", Password: "test", Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM webshells WHERE id=$1`, ws2.ID)

	sess, err := d.CreateIntranetSession(IntranetSessionInput{
		Name: "health-session", WebshellID: ws1.ID, Host: "127.0.0.1", Cwd: "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM intranet_sessions WHERE id=$1`, sess.ID)

	degraded, err := d.RecordIntranetSessionHealth(sess.ID, false, 25, "dial timeout", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := degraded.Metadata["health"].(string); got != IntranetHealthDegraded {
		t.Fatalf("first failure health = %q", got)
	}
	if got, _ := degraded.Metadata["health_failures"].(float64); int(got) != 1 {
		t.Fatalf("first failure count = %v", degraded.Metadata["health_failures"])
	}
	if _, err := d.RecordIntranetSessionHealth(sess.ID, false, 30, "dial timeout", 3); err != nil {
		t.Fatal(err)
	}
	lost, err := d.RecordIntranetSessionHealth(sess.ID, false, 35, "dial timeout", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := lost.Metadata["health"].(string); got != IntranetHealthLost {
		t.Fatalf("third failure health = %q", got)
	}
	if got, _ := lost.Metadata["health_failures"].(float64); int(got) != 3 {
		t.Fatalf("third failure count = %v", lost.Metadata["health_failures"])
	}

	ok, err := d.RecordIntranetSessionHealth(sess.ID, true, 8, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ok.Metadata["health"].(string); got != IntranetHealthOK {
		t.Fatalf("recovered health = %q", got)
	}
	if got, _ := ok.Metadata["health_failures"].(float64); int(got) != 0 {
		t.Fatalf("recovered count = %v", ok.Metadata["health_failures"])
	}
	if got, _ := ok.Metadata["health_error"].(string); got != "" {
		t.Fatalf("recovered error = %q", got)
	}

	list, err := d.ListIntranetSessionsForHeartbeat(time.Now().Add(time.Minute), 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range list {
		if s.ID == sess.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("session #%d missing from stale heartbeat list", sess.ID)
	}

	if _, err := d.SetIntranetSessionMetadata(sess.ID, map[string]any{"os": "posix"}); err != nil {
		t.Fatal(err)
	}
	rebound, err := d.SetIntranetSessionWebshell(sess.ID, ws2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rebound.WebshellID == nil || *rebound.WebshellID != ws2.ID {
		t.Fatalf("rebound webshell = %+v", rebound.WebshellID)
	}
	if _, exists := rebound.Metadata["os"]; exists {
		t.Fatalf("cached os not cleared on rebound: %+v", rebound.Metadata)
	}
	if _, err := d.SetIntranetSessionWebshell(0, ws2.ID); err == nil {
		t.Fatal("invalid session id must be rejected")
	}
}

func TestIntranetTunnelStoreAndLedger(t *testing.T) {
	d, _, _ := testSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	tun, err := d.CreateIntranetTunnel(IntranetTunnelInput{
		Name: "test-tunnel", Kind: IntranetTunnelKindPort,
		ListenHost: "127.0.0.1", ListenPort: 18099,
		RemoteHost: "10.0.0.5", RemotePort: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM intranet_tunnels WHERE id=$1`, tun.ID)
	if tun.Status != IntranetTunnelPlanned {
		t.Fatalf("new tunnel status = %q", tun.Status)
	}

	planned, err := d.UpdateIntranetTunnelPlan(tun.ID, "nohup socat x &", "ss -lnt | grep 18099", "kill 123", "probe evidence", "")
	if err != nil {
		t.Fatal(err)
	}
	if planned.DeployCommand != "nohup socat x &" || planned.Evidence != "probe evidence" || planned.Status != IntranetTunnelPlanned {
		t.Fatalf("planned tunnel = %+v", planned)
	}
	if planned.ListenSide != IntranetListenSideTarget {
		t.Fatalf("listen side = %q, want the target default", planned.ListenSide)
	}
	// An empty side must keep the recorded value: re-planning a tunnel must not
	// silently move its listener back to the target and misplace verification.
	if _, err := d.UpdateIntranetTunnelPlan(tun.ID, "chisel client x 18099:socks", "", "", "", IntranetListenSidePivot); err != nil {
		t.Fatal(err)
	}
	kept, err := d.UpdateIntranetTunnelPlan(tun.ID, "", "pivot:tcp:18099", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if kept.ListenSide != IntranetListenSidePivot {
		t.Fatalf("listen side after empty-side update = %q, want pivot", kept.ListenSide)
	}
	if kept.DeployCommand != "chisel client x 18099:socks" || kept.VerifyCommand != "pivot:tcp:18099" {
		t.Fatalf("plan columns lost on side-preserving update: %+v", kept)
	}

	deployed, err := d.SetIntranetTunnelStatus(tun.ID, IntranetTunnelDeployed, 4321, "JW_PID:4321", "")
	if err != nil {
		t.Fatal(err)
	}
	if deployed.Status != IntranetTunnelDeployed || deployed.PID == nil || *deployed.PID != 4321 {
		t.Fatalf("deployed tunnel = %+v", deployed)
	}

	res, err := d.RegisterManagedResource(ManagedResourceInput{
		Kind: ManagedKindTunnel, Name: "test-tunnel", Endpoint: "test://tunnel/18099",
		Metadata: map[string]any{"tunnel_id": tun.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM managed_resources WHERE id=$1`, res.ID)

	found, err := d.FindActiveManagedResourceByTunnel(tun.ID)
	if err != nil || found == nil || found.ID != res.ID {
		t.Fatalf("find ledger = %+v err=%v", found, err)
	}
	if err := d.ReleaseManagedResourceByTunnel(tun.ID, "teardown"); err != nil {
		t.Fatal(err)
	}
	found, _ = d.FindActiveManagedResourceByTunnel(tun.ID)
	if found != nil {
		t.Fatalf("ledger still active after release: %+v", found)
	}

	stopped, err := d.SetIntranetTunnelStatus(tun.ID, IntranetTunnelStopped, 0, "", "done")
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Status != IntranetTunnelStopped || stopped.Note != "done" {
		t.Fatalf("stopped tunnel = %+v", stopped)
	}
	if ok, err := d.DeleteIntranetTunnel(tun.ID); err != nil || !ok {
		t.Fatalf("delete tunnel ok=%v err=%v", ok, err)
	}
}

func TestIntranetScopeRequestStore(t *testing.T) {
	d, _, _ := testSetup(t)
	const host = "intranet-scope-test.invalid"
	defer d.Exec(`DELETE FROM intranet_scope_requests WHERE host=$1`, host)
	defer d.Exec(`DELETE FROM task_scope WHERE domain=$1`, host)

	var taskID int64
	if err := d.QueryRow(`SELECT id FROM tasks WHERE deleted_at IS NULL ORDER BY id DESC LIMIT 1`).Scan(&taskID); err != nil || taskID <= 0 {
		t.Skipf("no task available (%v)", err)
	}

	first, created, err := d.CreateIntranetScopeRequest(IntranetScopeRequestInput{
		TaskID: taskID, Host: host, Port: 8080, Reason: "internal test",
	})
	if err != nil || !created {
		t.Fatalf("create scope request created=%v err=%v", created, err)
	}
	defer d.Exec(`DELETE FROM intranet_scope_requests WHERE id=$1`, first.ID)

	dup, created, err := d.CreateIntranetScopeRequest(IntranetScopeRequestInput{
		TaskID: taskID, Host: host, Port: 8080, Reason: "again",
	})
	if err != nil || created || dup.ID != first.ID {
		t.Fatalf("duplicate pending: id=%v created=%v err=%v", dup, created, err)
	}
	if dup.Status != IntranetScopePending {
		t.Fatalf("pending status = %q", dup.Status)
	}

	row, found, err := d.DecideIntranetScopeRequest(first.ID, true, "approved")
	if err != nil || !found {
		t.Fatalf("approve found=%v err=%v", found, err)
	}
	if row.Status != IntranetScopeApproved || row.DecidedAt == nil || row.DecidedNote != "approved" {
		t.Fatalf("approved row = %+v", row)
	}
	if _, found, _ := d.DecideIntranetScopeRequest(first.ID, false, ""); found {
		t.Fatal("re-deciding a decided request should report found=false")
	}

	// Approval writes the host into the task's registered scope (server layer
	// calls AddAgentScope; here we verify the store contract it relies on).
	if _, err := d.Assets().AddAgentScope(taskID, "subdomain", host, "approved", "manual"); err != nil {
		t.Fatal(err)
	}
	scopes, err := d.Assets().ListTaskScope(taskID)
	if err != nil {
		t.Fatal(err)
	}
	foundScope := false
	for _, s := range scopes {
		if s.Domain == host && s.Source == "manual" {
			foundScope = true
		}
	}
	if !foundScope {
		t.Fatal("approved host not present in task scope")
	}
}
