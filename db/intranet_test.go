package db

import (
	"testing"
)

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

	planned, err := d.UpdateIntranetTunnelPlan(tun.ID, "nohup socat x &", "ss -lnt | grep 18099", "kill 123", "probe evidence")
	if err != nil {
		t.Fatal(err)
	}
	if planned.DeployCommand != "nohup socat x &" || planned.Evidence != "probe evidence" || planned.Status != IntranetTunnelPlanned {
		t.Fatalf("planned tunnel = %+v", planned)
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
