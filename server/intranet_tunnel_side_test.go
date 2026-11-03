package server

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

// A chisel client listener lives on the control end: the target's `ss` cannot see
// it, so verification has to look here — and a genuine failure must not leave the
// deployed process running behind an active resource row.
func TestIntranetVerifyTunnelRetiresFailedTunnel(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, _ := newIntranetPersistFixture(t, pg)
	ctx := context.Background()
	tun, err := pg.CreateIntranetTunnel(db.IntranetTunnelInput{
		Name: "verify-fail", SessionID: sess.ID, Kind: db.IntranetTunnelKindPort,
		ListenHost: "127.0.0.1", ListenPort: 18991, RemoteHost: "10.250.88.9", RemotePort: 80,
		VerifyCommand: "echo JW_TUNNEL_FAIL", TeardownCommand: "echo torn-down",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_tunnels WHERE id=$1`, tun.ID) })
	if _, err := pg.SetIntranetTunnelStatus(tun.ID, db.IntranetTunnelDeployed, 0, "JW_PID:0", ""); err != nil {
		t.Fatal(err)
	}
	res, err := pg.RegisterManagedResource(db.ManagedResourceInput{
		Kind: db.ManagedKindTunnel, Name: tun.Name, Endpoint: "session:test/18991",
		Metadata: map[string]any{"tunnel_id": tun.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM managed_resources WHERE id=$1`, res.ID) })

	updated, out, err := s.intranetVerifyTunnel(ctx, pg, tun)
	if err != nil {
		t.Fatalf("verify: %v out=%+v", err, out)
	}
	if updated.Status != db.IntranetTunnelFailed {
		t.Fatalf("status = %+v", updated)
	}
	if !strings.Contains(updated.Evidence, "失败回收") || !strings.Contains(updated.Evidence, "torn-down") {
		t.Fatalf("failed verify must run the teardown and say so: %q", updated.Evidence)
	}
	if found, _ := pg.FindActiveManagedResourceByTunnel(tun.ID); found != nil {
		t.Fatalf("a failed tunnel must release its ledger resource: %+v", found)
	}
}

func TestIntranetVerifyTunnelChecksPivotSideListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen locally: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	t.Setenv("JINGWEI_PIVOT_SERVER", "127.0.0.1:8788")

	pg := prescanTestDB(t)
	s, sess, _ := newIntranetPersistFixture(t, pg)
	tun, err := pg.CreateIntranetTunnel(db.IntranetTunnelInput{
		Name: "pivot-verify", SessionID: sess.ID, Kind: db.IntranetTunnelKindSocks5,
		ListenHost: "0.0.0.0", ListenPort: port, ListenSide: db.IntranetListenSidePivot,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_tunnels WHERE id=$1`, tun.ID) })
	if _, err := pg.SetIntranetTunnelStatus(tun.ID, db.IntranetTunnelDeployed, 0, "JW_PID:0", ""); err != nil {
		t.Fatal(err)
	}
	updated, out, err := s.intranetVerifyTunnel(context.Background(), pg, tun)
	if err != nil {
		t.Fatalf("pivot verify: %v", err)
	}
	if updated.Status != db.IntranetTunnelVerified {
		t.Fatalf("control-side listener must verify from the control end: %+v out=%+v", updated, out)
	}
	if !strings.Contains(updated.Evidence, "控制端即本机") {
		t.Fatalf("evidence must record which side was checked: %q", updated.Evidence)
	}
	if strings.Contains(updated.Evidence, "JW_TUNNEL_FAIL") {
		t.Fatalf("pivot marker must never be run on the target: %q", updated.Evidence)
	}
}

// An unconfigured pivot is a platform gap, not evidence the tunnel died: failing the
// row here would retire a working SOCKS proxy and hide the real fix.
func TestIntranetVerifyTunnelKeepsStatusWhenPivotUnknown(t *testing.T) {
	t.Setenv("JINGWEI_PIVOT_SERVER", "")
	pg := prescanTestDB(t)
	s, sess, _ := newIntranetPersistFixture(t, pg)
	tun, err := pg.CreateIntranetTunnel(db.IntranetTunnelInput{
		Name: "pivot-unknown", SessionID: sess.ID, Kind: db.IntranetTunnelKindSocks5,
		ListenHost: "0.0.0.0", ListenPort: 18992, ListenSide: db.IntranetListenSidePivot,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_tunnels WHERE id=$1`, tun.ID) })
	if _, err := pg.SetIntranetTunnelStatus(tun.ID, db.IntranetTunnelDeployed, 0, "JW_PID:1", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.intranetVerifyTunnel(context.Background(), pg, tun); err == nil ||
		!strings.Contains(err.Error(), "JINGWEI_PIVOT_SERVER") {
		t.Fatalf("expected a clear pivot-config error, got %v", err)
	}
	fresh, err := pg.GetIntranetTunnel(tun.ID)
	if err != nil || fresh.Status != db.IntranetTunnelDeployed {
		t.Fatalf("undeterminable check must leave the status alone: %+v err=%v", fresh, err)
	}
}

// A deploy that failed verification must not keep claiming an active foothold: the
// ledger would then burn a revoke on thin air while the caller believes the module is
// in place.
func TestIntranetRetireFailedDeployStates(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, _ := newIntranetPersistFixture(t, pg)
	ctx := context.Background()
	cases := []struct {
		name       string
		verify     string
		revoke     string
		wantActive bool
		want       string
	}{
		{"gone", "echo " + intranetArtifactGone, "echo must-not-run", false, "登记后立即撤销"},
		{"present", "echo " + intranetArtifactPresent, "echo must-not-run", true, "痕迹在位"},
		{"unclear", "echo maybe", "echo cleaned", true, "复核无定论"},
	}
	for _, c := range cases {
		art, err := pg.AddIntranetArtifact(db.IntranetArtifactInput{
			SessionID: sess.ID, Host: "10.250.88.5", Kind: db.IntranetArtifactOther,
			Name: "retire-" + c.name, DeployCommand: "echo broken",
			RevokeCommand: c.revoke, VerifyCommand: c.verify,
			Evidence: "部署原始证据",
		})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		keptActive, detail := s.intranetRetireFailedDeploy(ctx, pg, sess, art)
		if keptActive != c.wantActive || !strings.Contains(detail, c.want) {
			t.Fatalf("%s: keptActive=%v detail=%q, want %v containing %q",
				c.name, keptActive, detail, c.wantActive, c.want)
		}
		fresh, err := pg.GetIntranetArtifact(art.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := db.IntranetArtifactActive
		if !c.wantActive {
			want = db.IntranetArtifactRevoked
		}
		if fresh.Status != want {
			t.Fatalf("%s: status = %q, want %q", c.name, fresh.Status, want)
		}
		if !strings.Contains(fresh.Evidence, "部署原始证据") {
			t.Fatalf("%s: settle must keep the deploy evidence: %q", c.name, fresh.Evidence)
		}
		if c.name == "gone" && strings.Contains(fresh.Evidence, "must-not-run") {
			t.Fatalf("%s: revoke command ran on a confirmed-absent artifact: %q", c.name, fresh.Evidence)
		}
		if c.name == "present" && strings.Contains(fresh.Evidence, "must-not-run") {
			t.Fatalf("%s: a real foothold must not be revoked blind: %q", c.name, fresh.Evidence)
		}
	}
}
