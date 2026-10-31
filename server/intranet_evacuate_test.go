package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

// newIntranetEvacuationFixture binds the persist fixture to a real task, so
// artifacts inherit task_id the same way they do in production runs.
func newIntranetEvacuationFixture(t *testing.T, pg *db.DB) (*Server, *db.IntranetSession, *db.Task, string) {
	t.Helper()
	s, sess, home := newIntranetPersistFixture(t, pg)
	task, err := pg.CreateTask("evacuation-fixture", "撤离清理测试", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
	if err := pg.SetIntranetSessionTask(sess.ID, task.ID); err != nil {
		t.Fatal(err)
	}
	fresh, err := pg.GetIntranetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s, fresh, task, home
}

func TestIntranetEvacuateRevokesArtifactsInReverseOrder(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, home := newIntranetEvacuationFixture(t, pg)
	ctx := context.Background()

	cron, _, _, err := s.intranetPersist(ctx, pg, intranetPersistInput{
		SessionID: sess.ID, Kind: db.IntranetArtifactCron,
		Schedule: "@daily", Command: "echo jw-evac", Name: "evac-cron",
	})
	if err != nil {
		t.Fatalf("persist failed: %v", err)
	}
	target := filepath.Join(home, "evac-drop.sh")
	if _, err := s.intranetUpload(ctx, pg, sess, target, []byte("#!/bin/sh\necho drop\n")); err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	active, _, err := pg.ListIntranetArtifacts(db.IntranetArtifactFilter{TaskID: task.ID, Status: db.IntranetArtifactActive})
	if err != nil || len(active) != 2 {
		t.Fatalf("active artifacts = %+v err=%v", active, err)
	}
	fileID := int64(0)
	for _, a := range active {
		if a.Kind == db.IntranetArtifactFile {
			fileID = a.ID
		}
	}
	if fileID <= cron.ID {
		t.Fatalf("upload artifact #%d should be newer than cron #%d", fileID, cron.ID)
	}

	preview := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{TaskID: task.ID, DryRun: true, CloseSessions: true})
	if !preview.DryRun || preview.Artifacts.Total != 2 || preview.Artifacts.Done != 0 || preview.Sessions.Total != 1 {
		t.Fatalf("preview = %+v", preview)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("dry run removed %s: %v", target, err)
	}
	crontab, _ := os.ReadFile(filepath.Join(home, ".crontab"))
	if !strings.Contains(string(crontab), "jw-evac") {
		t.Fatalf("dry run changed crontab: %q", crontab)
	}
	if fresh, _ := pg.GetIntranetSession(sess.ID); fresh.Status != db.IntranetSessionActive {
		t.Fatalf("dry run closed the session: %+v", fresh)
	}

	rep := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{TaskID: task.ID, CloseSessions: true})
	if rep.DryRun || rep.Artifacts.Total != 2 || rep.Artifacts.Done != 2 || rep.Artifacts.Failed != 0 {
		t.Fatalf("artifacts report = %+v", rep)
	}
	if rep.Sessions.Total != 1 || rep.Sessions.Done != 1 || len(rep.Residual) != 0 {
		t.Fatalf("sessions/residual = %+v", rep)
	}
	if len(rep.Items) < 2 || rep.Items[0].Type != "artifact" || rep.Items[0].ID != fileID || rep.Items[0].Status != "revoked" {
		t.Fatalf("items are not in reverse ledger order: %+v", rep.Items)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("uploaded file survived evacuation: %v", err)
	}
	crontab, _ = os.ReadFile(filepath.Join(home, ".crontab"))
	if strings.Contains(string(crontab), "jw-evac") {
		t.Fatalf("cron entry survived evacuation: %q", crontab)
	}
	if row, err := pg.GetIntranetArtifact(cron.ID); err != nil || row.Status != db.IntranetArtifactRevoked {
		t.Fatalf("cron artifact = %+v err=%v", row, err)
	}
	if fresh, _ := pg.GetIntranetSession(sess.ID); fresh.Status != db.IntranetSessionClosed {
		t.Fatalf("session not closed: %+v", fresh)
	}

	again := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{TaskID: task.ID, CloseSessions: true})
	if again.Artifacts.Total != 0 || again.Sessions.Total != 0 || len(again.Residual) != 0 {
		t.Fatalf("second evacuation should be a no-op: %+v", again)
	}
}

func TestIntranetEvacuateKeepsFailedArtifactActive(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)
	ctx := context.Background()

	art, err := s.intranetRegisterArtifact(pg, intranetArtifactRegisterInput{
		SessionID: sess.ID, TaskID: task.ID, Kind: db.IntranetArtifactOther, Name: "stuck",
		RevokeCommand: "echo " + intranetArtifactFailed + "; exit 1",
		VerifyCommand: "echo " + intranetArtifactPresent,
	})
	if err != nil {
		t.Fatal(err)
	}

	rep := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{TaskID: task.ID, CloseSessions: true})
	if rep.Artifacts.Failed != 1 || rep.Artifacts.Done != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Residual) != 1 || !strings.Contains(rep.Residual[0], "stuck") {
		t.Fatalf("residual = %+v", rep.Residual)
	}
	if fresh, err := pg.GetIntranetArtifact(art.ID); err != nil || fresh.Status != db.IntranetArtifactActive {
		t.Fatalf("failed artifact must stay active for retry: %+v err=%v", fresh, err)
	}
}

func TestIntranetEvacuateTearsDownTunnels(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)
	ctx := context.Background()

	deployed, err := pg.CreateIntranetTunnel(db.IntranetTunnelInput{
		Name: "evac-deployed", SessionID: sess.ID, TaskID: task.ID, Kind: db.IntranetTunnelKindPort,
		ListenHost: "127.0.0.1", ListenPort: 18888, RemoteHost: "10.250.88.9", RemotePort: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_tunnels WHERE id=$1`, deployed.ID) })
	if _, err := pg.UpdateIntranetTunnelPlan(deployed.ID, "", "", "echo tear-down-ok", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.SetIntranetTunnelStatus(deployed.ID, db.IntranetTunnelDeployed, 0, "JW_PID:0", ""); err != nil {
		t.Fatal(err)
	}
	planned, err := pg.CreateIntranetTunnel(db.IntranetTunnelInput{
		Name: "evac-planned", SessionID: sess.ID, TaskID: task.ID, Kind: db.IntranetTunnelKindSocks5,
		ListenHost: "127.0.0.1", ListenPort: 18889,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_tunnels WHERE id=$1`, planned.ID) })

	rep := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{TaskID: task.ID, CloseSessions: true})
	if rep.Tunnels.Total != 2 || rep.Tunnels.Done != 2 || rep.Tunnels.Failed != 0 {
		t.Fatalf("tunnel report = %+v", rep)
	}
	fresh, err := pg.GetIntranetTunnel(deployed.ID)
	if err != nil || fresh.Status != db.IntranetTunnelStopped || !strings.Contains(fresh.Evidence, "tear-down-ok") {
		t.Fatalf("deployed tunnel = %+v err=%v", fresh, err)
	}
	if fresh, _ := pg.GetIntranetTunnel(planned.ID); fresh.Status != db.IntranetTunnelStopped {
		t.Fatalf("planned tunnel = %+v", fresh)
	}
}

func TestIntranetEvacuateReportsUnreachableTunnel(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)
	ctx := context.Background()

	tun, err := pg.CreateIntranetTunnel(db.IntranetTunnelInput{
		Name: "evac-orphan", SessionID: sess.ID, TaskID: task.ID, Kind: db.IntranetTunnelKindPort,
		ListenHost: "127.0.0.1", ListenPort: 18890, RemoteHost: "10.250.88.9", RemotePort: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_tunnels WHERE id=$1`, tun.ID) })
	if _, err := pg.UpdateIntranetTunnelPlan(tun.ID, "", "", "echo tear-down-ok", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.SetIntranetTunnelStatus(tun.ID, db.IntranetTunnelDeployed, 0, "JW_PID:0", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.UpdateIntranetSessionState(sess.ID, "", db.IntranetSessionClosed, "手工关闭"); err != nil {
		t.Fatal(err)
	}

	rep := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{TaskID: task.ID, CloseSessions: true})
	if rep.Tunnels.Total != 1 || rep.Tunnels.Failed != 1 || rep.Tunnels.Done != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Residual) != 1 || !strings.Contains(rep.Residual[0], "会话不可用") {
		t.Fatalf("residual = %+v", rep.Residual)
	}
	if fresh, _ := pg.GetIntranetTunnel(tun.ID); fresh.Status != db.IntranetTunnelDeployed {
		t.Fatalf("unreachable tunnel must not be marked stopped: %+v", fresh)
	}
}

func TestIntranetEvacuateKeepsSessionsWhenAsked(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)

	rep := s.intranetEvacuate(context.Background(), pg, intranetEvacuationOptions{TaskID: task.ID, CloseSessions: false})
	if rep.Sessions.Total != 1 || rep.Sessions.Done != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Residual) != 1 || !strings.Contains(rep.Residual[0], "保留") {
		t.Fatalf("residual = %+v", rep.Residual)
	}
	if fresh, _ := pg.GetIntranetSession(sess.ID); fresh.Status != db.IntranetSessionActive {
		t.Fatalf("session closed despite close_sessions=false: %+v", fresh)
	}
}
