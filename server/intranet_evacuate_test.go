package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
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

	cron, _, _, _, err := s.intranetPersist(ctx, pg, intranetPersistInput{
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
	if rep.Sessions.Total != 1 || rep.Sessions.Done != 1 {
		t.Fatalf("sessions = %+v", rep)
	}
	// The fixture session stays bound to a live shell: without delete_webshells
	// it must be reported instead of silently dropped.
	if rep.Webshells.Total != 1 || rep.Webshells.Done != 0 ||
		!strings.Contains(strings.Join(rep.Residual, "\n"), "persist-fixture") {
		t.Fatalf("webshells/residual = %+v / %+v", rep.Webshells, rep.Residual)
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
	if again.Artifacts.Total != 0 || again.Sessions.Total != 0 {
		t.Fatalf("second evacuation should not redo artifacts or sessions: %+v", again)
	}
	if len(again.Residual) != 1 || !strings.Contains(again.Residual[0], "未开启自动删除") {
		t.Fatalf("second evacuation residual = %+v", again.Residual)
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
	residual := strings.Join(rep.Residual, "\n")
	if !strings.Contains(residual, "stuck") || !strings.Contains(residual, "persist-fixture") {
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
	if _, err := pg.UpdateIntranetTunnelPlan(deployed.ID, "", "", "echo tear-down-ok", "", ""); err != nil {
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
	if _, err := pg.UpdateIntranetTunnelPlan(tun.ID, "", "", "echo tear-down-ok", "", ""); err != nil {
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
	residual := strings.Join(rep.Residual, "\n")
	if !strings.Contains(residual, "会话不可用") || !strings.Contains(residual, "persist-fixture") {
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
	residual := strings.Join(rep.Residual, "\n")
	if !strings.Contains(residual, "保留") || !strings.Contains(residual, "persist-fixture") {
		t.Fatalf("residual = %+v", rep.Residual)
	}
	if fresh, _ := pg.GetIntranetSession(sess.ID); fresh.Status != db.IntranetSessionActive {
		t.Fatalf("session closed despite close_sessions=false: %+v", fresh)
	}
}

func freeServerPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func waitServerTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("php server did not start on %s", addr)
}

// plantV2PHPWebshell serves a generated encrypted payload through php -S and
// binds it to the task's session. webshells.task_id references deep_tasks, so
// task ownership is expressed through the intranet session instead.
func plantV2PHPWebshell(t *testing.T, pg *db.DB, s *Server, sess *db.IntranetSession) (*db.Webshell, string) {
	t.Helper()
	return plantV2PHPWebshellSource(t, pg, s, sess, "planted-v2", "inject")
}

func plantV2PHPWebshellSource(t *testing.T, pg *db.DB, s *Server, sess *db.IntranetSession, name, source string) (*db.Webshell, string) {
	t.Helper()
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php CLI not installed")
	}
	if testing.Short() {
		t.Skip("skipping php runtime test in -short mode")
	}
	var payload scanner.ShellPayload
	var sealed string
	if source == "php_prepend" {
		key, kerr := scanner.GenerateShellKey()
		if kerr != nil {
			t.Fatal(kerr)
		}
		carrier, cerr := scanner.GenerateShellCarrier()
		if cerr != nil {
			t.Fatal(cerr)
		}
		payload, err = scanner.BuildPHPSemiPersistPayloadV2(key, carrier)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err = sealShellSecret(s.jwtKey, scanner.EncodeShellKey(key))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		payload, sealed, err = s.newV2ShellMaterial("php", 1)
		if err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	shellPath := filepath.Join(dir, "planted.php")
	if err := os.WriteFile(shellPath, []byte(payload.Content), 0o600); err != nil {
		t.Fatal(err)
	}
	port := freeServerPort(t)
	cmd := exec.Command(php, "-S", fmt.Sprintf("127.0.0.1:%d", port), "-t", dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	waitServerTCP(t, fmt.Sprintf("127.0.0.1:%d", port))
	url := fmt.Sprintf("http://127.0.0.1:%d/planted.php", port)
	shell, err := pg.CreateWebshell(db.WebshellInput{
		Name: name, URL: url, ShellType: "php", Protocol: scanner.ShellProtocolV2,
		Secret: sealed, Carrier: payload.Carrier, PayloadSHA256: payload.SHA256, KeyVersion: 1,
		Target: "127.0.0.1", Source: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.DeleteWebshell(shell.ID) })
	if _, err := pg.SetIntranetSessionWebshell(sess.ID, shell.ID); err != nil {
		t.Fatal(err)
	}
	return shell, shellPath
}

func TestIntranetEvacuateAutoDeletesPlantedWebshell(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)
	ctx := context.Background()
	shell, shellPath := plantV2PHPWebshell(t, pg, s, sess)

	preview := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{
		TaskID: task.ID, DryRun: true, CloseSessions: true, DeleteWebshells: true,
	})
	if preview.Webshells.Total != 1 || preview.Webshells.Done != 0 {
		t.Fatalf("preview webshells = %+v", preview.Webshells)
	}
	if _, err := os.Stat(shellPath); err != nil {
		t.Fatalf("dry run removed the shell: %v", err)
	}
	if !strings.Contains(strings.Join(preview.Residual, "\n"), "预览未删除") {
		t.Fatalf("preview residual = %+v", preview.Residual)
	}

	kept := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{TaskID: task.ID, CloseSessions: true})
	if kept.Webshells.Total != 1 || kept.Webshells.Done != 0 || kept.Webshells.Failed != 0 {
		t.Fatalf("kept webshells = %+v", kept.Webshells)
	}
	if _, err := pg.GetWebshell(shell.ID); err != nil {
		t.Fatalf("shell record deleted without opt-in: %v", err)
	}
	if !strings.Contains(strings.Join(kept.Residual, "\n"), "未开启自动删除") {
		t.Fatalf("kept residual = %+v", kept.Residual)
	}
	if _, err := os.Stat(shellPath); err != nil {
		t.Fatalf("shell file removed without opt-in: %v", err)
	}

	rep := s.intranetEvacuate(ctx, pg, intranetEvacuationOptions{
		TaskID: task.ID, CloseSessions: true, DeleteWebshells: true,
	})
	if rep.Webshells.Total != 1 || rep.Webshells.Done != 1 || rep.Webshells.Failed != 0 {
		t.Fatalf("delete webshells = %+v residual=%+v", rep.Webshells, rep.Residual)
	}
	var deletedItem *intranetEvacuationItem
	for i := range rep.Items {
		if rep.Items[i].Type == "webshell" && rep.Items[i].ID == shell.ID {
			deletedItem = &rep.Items[i]
		}
	}
	if deletedItem == nil || deletedItem.Status != "deleted" {
		t.Fatalf("webshell item = %+v", deletedItem)
	}
	if _, err := os.Stat(shellPath); !os.IsNotExist(err) {
		t.Fatalf("shell file survived self-delete: %v", err)
	}
	if _, err := pg.GetWebshell(shell.ID); err == nil {
		t.Fatal("webshell record survived verified deletion")
	}
	if len(rep.Residual) != 0 {
		t.Fatalf("residual after clean evacuation = %+v", rep.Residual)
	}
	if fresh, _ := pg.GetIntranetSession(sess.ID); fresh.Status != db.IntranetSessionClosed {
		t.Fatalf("session not closed: %+v", fresh)
	}
}

func TestIntranetEvacuateKeepsParentWebshellWhenMemshellSurvives(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)

	parent, err := pg.CreateWebshell(db.WebshellInput{
		Name: "ms-parent", URL: "http://127.0.0.1:1/parent.jsp", ShellType: "jsp",
		Protocol: scanner.ShellProtocolV2, Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.DeleteWebshell(parent.ID) })
	if _, err := pg.SetIntranetSessionWebshell(sess.ID, parent.ID); err != nil {
		t.Fatal(err)
	}
	// java_memshells.task_id references deep_tasks, so this fixture relies on
	// the parent webshell's session binding for task ownership.
	ms, err := pg.CreateJavaMemshell(db.JavaMemshellInput{
		WebshellID: &parent.ID, Type: "filter", Name: "ms-evac",
		Path: "/jw-ms-evac", URL: "http://127.0.0.1:9/jw-ms-evac", Target: "127.0.0.1", Status: "alive",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.DeleteJavaMemshell(ms.ID) })

	rep := s.intranetEvacuate(context.Background(), pg, intranetEvacuationOptions{
		TaskID: task.ID, CloseSessions: true, DeleteWebshells: true,
	})
	if rep.Memshells.Total != 1 || rep.Memshells.Failed != 1 || rep.Memshells.Done != 0 {
		t.Fatalf("memshells = %+v residual=%+v", rep.Memshells, rep.Residual)
	}
	var msItem, shellItem *intranetEvacuationItem
	for i := range rep.Items {
		switch {
		case rep.Items[i].Type == "memshell" && rep.Items[i].ID == ms.ID:
			msItem = &rep.Items[i]
		case rep.Items[i].Type == "webshell" && rep.Items[i].ID == parent.ID:
			shellItem = &rep.Items[i]
		}
	}
	if msItem == nil || msItem.Status != "failed" {
		t.Fatalf("memshell item = %+v", msItem)
	}
	if shellItem == nil || shellItem.Status != "blocked" {
		t.Fatalf("parent webshell should be kept, item = %+v", shellItem)
	}
	if !strings.Contains(strings.Join(rep.Residual, "\n"), "存在未清理的内存马") {
		t.Fatalf("residual = %+v", rep.Residual)
	}
	if _, err := pg.GetJavaMemshell(ms.ID); err != nil {
		t.Fatalf("unremoved memshell record must be kept: %v", err)
	}
	if _, err := pg.GetWebshell(parent.ID); err != nil {
		t.Fatalf("parent webshell deleted while memshell survives: %v", err)
	}
}

func TestIntranetEvacuateKeepsLegacyWebshell(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)
	shell, err := pg.CreateWebshell(db.WebshellInput{
		Name: "legacy-shell", URL: "http://127.0.0.1:9/legacy.php", ShellType: "php",
		Password: "test-password", Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.DeleteWebshell(shell.ID) })
	if _, err := pg.SetIntranetSessionWebshell(sess.ID, shell.ID); err != nil {
		t.Fatal(err)
	}

	rep := s.intranetEvacuate(context.Background(), pg, intranetEvacuationOptions{
		TaskID: task.ID, CloseSessions: true, DeleteWebshells: true,
	})
	if rep.Webshells.Total != 1 || rep.Webshells.Failed != 1 || rep.Webshells.Done != 0 {
		t.Fatalf("legacy webshells = %+v", rep.Webshells)
	}
	if !strings.Contains(strings.Join(rep.Residual, "\n"), "旧版协议") {
		t.Fatalf("legacy residual = %+v", rep.Residual)
	}
	if _, err := pg.GetWebshell(shell.ID); err != nil {
		t.Fatalf("legacy shell record must be kept: %v", err)
	}
}

func TestIntranetEvacuateBlocksShellWithActivePHPPersistArtifact(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)
	shell, err := pg.CreateWebshell(db.WebshellInput{
		Name: "prepend-parent", URL: "http://127.0.0.1:9/parent.php", ShellType: "php",
		Protocol: scanner.ShellProtocolV2, Secret: "sealed-test", Carrier: "X-Jw-Test",
		PayloadSHA256: "test", Target: "127.0.0.1", Source: "inject",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.DeleteWebshell(shell.ID) })
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_artifacts WHERE session_id=$1`, sess.ID) })
	if _, err := pg.SetIntranetSessionWebshell(sess.ID, shell.ID); err != nil {
		t.Fatal(err)
	}
	art, err := s.intranetRegisterArtifact(pg, intranetArtifactRegisterInput{
		SessionID: sess.ID, TaskID: task.ID, Kind: db.IntranetArtifactPHPUserINI, Name: "php-prepend-guard",
		Path:          "/var/www/html/.user.ini",
		RevokeCommand: "echo " + intranetArtifactFailed + "; exit 1",
		VerifyCommand: "echo " + intranetArtifactPresent,
		Metadata:      map[string]any{"webshell_id": shell.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	rep := s.intranetEvacuate(context.Background(), pg, intranetEvacuationOptions{
		TaskID: task.ID, CloseSessions: true, DeleteWebshells: true,
	})
	var item *intranetEvacuationItem
	for i := range rep.Items {
		if rep.Items[i].Type == "webshell" && rep.Items[i].ID == shell.ID {
			item = &rep.Items[i]
		}
	}
	if item == nil || item.Status != "blocked" || !strings.Contains(item.Detail, "PHP 半持久化") {
		t.Fatalf("webshell item = %+v", item)
	}
	if !strings.Contains(strings.Join(rep.Residual, "\n"), "PHP 半持久化落地物") {
		t.Fatalf("residual = %+v", rep.Residual)
	}
	if _, err := pg.GetWebshell(shell.ID); err != nil {
		t.Fatalf("shell record deleted while its artifact is active: %v", err)
	}
	if fresh, err := pg.GetIntranetArtifact(art.ID); err != nil || fresh.Status != db.IntranetArtifactActive {
		t.Fatalf("artifact must stay active after failed revoke: %+v err=%v", fresh, err)
	}
}

func TestIntranetEvacuateNeverSelfDeletesPHPPersistShell(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)
	shell, shellPath := plantV2PHPWebshellSource(t, pg, s, sess, "planted-prepend", "php_prepend")

	rep := s.intranetEvacuate(context.Background(), pg, intranetEvacuationOptions{
		TaskID: task.ID, CloseSessions: true, DeleteWebshells: true,
	})
	var item *intranetEvacuationItem
	for i := range rep.Items {
		if rep.Items[i].Type == "webshell" && rep.Items[i].ID == shell.ID {
			item = &rep.Items[i]
		}
	}
	if item == nil || item.Status != "kept" || !strings.Contains(item.Detail, "不会执行自删除") {
		t.Fatalf("webshell item = %+v", item)
	}
	if !strings.Contains(strings.Join(rep.Residual, "\n"), "PHP 半持久化通道") {
		t.Fatalf("residual = %+v", rep.Residual)
	}
	if _, err := os.Stat(shellPath); err != nil {
		t.Fatalf("prepend payload was self-deleted: %v", err)
	}
	if _, err := pg.GetWebshell(shell.ID); err != nil {
		t.Fatalf("prepend shell record must be kept while alive: %v", err)
	}
}

func TestIntranetArtifactExpiryRevokesSessionlessPHPPersist(t *testing.T) {
	pg := prescanTestDB(t)
	s, sess, task, _ := newIntranetEvacuationFixture(t, pg)
	shell, _ := plantV2PHPWebshell(t, pg, s, sess)
	expired := time.Now().Add(-time.Minute)
	art, err := pg.AddIntranetArtifact(db.IntranetArtifactInput{
		TaskID: task.ID, Host: "127.0.0.1", Kind: db.IntranetArtifactPHPUserINI, Name: "expired-prepend",
		Path:          "/tmp/.user.ini",
		RevokeCommand: "echo " + intranetArtifactOK,
		VerifyCommand: "echo " + intranetArtifactGone,
		ExpiresAt:     &expired,
		Metadata:      map[string]any{"webshell_id": shell.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_artifacts WHERE id=$1`, art.ID) })

	s.intranetArtifactExpirySweep(context.Background(), map[int64]time.Time{}, map[int64]bool{})

	fresh, err := pg.GetIntranetArtifact(art.ID)
	if err != nil || fresh.Status != db.IntranetArtifactRevoked {
		t.Fatalf("sessionless PHP artifact was not revoked by TTL sweep: %+v err=%v", fresh, err)
	}
}
