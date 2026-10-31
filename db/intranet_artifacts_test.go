package db

import (
	"strings"
	"testing"
)

func TestIntranetArtifactStore(t *testing.T) {
	d, _, _ := testSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	ws, err := d.CreateWebshell(WebshellInput{
		Name: "artifact-test-shell", URL: "http://127.0.0.1:9/artifact.php",
		ShellType: "php", Password: "test", Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM webshells WHERE id=$1`, ws.ID)

	sess, err := d.CreateIntranetSession(IntranetSessionInput{
		Name: "artifact-session", WebshellID: ws.ID, Host: "10.77.0.5",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM intranet_sessions WHERE id=$1`, sess.ID)
	defer d.Exec(`DELETE FROM intranet_artifacts WHERE host=$1`, "10.77.0.5")

	if _, err := d.AddIntranetArtifact(IntranetArtifactInput{
		Kind: IntranetArtifactFile, Host: "10.77.0.5", Path: "/tmp/x",
	}); err == nil {
		t.Fatal("artifact without revoke command must be rejected")
	}
	if _, err := d.AddIntranetArtifact(IntranetArtifactInput{
		Kind: "database", Host: "10.77.0.5", RevokeCommand: "true",
	}); err == nil {
		t.Fatal("unknown kind must be rejected")
	}

	first, err := d.AddIntranetArtifact(IntranetArtifactInput{
		TaskID: 990077, SessionID: sess.ID, Host: "10.77.0.5", Kind: IntranetArtifactFile,
		Name: "tool.bin", Path: "/tmp/tool.bin", Description: "上传文件",
		DeployCommand: "<upload>", RevokeCommand: "rm -f /tmp/tool.bin",
		VerifyCommand: "test -e /tmp/tool.bin && echo JW_ARTIFACT_PRESENT || echo JW_ARTIFACT_GONE",
		Metadata:      map[string]any{"bytes": 12},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != IntranetArtifactActive || first.TaskID == nil || *first.TaskID != 990077 {
		t.Fatalf("created artifact = %+v", first)
	}
	if first.Metadata["bytes"] != float64(12) {
		t.Fatalf("metadata = %+v", first.Metadata)
	}

	second, err := d.AddIntranetArtifact(IntranetArtifactInput{
		TaskID: 990077, SessionID: sess.ID, Host: "10.77.0.5", Kind: IntranetArtifactCron,
		Name: "beacon", Path: "crontab:tok", RevokeCommand: "crontab -l | grep -vF x | crontab -",
	})
	if err != nil {
		t.Fatal(err)
	}

	rows, total, err := d.ListIntranetArtifacts(IntranetArtifactFilter{TaskID: 990077})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 2 || rows[0].ID != second.ID || rows[1].ID != first.ID {
		t.Fatalf("list total=%d rows=%+v", total, rows)
	}
	hostRows, total, err := d.ListIntranetArtifacts(IntranetArtifactFilter{Host: "10.77.0.5", Kind: "cron"})
	if err != nil || total != 1 || len(hostRows) != 1 || hostRows[0].ID != second.ID {
		t.Fatalf("host filter = %+v total=%d err=%v", hostRows, total, err)
	}

	active, err := d.ListActiveIntranetArtifactsByTask(990077)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || active[0].ID != second.ID || active[1].ID != first.ID {
		t.Fatalf("active order is not newest-first: %+v", active)
	}

	revoked, err := d.MarkIntranetArtifactRevoked(second.ID, "撤销成功")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != IntranetArtifactRevoked || revoked.RevokedAt == nil {
		t.Fatalf("revoked artifact = %+v", revoked)
	}
	active, err = d.ListActiveIntranetArtifactsByTask(990077)
	if err != nil || len(active) != 1 || active[0].ID != first.ID {
		t.Fatalf("active after revoke = %+v err=%v", active, err)
	}
	revokedRows, total, err := d.ListIntranetArtifacts(IntranetArtifactFilter{TaskID: 990077, Status: IntranetArtifactRevoked})
	if err != nil || total != 1 || len(revokedRows) != 1 || !strings.Contains(revokedRows[0].Evidence, "撤销成功") {
		t.Fatalf("revoked filter = %+v total=%d err=%v", revokedRows, total, err)
	}

	// A failed revoke keeps the artifact active so it can be retried.
	held, err := d.UpdateIntranetArtifactEvidence(first.ID, "撤销未通过验证")
	if err != nil {
		t.Fatal(err)
	}
	if held.Status != IntranetArtifactActive || held.Evidence != "撤销未通过验证" {
		t.Fatalf("held artifact = %+v", held)
	}

	if _, err := d.GetIntranetArtifact(0); err == nil {
		t.Fatal("missing artifact should error")
	}
	if _, err := d.MarkIntranetArtifactRevoked(0, ""); err == nil {
		t.Fatal("revoking a missing artifact should error")
	}
}
