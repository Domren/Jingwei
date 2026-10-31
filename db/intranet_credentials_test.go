package db

import (
	"errors"
	"testing"
)

func TestIntranetCredentialStore(t *testing.T) {
	d, _, _ := testSetup(t)
	t.Cleanup(func() { _ = d.Close() })
	const host = "cred-store-test.invalid"
	defer d.Exec(`DELETE FROM intranet_credentials WHERE host=$1`, host)

	scanTask, err := d.CreateScanTask(ScanTaskInput{Name: "cred-store-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM scan_tasks WHERE id=$1`, scanTask.ID)

	first, err := d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: host, Port: 8080, Protocol: "https", URL: "https://" + host + ":8080/login",
		Username: "admin", Password: "p@ss:word", Source: "weakpass",
		ScanTaskID: scanTask.ID, Evidence: "登录成功",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == 0 || first.Status != IntranetCredUntested || first.LastUsedAt != nil {
		t.Fatalf("created credential = %+v", first)
	}
	if first.ScanTaskID == nil || *first.ScanTaskID != scanTask.ID {
		t.Fatalf("scan_task provenance missing: %+v", first)
	}

	// Same triple upserts; empty URL/evidence must not wipe stored values.
	dup, err := d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: host, Username: "admin", Password: "p@ss:word",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dup.ID != first.ID || dup.Port != 8080 || dup.URL == "" || dup.Evidence == "" {
		t.Fatalf("duplicate upsert should refresh, not wipe: %+v", dup)
	}

	marked, err := d.MarkIntranetCredentialUsed(first.ID, IntranetCredValid, "横向登录成功")
	if err != nil {
		t.Fatal(err)
	}
	if marked.Status != IntranetCredValid || marked.LastUsedAt == nil || marked.Evidence != "横向登录成功" {
		t.Fatalf("marked credential = %+v", marked)
	}
	// Re-registering the same pair must keep the decided status.
	dup, err = d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: host, Username: "admin", Password: "p@ss:word", TaskID: 42,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dup.Status != IntranetCredValid {
		t.Fatalf("upsert reset status to %q", dup.Status)
	}
	if dup.TaskID == nil || *dup.TaskID != 42 || dup.ScanTaskID == nil || *dup.ScanTaskID != scanTask.ID {
		t.Fatalf("provenance should merge, got task=%v scan_task=%v", dup.TaskID, dup.ScanTaskID)
	}

	list, err := d.ListIntranetCredentials(IntranetCredentialFilter{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != first.ID {
		t.Fatalf("list by host = %+v", list)
	}
	valid, err := d.ListIntranetCredentials(IntranetCredentialFilter{Host: host, Status: IntranetCredValid})
	if err != nil || len(valid) != 1 {
		t.Fatalf("list by status = %+v err=%v", valid, err)
	}
	none, err := d.ListIntranetCredentials(IntranetCredentialFilter{Host: host, Status: IntranetCredInvalid})
	if err != nil || len(none) != 0 {
		t.Fatalf("list by invalid status = %+v err=%v", none, err)
	}

	if _, err := d.GetIntranetCredential(0); !errors.Is(err, ErrIntranetCredentialNotFound) {
		t.Fatalf("get missing credential err = %v", err)
	}
	if _, err := d.MarkIntranetCredentialUsed(0, IntranetCredValid, ""); !errors.Is(err, ErrIntranetCredentialNotFound) {
		t.Fatalf("mark missing credential err = %v", err)
	}

	if _, err := d.UpsertIntranetCredential(IntranetCredentialInput{Host: host}); err == nil {
		t.Fatal("empty username/password should be rejected")
	}
}

func TestScanTaskProxyRoundtrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateScanTask(ScanTaskInput{
		Name:    "proxy-roundtrip-test",
		Targets: []string{"10.0.0.8"},
		Proxy:   "  socks5://127.0.0.1:1080  ",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM scan_tasks WHERE id=$1`, task.ID)
	if task.Proxy != "socks5://127.0.0.1:1080" {
		t.Fatalf("create returned proxy %q", task.Proxy)
	}

	got, err := d.GetScanTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Proxy != "socks5://127.0.0.1:1080" {
		t.Fatalf("get returned proxy %q", got.Proxy)
	}

	plain, err := d.CreateScanTask(ScanTaskInput{Name: "proxy-empty-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM scan_tasks WHERE id=$1`, plain.ID)
	if plain.Proxy != "" {
		t.Fatalf("empty proxy = %q", plain.Proxy)
	}
}
