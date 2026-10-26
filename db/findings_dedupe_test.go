package db

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestUpsertFindingDeduplicatesAndPreservesStatus(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	key := fmt.Sprintf("test|dedupe|%d", time.Now().UnixNano())
	defer d.Exec(`DELETE FROM findings WHERE dedupe_key = $1`, key)

	id, created, err := d.UpsertFinding(0, 0, "CVE-2024-0001", "SQL injection", SeverityHigh,
		"first scan", "evidence one", "scan:1", nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first upsert should create")
	}
	if _, err := d.Exec(`UPDATE findings SET status=$2 WHERE id=$1`, id, FindingConfirmed); err != nil {
		t.Fatal(err)
	}

	id2, created2, err := d.UpsertFinding(0, 0, "CVE-2024-0001", "SQL injection", SeverityCritical,
		"second scan", "evidence two", "scan:2", nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Fatal("second upsert should merge")
	}
	if id2 != id {
		t.Fatalf("id = %d, want %d", id2, id)
	}
	f, err := d.GetFinding(id)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != FindingConfirmed {
		t.Fatalf("status = %q, want confirmed (preserved)", f.Status)
	}
	if f.Evidence != "evidence two" {
		t.Fatalf("evidence = %q", f.Evidence)
	}
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %q", f.Severity)
	}
}

func TestUpsertFindingEmptyKeyAlwaysInserts(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	marker := fmt.Sprintf("no-dedupe-%d", time.Now().UnixNano())
	id1, created1, err := d.UpsertFinding(0, 0, marker, "", SeverityLow, "s", "e", "test", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	id2, created2, err := d.UpsertFinding(0, 0, marker, "", SeverityLow, "s", "e", "test", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id IN ($1,$2)`, id1, id2)
	if !created1 || !created2 || id1 == id2 {
		t.Fatalf("empty key must not dedupe: created=%v/%v ids=%d/%d", created1, created2, id1, id2)
	}
}

func TestConfirmFindingAppendsEvidenceOnce(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	key := fmt.Sprintf("test|confirm|%d", time.Now().UnixNano())
	id, _, err := d.UpsertFinding(0, 0, "CVE-2024-0002", "XSS", SeverityMedium,
		"summary", "original", "test", nil, key)
	if err != nil {
		t.Fatal(err)
	}
	defer purgeDetachedFindings(t, d, id)

	note := "自动复现确认：深度任务 #42"
	from, found, changed, err := d.ConfirmFinding(context.Background(), id, note)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !changed || from != FindingPending {
		t.Fatalf("from=%q found=%v changed=%v", from, found, changed)
	}
	f, err := d.GetFinding(id)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != FindingConfirmed {
		t.Fatalf("status = %q", f.Status)
	}
	if want := "original\n\n" + note; f.Evidence != want {
		t.Fatalf("evidence = %q, want %q", f.Evidence, want)
	}

	// A repeated confirmation must not append the same note again.
	if _, _, _, err := d.ConfirmFinding(context.Background(), id, note); err != nil {
		t.Fatal(err)
	}
	f, err = d.GetFinding(id)
	if err != nil {
		t.Fatal(err)
	}
	if f.Evidence != "original\n\n"+note {
		t.Fatalf("duplicate note appended: %q", f.Evidence)
	}

	if _, found, _, err := d.ConfirmFinding(context.Background(), 999999999, note); err != nil || found {
		t.Fatalf("missing finding: found=%v err=%v", found, err)
	}
}

// A specialized tool that cannot reproduce what a POC template asserted has to
// take the finding out of the confirmed set, otherwise the report keeps a
// verdict the platform itself now doubts.
func TestReopenFindingWithdrawsConfirmedVerdict(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	key := fmt.Sprintf("test|reopen|%d", time.Now().UnixNano())
	id, _, err := d.UpsertFinding(0, 0, "CVE-2024-0003", "SQL injection", SeverityHigh,
		"summary", "POC 命中", "test", nil, key)
	if err != nil {
		t.Fatal(err)
	}
	defer purgeDetachedFindings(t, d, id)

	if _, _, _, err := d.ConfirmFinding(context.Background(), id, "POC 模板自动确认"); err != nil {
		t.Fatal(err)
	}

	note := "sqlmap 专项验证未能复现该注入点，已撤销 POC 判定"
	from, found, changed, err := d.ReopenFinding(context.Background(), id, note)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !changed || from != FindingConfirmed {
		t.Fatalf("from=%q found=%v changed=%v", from, found, changed)
	}
	f, err := d.GetFinding(id)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != FindingPending {
		t.Fatalf("status = %q, want pending", f.Status)
	}
	want := "POC 命中\n\nPOC 模板自动确认\n\n" + note
	if f.Evidence != want {
		t.Fatalf("evidence = %q, want %q", f.Evidence, want)
	}

	// Reopening a finding that is already 待处理 changes nothing and adds no note.
	if _, _, changed, err := d.ReopenFinding(context.Background(), id, note); err != nil || changed {
		t.Fatalf("second reopen: changed=%v err=%v", changed, err)
	}
	f, err = d.GetFinding(id)
	if err != nil {
		t.Fatal(err)
	}
	if f.Evidence != want {
		t.Fatalf("duplicate note appended: %q", f.Evidence)
	}

	if _, found, _, err := d.ReopenFinding(context.Background(), 999999999, note); err != nil || found {
		t.Fatalf("missing finding: found=%v err=%v", found, err)
	}
}
