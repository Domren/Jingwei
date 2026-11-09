package db

import (
	"testing"
)

// F1：复用批次落账与整体撤销。断言三件事——
// 1) 每次尝试都入账（跳过/被拒/报错也算）；
// 2) 撤销只删本批新产生的凭据，批次前就存在的记录不动；
// 3) 重复撤销幂等。
func TestIntranetCredentialReuseLedger(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	host := "reuse-ledger-test.local"
	src, err := d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: host, Username: "svc", Password: "preexisting-pass", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intranet_credentials WHERE host=$1`, host) })

	// 本批新登记出来的两行（模拟复用成功后按目标登记）。
	newA, err := d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: "reuse-a.local", Username: "svc", Password: "preexisting-pass", Source: "reuse",
	})
	if err != nil {
		t.Fatal(err)
	}
	newB, err := d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: "reuse-b.local", Username: "svc", Password: "preexisting-pass", Source: "reuse",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intranet_credentials WHERE host IN ('reuse-a.local','reuse-b.local')`)
	})

	batch, err := d.CreateIntranetCredentialReuse(IntranetCredentialReuseInput{
		CredentialID: src.ID,
		TaskID:       7,
		Note:         "unit test batch",
		Attempts: []IntranetCredentialReuseAttemptInput{
			{URL: "http://reuse-a.local/login", Host: "reuse-a.local", Status: ReuseAttemptValid,
				Attempts: 1, ElapsedMS: 120, CreatedCredentialID: newA.ID},
			{URL: "http://reuse-b.local/login", Host: "reuse-b.local", Status: ReuseAttemptValid,
				Attempts: 1, ElapsedMS: 130, CreatedCredentialID: newB.ID},
			{URL: "http://reuse-c.local/login", Host: "reuse-c.local", Status: ReuseAttemptInvalid},
			{URL: "http://outside.local/login", Host: "outside.local", Status: ReuseAttemptSkipped,
				Error: "目标不在授权范围内"},
			{URL: "http://broken.local/login", Host: "broken.local", Status: ReuseAttemptError,
				Error: "未发出登录请求"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intranet_credential_reuses WHERE id=$1`, batch.ID)
	})
	if batch.Total != 5 || batch.ValidCount != 2 || batch.InvalidCount != 1 ||
		batch.SkippedCount != 1 || batch.ErrorCount != 1 {
		t.Fatalf("counts = %+v", batch)
	}

	attempts, err := d.ListIntranetCredentialReuseAttempts(batch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 5 {
		t.Fatalf("attempts = %d want 5", len(attempts))
	}
	var skipped *IntranetCredentialReuseAttempt
	for _, a := range attempts {
		if a.Status == ReuseAttemptSkipped {
			skipped = a
		}
	}
	if skipped == nil || skipped.Error == "" {
		t.Fatalf("skipped attempt should keep its reason: %+v", skipped)
	}

	list, err := d.ListIntranetCredentialReuses(src.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != batch.ID {
		t.Fatalf("list = %+v", list)
	}

	// 撤销：只删本批新建的两行，源凭据保留。
	deleted, err := d.RevokeIntranetCredentialReuse(batch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d want 2", deleted)
	}
	if _, err := d.GetIntranetCredential(src.ID); err != nil {
		t.Fatalf("pre-existing credential must survive revoke: %v", err)
	}
	if _, err := d.GetIntranetCredential(newA.ID); err == nil {
		t.Fatal("batch-created credential should be gone")
	}
	after, err := d.GetIntranetCredentialReuse(batch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.RevokedAt == nil {
		t.Fatal("batch should be marked revoked")
	}
	// 幂等：第二次撤销不重复删、不报错。
	if again, err := d.RevokeIntranetCredentialReuse(batch.ID); err != nil || again != 0 {
		t.Fatalf("second revoke = %d, %v", again, err)
	}
	// 尝试记录保留作审计。
	if kept, _ := d.ListIntranetCredentialReuseAttempts(batch.ID); len(kept) != 5 {
		t.Fatalf("attempts should survive revoke, got %d", len(kept))
	}
}

func TestFindIntranetCredentialID(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	row, err := d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: "find-cred-test.local", Username: "admin", Password: "s3cret", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intranet_credentials WHERE host='find-cred-test.local'`)
	})
	if id, ok := d.FindIntranetCredentialID("find-cred-test.local", "admin", "s3cret"); !ok || id != row.ID {
		t.Fatalf("find = %d,%v want %d", id, ok, row.ID)
	}
	if _, ok := d.FindIntranetCredentialID("find-cred-test.local", "admin", "wrong"); ok {
		t.Fatal("wrong password must not match")
	}
	if _, ok := d.FindIntranetCredentialID("find-cred-test.local", "other", "s3cret"); ok {
		t.Fatal("wrong username must not match")
	}
}
