package server

import (
	"testing"
	"time"

	pgdb "github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/guard"
)

// A3：1.4.1 把范围管控与资产禁令改成失败关闭后，「数据库抖一下」和「目标真的越界」
// 在操作员眼里是同一句话——工具被拒。这里按类别计数，让系统页能区分两者。

func TestGuardDenialMeteringRecordsCause(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("guard denial metering fixture", "scope.example", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM guard_denials WHERE task_id=$1`, task.ID)
	})
	if _, err := pg.Assets().AddAgentScope(task.ID, "subdomain", "scope.example", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	rule, err := pg.CreateAssetInterceptRule("exact_domain", "blocked.example", "[测试] 禁令", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteAssetInterceptRule(rule.ID) })

	pol := newGuardTargetPolicy(pg)

	if verdict, reason := pol.Check(task.ID, nil, []string{"scope.example"}); verdict != guard.ScopeIn {
		t.Fatalf("in-scope target = (%v,%q), want in", verdict, reason)
	}
	verdict, reason := pol.Check(task.ID, nil, []string{"evil.example"})
	if verdict != guard.ScopeOut || reason == "" {
		t.Fatalf("out-of-scope target = (%v,%q)", verdict, reason)
	}
	if verdict, _ := pol.Check(task.ID, nil, []string{"blocked.example"}); verdict != guard.ScopeOut {
		t.Fatal("blocked asset must be denied")
	}

	stats, err := pg.GuardDenialStats(time.Hour, 50)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, s := range stats {
		if s.TaskID == task.ID {
			got[s.Category] = s.Denials
			if s.LastReason == "" {
				t.Fatalf("category %q lost its last reason", s.Category)
			}
			if s.Mode == "" {
				t.Fatalf("category %q lost the enforcement mode", s.Category)
			}
		}
	}
	if got[pgdb.GuardDenialOutOfScope] != 1 {
		t.Fatalf("out_of_scope bucket = %v, want 1", got)
	}
	if got[pgdb.GuardDenialAssetBlock] != 1 {
		t.Fatalf("asset_block bucket = %v, want 1", got)
	}
	if _, bad := got[pgdb.GuardDenialScopeReadFailed]; bad {
		t.Fatal("a successful scope read must not meter a read failure")
	}
}

// The whole point of fail-closed is that an unreadable policy source denies the
// call. That path must still produce a row — and must not fall apart because the
// statistics write itself failed.
func TestGuardDenialNilSourceDeniesWithoutPanicking(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("guard denial nil source fixture", "10.98.0.0/24", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM guard_denials WHERE task_id=$1`, task.ID)
	})

	verdict, reason := newGuardTargetPolicy(nil).Check(task.ID, nil, []string{"10.98.0.1"})
	if verdict != guard.ScopeOut || reason == "" {
		t.Fatalf("nil source must deny: (%v,%q)", verdict, reason)
	}
	// A nil store cannot meter, and that must not change the verdict.
	if _, err := pg.GuardDenialStats(time.Hour, 50); err != nil {
		t.Fatal(err)
	}
}

func TestGuardDenialStatsBucketsByTaskAndCategory(t *testing.T) {
	pg := prescanTestDB(t)
	taskA, err := pg.CreateTask("guard denial stats A", "10.97.0.0/24", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskB, err := pg.CreateTask("guard denial stats B", "10.97.0.0/24", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, taskA.ID)
	purgeTaskFixture(t, pg, taskB.ID)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM guard_denials WHERE task_id IN ($1,$2)`, taskA.ID, taskB.ID)
	})
	for i := 0; i < 3; i++ {
		if err := pg.InsertGuardDenial(taskA.ID, pgdb.GuardDenialScopeReadFailed, "strict", "无法读取授权范围"); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.InsertGuardDenial(taskB.ID, pgdb.GuardDenialOutOfScope, "warn", "不在范围内"); err != nil {
		t.Fatal(err)
	}
	// Rows outside the window must not be counted, or a month-old outage keeps
	// showing up as if the policy were still misfiring.
	if err := pg.InsertGuardDenial(taskA.ID, pgdb.GuardDenialScopeReadFailed, "strict", "很久以前"); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE guard_denials SET ts = now() - interval '40 days'
		WHERE task_id=$1 AND reason='很久以前'`, taskA.ID); err != nil {
		t.Fatal(err)
	}

	stats, err := pg.GuardDenialStats(time.Hour*24*7, 100)
	if err != nil {
		t.Fatal(err)
	}
	var a, b pgdb.GuardDenialStat
	foundA, foundB := false, false
	for _, s := range stats {
		switch s.TaskID {
		case taskA.ID:
			a, foundA = s, true
		case taskB.ID:
			b, foundB = s, true
		}
	}
	if !foundA || !foundB {
		t.Fatalf("both tasks must appear: %v", stats)
	}
	if a.Category != pgdb.GuardDenialScopeReadFailed || a.Denials != 3 {
		t.Fatalf("task A bucket = %+v, want 3 scope_read_failed", a)
	}
	if a.LastReason != "无法读取授权范围" {
		t.Fatalf("task A last reason = %q", a.LastReason)
	}
	if b.Denials != 1 || b.Mode != "warn" {
		t.Fatalf("task B bucket = %+v", b)
	}
}
