package server

import (
	"strings"
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

// 按成因的分布要能把「抖动可重试」与「策略拒绝」分开：这两类在界面上长得一样，
// 但前者重试就好、后者重试一万次也不会放行。窗口外的行同样不能算进来。
func TestGuardDenialBreakdownSplitsRetryableCauses(t *testing.T) {
	pg := prescanTestDB(t)
	task, err := pg.CreateTask("guard denial breakdown", "10.97.1.0/24", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	purgeTaskFixture(t, pg, task.ID)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM guard_denials WHERE task_id=$1`, task.ID)
	})
	for i := 0; i < 4; i++ {
		if err := pg.InsertGuardDenial(task.ID, pgdb.GuardDenialBlockReadFailed, "strict", "读取资产禁令失败"); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.InsertGuardDenial(task.ID, pgdb.GuardDenialOutOfScope, "strict", "不在范围内"); err != nil {
		t.Fatal(err)
	}
	if err := pg.InsertGuardDenial(0, pgdb.GuardDenialOutOfScope, "warn", "无任务上下文"); err != nil {
		t.Fatal(err)
	}
	if err := pg.InsertGuardDenial(task.ID, pgdb.GuardDenialOutOfScope, "strict", "很久以前"); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE guard_denials SET ts = now() - interval '40 days' WHERE task_id=$1 AND reason='很久以前'`, task.ID); err != nil {
		t.Fatal(err)
	}

	causes, err := pg.GuardDenialBreakdown(time.Hour * 24 * 7)
	if err != nil {
		t.Fatal(err)
	}
	var blockRead, outOfScope *pgdb.GuardDenialCause
	for i := range causes {
		switch causes[i].Category {
		case pgdb.GuardDenialBlockReadFailed:
			blockRead = &causes[i]
		case pgdb.GuardDenialOutOfScope:
			outOfScope = &causes[i]
		}
	}
	// 分布是全局的（跨任务、跨用例共享同一张表），所以只断言「自己插的这几条被算进来了」，
	// 不断言总数等于几——那个数字会被并行用例与历史数据改掉。
	if blockRead == nil || blockRead.Total < 4 || blockRead.Tasks < 1 {
		t.Fatalf("block_read_failed = %+v，want 至少 total>=4 tasks>=1", blockRead)
	}
	if !blockRead.Retryable || !strings.Contains(blockRead.Advice, "重试") {
		t.Fatalf("读库抖动应当标为可重试并给出重试建议：%+v", blockRead)
	}
	if outOfScope == nil {
		t.Fatalf("窗口内的 out_of_scope 没统计到：%+v", causes)
	}
	// 窗口外那条的措辞是独一份的：它若出现在 LastReason 里，说明回看窗口没生效。
	if outOfScope.LastReason == "很久以前" {
		t.Fatalf("40 天前的拒绝被算进了窗口：%+v", outOfScope)
	}
	if outOfScope.Retryable || !strings.Contains(outOfScope.Advice, "重试不会放行") {
		t.Fatalf("策略拒绝不该标可重试，且要写明重试不会放行：%+v", outOfScope)
	}
	// 未登记的成因不能被默认当成可重试：默认值定成「不可重试」才安全。
	if retryable, advice := pgdb.GuardDenialCauseMeta("some_new_cause"); retryable || !strings.Contains(advice, "未登记") {
		t.Fatalf("未登记成因默认 = retryable=%v advice=%q，want 不可重试且点名未登记", retryable, advice)
	}
}
