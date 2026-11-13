package db

import (
	"context"
	"testing"
)

// 1.6.2 第 3 步的夹具：blocked 意图必须带原因。
//
// 这一条欠账的成因不是「忘了写」，而是三处泛型状态写入无条件
// `blocked_reason=NULL`——经由它们转 blocked 的意图原因被硬置空（实测 40 条）。
// 所以夹具的重点不是「SetIntentBlockedReason 能不能写」，而是：
//
//  1. 泛型写入转 blocked 时**必须**留下非空原因；
//  2. 转非 blocked 状态时**必须**清空原因（否则旧原因会挂在新状态上，误导）；
//  3. 存量回填是幂等的，且回填后「原因为空 = 0」。

// testDB 打开测试库；未配置时跳过（与 db 包其他用例口径一致）。
func testDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// 建一个带一条意图的探索记录，供本组用例共用。
func blockedReasonFixture(t *testing.T, d *DB) (*ExplorationStore, int64) {
	t.Helper()
	task, err := d.CreateTask("blocked reason fixture", "10.99.0.51", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { purgeBlockedFixture(d, task.ID) })
	store := d.Exploration(task.ExplorationID)
	id, err := store.AddIntent(map[string]any{"description": "blocked reason fixture intent"}, 5, nil, "worker")
	if err != nil {
		t.Fatal(err)
	}
	return store, id
}

func purgeBlockedFixture(d *DB, taskID int64) {
	var expID int64
	if err := d.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, taskID).Scan(&expID); err == nil && expID > 0 {
		_, _ = d.Exec(`DELETE FROM exploration_nodes WHERE exploration_id=$1`, expID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	}
	_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
}

// 核心：泛型写入转 blocked 必须留原因，不能是 NULL。
func TestSetIntentStateBlockedRequiresReason(t *testing.T) {
	d := testDB(t)
	store, id := blockedReasonFixture(t, d)
	ctx := context.Background()

	// 先让它 running（真实路径就是这样转的）。
	if err := store.SetIntentState(id, "running"); err != nil {
		t.Fatal(err)
	}

	// 泛型写入转 blocked，且给一个合法原因。
	if err := store.SetIntentStateWithReason(id, "blocked", IntentBlockedGuardDenied); err != nil {
		t.Fatal(err)
	}
	n, err := store.GetNode(id)
	if err != nil || n == nil {
		t.Fatalf("读回意图失败: %v", err)
	}
	if n.State != "blocked" {
		t.Fatalf("状态应为 blocked，实得 %q", n.State)
	}
	if n.BlockedReason != IntentBlockedGuardDenied {
		t.Fatalf("原因应落库为 %q，实得 %q（空值就是这条欠账本身）", IntentBlockedGuardDenied, n.BlockedReason)
	}

	// 再转 open：原因必须被清掉，否则旧原因会挂在新状态上。
	if err := store.SetIntentState(id, "open"); err != nil {
		t.Fatal(err)
	}
	n, err = store.GetNode(id)
	if err != nil || n == nil {
		t.Fatal(err)
	}
	if n.BlockedReason != "" {
		t.Fatalf("离开 blocked 后原因必须清空，实得 %q", n.BlockedReason)
	}
	_ = ctx
}

// 不给原因转 blocked → 落 unknown，绝不落 NULL。
// 给了未登记的原因 → 原样保留（泛型路径不该把调用方知道的具体成因洗掉）。
func TestSetIntentStateBlockedWithoutReasonFallsBackToUnknown(t *testing.T) {
	d := testDB(t)
	store, id := blockedReasonFixture(t, d)

	if err := store.SetIntentStateWithReason(id, "blocked", ""); err != nil {
		t.Fatal(err)
	}
	n, err := store.GetNode(id)
	if err != nil || n == nil {
		t.Fatal(err)
	}
	if n.BlockedReason == "" {
		t.Fatal("空原因被写成了 NULL——这正是 40 条原因全空的成因，必须降级为 unknown")
	}
	if n.BlockedReason != IntentBlockedUnknown {
		t.Fatalf("空原因应降级为 unknown，实得 %q", n.BlockedReason)
	}

	// 未登记的具体原因必须原样保留：调用方知道得比枚举多，洗掉就是丢信息。
	if err := store.SetIntentState(id, "open"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentStateWithReason(id, "blocked", "network_unavailable"); err != nil {
		t.Fatal(err)
	}
	n, err = store.GetNode(id)
	if err != nil || n == nil {
		t.Fatal(err)
	}
	if n.BlockedReason != "network_unavailable" {
		t.Fatalf("具体原因应原样保留，实得 %q（被归一化就是丢信息）", n.BlockedReason)
	}
}

// CAS 路径（worker 结算走这条）同样必须带原因。
func TestCompareAndSetIntentStateBlockedRequiresReason(t *testing.T) {
	d := testDB(t)
	store, id := blockedReasonFixture(t, d)
	if err := store.SetIntentState(id, "running"); err != nil {
		t.Fatal(err)
	}
	ok, err := store.CompareAndSetIntentStateWithReason(id, "running", "blocked", IntentBlockedAssetMissing)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("CAS 应成功")
	}
	n, err := store.GetNode(id)
	if err != nil || n == nil {
		t.Fatal(err)
	}
	if n.BlockedReason != IntentBlockedAssetMissing {
		t.Fatalf("CAS 转 blocked 也必须留原因，实得 %q", n.BlockedReason)
	}
}

// SetNodeState 也被同一处缺陷影响（它无条件置 NULL）。
func TestSetNodeStateBlockedKeepsReason(t *testing.T) {
	d := testDB(t)
	store, id := blockedReasonFixture(t, d)
	if err := store.SetNodeStateWithReason(id, "blocked", IntentBlockedBudget); err != nil {
		t.Fatal(err)
	}
	n, err := store.GetNode(id)
	if err != nil || n == nil {
		t.Fatal(err)
	}
	if n.BlockedReason != IntentBlockedBudget {
		t.Fatalf("SetNodeState 转 blocked 也必须留原因，实得 %q", n.BlockedReason)
	}
}

// 存量回填：幂等，且回填后「blocked 且原因为空」必须为 0。
func TestBackfillIntentBlockedReasonsIsIdempotent(t *testing.T) {
	d := testDB(t)
	store, id := blockedReasonFixture(t, d)

	// 直接造出「blocked 但原因为空」的存量形态（模拟修复前的数据）。
	if _, err := d.Exec(`UPDATE exploration_nodes SET state='blocked', blocked_reason=NULL WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}

	stats, err := store.IntentBlockedReasonStats()
	if err != nil {
		t.Fatal(err)
	}
	emptyBefore := 0
	for _, st := range stats {
		if st.Empty {
			emptyBefore += st.Count
		}
	}
	if emptyBefore != 1 {
		t.Fatalf("夹具应先造出 1 条空原因，实得 %d", emptyBefore)
	}

	// 第一次回填：应改到这一条。
	n, err := d.BackfillIntentBlockedReasons()
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("首次回填应至少改 1 条，实得 %d", n)
	}

	// 第二次回填：幂等，不该再改任何行。
	again, err := d.BackfillIntentBlockedReasons()
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Fatalf("回填必须幂等，第二次实得 %d", again)
	}

	// 判据④：回填后「blocked 且原因为空 = 0」。
	stats, err = store.IntentBlockedReasonStats()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range stats {
		if st.Empty {
			t.Fatalf("回填后仍有 %d 条原因为空（判据④不达标）", st.Count)
		}
	}
	// 而且这条应该正是 unknown，不是别的猜出来的原因。
	unknown := 0
	for _, st := range stats {
		if st.Reason == IntentBlockedUnknown {
			unknown += st.Count
		}
	}
	if unknown != 1 {
		t.Fatalf("应收敛为 1 条 unknown，实得 %d（分布 %+v）", unknown, stats)
	}
}

// 枚举本身：合法值可通过，空值与未登记值被拒。
func TestNormalizeIntentBlockedReason(t *testing.T) {
	for _, r := range IntentBlockedReasons {
		got, ok := NormalizeIntentBlockedReason(r)
		if !ok || got != r {
			t.Errorf("枚举内的 %q 应原样通过，实得 %q/%v", r, got, ok)
		}
	}
	if _, ok := NormalizeIntentBlockedReason(""); ok {
		t.Error("空值不是合法原因（它就是这条欠账的形态）")
	}
	if _, ok := NormalizeIntentBlockedReason("随便写的"); ok {
		t.Error("未登记的值不该通过")
	}
	// 别名落到最近的枚举。
	if got, ok := NormalizeIntentBlockedReason("quota"); !ok || got != IntentBlockedLLMQuota {
		t.Errorf("别名 quota 应落到 %q，实得 %q/%v", IntentBlockedLLMQuota, got, ok)
	}
	// 严格版：非法值返回 error。
	if _, err := MustNormalizeIntentBlockedReason(""); err == nil {
		t.Error("严格版对空值必须报错")
	}
}

// 每个枚举都要有中文标签，前端下拉不能出现空白项。
func TestEveryBlockedReasonHasLabel(t *testing.T) {
	for _, r := range IntentBlockedReasons {
		if IntentBlockedReasonLabel[r] == "" {
			t.Errorf("原因 %q 缺中文标签", r)
		}
	}
	if len(IntentBlockedReasonLabel) != len(IntentBlockedReasons) {
		t.Errorf("标签数与枚举数不一致：%d vs %d", len(IntentBlockedReasonLabel), len(IntentBlockedReasons))
	}
}
