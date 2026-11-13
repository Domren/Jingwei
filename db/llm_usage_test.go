package db

import (
	"fmt"
	"testing"
	"time"
)

// TokenByModel 的口径（R19 序 4 前置）：任务主链路（planner/worker）的 LLM 行在引擎
// 挂载 llmrec.WithTaskID 之前以「探索 id 字符串」落 task_id，之后落「任务注册 id」；
// exploration_id 列两代口径都恒有值且与任务一一对应。双谓词必须能把两代行都算进来，
// 而旧口径（单 task_id）会把历史行报成空——这正是「报表静默返空」缺陷本身。
//
// 测试 schema 跨运行持久、llm_usage 无唯一约束：夹具必须用每次运行唯一的标识并在
// Cleanup 里删干净，否则行会跨运行累积、断言被上一次的行污染（实测 2/150 被算成 16/1800）。
func TestTokenByModelCountsLegacyExplorationKeyedRows(t *testing.T) {
	d := testDB(t)
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	expID := time.Now().UnixNano() // 每次运行唯一的探索 id（正 int64）
	taskID := fmt.Sprintf("r19u%d", expID)
	otherExpID := expID + 1
	otherTaskID := fmt.Sprintf("r19u%d", otherExpID)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM llm_usage WHERE exploration_id = ANY($1)`, []int64{expID, otherExpID})
	})

	rows := []*LLMUsage{
		{TaskID: taskID, ExplorationID: expID, Worker: "planner", Model: "m1", InputTokens: 100, OutputTokens: 10, Status: "ok"},
		{TaskID: fmt.Sprint(expID), ExplorationID: expID, Worker: "worker", Model: "m1", InputTokens: 50, OutputTokens: 5, Status: "ok"},  // 挂载前的历史口径
		{TaskID: otherTaskID, ExplorationID: otherExpID, Worker: "planner", Model: "m1", InputTokens: 999, OutputTokens: 1, Status: "ok"}, // 别的任务
	}
	for i, u := range rows {
		if err := d.InsertLLMUsage(u); err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
	}
	stats, err := d.TokenByModel(taskID, expID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].Model != "m1" {
		t.Fatalf("want single m1 row, got %+v", stats)
	}
	if stats[0].Calls != 2 || stats[0].InputTokens != 150 {
		t.Fatalf("want 2 calls / 150 input tokens, got calls=%d input=%d", stats[0].Calls, stats[0].InputTokens)
	}
	// 反向验证：explorationID=0（旧口径，只按注册 id 查）会漏掉探索 id 键控的历史行。
	old, err := d.TokenByModel(taskID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 1 || old[0].Calls != 1 || old[0].InputTokens != 100 {
		t.Fatalf("legacy-only predicate should miss exploration-keyed rows, got %+v", old)
	}
}
