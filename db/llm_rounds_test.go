package db

import (
	"fmt"
	"testing"
	"time"
)

// TaskBudgetUsage 是 R19 序 4 预算闸门的用量来源：轮数按 llm_rounds 的任务注册 id
// 计数（planner 每轮一行），输入 token 按 llm_usage.exploration_id 累计——不按
// task_id 计 token，因为历史行落的是探索 id 字符串，exploration_id 两代口径都恒有值
// （与 TokenByModel/归档侧同一谓词）。
//
// 测试 schema 跨运行持久：夹具用每次运行唯一的标识并在 Cleanup 里删干净，否则
// llm_usage 行跨运行累积会把 token 断言污染掉。
func TestTaskBudgetUsageCountsRoundsAndInputTokens(t *testing.T) {
	d := testDB(t)
	if err := d.EnsureLLMRoundsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	expID := time.Now().UnixNano() // 每次运行唯一的探索 id（正 int64）
	taskID := fmt.Sprintf("r19b%d", expID)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM llm_rounds WHERE task_id LIKE 'r19b%' AND task_id = $1`, taskID)
		_, _ = d.Exec(`DELETE FROM llm_usage WHERE exploration_id = $1`, expID)
	})

	now := time.Now()
	for _, r := range []*LLMRound{
		{RoundID: taskID + "-plan-1", TaskID: taskID, Worker: "planner", Status: "ok", StartedAt: now},
		{RoundID: taskID + "-plan-2", TaskID: taskID, Worker: "planner", Status: "error", Attempts: 1, StartedAt: now},
	} {
		if err := d.InsertLLMRound(r); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []*LLMUsage{
		{TaskID: taskID, ExplorationID: expID, Worker: "planner", Model: "m1", InputTokens: 100, Status: "ok"},
		{TaskID: fmt.Sprint(expID), ExplorationID: expID, Worker: "worker", Model: "m1", InputTokens: 200, Status: "ok"}, // 历史口径行也要计入
	} {
		if err := d.InsertLLMUsage(u); err != nil {
			t.Fatal(err)
		}
	}
	rounds, tokens, err := d.TaskBudgetUsage(taskID, expID)
	if err != nil {
		t.Fatal(err)
	}
	if rounds != 2 || tokens != 300 {
		t.Fatalf("want rounds=2 tokens=300, got rounds=%d tokens=%d", rounds, tokens)
	}
	// 无探索 id（0）：token 不计，轮数照常（llm_rounds 只有注册 id 口径）。
	rounds, tokens, err = d.TaskBudgetUsage(taskID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rounds != 2 || tokens != 0 {
		t.Fatalf("want rounds=2 tokens=0, got rounds=%d tokens=%d", rounds, tokens)
	}
}
