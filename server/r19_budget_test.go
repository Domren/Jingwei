package server

import (
	"context"
	"testing"
)

// R19 序 4 预算闸门在 server 层的纯函数夹具（不连库）。用量查询与轮次计数已在
// db 层夹具覆盖（TaskBudgetUsage / TokenByModel）；这里钉因果映射与协调器守卫。

// settleCause → 终态/台账文案：budget 与 timeout 是两个终态，「为什么停」可读。
func TestSettleCauseMapping(t *testing.T) {
	if got := settleTimeout.status(); got != "timeout" {
		t.Fatalf("timeout cause must settle to timeout, got %q", got)
	}
	if got := settleBudgetRounds.status(); got != "budget" {
		t.Fatalf("rounds cause must settle to budget, got %q", got)
	}
	if got := settleBudgetTokens.settleKey(); got != "budget" {
		t.Fatalf("tokens cause must feed TaskClock.Settle=budget, got %q", got)
	}
	if got := settleBudgetRounds.stopReasonText(&Task{MaxRounds: 40}); got != "达到规划轮数上限（max_rounds=40）" {
		t.Fatalf("rounds stop reason mismatch, got %q", got)
	}
	if got := settleBudgetTokens.stopReasonText(&Task{MaxInputTokens: 1500000}); got != "达到输入 token 上限（max_input_tokens=1500000）" {
		t.Fatalf("tokens stop reason mismatch, got %q", got)
	}
	if got := settleTimeout.stopReasonText(&Task{}); got != "到达超时上限" {
		t.Fatalf("timeout stop reason mismatch, got %q", got)
	}
}

// TaskClock.Settle 的取值口径：agent 侧按它挑任务收尾词。反向验证点——若这里把
// budget 误回 "timeout"，预算任务会拿到超时词（「钱烧完」被说成「时间到」）。
func TestSettleKeyFeedsAgentTaskClock(t *testing.T) {
	if got := settleBudgetTokens.settleKey(); got != "budget" {
		t.Fatalf("budget key mismatch, got %q", got)
	}
	if got := settleTimeout.settleKey(); got != "timeout" {
		t.Fatalf("timeout key mismatch, got %q", got)
	}
}

// startBudgetCoordinator 只为设了上限的任务启动：无上限任务不得占用协调器标记。
// （有上限的启动路径需要完整 Manager/ctx，由实机复跑覆盖；这里钉守卫条件本身。）
func TestStartBudgetCoordinatorSkipsUnlimitedTasks(t *testing.T) {
	e := &Engine{}
	plain := &Task{}
	plain.ID = "51"
	e.startBudgetCoordinator(context.Background(), plain)
	if _, ok := e.budgetCoordStarted.Load("51"); ok {
		t.Fatal("无上限任务不该启动预算协调器（占去重标记会挡住后续真实上限）")
	}
}
