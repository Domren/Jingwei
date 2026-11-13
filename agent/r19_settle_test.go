package agent

import (
	"testing"

	"github.com/Autumn-27/norma/harness"
)

// R19 序 4：任务预算到限的收尾词与 compaction 窗口上限。

// settle="budget" 时无论 run 因哪种 reason 收尾，Timeout 侧都要换成预算词
// （这是任务正在终止的窗口）；MaxTurns 侧维持 per-run 词（夹逼窗口内步数先耗尽）。
func TestWrapupSettlementForTaskBudgetUsesBudgetWords(t *testing.T) {
	st := wrapupSettlementForTask("worker", nil, false, "budget")
	if st.PromptByReason == nil {
		t.Fatal("budget settle must wire PromptByReason")
	}
	if got := st.PromptByReason[harness.ReasonTimeout]; got != workerTaskBudgetDefault {
		t.Fatalf("ReasonTimeout should carry budget words, got %.40s...", got)
	}
	if got := st.PromptByReason[harness.ReasonMaxTurns]; got != resolveWrapup("worker") {
		t.Fatalf("ReasonMaxTurns should stay per-run, got %.40s...", got)
	}
	if st.MaxTurns != resolveWrapupTurns("worker") {
		t.Fatalf("budget settle should keep wrapup turn budget, got %d", st.MaxTurns)
	}
}

// 回归护栏：不带 settle 的超时路径行为不变（clamped=true → 超时词；false → 纯 per-run）。
func TestWrapupSettlementForTaskTimeoutUnchanged(t *testing.T) {
	clamped := wrapupSettlementForTask("worker", nil, true, "")
	if got := clamped.PromptByReason[harness.ReasonTimeout]; got != workerTaskTimeoutDefault {
		t.Fatalf("clamped timeout words changed, got %.40s...", got)
	}
	plain := wrapupSettlementForTask("worker", nil, false, "")
	if plain.PromptByReason != nil {
		t.Fatalf("plain run must not wire PromptByReason, got %+v", plain.PromptByReason)
	}
	if plain.Prompt != resolveWrapup("worker") {
		t.Fatalf("plain run prompt must be per-run words, got %.40s...", plain.Prompt)
	}
}

// planner 终局词按收尾原因挑选：budget → 预算词，否则超时词。
func TestPlannerFinalWordsPickedBySettleCause(t *testing.T) {
	if resolveTaskBudgetWrapup("planner") != plannerTaskBudgetDefault {
		t.Fatal("planner budget words mismatch")
	}
	if resolveTaskTimeoutWrapup("planner") != plannerTaskTimeoutDefault {
		t.Fatal("planner timeout words mismatch")
	}
}

// worker compaction 窗口上限：超过 100K 压到 100K；小窗口不动；未配置先回落默认
// 200K 再压到上限（直接对原始值判上限会让「未配置」漏网——反向验证点）。
func TestWorkerCompactionWindowCapped(t *testing.T) {
	if got := workerCompactionWindow(1000000); got != workerCompactionWindowCap {
		t.Fatalf("1M config must clamp to cap %d, got %d", workerCompactionWindowCap, got)
	}
	if got := workerCompactionWindow(50000); got != 50000 {
		t.Fatalf("smaller window must stay unchanged, got %d", got)
	}
	if got := workerCompactionWindow(0); got != workerCompactionWindowCap {
		t.Fatalf("unset must fall back to default then clamp to cap %d, got %d", workerCompactionWindowCap, got)
	}
	if got := workerCompactionWindow(-5); got != workerCompactionWindowCap {
		t.Fatalf("negative must fall back to default then clamp, got %d", got)
	}
}
