package server

import (
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/llmrec"
)

// R21 缺口②⑤ 在 server 层的夹具：告警判据与退避序列。
//
// 这两条都是纯函数，不连库、不连网——但正是「端点一废就白烧」那条链上最靠前的
// 两个判据：告警决定人能不能在头两分钟知道，退避决定知道之前会不会先轰一百轮。

// ② 告警必须与总轮数无关：任务开局只跑了一轮就废，也该立刻响。
//
// 反向验证：把判据改回 `failureRate>0.3 && total>=10`，本用例第一段必然失败
// （total=1 时旧判据永不告警）。
func TestLLMAlarmFiresOnFirstUnrecoverableFailure(t *testing.T) {
	// 任务刚开跑：1 轮，失败，且是不可自愈的那类。
	for _, class := range []llmrec.ErrorClass{
		llmrec.ErrClassUnreachable,
		llmrec.ErrClassAccountInvalid,
		llmrec.ErrClassModelNotFound,
	} {
		alarm, reason := llmAlarm(1, 1, map[string]int{string(class): 1})
		if !alarm {
			t.Errorf("首轮即 %s（不会自愈）必须立刻告警，否则要等两小时才知道", class)
		}
		if reason == "" {
			t.Errorf("%s 告警必须带人话原因，前端要直接显示", class)
		}
	}

	// 首轮失败但类是可自愈的（如一次 502）：不立刻告警，等第二轮。
	if alarm, _ := llmAlarm(1, 1, map[string]int{string(llmrec.ErrClassUpstream5xx): 1}); alarm {
		t.Error("首轮偶发 502 不该立刻告警（会给正常运行刷噪音），应由连续失败判据兜住")
	}
}

// ② 连续失败是主判据：它不看总轮数，所以端点一坏就生效。
func TestLLMAlarmFiresOnConsecutiveFailures(t *testing.T) {
	// 连续 2 轮失败：即使总共只有 2 轮（远不到旧的 total>=10）也必须响。
	if alarm, _ := llmAlarm(2, 2, map[string]int{"other": 2}); !alarm {
		t.Error("连续 2 轮失败必须告警，旧判据的 total>=10 门槛是错的")
	}
	// 连续失败优先于「首轮不可自愈」判断：中间有 ok 就断链，不该误报。
	if alarm, _ := llmAlarm(20, 0, map[string]int{"other": 5}); alarm {
		t.Error("最近一轮是成功（连续失败 0）时不该告警，即使历史废轮很多")
	}
}

func TestLLMAlarmQuietWhenNothingRan(t *testing.T) {
	if alarm, reason := llmAlarm(0, 0, nil); alarm || reason != "" {
		t.Error("一轮都没跑时不该告警")
	}
}

// ⑤ 退避必须真的挡住「失败轮不 commit 触发」带来的空转。
//
// 反向验证：把 plannerBackoff 改成恒返回 0（即旧行为），本用例会失败。
func TestPlannerBackoffBlocksImmediateRetry(t *testing.T) {
	e := &Engine{}
	const taskID = "42"

	// 第一次失败后：已经记了失败时刻，退避窗口内必须还有剩余。
	n := e.bumpConsecutiveFail(taskID)
	if n != 1 {
		t.Fatalf("连续失败计数应从 1 起，实得 %d", n)
	}
	if d := e.plannerBackoff(taskID, n); d <= 0 {
		t.Fatalf("第 1 次失败后必须有退避，实得 %v", d)
	}
	if remaining := e.backoffRemaining(taskID); remaining <= 0 {
		t.Fatal("缺口⑤：失败后立刻又能跑，规划循环会对着坏端点持续轰击")
	}

	// 把失败时刻挪到很久以前，等价于「退避已等够」。
	e.lastFailAt.Store(taskID, time.Now().Add(-time.Hour).UnixNano())
	if remaining := e.backoffRemaining(taskID); remaining != 0 {
		t.Fatalf("退避窗口过去后应放行，实得还剩 %v", remaining)
	}
}

func TestPlannerBackoffGrowsWithConsecutiveFailures(t *testing.T) {
	e := &Engine{}
	const taskID = "43"
	prev := time.Duration(0)
	for i := 1; i <= 4; i++ {
		e.bumpConsecutiveFail(taskID)
		d := llmrec.BackoffBefore(i)
		if d <= prev {
			t.Fatalf("第 %d 次退避 %v 没有比上一次 %v 更长", i, d, prev)
		}
		prev = d
	}
	// 成功轮清零后不再退避。
	e.clearConsecutiveFail(taskID)
	if got := e.consecutiveFailures(taskID); got != 0 {
		t.Fatalf("成功轮后连续失败计数应归零，实得 %d", got)
	}
	if remaining := e.backoffRemaining(taskID); remaining != 0 {
		t.Fatalf("计数归零后不该再退避，实得 %v", remaining)
	}
}

// L3 零进展：连续 N 轮没有新东西才算停摆，中途有进展就清零。
func TestNoteProgressNeverFiresOnGrowingTask(t *testing.T) {
	e := &Engine{}
	e.llmSup = llmrec.NewSupervisor(nil, nil)
	e.llmSup.SetStalledRounds(2)

	// 没有 Store 的任务：progressSnapshot 全 0，第一轮只建基线。
	task := &Task{}
	task.ID = "44"
	e.noteProgress(task, "", false)
	if e.noProgressCount(task.ID) != 0 {
		t.Fatal("第一轮只该建立基线，不该算零进展")
	}
	// 第二轮仍是全 0 → 零进展 1 次（阈值 2，还没到）。
	e.noteProgress(task, "", false)
	if got := e.noProgressCount(task.ID); got != 1 {
		t.Fatalf("第二轮零进展计数应为 1，实得 %d", got)
	}
	// 第三轮 → 2 次，达到阈值，判 stalled。
	e.noteProgress(task, "", false)
	if !e.stalledFlag(task.ID) {
		t.Fatal("连续 2 轮零进展（阈值 2）应判 stalled_task")
	}
	// 判出目标即清零并撤掉标记。
	e.noteProgress(task, "goal met", true)
	if e.stalledFlag(task.ID) {
		t.Fatal("出现进展后必须撤掉 stalled 标记，否则任务再也不会被正常判定")
	}
	if got := e.noProgressCount(task.ID); got != 0 {
		t.Fatalf("进展后零进展计数应归零，实得 %d", got)
	}
}

// 辅助读取内部计数（夹具用）。
func (e *Engine) noProgressCount(taskID string) int {
	if v, ok := e.noProgress.Load(taskID); ok {
		return int(*v.(*int32))
	}
	return 0
}

func (e *Engine) stalledFlag(taskID string) bool {
	_, ok := e.taskStalled.Load(taskID)
	return ok
}
