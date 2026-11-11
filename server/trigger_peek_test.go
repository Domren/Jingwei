package server

import (
	"testing"

	"github.com/Autumn-27/jingwei/agent"
)

// R21 §5.4 ④ 第一条：触发不丢。失败轮只 peek、不 commit；成功轮才清。
// 夹具还原一个真实场景：worker 完成 intent 42 → Plan() 失败（流被重置）→
// 触发不能被吞掉，下一轮重新读取。

func TestPeekTriggersDoesNotConsume(t *testing.T) {
	task := &Task{ID: "t1", notify: make(chan struct{}, 1)}
	task.NotifyDone(42)

	// 第一轮：peek 读到，但不 commit（模拟 Plan 失败）。
	got := task.peekTriggers()
	if len(got) != 1 || got[0].Kind != "done" || got[0].IntentID != 42 {
		t.Fatalf("peek 应读到触发，实际 %+v", got)
	}
	// 没 commit，再 peek 一次还在。
	got = task.peekTriggers()
	if len(got) != 1 {
		t.Fatalf("未 commit 时触发必须还在，实际 %d 条", len(got))
	}
}

func TestCommitTriggersClearsAfterSuccess(t *testing.T) {
	task := &Task{ID: "t1", notify: make(chan struct{}, 1)}
	task.NotifyDone(42)

	_ = task.peekTriggers()
	task.commitTriggers() // 模拟 Plan 成功

	if got := task.peekTriggers(); len(got) != 0 {
		t.Fatalf("commit 后触发应被清空，实际 %d 条", len(got))
	}
}

// 并发安全：peek 返回的是副本，不能被调用方改坏 pending。
func TestPeekReturnsCopy(t *testing.T) {
	task := &Task{ID: "t1", notify: make(chan struct{}, 1)}
	task.NotifyDone(1)
	got := task.peekTriggers()
	if len(got) != 1 {
		t.Fatalf("应读到 1 条")
	}
	got[0].IntentID = 999 // 写副本
	again := task.peekTriggers()
	if len(again) != 1 || again[0].IntentID != 1 {
		t.Fatalf("pending 不应被副本污染，实际 %+v", again)
	}
}

// 多类型触发在失败轮也能读全。
func TestPeekReadsAllKinds(t *testing.T) {
	task := &Task{ID: "t1", notify: make(chan struct{}, 1)}
	task.NotifyDone(1)
	task.NotifyFinding(2, "x")
	task.NotifyGoal([]string{"g1"})
	task.NotifyHint([]string{"h1"})

	got := task.peekTriggers()
	kinds := map[string]int{}
	for _, e := range got {
		kinds[e.Kind]++
	}
	for _, want := range []string{"done", "finding", "goal", "hint"} {
		if kinds[want] == 0 {
			t.Fatalf("缺触发类型 %q，实际 %+v", want, kinds)
		}
	}
}

// 供上面的触发构造用：agent.TriggerEvent 的最小字段。
var _ = agent.TriggerEvent{}
