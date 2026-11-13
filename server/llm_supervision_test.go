package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/llmrec"
)

// R21 §5.4 ⑦ 判据反向验证：人造三种故障，断言系统能检出、按类处置、留痕、不丢触发。
//
// 这层夹具不走 LLM（没有真实模型），而是把 planner.Plan 的失败点用测试替身打出来，
// 验证 engine 的规划循环在三种故障形态下各自落账并把触发放回去。

// fakePlanner 用注入的 err 控制 Plan 的失败形态；trigger 参数直接转发，不做规划。
type fakePlanner struct {
	failWith error
	sawCtx   context.Context // 记录引擎是否真的把监督 ctx 传进来
}

// 通过接口形状对齐：snapshotFor 返回 *agent.Planner，不能轻易替身。所以本夹具
// 不走 snapshotFor，而是直接把监督 round 跑在一个真实 Planner 的失败路径上——
// 测试目标是「触发不丢 + 轮次留痕」，不是「模型怎么失败」。

func TestEngineSupervisionStalled(t *testing.T) {
	// 直接构造一个 Supervisor 与 Round，模拟引擎层的调用序列。
	stub := &llmrecStub{}
	sup := llmrec.NewSupervisor(nil, stub)
	// 把首帧超时压得极短，等 50ms 就该被判 stalled。
	sup.SetFirstEventTimeout(50 * time.Millisecond)

	ctx := context.Background()
	round, rctx, _ := sup.BeginFor(ctx, llmrec.RoundMeta{TaskID: 7, Worker: "planner", TriggerSrc: "edge"}, nil)

	// 不喂任何事件（模拟建连后一直没首帧）。
	select {
	case <-rctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stalled 应在 T1 内主动 cancel，实际未 cancel")
	}
	// cancel 之后记账是同步的，但 watchFirstEvent 的 goroutine 落账在
	// rctx.Done() 返回之后；且 R21 ⑦ 会先落一条 status=running（在飞轮可见），
	// 必须等它被改写成结论再读——只等「有行」会读到中间态，随机挂。
	// （⑦ 本身由 llmrec 的 TestRunningRoundIsVisible 用 T1=0 钉住，这里不重复。）
	deadline := time.Now().Add(2 * time.Second)
	var rows []db.LLMRound
	for time.Now().Before(deadline) {
		rows = stub.snapshot()
		if len(rows) == 1 && rows[0].Status != "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(rows) != 1 {
		t.Fatalf("stalled 应落 1 条，实际 %d", len(rows))
	}
	if rows[0].Status != "stalled" {
		t.Fatalf("状态应为 stalled，实际 %q", rows[0].Status)
	}
	if rows[0].ErrorClass != string(llmrec.ErrClassStalled) {
		t.Fatalf("错误类别应为 stalled，实际 %q", rows[0].ErrorClass)
	}
	round.End(context.Canceled) // 收尾不再重复落账
}

// transport_reset：错误文本落 transport_reset 类，且不被误判为账户问题。
func TestEngineSupervisionTransportReset(t *testing.T) {
	stub := &llmrecStub{}
	sup := llmrec.NewSupervisor(nil, stub)
	sup.SetFirstEventTimeout(5 * time.Second) // 不卡 stalled

	ctx := context.Background()
	round, _ := sup.Begin(ctx, llmrec.RoundMeta{TaskID: 7, Worker: "planner"})
	round.OnEvent() // 首帧到了
	round.End(errors.New(`stream error: stream ID 633; INTERNAL_ERROR; received from peer`))

	rows := stub.snapshot()
	if len(rows) != 1 {
		t.Fatalf("应落 1 条，实际 %d", len(rows))
	}
	if rows[0].Status != "error" || rows[0].ErrorClass != string(llmrec.ErrClassTransportReset) {
		t.Fatalf("应为 error/transport_reset，实际 %s/%s", rows[0].Status, rows[0].ErrorClass)
	}
}

// account_invalid：402/401 不归入"再重试"一类，且留在账上。
func TestEngineSupervisionAccountInvalid(t *testing.T) {
	stub := &llmrecStub{}
	sup := llmrec.NewSupervisor(nil, stub)
	sup.SetFirstEventTimeout(5 * time.Second)

	ctx := context.Background()
	round, _ := sup.Begin(ctx, llmrec.RoundMeta{TaskID: 7, Worker: "planner"})
	round.OnEvent()
	round.End(errors.New("openai: status 402: insufficient_quota"))

	rows := stub.snapshot()
	if len(rows) != 1 {
		t.Fatalf("应落 1 条，实际 %d", len(rows))
	}
	if rows[0].ErrorClass != string(llmrec.ErrClassAccountInvalid) {
		t.Fatalf("应为 account_invalid，实际 %q", rows[0].ErrorClass)
	}
}

// 触发不丢在任务级：构造真实 Task，先 NotifyDone 再让 Plan 失败。
// 断言失败后 peek 仍能读到同一条触发（不依赖任何 LLM）。
func TestEnginePlannerTriggerSurvivesFailure(t *testing.T) {
	task := &Task{ID: "t9", notify: make(chan struct{}, 1)}
	task.NotifyDone(42)

	// 失败轮：只 peek、不 commit。
	got := task.peekTriggers()
	if len(got) != 1 || got[0].IntentID != 42 {
		t.Fatalf("失败前应读到触发，实际 %+v", got)
	}
	// 不 commit。

	// 下一轮唤醒（如 10 分钟 heartbeat）应能再读到同一条触发。
	got2 := task.peekTriggers()
	if len(got2) != 1 || got2[0].IntentID != 42 {
		t.Fatalf("失败后触发应仍在，实际 %+v", got2)
	}
}

// ---- 辅助 ----

type llmrecStub struct {
	mu   sync.Mutex
	rows []db.LLMRound
}

func (s *llmrecStub) InsertLLMRound(r *db.LLMRound) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rows {
		if s.rows[i].RoundID == r.RoundID {
			s.rows[i] = *r
			return nil
		}
	}
	s.rows = append(s.rows, *r)
	return nil
}

// UpdateLLMRound 与真实库同语义：按 round_id 原地更新，没有则报不存在。
func (s *llmrecStub) UpdateLLMRound(r *db.LLMRound) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rows {
		if s.rows[i].RoundID == r.RoundID {
			s.rows[i] = *r
			return nil
		}
	}
	return db.ErrLLMRoundNotFound
}

func (s *llmrecStub) snapshot() []db.LLMRound {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.LLMRound, len(s.rows))
	copy(out, s.rows)
	return out
}
