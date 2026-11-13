package llmrec

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// R21 §5.4 ⑦ 判据反向验证：夹具必须能人造三种故障，并断言「被检出 → 按类处置 →
// 留痕进 llm_round」。这里只测本层的三个独立面；流水线的端到端红由 engine 侧夹具覆盖。

// ---- 分类器 ----

func TestClassifyErrorTransportReset(t *testing.T) {
	err := errors.New(`stream error: stream ID 633; INTERNAL_ERROR; received from peer`)
	if got := ClassifyError(err, nil); got != ErrClassTransportReset {
		t.Fatalf("流重置应判 transport_reset，实际 %q", got)
	}
}

func TestClassifyErrorAccountInvalid(t *testing.T) {
	err := errors.New(`openai: status 402: insufficient_quota`)
	if got := ClassifyError(err, nil); got != ErrClassAccountInvalid {
		t.Fatalf("402 应判 account_invalid，实际 %q", got)
	}
}

func TestClassifyErrorRateLimited(t *testing.T) {
	err := errors.New(`status 429: rate limit exceeded`)
	if got := ClassifyError(err, nil); got != ErrClassRateLimited {
		t.Fatalf("429 应判 rate_limited，实际 %q", got)
	}
}

func TestClassifyErrorTimeoutTakesPriority(t *testing.T) {
	// 我们自己 cancel 的墙钟要识别为 timeout，而不是从对端错误里猜。
	err := errors.New("connection reset")
	if got := ClassifyError(err, context.DeadlineExceeded); got != ErrClassTimeout {
		t.Fatalf("墙钟超时应优先于文本分类，实际 %q", got)
	}
}

func TestClassifyErrorNilIsEmpty(t *testing.T) {
	if got := ClassifyError(nil, nil); got != "" {
		t.Fatalf("无错误应为空类别，实际 %q", got)
	}
}

// ---- 监督者 ----

// stubDB 收集写入的轮记录。
type stubDB struct {
	mu   sync.Mutex
	rows []db.LLMRound
}

func (s *stubDB) InsertLLMRound(r *db.LLMRound) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 与真实库的 ON CONFLICT 同语义：同一 round_id 只一行。
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
func (s *stubDB) UpdateLLMRound(r *db.LLMRound) error {
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

func (s *stubDB) snapshot() []db.LLMRound {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.LLMRound, len(s.rows))
	copy(out, s.rows)
	return out
}

// 堵死首帧的情况：T1 一过，Round 应主动 cancel 上下文，且落一条 stalled 记录。
func TestSupervisorStalled(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)
	sup.firstEventTimeout = 80 * time.Millisecond // 夹具等不了 45s

	ctx := context.Background()
	round, rctx := sup.Begin(ctx, RoundMeta{TaskID: 1, Worker: "planner", Model: "m"})

	// 模拟：一直没有流事件进来。
	<-rctx.Done() // 应被主动 cancel
	// 等记账完成（watchFirstEvent 在 cancel 后把 running 行改写成 stalled）。
	// R21 ⑦ 会在 Begin 时先落一条 status=running（在飞轮可见），只等「有行」会
	// 读到中间态；⑦ 本身由 TestRunningRoundIsVisible 用 T1=0 钉住，这里只等结论。
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
		t.Fatalf("stalled 应落一条记录，实际 %d 条", len(rows))
	}
	if rows[0].Status != "stalled" {
		t.Fatalf("状态应为 stalled，实际 %q", rows[0].Status)
	}
	if rows[0].ErrorClass != string(ErrClassStalled) {
		t.Fatalf("错误类别应为 stalled，实际 %q", rows[0].ErrorClass)
	}
	round.End(context.Canceled) // 收尾不再重复记账
}

// 正常一轮：首帧到达后不再 cancel，End 落一条 ok 记录。
func TestSupervisorHealthyRound(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)
	sup.firstEventTimeout = 200 * time.Millisecond

	ctx := context.Background()
	round, rctx := sup.Begin(ctx, RoundMeta{TaskID: 1, Worker: "planner", Model: "m"})
	round.OnEvent()                    // 首帧
	time.Sleep(250 * time.Millisecond) // 等过 T1
	if err := rctx.Err(); err != nil {
		t.Fatalf("首帧已到，不应被主动 cancel：%v", err)
	}
	round.End(nil)

	rows := stub.snapshot()
	if len(rows) != 1 {
		t.Fatalf("应落一条 ok 记录，实际 %d 条", len(rows))
	}
	if rows[0].Status != "ok" {
		t.Fatalf("状态应为 ok，实际 %q", rows[0].Status)
	}
}

// 失败轮也要落账（不靠录制开关），并带错误类别。
func TestSupervisorRecordsFailureRound(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)

	ctx := context.Background()
	round, _ := sup.Begin(ctx, RoundMeta{TaskID: 1, Worker: "worker", Model: "m", Attempts: 2})
	round.OnEvent()
	round.End(errors.New(`stream error: stream ID 633; INTERNAL_ERROR`))

	rows := stub.snapshot()
	if len(rows) != 1 {
		t.Fatalf("失败轮应落一条，实际 %d", len(rows))
	}
	if rows[0].Status != "error" {
		t.Fatalf("应为 error，实际 %q", rows[0].Status)
	}
	if rows[0].ErrorClass != string(ErrClassTransportReset) {
		t.Fatalf("应为 transport_reset，实际 %q", rows[0].ErrorClass)
	}
	if rows[0].Attempts != 2 {
		t.Fatalf("attempts 应保留，实际 %d", rows[0].Attempts)
	}
}

// 关掉 L1（T1<=0）时不主动 cancel，只在 End 时落账。
func TestSupervisorDisabled(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)
	sup.firstEventTimeout = 0

	ctx := context.Background()
	round, rctx := sup.Begin(ctx, RoundMeta{TaskID: 1})
	// 等远超原 T1 的时间，确认不会被主动 cancel。
	time.Sleep(120 * time.Millisecond)
	if err := rctx.Err(); err != nil {
		t.Fatalf("L1 关闭时不应主动 cancel：%v", err)
	}
	round.End(errors.New("boom"))
	rows := stub.snapshot()
	if len(rows) != 1 || rows[0].Status != "error" {
		t.Fatalf("应落一条 error，实际 %v", rows)
	}
}

// 供 stub 用：sync.Mutex 引用。
// （放在文件尾，避免与分类器部分混在一起。）
