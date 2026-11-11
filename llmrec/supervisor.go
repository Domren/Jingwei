package llmrec

import (
	"context"
	"fmt"
	"iter"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/norma/llm"
)

// 监督者（R21 §5.4）：把「进程在不在」升级成「LLM 在不在干活」。
//
// 两件事：
//   - L1 首帧超时：建连后 T1 内没有首个流事件，主动 cancel 并记 stalled。
//     这是新增的那把刀——现有 15 分钟墙钟给 thinking 模型留的宽口子不能用来判卡。
//   - L2 轮次留痕：每轮一定有 status/error_class/attempts/trigger_src，失败也落，
//     不靠 llm_record 开关（那是 R15 的账）。
//
// 用法：
//
//	sup := NewSupervisor(recorder, pg)
//	round := sup.Begin(ctx, meta)   // 开一轮，返回监督 context
//	defer round.End(nil)             // 结束；失败传 err
//	round.OnEvent()                  // 每个流事件回调一次（喂首帧时间）
type Supervisor struct {
	pg       dbInterface
	recorder *Recorder
	// T1 与 stalledRounds 从 env 读一次，便于夹具固定。
	firstEventTimeout time.Duration
	stalledRounds     int
}

// dbInterface 是 db.DB 的最小面：本层只需要 InsertLLMRound。测试用 stub。
type dbInterface interface {
	InsertLLMRound(r *db.LLMRound) error
}

// NewSupervisor 构造；pg 为 nil 时只监督、不记账（用于无库场景）。
func NewSupervisor(rec *Recorder, pg dbInterface) *Supervisor {
	return &Supervisor{pg: pg, recorder: rec,
		firstEventTimeout: FirstEventTimeout(), stalledRounds: DefaultStalledRounds}
}

// SetFirstEventTimeout 给夹具用：把 T1 压到毫秒级。生产代码不改它。
func (s *Supervisor) SetFirstEventTimeout(d time.Duration) { s.firstEventTimeout = d }

// SetStalledRounds 同上：把"连续 N 轮零进展"阈值压低。
func (s *Supervisor) SetStalledRounds(n int) { s.stalledRounds = n }

var roundSeq atomic.Int64

// newRoundID 生成一轮的标识（同进程内唯一；重试共用一个）。
func newRoundID() string {
	return fmt.Sprintf("r-%d-%d", time.Now().UnixNano(), roundSeq.Add(1))
}

// RoundMeta 是一轮的元数据；不改变轮内容的字段都放这里。
type RoundMeta struct {
	RoundID     string
	TaskID      int64
	Worker      string
	Model       string
	ProfileName string
	Attempts    int
	TriggerSrc  string
}

// Round 是一轮调用的监督句柄。
// Round 同时是 llmrec 侧的一轮句柄和 agent.FirstEventObserver 的实现者。
// 这里刻意不 import agent（llmrec 是底层包）：接口对齐靠编译期断言。
var _ interface{ OnEvent() } = (*Round)(nil)

type Round struct {
	sup     *Supervisor
	meta    RoundMeta
	started time.Time

	mu           sync.Mutex
	firstEventAt time.Time
	ended        bool
	cancel       context.CancelFunc
	cancelCtx    context.Context
}

// Begin 开一轮，返回监督 context（含主动 cancel）。调用方拿到 ctx 后正常发调用；
// 若 T1 内没等到首帧，Round 会主动 cancel 这个 ctx，调用方的流被切断并落到
// ErrClassTimeout。
func (s *Supervisor) Begin(ctx context.Context, meta RoundMeta) (*Round, context.Context) {
	if meta.RoundID == "" {
		meta.RoundID = newRoundID()
	}
	r := &Round{sup: s, meta: meta, started: time.Now()}
	r.cancelCtx, r.cancel = context.WithCancel(ctx)
	if s.firstEventTimeout > 0 {
		go r.watchFirstEvent()
	}
	return r, r.cancelCtx
}

// BeginFor 在一轮里同时给监督 context 和首帧观测 provider。这样 L1 的
// "首个流事件时刻"不是凭调用方自觉回调，而是从流本身取——流不到,观察者就不响。
// WrapFirstEvent 在 agent 包（底层观测器），llmrec 不反向依赖 agent。
func (s *Supervisor) BeginFor(ctx context.Context, meta RoundMeta, inner llm.Provider) (*Round, context.Context, llm.Provider) {
	r, rctx := s.Begin(ctx, meta)
	return r, rctx, r.WrapProvider(inner)
}

// WrapProvider 给 provider 套首帧观测；单独成方法，便于夹具绕开。
func (r *Round) WrapProvider(inner llm.Provider) llm.Provider {
	if inner == nil {
		return inner
	}
	return &firstEventProvider{inner: inner, r: r}
}

// watchFirstEvent 每 2s 检查一次首帧；超过 T1 没见就 cancel。检查而不是一次
// AfterFunc，是为了在 Round.End 后能立即停掉这条 goroutine（不会误伤晚到的首帧）。
//
// 轮询间隔取 T1 的 1/20（下限 25ms，上限 2s）：夹具把 T1 压到几十毫秒时
// 也能在合理时间内触发，生产默认 45s 时轮询间隔仍是 2s，不增加开销。
func (r *Round) watchFirstEvent() {
	interval := r.sup.firstEventTimeout / 20
	if interval < 25*time.Millisecond {
		interval = 25 * time.Millisecond
	}
	if interval > 2*time.Second {
		interval = 2 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-r.cancelCtx.Done():
			return
		case <-tick.C:
			r.mu.Lock()
			fired := !r.firstEventAt.IsZero()
			r.mu.Unlock()
			if fired {
				return
			}
			if time.Since(r.started) > r.sup.firstEventTimeout {
				r.cancel()
				// stalled 也要落账；Attempts 取当前值，trigger_src 保留。
				r.record(context.Canceled, ErrClassStalled)
				return
			}
		}
	}
}

// firstEventProvider 包装一层 provider：每个流事件回调 Round.OnEvent，
// 首次即喂首帧时间戳；后续不再重复记。放在 llmrec 是因为这层只依赖 llm.Provider。
type firstEventProvider struct {
	inner llm.Provider
	r     *Round
}

func (p *firstEventProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		first := true
		for ev, err := range p.inner.Stream(ctx, req) {
			if first && err == nil {
				first = false
				p.r.OnEvent()
			}
			if !yield(ev, err) {
				return
			}
			if err != nil {
				return
			}
		}
	}
}

func (p *firstEventProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	msg, text, usage, err := p.inner.Complete(ctx, req)
	if err == nil {
		p.r.OnEvent()
	}
	return msg, text, usage, err
}

// OnEvent 喂给流事件：首个事件落下时间戳。
func (r *Round) OnEvent() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.firstEventAt.IsZero() {
		r.firstEventAt = time.Now()
	}
}

// End 结束一轮并记账。err 为最终错误（可为 nil）；wallErr 是上层墙钟
// （用来把「超时」与「对端流重置」区分开）。attempts 在这一轮里可能 >1。
func (r *Round) End(err error) {
	r.mu.Lock()
	if r.ended {
		r.mu.Unlock()
		return
	}
	r.ended = true
	first := r.firstEventAt
	r.mu.Unlock()
	r.cancel()
	r.recordLocked(err, first)
}

// recordLocked 在 End 之后落一条记录；stalled 的提前记账由 watchFirstEvent 做。
func (r *Round) recordLocked(err error, first time.Time) {
	class := ClassifyError(err, nil)
	status := "ok"
	if err != nil {
		status = "error"
	}
	if r.sup.pg == nil {
		return
	}
	var fe *time.Time
	if !first.IsZero() {
		fe = &first
	}
	now := time.Now()
	rec := &db.LLMRound{
		RoundID: r.meta.RoundID, TaskID: strconv.FormatInt(r.meta.TaskID, 10), Worker: r.meta.Worker,
		Model: r.meta.Model, ProfileName: r.meta.ProfileName,
		Status: status, ErrorClass: string(class),
		Attempts: r.meta.Attempts, TriggerSrc: r.meta.TriggerSrc,
		StartedAt: r.started, FirstEventAt: fe, EndedAt: &now,
	}
	_ = r.sup.pg.InsertLLMRound(rec)
}

// record 给 watchFirstEvent 用：stalled 还没等到 End，也要落账。
func (r *Round) record(err error, class ErrorClass) {
	if r.sup.pg == nil {
		return
	}
	r.mu.Lock()
	first := r.firstEventAt
	r.mu.Unlock()
	now := time.Now()
	var fe *time.Time
	if !first.IsZero() {
		fe = &first
	}
	_ = r.sup.pg.InsertLLMRound(&db.LLMRound{
		RoundID: r.meta.RoundID, TaskID: strconv.FormatInt(r.meta.TaskID, 10), Worker: r.meta.Worker,
		Model: r.meta.Model, ProfileName: r.meta.ProfileName,
		Status: "stalled", ErrorClass: string(class),
		Attempts: r.meta.Attempts, TriggerSrc: r.meta.TriggerSrc,
		StartedAt: r.started, FirstEventAt: fe, EndedAt: &now,
	})
}
