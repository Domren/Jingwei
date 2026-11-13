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
// 三件事：
//   - L1 首帧超时：建连后 T1 内没有首个流事件，主动 cancel 并记 stalled。
//   - L2 轮次留痕：每轮一定有 status/error_class/attempts/trigger_src，失败也落，
//     不靠 llm_record 开关（那是 R15 的账）。
//   - L3 零进展：连续 N 轮没有任何进展（goal met / 新意图 / 新资产 / token 变化）
//     判 stalled_task，停下来问人。判据由调用方提供「本轮是否有进展」。
//
// 十条补丁（R21 §5.1）在本文件的落点：
//
//	① 分类器新增 unreachable / upstream_5xx / model_not_found      → classify.go
//	② 告警判据与轮数无关、首轮即响                                  → 见 server/llm_health.go
//	③ RoundMeta 补 model/profile_name（由调用方填）
//	④ attempts 记本轮真实发数（BeginAttempt）
//	⑤ 失败轮退避（同一 provider 连续失败后强制等待）                → BackoffBefore
//	⑥ 轮级 token（AddUsage，End 时落库）
//	⑦ 进行中的轮可见（Begin 即落一行 status=running，End 时更新）
//	⑧ 同一轮去重记账（Round.recorded 守卫 + db 侧 upsert）
//	⑨ 逐发错误汇总（Round.AttemptClass 记每一次的形态）
//	⑩ T1 默认 75s + 两侧共用解析函数
type Supervisor struct {
	pg       dbInterface
	recorder *Recorder
	// T1 与 stalledRounds 从 env 读一次，便于夹具固定。
	firstEventTimeout time.Duration
	stalledRounds     int
}

// dbInterface 是 db.DB 的最小面：本层只需要轮的写入与更新。测试用 stub。
type dbInterface interface {
	InsertLLMRound(r *db.LLMRound) error
	UpdateLLMRound(r *db.LLMRound) error
}

// NewSupervisor 构造；pg 为 nil 时只监督、不记账（用于无库场景）。
func NewSupervisor(rec *Recorder, pg dbInterface) *Supervisor {
	return &Supervisor{pg: pg, recorder: rec,
		firstEventTimeout: FirstEventTimeout(), stalledRounds: DefaultStalledRounds}
}

// SetFirstEventTimeout 给夹具用：把 T1 压到毫秒级。生产代码不改它。
func (s *Supervisor) SetFirstEventTimeout(d time.Duration) { s.firstEventTimeout = d }

// SetStalledRounds 同上：把「连续 N 轮零进展」阈值压低。
func (s *Supervisor) SetStalledRounds(n int) { s.stalledRounds = n }

// StalledRounds 给 L3 判据读（缺口：过去只有常量与 setter，没有任何判据读它）。
func (s *Supervisor) StalledRounds() int { return s.stalledRounds }

var roundSeq atomic.Int64

// newRoundID 生成一轮的标识（同进程内唯一；重试共用同一个）。
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
type Round struct {
	sup     *Supervisor
	meta    RoundMeta
	started time.Time

	mu           sync.Mutex
	firstEventAt time.Time
	ended        bool
	recorded     bool // ⑧ 同一轮只落一次终态
	cancel       context.CancelFunc
	cancelCtx    context.Context

	// ⑥ 轮级 token：由调用方在收到 usage 时累加。
	inTokens  int
	outTokens int

	// ⑨ 逐发错误：每一发（含重试）的真实形态都留下，分类按「最后一次有意义
	// 的错误」判，而不是被最外层的 context canceled 盖掉。
	attempts  int
	lastClass ErrorClass
	classes   []string
}

// Begin 开一轮，返回监督 context（含主动 cancel）。调用方拿到 ctx 后正常发调用；
// 若 T1 内没等到首帧，Round 会主动 cancel 这个 ctx，调用方的流被切断并落到
// ErrClassTimeout。
//
// ⑦ 进行中的轮可见：Begin 即落一行 status=running（EndedAt 为空），
// 这样「有没有轮在跑、跑到哪」不必翻日志。
func (s *Supervisor) Begin(ctx context.Context, meta RoundMeta) (*Round, context.Context) {
	if meta.RoundID == "" {
		meta.RoundID = newRoundID()
	}
	if meta.Attempts < 1 {
		meta.Attempts = 1
	}
	r := &Round{sup: s, meta: meta, started: time.Now(), attempts: meta.Attempts}
	r.cancelCtx, r.cancel = context.WithCancel(ctx)
	s.insertRunning(r)
	if s.firstEventTimeout > 0 {
		go r.watchFirstEvent()
	}
	return r, r.cancelCtx
}

// BeginFor 在一轮里同时给监督 context 和首帧观测 provider。
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

// insertRunning ⑦：本轮开始时先落一行，让「在飞的轮」可见。
// 失败不影响主流程（记账是 best-effort）。
func (s *Supervisor) insertRunning(r *Round) {
	if s.pg == nil {
		return
	}
	rec := r.baseRecord()
	rec.Status = "running"
	_ = s.pg.InsertLLMRound(rec)
}

// baseRecord 组装一条轮记录的公共字段。
func (r *Round) baseRecord() *db.LLMRound {
	return &db.LLMRound{
		RoundID: r.meta.RoundID, TaskID: strconv.FormatInt(r.meta.TaskID, 10),
		Worker: r.meta.Worker, Model: r.meta.Model, ProfileName: r.meta.ProfileName,
		Attempts: r.meta.Attempts, TriggerSrc: r.meta.TriggerSrc, StartedAt: r.started,
	}
}

// watchFirstEvent 每 2s 检查一次首帧；超过 T1 没见就 cancel。检查而不是一次
// AfterFunc，是为了在 Round.End 后能立即停掉这条 goroutine（不会误伤晚到的首帧）。
//
// 轮询间隔取 T1 的 1/20（下限 25ms，上限 2s）：夹具把 T1 压到几十毫秒时
// 也能在合理时间内触发，生产默认 75s 时轮询间隔仍是 2s，不增加开销。
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
				// ⑨ 这次的形态是 stalled，先记进逐发清单再取消。
				r.noteAttemptClass(ErrClassStalled)
				r.cancel()
				// ⑧ 用统一的终态落库路径，避免「先落 stalled 再落 error」两行。
				r.finish(context.Canceled, ErrClassStalled)
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
		// ⑥ 流式路径的 usage 折算：message_start 只带输入侧、message_delta 只带
		// 输出侧，必须 Add 折叠（口径与 Recorder 一致）。此前这里只喂首帧、不折
		// token，导致所有流式轮的 llm_rounds.input_tokens 恒为 0——「这一轮烧了
		// 多少」只能靠 llm_usage 的会话累计去猜。
		var used llm.Usage
		for ev, err := range p.inner.Stream(ctx, req) {
			if first && err == nil {
				first = false
				p.r.OnEvent()
			}
			if err == nil && (ev.Type == llm.SEMessageStart || ev.Type == llm.SEMessageDelta) {
				used.Add(ev.Usage)
			}
			// 终态错误必须先折 usage 再交给消费方：调用方拿到 error 就会立刻
			// End() 落库，晚一步折的 token 就丢了（实测失败轮 token 全 0）。
			if err != nil {
				p.r.AddUsage(used.InputTokens, used.OutputTokens)
				if !yield(ev, err) {
					return
				}
				return
			}
			if !yield(ev, err) {
				p.r.AddUsage(used.InputTokens, used.OutputTokens)
				return
			}
		}
		p.r.AddUsage(used.InputTokens, used.OutputTokens)
	}
}

func (p *firstEventProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	msg, text, usage, err := p.inner.Complete(ctx, req)
	if err == nil {
		p.r.OnEvent()
	}
	p.r.AddUsage(usage.InputTokens, usage.OutputTokens)
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

// AddUsage ⑥ 累加本轮消耗的 token。流式调用结束时应由调用方回报；
// 多次重试时累加（重试也花钱）。
func (r *Round) AddUsage(in, out int) {
	if in == 0 && out == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inTokens += in
	r.outTokens += out
}

// BeginAttempt ④ 记一次实际发出（含同 provider 重试）。
//
// 语义：Begin 之后这一轮已经发了第 1 次，所以每次**重试前**调用本方法表示
// 「还要再发一次」。返回值是即将开始的这一次的序号（第 2 次、第 3 次…）。
func (r *Round) BeginAttempt() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts++
	return r.attempts
}

// Attempts 返回当前已发次数（供调用方与夹具读）。
func (r *Round) Attempts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempts
}

// NoteAttemptError ⑨ 记下这一发的真实错误形态。
// 调用方在每次重试前调用，把「内层遇到的 429/502/504」留下来——
// 否则重试成功后这些原因就消失了，最终只剩一个 context canceled。
func (r *Round) NoteAttemptError(err error) {
	if err == nil {
		return
	}
	r.noteAttemptClass(ClassifyError(err, nil))
}

func (r *Round) noteAttemptClass(class ErrorClass) {
	if class == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastClass = class
	r.classes = append(r.classes, string(class))
}

// AttemptClasses 返回逐发错误形态（按发生顺序）。
func (r *Round) AttemptClasses() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.classes...)
}

// End 结束一轮并记账。err 为最终错误（可为 nil）。
func (r *Round) End(err error) {
	r.mu.Lock()
	already := r.ended
	r.mu.Unlock()
	if already {
		return
	}
	r.cancel()
	r.finish(err, "")
}

// finish 是唯一的终态落库路径（⑧）：先到者写，后到者丢弃。
// forced 非空时用它作为分类（stalled 路径显式指定）。
func (r *Round) finish(err error, forced ErrorClass) {
	r.mu.Lock()
	if r.recorded {
		r.mu.Unlock()
		return
	}
	r.recorded = true
	r.ended = true
	first := r.firstEventAt
	attempts := r.attempts
	in, out := r.inTokens, r.outTokens
	recorded := append([]string{}, r.classes...)
	last := r.lastClass
	r.mu.Unlock()

	class := forced
	if class == "" {
		class = ClassifyError(err, nil)
	}
	// ⑨ 最终错误常常是被包装过的 context.Canceled / context.DeadlineExceeded，
	// 而内层真实原因（429/502）只留在逐发清单里。这时以「最后一次有意义的
	// 错误」为准，避免同一次故障先记 rate_limited 又记 other。
	if class == ErrClassOther && last != "" && last != ErrClassOther {
		class = last
	}
	// 我们自己 cancel 出来的 Canceled：如果逐发里已有明确的传输/限流形态，用它；
	// 否则归 stalled 之外的 timeout 语义不成立，仍留 other 并保留逐发清单。
	if class == ErrClassOther && err != nil && len(recorded) > 0 {
		for i := len(recorded) - 1; i >= 0; i-- {
			if recorded[i] != string(ErrClassOther) {
				class = ErrorClass(recorded[i])
				break
			}
		}
	}

	status := "ok"
	if err != nil || forced != "" {
		status = "error"
	}
	if forced == ErrClassStalled {
		status = "stalled"
	}

	if r.sup.pg == nil {
		return
	}
	rec := r.baseRecord()
	rec.Status = status
	rec.ErrorClass = string(class)
	rec.Attempts = attempts
	rec.InputTokens = in
	rec.OutputTokens = out
	rec.AttemptClasses = recorded
	if !first.IsZero() {
		fe := first
		rec.FirstEventAt = &fe
	}
	now := time.Now()
	rec.EndedAt = &now
	// 先尝试更新（Begin 已插入 running 行）；没有可更新的行再插入。
	// 这样同一 round_id 永远只有一行（⑧）。
	if err := r.sup.pg.UpdateLLMRound(rec); err != nil {
		_ = r.sup.pg.InsertLLMRound(rec)
	}
}

// BackoffBefore ⑤ 失败轮退避：同一端点连续失败后，下一次唤醒必须等够时间，
// 否则「失败轮不 commit 触发」会让唤醒条件立刻再次成立，规划循环变成对
// 坏端点的持续轰击（实测每 20–30 秒一整轮）。
//
// 返回建议等待时长（0 表示不用等）。判据用「连续失败轮数」，与 total 无关，
// 所以端点一坏就能立刻生效（缺口②的另一半）。
func BackoffBefore(consecutiveFailures int) time.Duration {
	switch {
	case consecutiveFailures <= 0:
		return 0
	case consecutiveFailures == 1:
		return 5 * time.Second
	case consecutiveFailures == 2:
		return 15 * time.Second
	case consecutiveFailures == 3:
		return 45 * time.Second
	default:
		// 封顶 2 分钟：再久会让「端点恢复后仍要等」变得难以察觉。
		return 2 * time.Minute
	}
}

// Converged 是 L3 判据的输入：本轮有没有任何进展。
// 任一为真即算有进展——目标判定、新意图、新资产、实质 token 消耗。
type Progress struct {
	GoalMet   int
	NewIntent int
	NewAsset  int
}

// Converged 判断这一轮是否有进展。
func (p Progress) Converged() bool {
	return p.GoalMet > 0 || p.NewIntent > 0 || p.NewAsset > 0
}

// StalledTask 判断是否该判「无声停摆」并停下来问人。
// 只在「连续 N 轮零进展」时为真；中途有任何进展就清零。
func StalledTask(consecutiveNoProgress, threshold int) bool {
	if threshold <= 0 {
		threshold = DefaultStalledRounds
	}
	return consecutiveNoProgress >= threshold
}
