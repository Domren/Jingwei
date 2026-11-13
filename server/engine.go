package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/jingwei/agent"
	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/intercept"
	"github.com/Autumn-27/jingwei/llmrec"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/jackc/pgx/v5/pgconn"
)

// isFKViolation reports whether err is a Postgres foreign-key violation (SQLSTATE
// 23503) — e.g. an activity insert whose exploration_id has no parent row.
func isFKViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// dropReason classifies why an activity write was dropped, so the log can be
// grouped/analysed by cause rather than by raw error text.
func dropReason(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503":
			return "fk_violation(23503,父exploration不存在)"
		case "23505":
			return "unique_violation(23505)"
		default:
			return "pg_error(" + pgErr.Code + ")"
		}
	}
	return "write_error"
}

// bumpDrop increments and returns the running count of dropped (unpersistable)
// activity records for a task. Concurrent planner + worker emits race here, so the
// counter is an atomic behind sync.Map. The count in the log shows loss scale at a
// glance instead of forcing a grep-and-count.
func (e *Engine) bumpDrop(taskID string) int64 {
	v, _ := e.dropCnt.LoadOrStore(taskID, new(int64))
	return atomic.AddInt64(v.(*int64), 1)
}

// preview collapses newlines and trims s to a short rune-safe snippet for one-line
// log output (avoids dumping a multi-KB summary/detail into the log).
func preview(s string, n int) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// model_error（provider/API 故障：LLM 层瞬时重试耗尽，或流已开始后中途断流）
// 收场的 work 不是「试过没做完」也不是真失败，而是外部抖动。默认把它当永久
// blocked 会白丢一条意图，所以这里对该终态额外重跑几次，每次之间退避一下，给
// provider 恢复的时间；重试期间若被暂停/终止/取消则立即让位给对应分支处理。
const (
	modelErrorRetries      = 2               // model_error 收场后额外重试的次数
	modelErrorRetryBackoff = 3 * time.Second // 每次重试前的退避
	workControlWaitTimeout = 30 * time.Second
)

var errWorkControlConflict = errors.New("work control conflict")

// errActivityNoStore 表示任务还没有可写的活动库（裸 Task 或探索尚未建立）。
// 记账是观测面，缺了它主流程仍要能跑完，因此这里返回可判别的错误而不是 panic。
var errActivityNoStore = errors.New("activity store not ready")

// retryableWorkerModelError excludes errors already handled by the task router.
// In particular, a quota error after partial streaming advances the task cursor
// for the next LLM call but must not replay this whole intent on the backup.
func retryableWorkerModelError(reason harness.TerminalReason, err error) bool {
	return reason == harness.ReasonModelError && !isTaskLLMRuntimeError(err)
}

// Engine drives the event-driven exploration loop with real LLM agents
// (docs §4.3/§4.4): on asset/exploration-graph change (debounced) it wakes the
// planner, which reads the route, queries assets, judges goals and emits intents;
// N concurrent work agents claim intents and execute them. There is no
// simulation mode — an LLM provider is required. The planner/worker can be
// (re)installed at runtime (LLM configured from the UI); the loops always run
// but idle until an LLM is set.
type Engine struct {
	m        *Manager
	debounce time.Duration

	bc *Broadcaster // live activity pub/sub (SSE)

	started  sync.Map // taskID -> bool, so Run is idempotent per task
	lastAct  sync.Map // taskID -> int64 unix, last planner/worker activity (heartbeat)
	llmCalls sync.Map // taskID -> *int64, actual planner/worker/main-agent LLM calls
	paused   sync.Map // taskID -> bool, user-paused (planner + workers idle but loops alive)
	deleting sync.Map // taskID -> bool, delete barrier (no new task-owned writes)
	dropCnt  sync.Map // taskID -> *int64, running count of dropped (unpersistable) activity records

	// deleteMu makes installing the delete barrier atomic with registering a new
	// task operation. Once BeginDelete returns, every admitted writer is reflected
	// in inflight and every later writer is rejected.
	deleteMu sync.RWMutex

	// Every long-lived task goroutine (planner, workers and deadline coordinator)
	// runs under one task-scoped context. Successful deletion cancels that context,
	// waits for all goroutines, then releases every task-level Engine reference.
	runtimeMu sync.Mutex
	runtimes  map[string]*taskRuntime

	// llmSup 是 R21 的监督者：首帧超时主动 cancel + 每轮留痕（llm_round）。
	// 与 e.llmCalls（「此刻有几发在飞」）不同：那个是计数，这个是判据。
	llmSup *llmrec.Supervisor

	// per-task execution context: each planner.Plan / worker.Execute runs under it,
	// so pausing can CANCEL an in-flight run (not just skip the next one). Recreated
	// on resume since cancelling is one-shot. Every cancellation carries a named
	// cause so the activity trace can identify the initiating control path.
	execMu     sync.Mutex
	execCancel map[string]context.CancelCauseFunc
	execCtx    map[string]context.Context

	// Per-work control lets the planner kill a worker and lets the UI pause/cancel
	// one intent without pausing the whole task. The done channel closes only after
	// runWorkerStep has stopped writing and committed its final state.
	workMu sync.Mutex
	work   map[int64]*workExecution

	// steerBox queues planner course-corrections for a running work (keyed by intent
	// id). The worker's PreToolUse hook drains it before its next tool call and hands
	// the message to the model (blocking that call) so it re-plans — no kill needed.
	steerMu  sync.Mutex
	steerBox map[int64][]string

	plannerRound sync.Map // taskID -> int, planner round counter (for UI round separators)

	// 任务级超时(见 docs/任务级超时与收尾设计.md):
	settling           sync.Map // taskID -> bool, 任务已进入收尾时序(停止派/领新意图)
	deadline           sync.Map // taskID -> int64 unix, 绝对截止时刻(首次运行时盖章;0/缺省=不限)
	stamped            sync.Map // taskID -> bool, first_run_at 是否已盖章(本进程内只盖一次)
	inflight           sync.Map // taskID -> *int64, 在跑的 planner.Plan + worker.Execute 计数(用于 drain)
	coordStarted       sync.Map // taskID -> bool, deadline 协调器是否已启动(Run/reload 去重)
	budgetCoordStarted sync.Map // taskID -> bool, 预算协调器是否已启动(Run/reload 去重;R19 序 4)

	// resolve returns a task's dedicated planner/worker (wired by the server as the
	// authoritative task-router). nil,nil means this task is deliberately unavailable
	// (for example an exhausted failover chain) — there is no global-pair fallback.
	resolve              func(t *Task) (*agent.Planner, *agent.Worker)
	resolveAuthoritative bool
	// readiness reports whether a global LLM provider is configured — the signal behind
	// Ready()/the llm_configured indicator. Wired once at startup; nil → not ready.
	readiness func() bool
	// llmTarget 返回该任务当前实际会用的 model 与 profile 名（R21 缺口③）。
	// 轮记录缺这两列时，事后答不出「是哪个端点废的这一轮」，只能去翻日志。
	// 由 server 层注入（它才知道 profile 链与 agent 绑定）；nil 时留空不报错。
	llmTarget func(t *Task) (model, profileName string)

	// consecutiveFail 记每个任务连续失败的规划轮数（⑤退避 与 L3 用）。
	consecutiveFail sync.Map // taskID -> *int32
	// noProgress 记连续零进展轮数（L3 判据）。
	noProgress sync.Map // taskID -> *int32
	// taskStalled 记已判过 stalled_task 的任务，避免每轮重复告警。
	taskStalled sync.Map // taskID -> bool
	// lastFailAt 记上一次失败轮的时刻（纳秒）；退避是否已等够由它算。
	lastFailAt sync.Map // taskID -> int64
	// lastProgress 记上一轮结束时的产出计数，用于「这一轮有没有新东西」。
	lastProgress sync.Map // taskID -> progressSnapshot
}

type taskRuntime struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type workExecution struct {
	cancel context.CancelCauseFunc
	done   chan error
	action string // user action: pause | cancel
}

// nextPlannerRound returns the next planner round number for a task (1-based).
func (e *Engine) nextPlannerRound(taskID string) int {
	v, _ := e.plannerRound.LoadOrStore(taskID, 0)
	n := v.(int) + 1
	e.plannerRound.Store(taskID, n)
	return n
}

// plannerRoundNo 只读当前轮号（不推进）；监督轮记录用它做 RoundID 的稳定后缀。
func (e *Engine) plannerRoundNo(taskID string) int {
	v, _ := e.plannerRound.Load(taskID)
	if v == nil {
		return 0
	}
	return v.(int)
}

// ── R21 缺口⑤②/L3：连续失败与零进展的计数 ─────────────────────────────────
//
// 这些计数只活在本进程内：进程重启后清零是对的——重启本身就是一次人工干预，
// 不该把重启前的失败序列继续算在退避里（否则「修好端点后重启」仍要被退避挡住）。

// bumpConsecutiveFail 记一次失败轮并返回连续失败数。
func (e *Engine) bumpConsecutiveFail(taskID string) int {
	v, _ := e.consecutiveFail.LoadOrStore(taskID, new(int32))
	return int(atomic.AddInt32(v.(*int32), 1))
}

// clearConsecutiveFail 在成功轮后清零。
func (e *Engine) clearConsecutiveFail(taskID string) {
	if v, ok := e.consecutiveFail.Load(taskID); ok {
		atomic.StoreInt32(v.(*int32), 0)
	}
}

// consecutiveFailures 读当前连续失败数。
func (e *Engine) consecutiveFailures(taskID string) int {
	if v, ok := e.consecutiveFail.Load(taskID); ok {
		return int(atomic.LoadInt32(v.(*int32)))
	}
	return 0
}

// plannerBackoff 返回本轮失败后应当等待的时长（⑤）。
//
// 除了连续失败序列决定的退避，还要保证「退避期内的心跳唤醒不消耗 LLM 调用」：
// 心跳默认每 10 分钟一次，而退避最长 2 分钟，所以只要退避在唤醒时生效即可。
// 这里返回时长，由 runRound 入口判断「距上次失败是否还没等够」。
func (e *Engine) plannerBackoff(taskID string, consecutive int) time.Duration {
	d := llmrec.BackoffBefore(consecutive)
	if d <= 0 {
		return 0
	}
	// 记下「本轮失败发生在何时」，供下一次唤醒比对。
	e.lastFailAt.Store(taskID, time.Now().UnixNano())
	return d
}

// backoffRemaining 返回距离上次失败还需要等多久（0 表示可以立刻跑）。
func (e *Engine) backoffRemaining(taskID string) time.Duration {
	v, ok := e.lastFailAt.Load(taskID)
	if !ok {
		return 0
	}
	need := llmrec.BackoffBefore(e.consecutiveFailures(taskID))
	if need <= 0 {
		return 0
	}
	elapsed := time.Since(time.Unix(0, v.(int64)))
	if elapsed >= need {
		return 0
	}
	return need - elapsed
}

// noteProgress 实现 L3（§5.4 ①）：连续 N 轮零进展 → stalled_task。
//
// 「进展」的定义是「有新东西落库」而不是「进程还活着」：目标判定、新意图、
// 新资产、新漏洞任一发生即算。这样长任务只要还有产出就不会被打断，
// 而卡死的任务一定会被逮到——这正是 §4.2 那次「5 小时 48 分无人发现」的反面。
func (e *Engine) noteProgress(t *Task, reason string, met bool) {
	if met {
		e.clearNoProgress(t.ID)
		return
	}
	// 本轮有没有产出：拿意图/资产/发现的当前数与上一轮记的比。
	cur := e.progressSnapshot(t)
	prev, had := e.lastProgress.Load(t.ID)
	e.lastProgress.Store(t.ID, cur)
	if had && cur.newerThan(prev.(progressSnapshot)) {
		e.clearNoProgress(t.ID)
		return
	}
	if !had {
		// 第一轮只建立基线，不算零进展。
		return
	}
	n := e.bumpNoProgress(t.ID)
	threshold := llmrec.DefaultStalledRounds
	if e.llmSup != nil {
		threshold = e.llmSup.StalledRounds()
	}
	if !llmrec.StalledTask(n, threshold) {
		return
	}
	// 只告警一次，避免每轮都刷。
	if _, loaded := e.taskStalled.LoadOrStore(t.ID, true); loaded {
		return
	}
	log.Printf("[planner] task %s 连续 %d 轮零进展，判为 stalled_task（阈值 %d）", t.ID, n, threshold)
	e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("连续 %d 轮规划没有任何进展（无目标判定、无新意图、无新资产），已停下等待人工确认", n)})
}

// progressSnapshot 是一轮结束时的产出计数，用于判断「这一轮有没有新东西」。
type progressSnapshot struct {
	goalsMet  int
	intents   int
	assets    int
	findings  int
	collected int64
}

// newerThan 判断当前快照是否比上一轮有进展。任一计数增长即算有进展。
func (p progressSnapshot) newerThan(q progressSnapshot) bool {
	return p.goalsMet > q.goalsMet || p.intents > q.intents ||
		p.assets > q.assets || p.findings > q.findings || p.collected > q.collected
}

// progressSnapshot 读当前任务的产出计数（best-effort：读不到就用 0，
// 只影响「有没有进展」的判定灵敏度，不影响主流程）。
func (e *Engine) progressSnapshot(t *Task) progressSnapshot {
	var s progressSnapshot
	if t == nil || t.Store == nil {
		return s
	}
	if n, err := t.Store.CountGoalsMet(); err == nil {
		s.goalsMet = n
	}
	if n, err := t.Store.CountIntents(); err == nil {
		s.intents = n
	}
	if e.m != nil && e.m.pg != nil && t.ID != "" {
		if id, err := strconv.ParseInt(t.ID, 10, 64); err == nil {
			if n, err := e.m.pg.CountTaskAssets(id); err == nil {
				s.assets = n
			}
			if n, err := e.m.pg.CountTaskFindings(id); err == nil {
				s.findings = n
			}
		}
	}
	return s
}

func (e *Engine) bumpNoProgress(taskID string) int {
	v, _ := e.noProgress.LoadOrStore(taskID, new(int32))
	return int(atomic.AddInt32(v.(*int32), 1))
}

func (e *Engine) clearNoProgress(taskID string) {
	if v, ok := e.noProgress.Load(taskID); ok {
		atomic.StoreInt32(v.(*int32), 0)
	}
	e.taskStalled.Delete(taskID)
}

// Pause stops a task: marks it paused AND cancels any in-flight planner/worker run
// for it (a long worker.Execute would otherwise keep going until it finishes).
func (e *Engine) Pause(taskID string, cause error) {
	e.paused.Store(taskID, true)
	e.cancelExec(taskID, cause)
}

// BeginDelete installs an execution barrier before task data/files are removed.
// The temporary pause is not a user pause. The server serializes this transition
// with lifecycle admission and tells AbortDelete whether the persisted task is
// paused/queued if cleanup fails.
func (e *Engine) BeginDelete(taskID string) bool {
	e.deleteMu.Lock()
	if _, loaded := e.deleting.LoadOrStore(taskID, true); loaded {
		e.deleteMu.Unlock()
		return false
	}
	e.paused.Store(taskID, true)
	e.deleteMu.Unlock()
	e.cancelExec(taskID, agent.AbortTaskDeleted)
	return true
}

func (e *Engine) AbortDelete(taskID string, keepPaused bool) {
	e.deleteMu.Lock()
	if !e.IsDeleting(taskID) {
		e.deleteMu.Unlock()
		return
	}
	e.deleting.Delete(taskID)
	if !keepPaused {
		e.paused.Delete(taskID)
	}
	e.deleteMu.Unlock()
	if !keepPaused && e.m != nil {
		if t, ok := e.m.Task(taskID); ok {
			t.Notify()
		}
	}
}

func (e *Engine) IsDeleting(taskID string) bool {
	_, ok := e.deleting.Load(taskID)
	return ok
}

// registerTaskRoutines reserves count goroutines in the task runtime. Callers
// hold deleteMu for reading so StopTask cannot race WaitGroup.Add with Wait.
func (e *Engine) registerTaskRoutines(parent context.Context, taskID string, count int) *taskRuntime {
	e.runtimeMu.Lock()
	defer e.runtimeMu.Unlock()
	rt := e.runtimes[taskID]
	if rt == nil {
		ctx, cancel := context.WithCancel(parent)
		rt = &taskRuntime{ctx: ctx, cancel: cancel}
		e.runtimes[taskID] = rt
	}
	rt.wg.Add(count)
	return rt
}

func runTaskRoutine(rt *taskRuntime, fn func(context.Context)) {
	go func() {
		defer rt.wg.Done()
		fn(rt.ctx)
	}()
}

// StopTask permanently stops every long-lived goroutine and removes all Engine
// state for a successfully deleted task. The delete barrier remains installed
// until cleanup finishes, so no new task operation can race the teardown.
func (e *Engine) StopTask(taskID string) {
	e.deleteMu.Lock()
	e.deleting.Store(taskID, true)
	e.deleteMu.Unlock()

	e.cancelExec(taskID, agent.AbortTaskDeleted)
	e.runtimeMu.Lock()
	rt := e.runtimes[taskID]
	if rt != nil {
		rt.cancel()
	}
	e.runtimeMu.Unlock()
	if rt != nil {
		rt.wg.Wait()
	}

	e.execMu.Lock()
	if cancel := e.execCancel[taskID]; cancel != nil {
		cancel(agent.AbortTaskDeleted)
	}
	delete(e.execCancel, taskID)
	delete(e.execCtx, taskID)
	e.execMu.Unlock()

	e.runtimeMu.Lock()
	if e.runtimes[taskID] == rt {
		delete(e.runtimes, taskID)
	}
	e.runtimeMu.Unlock()

	e.started.Delete(taskID)
	e.lastAct.Delete(taskID)
	e.llmCalls.Delete(taskID)
	e.paused.Delete(taskID)
	e.dropCnt.Delete(taskID)
	e.plannerRound.Delete(taskID)
	e.settling.Delete(taskID)
	e.deadline.Delete(taskID)
	e.stamped.Delete(taskID)
	e.inflight.Delete(taskID)
	e.coordStarted.Delete(taskID)
	e.deleteMu.Lock()
	e.deleting.Delete(taskID)
	e.deleteMu.Unlock()
}

// cancelExec cancels a task's current per-task exec context (any in-flight
// planner.Plan / worker.Execute), if present. Shared by Pause and the settle
// sequence's hard-drain backstop.
func (e *Engine) cancelExec(taskID string, cause error) {
	e.execMu.Lock()
	if cancel := e.execCancel[taskID]; cancel != nil {
		cancel(cause)
	}
	e.execMu.Unlock()
}

// Resume un-pauses a task and nudges a fresh planning round. The next exec under
// it gets a fresh (uncancelled) context.
func (e *Engine) Resume(t *Task) {
	// BeginDelete owns the pause barrier once deletion starts. A concurrent
	// resume must never clear it and let a planner/worker re-enter while cleanup
	// is waiting for task operations to drain.
	if t == nil {
		return
	}
	e.deleteMu.RLock()
	defer e.deleteMu.RUnlock()
	if e.IsDeleting(t.ID) {
		return
	}
	e.paused.Delete(t.ID)
	t.Notify()
}

// execContextFor returns a live per-task context derived from parent, recreating
// it if a prior pause cancelled it.
func (e *Engine) execContextFor(parent context.Context, taskID string) context.Context {
	e.execMu.Lock()
	defer e.execMu.Unlock()
	if e.IsPaused(taskID) {
		// never hand out a live context while paused (guards the claim→Execute race)
		c, cancel := context.WithCancelCause(parent)
		cancel(agent.AbortPausedRaceGuard)
		return llmrec.WithTaskID(c, taskID)
	}
	if c := e.execCtx[taskID]; c != nil && c.Err() == nil {
		return llmrec.WithTaskID(c, taskID)
	}
	c, cancel := context.WithCancelCause(parent)
	e.execCtx[taskID] = c
	e.execCancel[taskID] = cancel
	// R19 序 4 前置：给任务主链路（planner/worker）的每次 LLM 调用显式挂任务注册 id。
	// llm_usage.task_id 是 TEXT，历史上主链路行回退落的是会话解析出的探索 id 字符串
	//（会话 id 基于探索 id，与任务注册 id 不可互换），按注册 id 查每任务 token 报表会静默返空。
	return llmrec.WithTaskID(c, taskID)
}

// IsPaused reports whether a task is user-paused.
func (e *Engine) IsPaused(taskID string) bool {
	v, ok := e.paused.Load(taskID)
	return ok && v.(bool)
}

// Started reports whether the engine loops are running for a task.
func (e *Engine) Started(taskID string) bool {
	_, ok := e.started.Load(taskID)
	return ok
}

// LastActivity returns the unix time of the last planner/worker activity for a
// task (0 if none yet).
func (e *Engine) LastActivity(taskID string) int64 {
	if v, ok := e.lastAct.Load(taskID); ok {
		return v.(int64)
	}
	return 0
}

// BeginLLMCall/EndLLMCall track actual provider calls separately from the
// scheduler's task-operation counter. A task can have live loops while all of
// them are waiting for a trigger; that state must remain idle in the UI.
func (e *Engine) BeginLLMCall(taskID string) {
	v, _ := e.llmCalls.LoadOrStore(taskID, new(int64))
	atomic.AddInt64(v.(*int64), 1)
}

func (e *Engine) EndLLMCall(taskID string) {
	if v, ok := e.llmCalls.Load(taskID); ok {
		p := v.(*int64)
		if atomic.AddInt64(p, -1) <= 0 {
			atomic.StoreInt64(p, 0)
		}
	}
}

func (e *Engine) ActiveLLMCalls(taskID string) int64 {
	if v, ok := e.llmCalls.Load(taskID); ok {
		return atomic.LoadInt64(v.(*int64))
	}
	return 0
}

func (e *Engine) touch(taskID string) { e.lastAct.Store(taskID, time.Now().Unix()) }

func NewEngine(m *Manager) *Engine {
	e := &Engine{m: m, debounce: 800 * time.Millisecond, bc: NewBroadcaster(),
		execCancel: map[string]context.CancelCauseFunc{}, execCtx: map[string]context.Context{},
		work: map[int64]*workExecution{}, steerBox: map[int64][]string{},
		runtimes: map[string]*taskRuntime{}}
	if m != nil && m.pg != nil {
		e.llmSup = llmrec.NewSupervisor(nil, m.pg)
	}
	return e
}

// registerWork records the cancel for the work currently running intentID.
func (e *Engine) registerWork(intentID int64, cancel context.CancelCauseFunc) {
	e.workMu.Lock()
	e.work[intentID] = &workExecution{cancel: cancel, done: make(chan error, 1)}
	e.workMu.Unlock()
}

// detachWork removes the live control handle once Execute has returned. complete
// must be called after the final intent state write so a waiting cancel handler can
// safely delete the worker's blackboard output without racing a late write.
func (e *Engine) detachWork(intentID int64) (action string, complete func(error)) {
	e.workMu.Lock()
	run := e.work[intentID]
	if run != nil {
		delete(e.work, intentID)
		action = run.action
		run.cancel(agent.AbortWorkFinished) // release resources (no-op if already cancelled)
	}
	e.workMu.Unlock()
	e.steerMu.Lock()
	delete(e.steerBox, intentID) // drop any undelivered steering for a finished work
	e.steerMu.Unlock()
	if run == nil {
		return action, func(error) {}
	}
	return action, func(err error) { run.done <- err }
}

// ControlWork requests a user-visible pause or cancellation and waits until the
// worker has fully stopped writing. Cancellation cleanup is performed by the API
// handler after this returns; pause state is committed by runWorkerStep itself.
func (e *Engine) ControlWork(ctx context.Context, intentID int64, action string) error {
	if action != "pause" && action != "cancel" {
		return fmt.Errorf("unsupported work action %q", action)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	e.workMu.Lock()
	run := e.work[intentID]
	if run == nil {
		e.workMu.Unlock()
		return fmt.Errorf("%w: 意图 %d 当前没有运行中的 work（可能已结束或未被领取）", errWorkControlConflict, intentID)
	}
	if run.action != "" {
		e.workMu.Unlock()
		return fmt.Errorf("%w: 意图 %d 正在执行 %s 操作", errWorkControlConflict, intentID, run.action)
	}
	run.action = action
	done := run.done
	cause := error(agent.AbortWorkPausedByUser)
	if action == "cancel" {
		cause = agent.AbortWorkCancelledByUser
	}
	run.cancel(cause)
	e.workMu.Unlock()

	timer := time.NewTimer(workControlWaitTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		e.releaseWorkControl(intentID, run, action)
		return fmt.Errorf("等待意图 %d %s 收尾: %w", intentID, action, ctx.Err())
	case <-timer.C:
		e.releaseWorkControl(intentID, run, action)
		return fmt.Errorf("等待意图 %d %s 收尾: %w", intentID, action, context.DeadlineExceeded)
	}
}

// releaseWorkControl drops only this caller's reservation after its wait is
// cancelled. The work context stays cancelled; runWorkerStep recognizes the
// named cancellation cause and settles the intent into the recoverable paused
// state even if the HTTP caller has gone away.
func (e *Engine) releaseWorkControl(intentID int64, run *workExecution, action string) {
	e.workMu.Lock()
	if current := e.work[intentID]; current == run && current.action == action {
		current.action = ""
	}
	e.workMu.Unlock()
}

func transitionIntentState(store *db.ExplorationStore, intentID int64, expected, state string) error {
	return transitionIntentStateWithReason(store, intentID, expected, state, "")
}

// transitionIntentStateWithReason 是带原因的版本（1.6.2 第 3 步）。
//
// 转 blocked 时必须给出原因，否则写入口会把它降级成 unknown。调用点要尽量
// 给出**具体**原因（配额/守卫/资产丢失），给不出才留空 → unknown。
func transitionIntentStateWithReason(store *db.ExplorationStore, intentID int64, expected, state, reason string) error {
	changed, err := store.CompareAndSetIntentStateWithReason(intentID, expected, state, reason)
	if err != nil {
		return err
	}
	if !changed {
		return fmt.Errorf("%w: 意图 %d 不再是 %s 状态", db.ErrIntentStateConflict, intentID, expected)
	}
	return nil
}

// blockedReasonForError 把 worker 的失败原因归到 blocked 枚举。
//
// 这一步是「40 条原因为空」的直接修复点：旧代码只在 LLM 链耗尽时才写原因，
// 其余错误一律走泛型路径落 NULL。现在每一种都映射到一个可行动的类别——
// 运维看台账就知道该改配置、该补授权、还是该等预算。
func blockedReasonForError(err error) string {
	if err == nil {
		return db.IntentBlockedUnknown
	}
	if isTaskLLMChainExhausted(err) {
		return db.IntentBlockedLLMQuota
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "llm profile"), strings.Contains(msg, "no available fallback"),
		strings.Contains(msg, "model_not_found"), strings.Contains(msg, "unreachable"):
		return db.IntentBlockedLLMUnavailable
	case strings.Contains(msg, "out_of_scope"), strings.Contains(msg, "不在授权范围"),
		strings.Contains(msg, "not in scope"):
		return db.IntentBlockedOutOfScope
	case strings.Contains(msg, "guard"), strings.Contains(msg, "守卫"), strings.Contains(msg, "denied"):
		return db.IntentBlockedGuardDenied
	case strings.Contains(msg, "intent 必须是本任务的意图"), strings.Contains(msg, "asset"),
		strings.Contains(msg, "资产"):
		return db.IntentBlockedAssetMissing
	case strings.Contains(msg, "budget"), strings.Contains(msg, "max_tokens"), strings.Contains(msg, "轮数"):
		return db.IntentBlockedBudget
	case strings.Contains(msg, "context canceled"), strings.Contains(msg, "任务已"),
		strings.Contains(msg, "task stopped"):
		return db.IntentBlockedTaskStopped
	}
	// 归不出来的：留空 → 写入口降级为 unknown。不硬编一个像模像样的原因，
	// 那会让台账看起来完整、实际是猜的。
	return ""
}

// SteerWork queues a mid-run course-correction for the work running intentID (the
// planner's steer_work tool). The worker delivers it before its next tool call and
// re-plans — no kill. Errors if no work is currently running that intent.
func (e *Engine) SteerWork(intentID int64, msg string) error {
	if strings.TrimSpace(msg) == "" {
		return fmt.Errorf("纠偏消息不能为空")
	}
	e.workMu.Lock()
	running := e.work[intentID] != nil
	e.workMu.Unlock()
	if !running {
		return fmt.Errorf("意图 %d 当前没有运行中的 work（可能已结束或未被领取）", intentID)
	}
	e.steerMu.Lock()
	e.steerBox[intentID] = append(e.steerBox[intentID], msg)
	e.steerMu.Unlock()
	return nil
}

// drainSteer pops the oldest queued steering message for intentID (FIFO), if any.
func (e *Engine) drainSteer(intentID int64) (string, bool) {
	e.steerMu.Lock()
	defer e.steerMu.Unlock()
	q := e.steerBox[intentID]
	if len(q) == 0 {
		return "", false
	}
	msg := q[0]
	if len(q) == 1 {
		delete(e.steerBox, intentID)
	} else {
		e.steerBox[intentID] = q[1:]
	}
	return msg, true
}

// steerHooks wraps the guard's hook runner so the planner can steer a running work:
// before each tool call it drains a queued course-correction (if any) and blocks the
// call, handing the message back to the model — which re-plans its next step instead
// of running the tool. No queued message → the guard behaves exactly as before.
// 它同时负责「空转回合」的续跑，见 Stop。
type steerHooks struct {
	inner harness.HookRunner
	drain func() (string, bool)
	// nudges 是本条意图已注入的空转续跑次数，上限 limit。指针:harness 持有的是
	// steerHooks 的值拷贝，计数必须共享同一份。
	nudges *atomic.Int64
	// limit 是空转续跑的次数上限，由 Engine.emptyTurnNudgeLimit() 从「空响应重试
	// 次数」解析而来。<=0 = 不介入(用户显式关掉了这层)。
	limit int
	// stagnant 检测「同一工具+参数返回完全相同结果」的重复调用，以及结束时反复
	// 相同的正文。nil = 不启用。per-intent 新建，不跨意图共享状态。
	stagnant *stagnationDetector
	// label 形如 "worker-1 · #42"，只用于日志。
	label string
}

// 空转回合(只有思考、既无正文也无工具调用)续跑次数的默认值，与 SDK 空响应重试的
// 内置默认(norma/llm/openai.go 的 emptyResponseRetries)保持一致——两层共用同一个
// 旋钮，不配置时的行为也该对齐。解析见 Engine.emptyTurnNudgeLimit。
//
// 注意这个数是「一条意图的总量」，不是「连续几次」:harness 自身的 stopHookActive
// 已经限死了连续空转只推一次——推完那一轮若还是空转，Stop 钩子不会再被调到，run 直接
// 收场;只有真正发生过一次工具回合，配额才刷新(norma/harness/query.go:534)。所以这个
// 闸挡的是「工具 → 空转 → 推 → 工具 → 空转」这种病态循环，别让它把意图预算耗光。
const defaultEmptyTurnNudges = 2

// emptyTurnNudge 是空转回合注入的续跑指令。
//
// 这种回合在 harness 眼里是一次自然结束(stop_reason=end_turn 且无 tool_use)，五层
// LLM 重试一层都不适用——它不是错误，是模型「想完了但没动手」。SDK 的空响应重试也
// 够不着:它以「有没有 yield 过事件」判空，而思考增量本身就是事件(norma/llm/openai.go
// 的 SEThinkingDelta)，所以 thinking-only 不算空。何况那层是原样重发整个 prompt，
// 对这种由上下文形状决定的空转，重发只会让模型再想一遍。这里换成追加一条指令，让它
// 带着已经产出的思考继续，输入变了才有理由给出不同的行为。
const emptyTurnNudge = "【空转提醒】你上一轮只输出了思考过程，既没有给出正文回复，也没有调用任何工具，" +
	"这一轮等于没有产出。请直接执行你刚才想好的下一步：要么调用工具，要么给出结论文字。不要重复思考。"

// isThinkingOnlyTurn reports whether the latest assistant turn produced neither
// text nor a tool call — i.e. the model spent the whole round thinking.
func isThinkingOnlyTurn(messages []llm.Message) bool {
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role != llm.RoleAssistant {
			continue
		}
		return strings.TrimSpace(m.Text()) == "" && len(m.ToolUses()) == 0
	}
	return false
}

// steerExemptTools are persistence tools: they are the worker's only way to write
// what it already found back into the ledger. A queued steer used to block the
// next tool unconditionally, so a correction arriving right before report_finding
// silently discarded the finding. These tools always run; the steer stays queued
// and applies to the next non-write tool.
var steerExemptTools = map[string]bool{
	"report_finding":       true,
	"record_fact":          true,
	"record_intelligence":  true,
	"insert_assets":        true,
	"bind_finding_traffic": true,
}

func (h steerHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if !steerExemptTools[name] {
		if msg, ok := h.drain(); ok {
			return true, "【规划者实时纠偏】" + msg +
				"\n（这是规划者对本意图的即时指令；本次工具调用未执行，请据此调整下一步。若与你当前打算冲突，以此为准。）", nil
		}
	}
	var updated []byte
	if h.inner != nil {
		blocked, msg, up := h.inner.PreToolUse(ctx, name, input)
		if blocked {
			return true, msg, nil
		}
		updated = up
	}
	if msg, stalled := h.stagnant.checkCall(name, input); stalled {
		log.Printf("[work %s] 停滞检测：%s 使用相同参数已连续返回相同结果，拦截本次调用", h.label, name)
		return true, msg, nil
	}
	return false, "", updated
}

func (h steerHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
	h.stagnant.observeResult(name, input, result, isErr)
}

// Stop 在 guard 原有语义之上补一层「空转回合」续跑:模型只输出了思考、既没给正文
// 也没调工具时，harness 会把它当成自然结束并以空 summary 收场(query.go 的
// ReasonCompleted + asst.Text())，一条本来还没做完的意图就这样断在半路。此时注入
// 一条续跑指令，让模型带着已有思考接着走。
func (h steerHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	var (
		prevent  bool
		blocking []string
		msg      string
	)
	if h.inner != nil {
		prevent, blocking, msg = h.inner.Stop(ctx, messages)
	}
	// inner 已经决定硬停、或已经要注入自己的续跑消息 → 尊重它，不再叠加。
	if prevent || len(blocking) > 0 {
		return prevent, blocking, msg
	}
	// 结束时正文连续同质 → 先续跑一次要求换路径，超过上限硬停。limit<=0 表示用户
	// 显式关掉了「续跑」这层(与空转续跑共用同一旋钮)，此时不介入。
	if h.limit > 0 && h.stagnant != nil {
		if nudge, hard := h.stagnant.checkStop(messages); nudge != "" {
			if hard {
				log.Printf("[work %s] 停滞检测：回复连续同质且已续跑 %d 次，硬停止", h.label, stagnationNudgeLimit)
				return true, nil, nudge
			}
			log.Printf("[work %s] 停滞检测：回复连续同质，注入续跑指令", h.label)
			return false, []string{nudge}, ""
		}
	}
	// limit<=0 = 用户把「空响应重试次数」配成了 -1，即显式关掉这层。
	if h.nudges == nil || h.limit <= 0 || !isThinkingOnlyTurn(messages) {
		return prevent, blocking, msg
	}
	n := h.nudges.Add(1)
	if n > int64(h.limit) {
		log.Printf("[work %s] 空转回合(仅思考、无正文无工具)已达续跑上限 %d，放行收场", h.label, h.limit)
		return prevent, blocking, msg
	}
	log.Printf("[work %s] 空转回合(仅思考、无正文无工具)，注入续跑指令 (%d/%d)", h.label, n, h.limit)
	return false, []string{emptyTurnNudge}, ""
}

// KillWork cancels the in-flight work running intentID (planner's kill_work tool).
// The work's agent-core session honors ctx cancellation and aborts promptly.
func (e *Engine) KillWork(intentID int64) error {
	e.workMu.Lock()
	run := e.work[intentID]
	e.workMu.Unlock()
	if run == nil {
		return fmt.Errorf("意图 %d 当前没有运行中的 work（可能已结束或未被领取）", intentID)
	}
	run.cancel(agent.AbortKilledByPlanner)
	return nil
}

// Broadcaster exposes the engine's live activity pub/sub (used by the SSE handler).
func (e *Engine) Broadcaster() *Broadcaster { return e.bc }

// emitActivity persists one captured step AND fans it out to live subscribers,
// from a single point so storage and the SSE stream never diverge.
func (e *Engine) emitActivity(t *Task, r db.Activity) db.Activity {
	id, err := e.appendActivity(t, r)
	if err != nil {
		// NO LONGER SILENT: dropping a record breaks command↔result pairing in the
		// trace — a tool_use whose tool_result was lost shows as "执行中" forever, and
		// a lost 'result'/'round' record leaves the session with no summary ("无总结").
		// Everything needed to分析根因 goes into ONE error-level line: reason class,
		// summary preview, running drop count for this task, and — on the FK case — a
		// live probe of WHY the parent exploration is unreachable.
		n := e.bumpDrop(t.ID)
		diag := ""
		// On the FK-parent failure (23503) probe the live DB so the log records WHY the
		// exploration is unreachable (row gone / wrong expID) instead of just that it is.
		if isFKViolation(err) {
			storeID := t.Store.ID()
			if exists, refs, maxID, dErr := e.m.pg.ExplorationDiag(storeID); dErr != nil {
				diag = fmt.Sprintf(" | FK诊断查询失败(store.expID=%d task.ExpID=%d): %v", storeID, t.ExpID, dErr)
			} else {
				diag = fmt.Sprintf(" | FK诊断: store.expID=%d task.ExpID=%d exploration存在=%v 引用它的task数=%d MAX(exploration.id)=%d",
					storeID, t.ExpID, exists, refs, maxID)
			}
		}
		log.Printf("[activity] task %s 丢弃活动记录(该任务累计第 %d 条) worker=%s kind=%s tool=%s tuid=%s reason=%s summary=%q: %v%s",
			t.ID, n, r.Worker, r.Kind, r.Tool, r.ToolUseID, dropReason(err), preview(r.Summary, 80), err, diag)
		e.touch(t.ID)
		return r
	}
	r.ID = id
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	e.bc.Publish(t.ID, r)
	e.touch(t.ID)
	return r
}

// appendActivity persists one activity row, retrying briefly on write failure.
// Concurrent planner + worker inserts into the same exploration's activity log
// occasionally fail; a couple of quick retries recover most. Crucially, every
// failure is now LOGGED (it used to be swallowed by an `if err == nil`), so the
// underlying DB error is finally visible for diagnosis.
func (e *Engine) appendActivity(t *Task, r db.Activity) (int64, error) {
	var id int64
	var err error
	// 没有 Store 的任务（单测构造的裸 Task、或探索记录尚未建立的极早期）不该
	// 让记账路径 panic：活动只是观测面，缺了它主流程仍必须能跑完。
	// R21 的 L3 告警正是在这种「刚起、Store 还没就绪」的时刻最可能触发。
	if t == nil || t.Store == nil {
		return 0, errActivityNoStore
	}
	for attempt := 1; attempt <= 3; attempt++ {
		if id, err = t.Store.AppendActivity(r); err == nil {
			if attempt > 1 {
				log.Printf("[activity] task %s 写入第 %d 次重试成功 (worker=%s kind=%s tool=%s)",
					t.ID, attempt, r.Worker, r.Kind, r.Tool)
			}
			return id, nil
		}
		log.Printf("[activity] task %s 写入失败 (第 %d/3 次, worker=%s kind=%s tool=%s expID=%d): %v",
			t.ID, attempt, r.Worker, r.Kind, r.Tool, t.Store.ID(), err)
		time.Sleep(time.Duration(attempt) * 25 * time.Millisecond)
	}
	return 0, err
}

// SetReadiness wires the global "an LLM provider is configured" predicate (read by
// Ready() / the llm_configured indicator). Called once at startup.
func (e *Engine) SetReadiness(fn func() bool) { e.readiness = fn }

// SetLLMTargetResolver installs a resolver returning the model/profile a task
// currently runs on. Wired by the server once at startup (only it knows the
// profile chain and agent bindings). Nil → round records keep those columns empty.
func (e *Engine) SetLLMTargetResolver(fn func(t *Task) (string, string)) { e.llmTarget = fn }

// SetAgentResolver installs a per-task planner/worker resolver (wired by the server).
// Called once at startup before any task loop runs, so no lock is needed on reads.
func (e *Engine) SetAgentResolver(fn func(t *Task) (*agent.Planner, *agent.Worker)) {
	e.resolve = fn
	e.resolveAuthoritative = false
}

// SetAuthoritativeAgentResolver installs a resolver whose nil result must not
// fall through to the global provider. Task-level failover chains use this so a
// fully exhausted chain cannot silently bypass its configured boundary.
func (e *Engine) SetAuthoritativeAgentResolver(fn func(t *Task) (*agent.Planner, *agent.Worker)) {
	e.resolve = fn
	e.resolveAuthoritative = true
}

// snapshotFor returns the planner/worker a task should run on, from the task-router
// resolver. nil,nil means the task is deliberately unavailable (e.g. an exhausted
// failover chain); there is no global-pair fallback.
func (e *Engine) snapshotFor(t *Task) (*agent.Planner, *agent.Worker) {
	if e.resolve != nil {
		p, w := e.resolve(t)
		if (p != nil && w != nil) || e.resolveAuthoritative {
			return p, w
		}
	}
	return nil, nil
}

// Ready reports whether a global LLM provider is configured (via the readiness
// predicate wired at startup).
func (e *Engine) Ready() bool {
	return e.readiness != nil && e.readiness()
}

// ReadyFor reports whether a specific task can resolve a planner/worker pair.
// An explicit task profile chain can be runnable even when no global default
// provider is configured, so task status must not rely on Ready alone.
func (e *Engine) ReadyFor(t *Task) bool {
	p, w := e.snapshotFor(t)
	return p != nil && w != nil
}

// Run starts the planner loop + N worker loops for a task. The loops always run
// but no-op until an LLM is configured (so a task created while idle picks up
// automatically once LLM is set from the UI).
func (e *Engine) Run(ctx context.Context, t *Task) {
	workers := e.m.Workers()
	e.deleteMu.RLock()
	if e.IsDeleting(t.ID) {
		e.deleteMu.RUnlock()
		return
	}
	if _, loaded := e.started.LoadOrStore(t.ID, true); loaded {
		e.deleteMu.RUnlock()
		t.Notify() // already running — just nudge a planning round
		return
	}
	rt := e.registerTaskRoutines(ctx, t.ID, 1+workers)
	e.deleteMu.RUnlock()
	e.touch(t.ID)
	runTaskRoutine(rt, func(loopCtx context.Context) { e.plannerLoop(loopCtx, t) })
	for i := 0; i < workers; i++ {
		name := fmt.Sprintf("work#%d", i+1)
		runTaskRoutine(rt, func(loopCtx context.Context) { e.workerLoop(loopCtx, t, name) })
	}
	e.startDeadlineCoordinator(ctx, t) // 任务级超时定时器(仅 timeout>0;去重)
	e.startBudgetCoordinator(ctx, t)   // 任务级预算协调器(R19 序 4;仅设上限的任务;去重)
	// 仅在「完全没有活动意图(open+running)」时才 kick 首轮规划。带种子意图的任务:种子已
	// 是 open,或已被上面刚起的 worker 抢先 claim 成 running——两种都算「有活干」,一律跳过
	// 首轮 planner,worker 直接领种子意图开跑,跑完由 NotifyDone/心跳唤醒 planner。
	// ⚠️ 不能用 Frontier(只数 open):worker 领取(open→running)与本检查存在竞态,会误 kick。
	// 重启自动恢复时也可能只剩 running 意图,同样应跳过。
	if has, _ := t.Store.HasActiveIntent(); !has {
		t.Notify() // kick the first planning round (acted on once LLM is ready)
	}
}

// plannerHeartbeatInterval 解析任务的 planner 心跳间隔。db.CreateTask 已归一
// (低于 600 一律抬到 600);这里再兜一次底,防内存态异常值。
func plannerHeartbeatInterval(t *Task) time.Duration {
	sec := t.PlanHeartbeatSeconds
	if sec < db.MinPlanHeartbeatSeconds { // 下限=默认=600(10min)
		sec = db.MinPlanHeartbeatSeconds
	}
	return time.Duration(sec) * time.Second
}

// resetPlannerTimer 安全重臂一个可能已触发的 Timer(标准 Stop→drain→Reset 模式)。
func resetPlannerTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

func (e *Engine) plannerLoop(ctx context.Context, t *Task) {
	interval := plannerHeartbeatInterval(t)
	// 心跳定时器在 loop 入口臂 = 从任务 start 计时:即使是跳过首轮 planner 的 seed 任务
	// (Run 里 frontier 非空不 kick 首轮)、这里一直阻塞,心跳也会在「任务 start + interval」
	// 触发第一轮规划。之后每次唤醒(边沿/心跳)都重臂 = 距上次任意规划触发的时长。
	heartbeat := time.NewTimer(interval)
	defer heartbeat.Stop()

	// runRound 跑一轮规划(含 debounce 合并 + 各 guard)。src 仅用于日志区分触发来源。
	runRound := func(src string) {
		// debounce: coalesce a burst of changes into one planning round
		timer := time.NewTimer(e.debounce)
	drain:
		for {
			select {
			case <-t.notify:
			case <-timer.C:
				break drain
			}
		}
		planner, _ := e.snapshotFor(t)
		if planner == nil {
			return // idle until LLM configured
		}
		if e.IsPaused(t.ID) {
			return // user-paused: don't plan
		}
		if e.IsDeleting(t.ID) {
			return
		}
		// terminal task (goals all met → done, or failed): the run is over. A
		// resume/nudge — e.g. auto-resume of the active task on restart — must NOT
		// re-plan (it would burn an LLM round and re-confirm a settled result).
		if isTerminalStatus(t.lifecycleSnapshot().Status) {
			return
		}
		// 任务级超时收尾中:丢弃普通唤醒——worker 收尾写回、Resume 的 Notify 都不再
		// 触发常规规划轮;终局那一轮由协调器(settleTask)直接驱动,不走这里。
		if e.isSettling(t.ID) {
			return
		}
		// 失败退避（R21 缺口⑤）：连续失败后的这段窗口里，心跳与边沿唤醒都不该再
		// 发 LLM 调用。不放在最前面是刻意的——暂停/删除/终态这些守卫更便宜，
		// 先判它们能少打一行日志。
		if wait := e.backoffRemaining(t.ID); wait > 0 {
			log.Printf("[planner] task %s 失败退避中，剩余 %s，本轮跳过", t.ID, wait.Round(time.Second))
			return
		}
		// goalless（人工直投）分支：任务已无 open 目标时 planner 不跑——跑了会重判
		// met→cancelExec 杀掉用户经主 agent 直投的意图。是否结束改由 frontier 决定：
		// 还有 open/running 意图 → 保持 running、静默等待；意图已全部跑干 → 落 done。
		// 整段纯 Go、不触发任何 LLM 调用，也不打规划轮 marker。
		if open, err := t.Store.HasOpenGoal(); err == nil && !open {
			t.drainTriggers() // 丢弃累积的 done/finding 触发，避免 goalless 长会话里无界增长
			if active, err := t.Store.HasActiveIntent(); err == nil && !active {
				// frontier 抽干且无在跑意图 → 收尾。用 Guarded 版做 CAS，避免踩到并发的
				// pause/delete/超时收尾的状态转换。
				if won, err := e.m.SetTaskStatusGuarded(t.ID, "done"); err != nil {
					log.Printf("[goalless] task %s 收尾落 done 失败: %v", t.ID, err)
				} else if won {
					e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
						Summary: "目标已全部达成，直投意图已执行完毕，任务结束"})
				}
			}
			return // goalless 分支永不进入 planner.Plan
		}
		// R19 序 4：预算闸门的同步快查——每次真正要花 LLM 的规划轮之前先对一次上限，
		// 超限就不再发起本轮调用，把「协调器轮询窗口内白烧」夹到零。收尾时序本身
		// （写台账、终局判定、落终态）由预算协调器执行（每 30s 兑底）。
		if pg := e.m.PG(); pg != nil && (t.MaxRounds > 0 || t.MaxInputTokens > 0) {
			if cause, hit := e.budgetHit(t, pg); hit {
				log.Printf("[planner] task %s %s，跳过本轮规划，等收尾时序", t.ID, cause.label())
				return
			}
		}
		if !e.beginTaskOperation(t.ID) {
			return
		}
		defer e.decInflight(t.ID)
		e.stampFirstRun(t) // 首次真正规划 → 盖 first_run_at + 算 deadline(仅带 timeout 的任务)
		e.touch(t.ID)
		emit := func(r db.Activity) { e.emitActivity(t, r) }
		ectx := e.clockCtx(e.execContextFor(ctx, t.ID), t, false) // cancellable by Pause; 带任务 deadline
		if ectx.Err() != nil || e.IsDeleting(t.ID) {
			return
		}
		log.Printf("[planner] task %s 规划中…(%s 触发)", t.ID, src)
		// round marker: each Plan() is one planner round; emit a boundary so the
		// UI can separate rounds in the transcript (kind='round').
		e.emitActivity(t, db.Activity{Worker: "planner", Kind: "round",
			Summary: fmt.Sprintf("第 %d 轮规划", e.nextPlannerRound(t.ID))})
		// what fired this round (worker done / finding; may be several — debounce
		// coalesces a burst; empty for time/heartbeat wakes).
		triggers := t.peekTriggers()
		taskIDInt, _ := strconv.ParseInt(t.ID, 10, 64)
		e.BeginLLMCall(t.ID)
		// R21：每轮规划开一条监督 context；T1 内不见首帧主动 cancel（stalled），
		// 每轮结束无条件落 llm_round（不靠 llm_record 开关，这是 R15 的正解）。
		pctx := ectx
		var supRound *llmrec.Round
		if e.llmSup != nil {
			roundID := t.ID + "-plan-" + strconv.Itoa(e.plannerRoundNo(t.ID))
			// 缺口③：把本轮实际用的 model 与 profile 名带进轮记录。缺了这两列，
			// 事后只能翻日志才知道「是哪个端点废的这一轮」。
			model, profileName := "", ""
			if e.llmTarget != nil {
				model, profileName = e.llmTarget(t)
			}
			supRound, pctx = e.llmSup.Begin(ectx, llmrec.RoundMeta{
				RoundID: roundID, TaskID: taskIDInt, Worker: "planner", TriggerSrc: src,
				Model: model, ProfileName: profileName,
			})
			// 首帧观测：provider 被包一层，首个流事件到达会喂给 supRound，
			// 否则 T1 内没人回调，watchFirstEvent 会主动 cancel 本轮（stalled）。
			// 首帧观测：本轮调用走带观测的 provider；观测器就是监督轮本身。
			planner.SetProvider(supRound.WrapProvider(planner.Provider()))
		}
		met, reason, err := planner.Plan(pctx, taskIDInt, e.m.assets, t.Store, t.Goal, triggers, emit)
		if supRound != nil {
			supRound.End(err)
		}
		e.EndLLMCall(t.ID)
		switch {
		case err != nil && ectx.Err() == nil:
			log.Printf("[planner] task %s 规划出错: %v", t.ID, err)
			// 失败轮只读不清：触发留在 pending，等下一次唤醒重新读取（R21 ④第一条）。
			// 不 commit；下一次成功轮才会清掉。
			//
			// R21 缺口⑤：光「不丢触发」会让唤醒条件立刻再次成立，于是规划循环对着
			// 同一个坏端点每 20–30 秒轰一轮。这里记连续失败并退避，退避期内的心跳
			// 唤醒直接跳过（不消耗 LLM 调用）。
			n := e.bumpConsecutiveFail(t.ID)
			if d := e.plannerBackoff(t.ID, n); d > 0 {
				e.emitActivity(t, db.Activity{Worker: "planner", Kind: "text",
					Summary: fmt.Sprintf("规划连续失败 %d 轮，退避 %s 后重试", n, d.Round(time.Second))})
			}
		case met:
			log.Printf("[planner] task %s 判定目标达成: %s", t.ID, reason)
			e.clearConsecutiveFail(t.ID)
			// 所有目标达成 → 持久化任务状态为 done（前端 DTO 会优先展示该终态）。
			if err := e.m.SetTaskStatus(t.ID, "done"); err != nil {
				log.Printf("[planner] task %s 标记完成落库失败: %v", t.ID, err)
			}
			// 任务已判完成 → 立刻取消在跑的 worker：它们手头的意图跑出来也没意义了。
			// 下一轮 worker 循环撞终态门就不再领新意图;被取消的这批走下方"任务已完成"分支
			// 归为 stopped(而非 blocked)。
			e.cancelExec(t.ID, agent.AbortGoalMet)
		default:
			log.Printf("[planner] task %s 规划完成", t.ID)
			e.clearConsecutiveFail(t.ID)
			// 规划成功：触发已被消费，清 pending（R21 ④第一条的另一半）。
			t.commitTriggers()
			// L3（§5.4 ①）：连续 N 轮零进展 → stalled_task，停下来问人。
			// 判据用「本轮有没有任何进展」而不是「跑到第几轮」，这样长任务只要
			// 还有产出就不会被打断，卡死的任务则一定会被逮到。
			e.noteProgress(t, reason, met)
		}
		e.touch(t.ID)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.notify:
			runRound("edge") // worker 结束 / finding / kill / resume / seed 首轮
		case <-heartbeat.C:
			// 周期兜底:死锁兜底 + 唤醒去监督飞行中的 worker(steer/kill) + 周期复查。
			runRound("heartbeat")
		}
		// 每次唤醒(边沿或心跳)后重臂心跳:任意规划触发都重算这段静置计时。
		resetPlannerTimer(heartbeat, interval)
	}
}

func (e *Engine) workerLoop(ctx context.Context, t *Task, name string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, worker := e.snapshotFor(t)
		if worker == nil {
			if sleepCtx(ctx, 1500*time.Millisecond) {
				return
			}
			continue
		}
		if e.IsPaused(t.ID) {
			if sleepCtx(ctx, 1000*time.Millisecond) {
				return
			}
			continue // user-paused: don't claim/execute intents
		}
		if e.IsDeleting(t.ID) {
			return
		}
		if e.isSettling(t.ID) {
			if sleepCtx(ctx, 1000*time.Millisecond) {
				return
			}
			continue // 任务超时收尾中:不再领新意图(在跑的自行收尾,协调器等其 drain)
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			if sleepCtx(ctx, 1000*time.Millisecond) {
				return
			}
			continue // 任务已终态(done/failed/timeout):停止领取遗留意图,别在完成后空跑 frontier
		}
		if !e.beginTaskOperation(t.ID) {
			return
		}
		claimed := e.runWorkerStep(ctx, t, name, worker)
		e.decInflight(t.ID)
		if !claimed && sleepCtx(ctx, 800*time.Millisecond) {
			return
		}
	}
}

// runWorkerStep claims one intent from the frontier and fully settles it via
// runIntent. Returns false when nothing was claimable. The pool worker loop is its
// only caller.
func (e *Engine) runWorkerStep(ctx context.Context, t *Task, name string, worker *agent.Worker) bool {
	intent := e.claimNext(t, name)
	if intent == nil {
		return false
	}
	log.Printf("[worker %s] task %s 领取意图 #%d", name, t.ID, intent.ID)
	return e.runIntent(ctx, t, name, worker, intent, "", "")
}

// runIntent executes and fully settles one already-claimed (state=running) intent.
// Both the pool worker loop (via runWorkerStep) and the human-message handler (via
// runDetachedIntent, a dedicated goroutine outside the worker pool) call it, so the
// execute/retry/state-write logic lives in exactly one place. A non-empty message
// is injected as this turn's input through ExecuteWithMessage; requestID keys the
// transcript marker that dedups re-injection across model_error retries. The caller
// must already hold one task-operation admission for the whole sequence so a delete
// cannot observe quiescence between the LLM return and the final DB writes.
func (e *Engine) runIntent(ctx context.Context, t *Task, name string, worker *agent.Worker, intent *db.Node, requestID, message string) bool {
	hasChatMessage := message != ""
	e.stampFirstRun(t) // 首次真正执行 → 盖 first_run_at + 算 deadline(仅带 timeout 的任务)
	e.touch(t.ID)
	emit := func(r db.Activity) { e.emitActivity(t, r) }
	ectx := e.clockCtx(e.execContextFor(ctx, t.ID), t, false) // cancellable by Pause; 带任务 deadline
	if ectx.Err() != nil || e.IsDeleting(t.ID) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "open"); err != nil {
			log.Printf("[worker %s] task %s 意图 #%d 领取后回退失败: %v", name, t.ID, intent.ID, err)
		}
		return true
	}
	// per-work child context so the planner's kill_work can stop just this work.
	workCtx, workCancel := context.WithCancelCause(ectx)
	e.registerWork(intent.ID, workCancel)
	// wrap the guard hooks so steer_work can inject a mid-run course-correction
	// for THIS intent (drained before the worker's next tool call).
	iid := intent.ID
	taskEmit := func(a db.Activity) {
		nid := iid
		a.NodeID, a.Worker = &nid, name
		emit(a)
	}
	label := fmt.Sprintf("%s · #%d", name, iid)
	workCtx = intercept.WithTaskContext(workCtx, t.ID, label, taskEmit)
	// nudges 有意建在 model_error 重跑循环之外:空转续跑的上限是「这条意图」的总量，
	// 重跑一轮不该把额度清零重来。
	hooks := steerHooks{
		inner:    t.Guard.Hooks(),
		drain:    func() (string, bool) { return e.drainSteer(iid) },
		nudges:   &atomic.Int64{},
		limit:    e.emptyTurnNudgeLimit(),
		stagnant: newStagnationDetector(),
		label:    label,
	}
	wTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
	e.BeginLLMCall(t.ID)
	var reason harness.TerminalReason
	var wrote agent.WriteCounts
	var err error
	if hasChatMessage {
		reason, wrote, err = worker.ExecuteWithMessage(workCtx, name, wTaskID, e.m.assets, t.Store, intent, hooks, emit, e.m.enrich, t.NotifyFinding, requestID, message)
	} else {
		reason, wrote, err = worker.Execute(workCtx, name, wTaskID, e.m.assets, t.Store, intent, hooks, emit, e.m.enrich, t.NotifyFinding)
	}
	e.EndLLMCall(t.ID)
	// model_error 收场 → 额外重跑几次（退避后再试）。仅在意图仍属本 work、任务
	// 未暂停/未终止/未取消【且未进入收尾】时重试；否则让位给对应分支处理(收尾期不
	// 再重试,避免退避挤占其他 worker 的优雅收尾窗口)。
	maxRetries, retryBackoff := e.modelErrorRetryPolicy()
	for attempt := 1; attempt <= maxRetries &&
		retryableWorkerModelError(reason, err) &&
		workCtx.Err() == nil && ectx.Err() == nil && !e.IsPaused(t.ID) && !e.isSettling(t.ID); attempt++ {
		log.Printf("[worker %s] task %s 意图 #%d model_error 收场，%v 后重试 (%d/%d)",
			name, t.ID, intent.ID, retryBackoff, attempt, maxRetries)
		if sleepCtx(workCtx, retryBackoff) {
			break // 退避期间被取消（终止/暂停）→ 交给下方分支处理
		}
		e.BeginLLMCall(t.ID)
		if hasChatMessage {
			reason, wrote, err = worker.ExecuteWithMessage(workCtx, name, wTaskID, e.m.assets, t.Store, intent, hooks, emit, e.m.enrich, t.NotifyFinding, requestID, message)
		} else {
			reason, wrote, err = worker.Execute(workCtx, name, wTaskID, e.m.assets, t.Store, intent, hooks, emit, e.m.enrich, t.NotifyFinding)
		}
		e.EndLLMCall(t.ID)
	}
	// Capture kill state before detachWork cancels workCtx. kill = this work's
	// ctx was cancelled (planner kill_work) while the TASK ctx kept running; a
	// pause cancels the task ctx (ectx) instead. Checking workCtx.Err() AFTER
	// unregister would always be true (unregister cancels it) → every completed
	// work would be wrongly marked stopped.
	workCause := context.Cause(workCtx)
	killed := workCtx.Err() != nil && ectx.Err() == nil
	action, completeWork := e.detachWork(intent.ID)
	// A caller may stop waiting and release its in-memory reservation before the
	// agent honors cancellation. The named context cause remains authoritative and
	// still settles the stopped run into a recoverable state.
	if action == "" {
		switch {
		case errors.Is(workCause, agent.AbortWorkPausedByUser):
			action = "pause"
		case errors.Is(workCause, agent.AbortWorkCancelledByUser):
			action = "cancel"
		}
	}
	var controlErr error
	defer func() { completeWork(controlErr) }()
	if action == "pause" {
		controlErr = transitionIntentState(t.Store, intent.ID, "running", "paused")
		if controlErr != nil {
			log.Printf("[worker %s] task %s 意图 #%d 暂停状态落库失败: %v", name, t.ID, intent.ID, controlErr)
			return true
		}
		log.Printf("[worker %s] task %s 意图 #%d 已暂停", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	if action == "cancel" {
		// Park the stopped run in paused before handing cleanup to the API. If the
		// request disconnects after cancellation, the intent remains recoverable and
		// a later cancel can finish cleanup instead of leaving a phantom running row.
		controlErr = transitionIntentState(t.Store, intent.ID, "running", "paused")
		if controlErr != nil {
			log.Printf("[worker %s] task %s 意图 #%d 取消栅栏落库失败: %v", name, t.ID, intent.ID, controlErr)
			return true
		}
		log.Printf("[worker %s] task %s 意图 #%d 已停止，等待取消清理", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	// if a pause cancelled this run mid-flight, return the intent to the frontier
	// so it is re-claimed on resume — the worker will resume the prior LLM
	// conversation from its transcript instead of restarting from scratch.
	if ectx.Err() != nil && taskExecutionPaused(context.Cause(ectx)) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "open"); err != nil {
			log.Printf("[worker %s] task %s 意图 #%d 任务暂停回退失败: %v", name, t.ID, intent.ID, err)
		}
		return true
	}
	// 任务超时收尾的硬兜底 cancel(非 pause、非 kill)取消了本 run → 归为 exhausted(已收尾),
	// 不要误标 blocked。此时 worker 通常已在 settlement 阶段把结果写回。
	if ectx.Err() != nil && e.isSettling(t.ID) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "exhausted"); err != nil {
			log.Printf("[worker %s] task %s 意图 #%d 超时收尾状态落库失败: %v", name, t.ID, intent.ID, err)
		}
		log.Printf("[worker %s] task %s 意图 #%d 因任务超时收尾结束(exhausted)，写回 %s", name, t.ID, intent.ID, wrote)
		e.touch(t.ID)
		return true
	}
	// 任务已判完成(done via 常规路径)→ 上面 cancelExec 取消了本 run。意图结果已无意义,
	// 标 stopped(不是 blocked),别污染已完成任务的意图状态。
	if ectx.Err() != nil && isTerminalStatus(e.m.TaskStatus(t.ID)) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "stopped"); err != nil {
			log.Printf("[worker %s] task %s 意图 #%d 终态停止落库失败: %v", name, t.ID, intent.ID, err)
		}
		log.Printf("[worker %s] task %s 意图 #%d 因任务已完成而取消(stopped)", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	// killed by the planner: mark stopped (don't write back results, don't auto-reclaim).
	if killed {
		if err := transitionIntentState(t.Store, intent.ID, "running", "stopped"); err != nil {
			log.Printf("[worker %s] task %s 意图 #%d planner 停止落库失败: %v", name, t.ID, intent.ID, err)
		}
		log.Printf("[worker %s] task %s 意图 #%d 被终止(stopped)", name, t.ID, intent.ID)
		e.touch(t.ID)
		t.Notify()
		return true
	}
	if err != nil {
		log.Printf("[worker %s] intent %d: %v", name, intent.ID, err)
	}
	// terminal分流：撞步数上限 ≠ 完成。max_turns→exhausted（规划者据此知道这个方向
	// 试过但没真正做完、需换角度，而非当成已覆盖永久跳过）；出错→blocked；正常→done。
	state := "done"
	switch {
	case err != nil:
		state = "blocked"
	case reason == harness.ReasonMaxTurns:
		state = "exhausted"
		log.Printf("[worker %s] intent %d 撞步数上限(exhausted)，本次写回 %s", name, intent.ID, wrote)
	case reason == harness.ReasonTimeout:
		state = "exhausted"
		log.Printf("[worker %s] intent %d 运行超时(exhausted)，收尾后写回 %s", name, intent.ID, wrote)
	}
	// 1.6.2 第 3 步：转 blocked 必须带原因。旧代码只在 LLM 链耗尽时写原因，
	// 其余错误全走泛型路径落 NULL（实测 40 条原因全空）。
	if state == "blocked" {
		reason := blockedReasonForError(err)
		if reason == db.IntentBlockedLLMQuota {
			// 配额耗尽有专门的写入口（它会带 completed_at），沿用。
			_ = t.Store.SetIntentBlockedReason(intent.ID, reason)
		} else if stateErr := transitionIntentStateWithReason(t.Store, intent.ID, "running", state, reason); stateErr != nil {
			log.Printf("[worker %s] task %s 意图 #%d 终态 %s 落库失败: %v", name, t.ID, intent.ID, state, stateErr)
		}
	} else {
		if stateErr := transitionIntentState(t.Store, intent.ID, "running", state); stateErr != nil {
			log.Printf("[worker %s] task %s 意图 #%d 终态 %s 落库失败: %v", name, t.ID, intent.ID, state, stateErr)
		}
	}
	log.Printf("[worker %s] task %s 意图 #%d 结束: %s (写回 %s)", name, t.ID, intent.ID, state, wrote)
	e.touch(t.ID)
	t.NotifyDone(intent.ID) // results changed the graph -> wake the planner (with the just-finished intent id)
	return true
}

// runDetachedIntent runs one paused intent OUTSIDE the worker pool in its own
// goroutine — the human-message path. It transitions the intent paused->running
// itself (never through 'open'), so the pool, which only claims 'open', can never
// race it; the "at most one run per intent" invariant still holds because winning
// the CAS is the sole entry and work[intentID] was cleared when the pause settled.
// Because it does not compete for a frontier slot, a user message continues the
// worker immediately even when all pool slots are busy (mirroring how the
// main-agent chat handler starts its run directly). The spawned goroutine owns one
// task-operation admission for the whole run and roots its context at ctx (pass the
// server root, never the HTTP request, so a disconnect cannot strand the run while
// task pause/delete/shutdown still stops it). Returns an error if the run could not
// be started; the intent is left untouched in that case.
func (e *Engine) runDetachedIntent(ctx context.Context, t *Task, intentID int64, requestID, message, agentMessage string) error {
	if !e.beginTaskOperation(t.ID) {
		return fmt.Errorf("task is being deleted")
	}
	release := true
	defer func() {
		if release {
			e.decInflight(t.ID)
		}
	}()
	_, worker := e.snapshotFor(t)
	if worker == nil {
		return fmt.Errorf("worker 尚未就绪")
	}
	node, err := t.Store.GetNode(intentID)
	if err != nil {
		return err
	}
	if node == nil || node.Kind != db.KindIntent {
		return fmt.Errorf("intent not found")
	}
	changed, err := t.Store.CompareAndSetIntentState(intentID, "paused", "running")
	if err != nil {
		return err
	}
	if !changed {
		return fmt.Errorf("%w: 意图不再是 paused 状态", db.ErrIntentStateConflict)
	}
	node.State, node.Owner = "running", "chat"
	// Record the human turn as a visible activity BEFORE the run starts, so it is
	// ordered ahead of any worker step and never appears without the run happening.
	// Keep the UI copy concise; ExecuteWithMessage writes the server-resolved
	// reference snapshot into the intent transcript as the LLM input.
	uid := intentID
	e.emitActivity(t, db.Activity{NodeID: &uid, Worker: "user", Kind: "user", Summary: message, Detail: message})
	release = false // ownership of the admission passes to the goroutine
	go func() {
		defer e.decInflight(t.ID)
		e.runIntent(ctx, t, "chat", worker, node, requestID, agentMessage)
	}()
	return nil
}

func taskExecutionPaused(cause error) bool {
	var abort *agent.AbortCause
	if !errors.As(cause, &abort) {
		return false
	}
	switch abort.Code {
	case "paused_by_schedule", "paused_by_user", "paused_by_orchestrator", "paused_on_reload", "paused_race_guard",
		"queued_for_admission", "llm_unavailable_queued", "task_deleted":
		return true
	default:
		return false
	}
}

func sleepCtx(ctx context.Context, d time.Duration) (done bool) {
	select {
	case <-ctx.Done():
		return true
	case <-time.After(d):
		return false
	}
}

func (e *Engine) claimNext(t *Task, name string) *db.Node {
	fr, _ := t.Store.Frontier(20)
	for _, in := range fr {
		if ok, _ := t.Store.ClaimIntent(in.ID, name); ok {
			return in
		}
	}
	return nil
}
