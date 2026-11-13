package server

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/jingwei/agent"
	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/llmrec"
)

// 任务级超时协调器(见 docs/任务级超时与收尾设计.md §4/§8.5)。
// 绝对墙钟:每个带 timeout 的任务一个定时 goroutine,到点驱动有序收尾时序:
//   ① settling → ② worker 停领新意图 / ③ planner 丢弃普通 notify
//   ④ 等在跑 worker drain(受 grace) → ⑤ 终局一轮 planner 判定 → ⑥ 定终态(带守卫)

const (
	settleDrainGrace     = 90 * time.Second // 等在跑 worker 优雅收尾的上限;超过则硬 cancel
	deadlinePollInterval = 2 * time.Second  // deadline 未盖章/LLM 未就绪时的轮询间隔
	deadlineMaxSleep     = 30 * time.Second // 单次最长睡眠(便于周期复查终态)
)

// ---------- settling 状态 ----------

func (e *Engine) isSettling(taskID string) bool {
	v, _ := e.settling.Load(taskID)
	b, _ := v.(bool)
	return b
}

// markSettling flips settling on; returns true only for the first caller.
func (e *Engine) markSettling(taskID string) bool {
	_, loaded := e.settling.LoadOrStore(taskID, true)
	return !loaded
}

// ---------- 在跑计数(worker.Execute + planner.Plan),用于 drain ----------

func (e *Engine) inflightCounter(taskID string) *int64 {
	v, _ := e.inflight.LoadOrStore(taskID, new(int64))
	return v.(*int64)
}

// beginTaskOperation atomically registers a task-owned operation unless deletion
// has already installed its barrier. The delete handler can therefore wait for
// inflight==0 without a check-then-start race recreating files after cleanup.
func (e *Engine) beginTaskOperation(taskID string) bool {
	e.deleteMu.RLock()
	defer e.deleteMu.RUnlock()
	if e.IsDeleting(taskID) {
		return false
	}
	atomic.AddInt64(e.inflightCounter(taskID), 1)
	return true
}

func (e *Engine) decInflight(taskID string) { atomic.AddInt64(e.inflightCounter(taskID), -1) }
func (e *Engine) inflightCount(taskID string) int64 {
	return atomic.LoadInt64(e.inflightCounter(taskID))
}

// ---------- settle 原因（R19 序 4） ----------

// settleCause 区分两类任务到限收尾：绝对墙钟超时 vs 预算（轮数/输入 token）到限。
// 两者走同一套有序时序（drain → 终局规划轮 → 终态），差别只在终局收尾词（agent
// 按 TaskClock.Settle 挑）、活动台账文案与终态（timeout / budget）。
type settleCause int

const (
	settleTimeout      settleCause = iota // 绝对墙钟到点
	settleBudgetRounds                    // 规划轮数达到 max_rounds
	settleBudgetTokens                    // 输入 token 达到 max_input_tokens
)

// settleKey 是 agent.TaskClock.Settle 的取值："timeout" | "budget"。agent 侧按它挑
// 任务收尾词（超时词/预算词）。
func (c settleCause) settleKey() string {
	if c == settleTimeout {
		return "timeout"
	}
	return "budget"
}

// status 是收尾落库的终态名（timeout / budget；met 优先 done 由调用方决定）。
func (c settleCause) status() string { return c.settleKey() }

// summary 是活动台账里「任务xx收尾」的短文案。
func (c settleCause) summary() string {
	if c == settleTimeout {
		return "超时收尾"
	}
	return "预算到限收尾"
}

func (c settleCause) label() string {
	switch c {
	case settleBudgetRounds:
		return "达到规划轮数上限"
	case settleBudgetTokens:
		return "达到输入 token 上限"
	default:
		return "到达超时上限"
	}
}

// stopReasonText 是落 tasks.stop_reason 的台账文案（「为什么停」要能在台账里回答）。
// done 不写。
func (c settleCause) stopReasonText(t *Task) string {
	switch c {
	case settleBudgetRounds:
		return fmt.Sprintf("达到规划轮数上限（max_rounds=%d）", t.MaxRounds)
	case settleBudgetTokens:
		return fmt.Sprintf("达到输入 token 上限（max_input_tokens=%d）", t.MaxInputTokens)
	default:
		return "到达超时上限"
	}
}

// ---------- deadline ----------

// taskDeadline returns the task's absolute deadline (unix). Prefers the in-process
// map (stamped this session); falls back to the DB-loaded value (restart), seeding
// the map. 0 = no timeout / not yet stamped.
func (e *Engine) taskDeadline(t *Task) int64 {
	if v, ok := e.deadline.Load(t.ID); ok {
		return v.(int64)
	}
	deadlineAt := t.lifecycleSnapshot().DeadlineAt
	if deadlineAt > 0 {
		e.deadline.Store(t.ID, deadlineAt)
		return deadlineAt
	}
	return 0
}

// resetTimeoutRevival clears only the per-run timeout state after PostgreSQL has
// atomically committed timeout -> running and reset first_run_at/deadline_at. The
// configured TimeoutSeconds remains on Task, so the next real Planner/Worker run
// stamps a fresh full budget. coordStarted is reset because the coordinator that
// produced the timeout has already completed (or is in its final return path).
func (e *Engine) resetTimeoutRevival(taskID string) {
	e.settling.Delete(taskID)
	e.deadline.Delete(taskID)
	e.stamped.Delete(taskID)
	e.coordStarted.Delete(taskID)
}

// stampFirstRun records first_run_at + deadline_at on the FIRST real run (LLM ready)
// of a timeout task, once per process. No-op when the task has no timeout.
func (e *Engine) stampFirstRun(t *Task) {
	// 盖章与「有没有设超时」无关：没设超时的任务同样要能在库里回答「什么时候真正开始跑」。
	// 库里 tasks.status 只写 created→终态，running 是 API 派生的，first_run_at 是唯一的落库痕迹。
	// deadline 仍只在 timeout>0 时算（StampFirstRun 内部按 timeout 决定是否给 deadline_at）。
	if _, loaded := e.stamped.LoadOrStore(t.ID, true); loaded {
		return
	}
	dl, err := e.m.StampTaskFirstRun(t.ID)
	if err != nil {
		log.Printf("[deadline] task %s 盖章 first_run 失败: %v", t.ID, err)
		e.stamped.Delete(t.ID) // 允许下次重试
		return
	}
	if dl > 0 {
		e.deadline.Store(t.ID, dl)
		log.Printf("[deadline] task %s 首次运行,截止于 %s", t.ID, time.Unix(dl, 0).Format("2006-01-02 15:04:05"))
	}
}

// clockCtx layers the task's TaskClock (absolute deadline) onto a run's context so
// worker/planner can clamp their wall-clock budget and pick per-run vs task-timeout
// wrap-up words. final marks the coordinator-driven terminal planner round.
func (e *Engine) clockCtx(base context.Context, t *Task, final bool) context.Context {
	dl := e.taskDeadline(t)
	if dl <= 0 && !final {
		return base // no timeout → unchanged behavior
	}
	return agent.WithTaskClock(base, agent.TaskClock{DeadlineUnix: dl, Final: final})
}

// ---------- 协调器 ----------

// startDeadlineCoordinator launches the per-task deadline timer once (idempotent).
// Called from Run() and from the restart reload path, so non-active timeout tasks
// still get settled after their deadline even without live planner/worker loops.
func (e *Engine) startDeadlineCoordinator(ctx context.Context, t *Task) {
	if t == nil || t.TimeoutSeconds <= 0 {
		return
	}
	e.deleteMu.RLock()
	if e.IsDeleting(t.ID) {
		e.deleteMu.RUnlock()
		return
	}
	if _, loaded := e.coordStarted.LoadOrStore(t.ID, true); loaded {
		e.deleteMu.RUnlock()
		return
	}
	rt := e.registerTaskRoutines(ctx, t.ID, 1)
	e.deleteMu.RUnlock()
	runTaskRoutine(rt, func(loopCtx context.Context) { e.deadlineCoordinator(loopCtx, t) })
}

// deadlineCoordinator waits until the task's absolute deadline, then runs the settle
// sequence. Absolute wall-clock: it keeps counting through pauses.
func (e *Engine) deadlineCoordinator(ctx context.Context, t *Task) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			return // already finished (goals met / failed) — nothing to time out
		}
		dl := e.taskDeadline(t)
		if dl <= 0 {
			if sleepCtx(ctx, deadlinePollInterval) { // not yet stamped (task hasn't really run)
				return
			}
			continue
		}
		if remaining := time.Until(time.Unix(dl, 0)); remaining > 0 {
			nap := remaining
			if nap > deadlineMaxSleep {
				nap = deadlineMaxSleep
			}
			if sleepCtx(ctx, nap) {
				return
			}
			continue
		}
		e.settleTask(ctx, t, settleTimeout)
		return
	}
}

// ---------- 预算协调器（R19 序 4：轮数 + 输入 token 双上限） ----------

// budgetPollInterval 预算协调器的轮询间隔。与 deadline 协调器的「到点才动」不同，
// 预算是累积量，只能周期查询；规划轮入口另有同步快查（plannerLoop），窗口内的
// 白烧被夹到一轮以内。
const budgetPollInterval = 30 * time.Second

// startBudgetCoordinator 为设置了预算上限的任务启动预算协调器（与 deadline 协调器
// 同一套去重/例程模式）。轮数与输入 token 任一命中即进入收尾时序。
func (e *Engine) startBudgetCoordinator(ctx context.Context, t *Task) {
	if t == nil || (t.MaxRounds <= 0 && t.MaxInputTokens <= 0) {
		return
	}
	e.deleteMu.RLock()
	if e.IsDeleting(t.ID) {
		e.deleteMu.RUnlock()
		return
	}
	if _, loaded := e.budgetCoordStarted.LoadOrStore(t.ID, true); loaded {
		e.deleteMu.RUnlock()
		return
	}
	rt := e.registerTaskRoutines(ctx, t.ID, 1)
	e.deleteMu.RUnlock()
	runTaskRoutine(rt, func(loopCtx context.Context) { e.budgetCoordinator(loopCtx, t) })
}

func (e *Engine) budgetCoordinator(ctx context.Context, t *Task) {
	pg := e.m.PG()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			return
		}
		if pg != nil {
			if cause, hit := e.budgetHit(t, pg); hit {
				e.settleTask(ctx, t, cause)
				return
			}
		}
		if sleepCtx(ctx, budgetPollInterval) {
			return
		}
	}
}

// budgetHit 查询任务当前用量并对上限；查询出错只记日志（下一轮再试），不误杀任务。
func (e *Engine) budgetHit(t *Task, pg *db.DB) (settleCause, bool) {
	rounds, tokens, err := pg.TaskBudgetUsage(t.ID, t.ExpID)
	if err != nil {
		log.Printf("[budget] task %s 查询预算用量失败: %v", t.ID, err)
		return 0, false
	}
	if t.MaxRounds > 0 && rounds >= int64(t.MaxRounds) {
		log.Printf("[budget] task %s 规划轮数 %d/%d 到限", t.ID, rounds, t.MaxRounds)
		return settleBudgetRounds, true
	}
	if t.MaxInputTokens > 0 && tokens >= t.MaxInputTokens {
		log.Printf("[budget] task %s 输入 token %d/%d 到限", t.ID, tokens, t.MaxInputTokens)
		return settleBudgetTokens, true
	}
	return 0, false
}

// settleTask runs the ordered settle sequence once (§4 steps ①–⑥). cause 决定
// 终局收尾词、台账文案与终态（timeout / budget；met 仍优先 done）。
func (e *Engine) settleTask(ctx context.Context, t *Task, cause settleCause) {
	if !e.markSettling(t.ID) {
		return
	}
	log.Printf("[settle] task %s %s,进入收尾时序", t.ID, cause.label())
	e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("任务%s，进入收尾时序：在跑 worker 优雅写回，随后终局判定落终态", cause.label())})

	// ④ 等在跑 worker/planner drain(在跑 run 因夹逼的 MaxDuration 自行进收尾);
	// 超过 grace 仍未清空 → 硬 cancel 该任务 exec ctx(settling-aware 分支正确归类)。
	hardStop := time.Now().Add(settleDrainGrace)
	for e.inflightCount(t.ID) > 0 {
		if time.Now().After(hardStop) {
			log.Printf("[deadline] task %s drain 超时(%s),硬取消在跑 run", t.ID, settleDrainGrace)
			e.cancelExec(t.ID, agent.AbortSettleDrainTimeout)
			_ = sleepCtx(ctx, 3*time.Second) // 给 worker 分支一点时间落库/归类
			break
		}
		if sleepCtx(ctx, 500*time.Millisecond) {
			return // 引擎整体关停
		}
	}

	// ⑤ 终局一轮 planner(任务超时/预算收尾词,最后目标判定,不产新意图)。
	met := e.runFinalPlannerRound(ctx, t, cause)
	if !e.beginTaskOperation(t.ID) {
		return
	}
	defer e.decInflight(t.ID)

	// ⑥ 定终态(带守卫):met → done(completed);否则按 cause 落 timeout/budget。
	// 若常规路径已先落 done,守卫(SetTaskStatusGuarded)会拒绝覆盖,保留 completed 语义。
	status := cause.status()
	if met {
		status = "done"
	}
	won, err := e.m.SetTaskStatusGuarded(t.ID, status)
	switch {
	case err != nil:
		log.Printf("[settle] task %s 落终态失败: %v", t.ID, err)
	case won:
		log.Printf("[settle] task %s 收尾完成,终态=%s", t.ID, status)
		// 「为什么停」写进台账（R19 序 4）：超时/预算各留一句可读原因；done 不写。
		if reason := cause.stopReasonText(t); status != "done" && reason != "" {
			if idInt, perr := strconv.ParseInt(t.ID, 10, 64); perr == nil {
				if pg := e.m.PG(); pg != nil {
					if serr := pg.SetTaskStopReason(idInt, reason); serr != nil {
						log.Printf("[settle] task %s 写 stop_reason 失败: %v", t.ID, serr)
					} else {
						t.updateLifecycle(func(s *taskLifecycleState) { s.StopReason = reason })
					}
				}
			}
		}
	default:
		log.Printf("[settle] task %s 收尾时已是终态,保留原状态", t.ID)
	}
}

// runFinalPlannerRound drives exactly ONE terminal planner round with the
// task-timeout/budget planner words (final goal judgment; no new intents). Waits for the
// LLM to be ready (bounded by ctx) so a completable task isn't mis-judged timeout.
func (e *Engine) runFinalPlannerRound(ctx context.Context, t *Task, cause settleCause) (met bool) {
	if e.IsDeleting(t.ID) {
		return false
	}
	planner, _ := e.snapshotFor(t)
	for planner == nil {
		if sleepCtx(ctx, deadlinePollInterval) {
			return false
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			return false
		}
		if e.IsDeleting(t.ID) {
			return false
		}
		planner, _ = e.snapshotFor(t)
	}
	// 独立 ctx(不挂 execCancel,避免 pause/硬 cancel 打断这最后一轮),带 Final + Settle
	// 注入对应收尾词(超时词/预算词,agent 按 TaskClock.Settle 挑)。
	fctx := llmrec.WithTaskID(agent.WithTaskClock(ctx, agent.TaskClock{
		DeadlineUnix: e.taskDeadline(t), Final: true, Settle: cause.settleKey(),
	}), t.ID)
	if !e.beginTaskOperation(t.ID) {
		return false
	}
	defer e.decInflight(t.ID)
	emit := func(r db.Activity) { e.emitActivity(t, r) }
	e.emitActivity(t, db.Activity{Worker: "planner", Kind: "round",
		Summary: fmt.Sprintf("任务%s·终局判定(第 %d 轮)", cause.summary(), e.nextPlannerRound(t.ID))})
	tTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
	e.BeginLLMCall(t.ID)
	met, reason, err := planner.Plan(fctx, tTaskID, e.m.assets, t.Store, t.Goal, t.drainTriggers(), emit)
	e.EndLLMCall(t.ID)
	if err != nil {
		log.Printf("[deadline] task %s 终局规划出错: %v", t.ID, err)
	} else if met {
		log.Printf("[deadline] task %s 终局判定目标达成: %s", t.ID, reason)
	}
	return met
}
