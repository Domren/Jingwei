package db

import (
	"context"
	"encoding/json"
	"time"
)

// LLMRound 是一轮 LLM 调用（含重试）的轻量快照，回答「这次任务废了几轮、
// 每轮是怎么废的」。与 llm_records 不同：它永远写，哪怕录制开关关着、哪怕失败。
// 与 llm_usage 不同：它按"轮"记，而不是按"调用"记（一次规划里可能有多次调用，
// 但只有一个 round；重试多次算一个 round，attempts 递增）。
type LLMRound struct {
	ID          int64  `json:"id"`
	RoundID     string `json:"round_id"` // 调用方分配
	TaskID      string `json:"task_id"`
	Worker      string `json:"worker"`
	Model       string `json:"model"`
	ProfileName string `json:"profile_name"`
	// Status: running（在飞）/ ok / error / stalled。
	// running 只在轮开始时写一行，结束时原地更新——同一 round_id 永远一行。
	Status       string `json:"status"`
	ErrorClass   string `json:"error_class"` // 空或十类之一
	Attempts     int    `json:"attempts"`
	TriggerSrc   string `json:"trigger_src"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	// AttemptClasses 是逐发错误形态（按发生顺序）。最终错误常被包装成
	// context canceled，内层真实的 429/502 只在这里留得下。
	AttemptClasses []string   `json:"attempt_classes,omitempty"`
	StartedAt      time.Time  `json:"started_at"`
	FirstEventAt   *time.Time `json:"first_event_at,omitempty"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
}

const llmRoundsSchema = `
CREATE TABLE IF NOT EXISTS llm_rounds (
    id              BIGSERIAL PRIMARY KEY,
    round_id        TEXT NOT NULL,
    task_id         TEXT,
    worker          TEXT,
    model           TEXT,
    profile_name    TEXT,
    status          TEXT NOT NULL DEFAULT 'ok',
    error_class     TEXT,
    attempts        INTEGER NOT NULL DEFAULT 1,
    trigger_src     TEXT,
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    attempt_classes TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_event_at  TIMESTAMPTZ,
    ended_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_llm_rounds_task ON llm_rounds(task_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_llm_rounds_status ON llm_rounds(task_id, status, error_class);
`

// llmRoundsMigration 把旧表补齐到当前形状，并加唯一约束。
//
// 为什么要唯一约束（R21 缺口⑧）：实测同一 round_id 会落两行（`4-plan-6` 既是
// `error/other` 又是 `stalled/stalled`），废轮率被虚高 53%。只靠应用层守卫不够——
// 两条路径并发时守卫也会同时通过。唯一索引把「一行一轮」变成数据库事实，
// 应用层再用 ON CONFLICT 更新，两条路径谁先谁写、后者只更新。
//
// 存量数据里已经存在的重复行要先收敛，否则建唯一索引会失败。
const llmRoundsMigration = `
ALTER TABLE llm_rounds ADD COLUMN IF NOT EXISTS attempt_classes TEXT;

-- 存量重复行收敛：同一 round_id 只保留最新一行（id 最大），其余删除。
-- 这是迁移里唯一会删数据的语句，且只删自己表里的重复记账行。
DELETE FROM llm_rounds a
 USING llm_rounds b
 WHERE a.round_id = b.round_id AND a.id < b.id;

-- 唯一约束：round_id 一轮一行。索引名固定，便于以后 DROP/排查。
CREATE UNIQUE INDEX IF NOT EXISTS uq_llm_rounds_round ON llm_rounds(round_id);
`

// EnsureLLMRoundsTable 幂等建表（幂等迁移的口径与 llm_usage 一致）。
func (d *DB) EnsureLLMRoundsTable() error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(llmRoundsSchema); err != nil {
		return err
	}
	if _, err := tx.Exec(llmRoundsMigration); err != nil {
		return err
	}
	return tx.Commit()
}

// InsertLLMRound 落一条轮记录。Best-effort：调用方日志后继续，不能让一次
// 记账失败打断 LLM 调用本身。
//
// 同一 round_id 冲突时改为更新（与 UpdateLLMRound 等价），这样「先插入在飞行、
// 结束时更新」与「直接插入终态行」两条路径都不会产生第二行。
func (d *DB) InsertLLMRound(r *LLMRound) error {
	_, err := d.Exec(`
INSERT INTO llm_rounds(round_id, task_id, worker, model, profile_name, status, error_class, attempts, trigger_src, input_tokens, output_tokens, attempt_classes, started_at, first_event_at, ended_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT (round_id) DO UPDATE SET
    status=EXCLUDED.status,
    error_class=EXCLUDED.error_class,
    attempts=EXCLUDED.attempts,
    trigger_src=COALESCE(NULLIF(EXCLUDED.trigger_src,''), llm_rounds.trigger_src),
    input_tokens=GREATEST(EXCLUDED.input_tokens, llm_rounds.input_tokens),
    output_tokens=GREATEST(EXCLUDED.output_tokens, llm_rounds.output_tokens),
    attempt_classes=COALESCE(EXCLUDED.attempt_classes, llm_rounds.attempt_classes),
    model=COALESCE(NULLIF(EXCLUDED.model,''), llm_rounds.model),
    profile_name=COALESCE(NULLIF(EXCLUDED.profile_name,''), llm_rounds.profile_name),
    first_event_at=COALESCE(EXCLUDED.first_event_at, llm_rounds.first_event_at),
    ended_at=COALESCE(EXCLUDED.ended_at, llm_rounds.ended_at)`,
		r.RoundID, nullIfEmpty(r.TaskID), nullIfEmpty(r.Worker), nullIfEmpty(r.Model),
		nullIfEmpty(r.ProfileName), nullIfEmpty(r.Status), nullIfEmpty(r.ErrorClass),
		r.Attempts, nullIfEmpty(r.TriggerSrc), r.InputTokens, r.OutputTokens,
		encodeAttemptClasses(r.AttemptClasses), r.StartedAt, r.FirstEventAt, r.EndedAt)
	return err
}

// UpdateLLMRound 原地更新一轮（Begin 已插入 running 行时用）。
// 返回 error 表示没有可更新的行或更新失败；调用方据此决定是否退化为插入。
func (d *DB) UpdateLLMRound(r *LLMRound) error {
	res, err := d.Exec(`
UPDATE llm_rounds SET
    status=$2, error_class=$3, attempts=$4,
    trigger_src=COALESCE(NULLIF($5,''), trigger_src),
    input_tokens=GREATEST($6, input_tokens),
    output_tokens=GREATEST($7, output_tokens),
    attempt_classes=COALESCE($8, attempt_classes),
    model=COALESCE(NULLIF($9,''), model),
    profile_name=COALESCE(NULLIF($10,''), profile_name),
    first_event_at=COALESCE($11, first_event_at),
    ended_at=COALESCE($12, ended_at)
WHERE round_id=$1`,
		r.RoundID, nullIfEmpty(r.Status), nullIfEmpty(r.ErrorClass), r.Attempts,
		nullIfEmpty(r.TriggerSrc), r.InputTokens, r.OutputTokens,
		encodeAttemptClasses(r.AttemptClasses), nullIfEmpty(r.Model), nullIfEmpty(r.ProfileName),
		r.FirstEventAt, r.EndedAt)
	if err != nil {
		return err
	}
	if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
		return ErrLLMRoundNotFound
	}
	return nil
}

// ErrLLMRoundNotFound 表示该 round_id 还没有行（Begin 没走或已被清理）。
var ErrLLMRoundNotFound = errLLMRoundNotFound{}

type errLLMRoundNotFound struct{}

func (errLLMRoundNotFound) Error() string { return "llm_round 不存在" }

func encodeAttemptClasses(classes []string) any {
	if len(classes) == 0 {
		return nil
	}
	b, err := json.Marshal(classes)
	if err != nil {
		return nil
	}
	return string(b)
}

func decodeAttemptClasses(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// 任务视图：按轮统计。给「这个任务废了几轮、分别废在哪类」用。
type LLMRoundStat struct {
	Status     string `json:"status"`
	ErrorClass string `json:"error_class"`
	Count      int    `json:"count"`
}

// ListLLMRoundsByTask 返回该任务的轮记录（按时间倒序）。
func (d *DB) ListLLMRoundsByTask(ctx context.Context, taskID string, limit int) ([]LLMRound, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.QueryContext(ctx, `
SELECT id, round_id, COALESCE(task_id,''), COALESCE(worker,''), COALESCE(model,''),
       COALESCE(profile_name,''), status, COALESCE(error_class,''), attempts,
       COALESCE(trigger_src,''), input_tokens, output_tokens,
       COALESCE(attempt_classes,''), started_at, first_event_at, ended_at
FROM llm_rounds WHERE task_id=$1 ORDER BY id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LLMRound{}
	for rows.Next() {
		var r LLMRound
		var classes string
		if err := rows.Scan(&r.ID, &r.RoundID, &r.TaskID, &r.Worker, &r.Model, &r.ProfileName,
			&r.Status, &r.ErrorClass, &r.Attempts, &r.TriggerSrc, &r.InputTokens, &r.OutputTokens,
			&classes, &r.StartedAt, &r.FirstEventAt, &r.EndedAt); err != nil {
			return nil, err
		}
		r.AttemptClasses = decodeAttemptClasses(classes)
		out = append(out, r)
	}
	return out, rows.Err()
}

// LLMRoundStatsByTask 按 (status, error_class) 汇总，给「废轮率」用。
// 在飞的轮（status=running）不算失败也不算成功，单独成一行返回，
// 由调用方决定是否计入分母——「有没有轮在跑」正是缺口⑦要回答的问题。
func (d *DB) LLMRoundStatsByTask(ctx context.Context, taskID string) ([]LLMRoundStat, error) {
	rows, err := d.QueryContext(ctx, `
SELECT status, COALESCE(error_class,''), COUNT(*) FROM llm_rounds
WHERE task_id=$1 GROUP BY status, COALESCE(error_class,'') ORDER BY 1,2`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LLMRoundStat{}
	for rows.Next() {
		var st LLMRoundStat
		if err := rows.Scan(&st.Status, &st.ErrorClass, &st.Count); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ConsecutiveFailedRounds 返回该任务**最近连续失败**的轮数（从最新往回数），
// 用于 ⑤ 失败退避与 ② 首轮即告警：这两个判据都只看「连续失败」，与总轮数无关，
// 所以端点一坏就能立刻生效，而不必等攒够 10 轮。
//
// 只统计已终态的轮；遇到 ok 或 running 就停（running 说明还有活轮在跑，
// 此时判「连续失败」会把在飞的轮算成失败）。
func (d *DB) ConsecutiveFailedRounds(ctx context.Context, taskID string) (int, error) {
	rows, err := d.QueryContext(ctx, `
SELECT status FROM llm_rounds WHERE task_id=$1 ORDER BY id DESC LIMIT 50`, taskID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var st string
		if err := rows.Scan(&st); err != nil {
			return 0, err
		}
		switch st {
		case "ok":
			return n, nil
		case "running":
			return n, nil
		default:
			n++
		}
	}
	return n, rows.Err()
}

// TaskBudgetUsage 返回任务级预算闸门的两个用量（R19 序 4）：规划轮数（llm_rounds
// 按任务注册 id 计数，每轮一行）与累计输入 token（llm_usage 按 exploration_id 累计。
// 不按 task_id 计 token：历史行落的是探索 id 字符串，exploration_id 列两代口径都
// 恒有值，与 TokenByModel/归档侧同一谓词）。explorationID=0 时 exploration_id=0
// 匹配不到任何真实行，token 自然为 0——谓词里不写 `$2 > 0` 裸比较（参数会被推断成
// int4，探索 id 一大就在编码侧报错，实测）。
func (d *DB) TaskBudgetUsage(taskID string, explorationID int64) (rounds int64, inputTokens int64, err error) {
	err = d.QueryRow(`
SELECT (SELECT COUNT(*) FROM llm_rounds WHERE task_id = $1),
       (SELECT COALESCE(SUM(input_tokens),0) FROM llm_usage
         WHERE exploration_id = $2)`,
		taskID, explorationID).Scan(&rounds, &inputTokens)
	return rounds, inputTokens, err
}
