package db

import (
	"context"
	"time"
)

// LLMRound 是一轮 LLM 调用（含重试）的轻量快照，回答「这次任务废了几轮、
// 每轮是怎么废的」。与 llm_records 不同：它永远写，哪怕录制开关关着、哪怕失败。
// 与 llm_usage 不同：它按"轮"记，而不是按"调用"记（一次规划里可能有多次调用，
// 但只有一个 round；重试多次算一个 round，attempts 递增）。
type LLMRound struct {
	ID           int64      `json:"id"`
	RoundID      string     `json:"round_id"` // 调用方分配
	TaskID       string     `json:"task_id"`
	Worker       string     `json:"worker"`
	Model        string     `json:"model"`
	ProfileName  string     `json:"profile_name"`
	Status       string     `json:"status"`      // ok / error / stalled
	ErrorClass   string     `json:"error_class"` // 空或五类之一
	Attempts     int        `json:"attempts"`
	TriggerSrc   string     `json:"trigger_src"`
	InputTokens  int        `json:"input_tokens"`
	OutputTokens int        `json:"output_tokens"`
	StartedAt    time.Time  `json:"started_at"`
	FirstEventAt *time.Time `json:"first_event_at,omitempty"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
}

const llmRoundsSchema = `
CREATE TABLE IF NOT EXISTS llm_rounds (
    id             BIGSERIAL PRIMARY KEY,
    round_id       TEXT NOT NULL,
    task_id        TEXT,
    worker         TEXT,
    model          TEXT,
    profile_name   TEXT,
    status         TEXT NOT NULL DEFAULT 'ok',
    error_class    TEXT,
    attempts       INTEGER NOT NULL DEFAULT 1,
    trigger_src    TEXT,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_event_at TIMESTAMPTZ,
    ended_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_llm_rounds_task ON llm_rounds(task_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_llm_rounds_status ON llm_rounds(task_id, status, error_class);
CREATE INDEX IF NOT EXISTS idx_llm_rounds_round ON llm_rounds(round_id);
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
	return tx.Commit()
}

// InsertLLMRound 落一条轮记录。Best-effort：调用方日志后继续，不能让一次
// 记账失败打断 LLM 调用本身。
func (d *DB) InsertLLMRound(r *LLMRound) error {
	_, err := d.Exec(`
INSERT INTO llm_rounds(round_id, task_id, worker, model, profile_name, status, error_class, attempts, trigger_src, input_tokens, output_tokens, started_at, first_event_at, ended_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		r.RoundID, nullIfEmpty(r.TaskID), nullIfEmpty(r.Worker), nullIfEmpty(r.Model),
		nullIfEmpty(r.ProfileName), nullIfEmpty(r.Status), nullIfEmpty(r.ErrorClass),
		r.Attempts, nullIfEmpty(r.TriggerSrc), r.InputTokens, r.OutputTokens,
		r.StartedAt, r.FirstEventAt, r.EndedAt)
	return err
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
       COALESCE(trigger_src,''), input_tokens, output_tokens, started_at, first_event_at, ended_at
FROM llm_rounds WHERE task_id=$1 ORDER BY id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LLMRound{}
	for rows.Next() {
		var r LLMRound
		if err := rows.Scan(&r.ID, &r.RoundID, &r.TaskID, &r.Worker, &r.Model, &r.ProfileName,
			&r.Status, &r.ErrorClass, &r.Attempts, &r.TriggerSrc, &r.InputTokens, &r.OutputTokens,
			&r.StartedAt, &r.FirstEventAt, &r.EndedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LLMRoundStatsByTask 按 (status, error_class) 汇总，给「废轮率」用。
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
