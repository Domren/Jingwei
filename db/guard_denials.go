package db

import (
	"time"
)

// Guard denial categories. Fail-closed target policy (see server/guard_policy.go)
// refuses a tool call when the scope or the asset-block list cannot be read, and
// when a target is genuinely out of scope or explicitly blocked. Those look
// identical from the outside — "工具被拒" — so each refusal is metered by cause:
// a database hiccup showing up as out_of_scope would be a different fix than an
// operator forgetting to register the scope.
const (
	GuardDenialOutOfScope = "out_of_scope"
	// GuardDenialOutOfAuthorization：启用了客户授权清单时，目标不在任何有效
	// 授权内（或命中了授权排除项）。
	GuardDenialOutOfAuthorization = "out_of_authorization"
	GuardDenialAssetBlock         = "asset_block"
	GuardDenialScopeReadFailed    = "scope_read_failed"
	// GuardDenialCompanyExpandFailed is the third read that can fail closed: the
	// task scope registered a company, and the company's asset list could not be
	// expanded. Operators see the same refusal, but the fix is on the asset side.
	GuardDenialCompanyExpandFailed = "company_expand_failed"
	GuardDenialBlockReadFailed     = "block_read_failed"
	GuardDenialSourceUnavailable   = "source_unavailable"
)

// GuardDenialsWithin caps the look-back so the system page query stays bounded
// even on an instance that has been refusing calls for months.
const GuardDenialsWithin = 30 * 24 * time.Hour

// GuardDenialStat is one (task, category) bucket of refusals.
type GuardDenialStat struct {
	TaskID     int64     `json:"task_id"`
	Category   string    `json:"category"`
	Denials    int       `json:"denials"`
	Mode       string    `json:"mode"`
	LastReason string    `json:"last_reason"`
	LastAt     time.Time `json:"last_at"`
}

// InsertGuardDenial appends one refusal row. Metering is best-effort: callers
// already decided to deny the call, and a statistics write must never turn into a
// second failure path for the guard itself.
func (d *DB) InsertGuardDenial(taskID int64, category, mode, reason string) error {
	if d == nil {
		return nil
	}
	_, err := d.Exec(`
INSERT INTO guard_denials(task_id, category, mode, reason)
VALUES ($1, $2, $3, $4)`,
		nullIfZero(taskID), category, mode, truncateUTF8(reason, 2000))
	return err
}

// GuardDenialCause 是按成因汇总的一行：跨任务的总数、影响的任务数、最近 24 小时的数量。
//
// 为什么要这一层：per-(task, category) 只能回答「哪个任务被拒了多少次」，回答不了
// 「要不要给这一类加短暂重试」。后者要看的是成因分布——读库抖动（scope_read_failed /
// block_read_failed）与策略拒绝（out_of_scope / asset_block）在报告里长得一样，
// 但前者重试就好、后者重试一万次也不会放行。
type GuardDenialCause struct {
	Category   string    `json:"category"`
	Total      int       `json:"total"`
	Tasks      int       `json:"tasks"`
	Last24h    int       `json:"last_24h"`
	LastReason string    `json:"last_reason"`
	LastAt     time.Time `json:"last_at"`
	// Retryable 是「这一成因属于基础设施抖动、可短暂重试」的判断，由成因常量决定，
	// 不靠猜 reason 文本。
	Retryable bool `json:"retryable"`
	// Advice 是给操作员的一句话：这一类该往哪修。策略类拒绝永远不写成「重试」。
	Advice string `json:"advice"`
}

// guardDenialCauseMeta 把成因映射成「可重试 + 该往哪修」。
// 新增成因必须在这里登记：没有登记的行在界面上会显示「未登记的成因」，
// 而不是被默认当成可重试——默认值定成「不可重试」更安全。
func GuardDenialCauseMeta(category string) (retryable bool, advice string) {
	switch category {
	case GuardDenialScopeReadFailed:
		return true, "读取任务范围失败（数据库抖动）：可短暂重试；持续出现是库或连接池的问题，不是范围配错"
	case GuardDenialBlockReadFailed:
		return true, "读取资产禁令失败（数据库抖动）：可短暂重试；加固期间宁可失败关闭，不要改放行"
	case GuardDenialCompanyExpandFailed:
		return true, "展开公司资产失败：可短暂重试；持续出现先查公司资产表的完整性"
	case GuardDenialSourceUnavailable:
		return true, "资产来源不可用：可短暂重试；持续出现先恢复来源，再谈扫描覆盖"
	case GuardDenialOutOfScope:
		return false, "目标不在任务范围：先登记范围或走范围申请，重试不会放行"
	case GuardDenialOutOfAuthorization:
		return false, "目标不在客户授权清单内（或命中排除项）：补授权或改排除项，不能放宽拦截"
	case GuardDenialAssetBlock:
		return false, "命中资产禁令：确认为误禁后由操作员调整禁令，拦截本身不该被绕过"
	}
	return false, "未登记的成因：先看 reason 原文，不要按「范围问题」或「重试」处理"
}

// GuardDenialBreakdown 返回窗口内按成因的分布，总数降序。
// 它只读，且与 GuardDenialStats 共用同一张表与同一个回看窗口上限。
func (d *DB) GuardDenialBreakdown(within time.Duration) ([]GuardDenialCause, error) {
	if d == nil {
		return nil, nil
	}
	if within <= 0 || within > GuardDenialsWithin {
		within = GuardDenialsWithin
	}
	rows, err := d.Query(`
SELECT category,
       count(*) AS total,
       count(DISTINCT task_id) AS tasks,
       count(*) FILTER (WHERE ts >= now() - interval '24 hours') AS last24,
       (array_agg(reason ORDER BY ts DESC))[1] AS last_reason,
       max(ts) AS last_at
FROM guard_denials
WHERE ts >= now() - ($1 * interval '1 second')
GROUP BY category
ORDER BY total DESC, category`, within.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GuardDenialCause{}
	for rows.Next() {
		var c GuardDenialCause
		if err := rows.Scan(&c.Category, &c.Total, &c.Tasks, &c.Last24h, &c.LastReason, &c.LastAt); err != nil {
			return nil, err
		}
		c.Retryable, c.Advice = GuardDenialCauseMeta(c.Category)
		out = append(out, c)
	}
	return out, rows.Err()
}

// GuardDenialStats returns per-(task, category) refusal counts newest-first,
// within the look-back window. Tasks without denials are absent.
func (d *DB) GuardDenialStats(within time.Duration, limit int) ([]GuardDenialStat, error) {
	if d == nil {
		return nil, nil
	}
	if within <= 0 || within > GuardDenialsWithin {
		within = GuardDenialsWithin
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.Query(`
WITH recent AS (
  SELECT task_id, category, mode, reason, ts,
         COUNT(*) OVER (PARTITION BY task_id, category) AS bucket_count,
         ROW_NUMBER() OVER (PARTITION BY task_id, category ORDER BY ts DESC) AS newest
  FROM guard_denials
  WHERE ts >= now() - ($1 * interval '1 second')
)
SELECT task_id, category, bucket_count, mode, reason, ts
FROM recent WHERE newest = 1
ORDER BY bucket_count DESC, ts DESC
LIMIT $2`, within.Seconds(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GuardDenialStat{}
	for rows.Next() {
		var s GuardDenialStat
		var taskID *int64
		if err := rows.Scan(&taskID, &s.Category, &s.Denials, &s.Mode, &s.LastReason, &s.LastAt); err != nil {
			return nil, err
		}
		if taskID != nil {
			s.TaskID = *taskID
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
