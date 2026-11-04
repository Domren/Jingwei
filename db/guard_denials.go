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
	GuardDenialOutOfScope      = "out_of_scope"
	GuardDenialAssetBlock      = "asset_block"
	GuardDenialScopeReadFailed = "scope_read_failed"
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
