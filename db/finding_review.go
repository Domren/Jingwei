package db

import (
	"time"
)

// FindingReviewEvent is one operator review action on a finding — who changed
// what, when, and the value transition. Powers the 复核时间线 on the finding
// detail page so evidence of human review is auditable.
type FindingReviewEvent struct {
	ID        int64     `json:"id"`
	FindingID int64     `json:"finding_id"`
	Action    string    `json:"action"` // status | severity | name | vulnclass | cvss
	Actor     string    `json:"actor"`
	Note      string    `json:"note,omitempty"`
	FromVal   string    `json:"from_val,omitempty"`
	ToVal     string    `json:"to_val,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// RecordFindingReviewEvent appends one review event to a finding's timeline.
func (d *DB) RecordFindingReviewEvent(findingID int64, action, actor, note, fromVal, toVal string) error {
	_, err := d.Exec(`INSERT INTO finding_review_events(finding_id, action, actor, note, from_val, to_val)
		VALUES($1,$2,$3,$4,$5,$6)`, findingID, action, actor, note, nullIfEmptyStr(fromVal), nullIfEmptyStr(toVal))
	return err
}

// ListFindingReviewEvents returns a finding's review timeline in chronological order.
func (d *DB) ListFindingReviewEvents(findingID int64) ([]FindingReviewEvent, error) {
	rows, err := d.Query(`SELECT id, finding_id, action, COALESCE(actor,''), COALESCE(note,''),
		COALESCE(from_val,''), COALESCE(to_val,''), created_at
		FROM finding_review_events WHERE finding_id=$1 ORDER BY id ASC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingReviewEvent
	for rows.Next() {
		var e FindingReviewEvent
		if err := rows.Scan(&e.ID, &e.FindingID, &e.Action, &e.Actor, &e.Note, &e.FromVal, &e.ToVal, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullIfEmptyStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
