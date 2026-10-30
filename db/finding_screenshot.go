package db

import (
	"fmt"
	"strings"
	"time"
)

// FindingScreenshot is one evidence screenshot attached to a finding — a PNG
// capture of a replayed request/response (or the affected page) kept for the
// report's 取证 section. Data is stored base64-encoded for self-containment.
type FindingScreenshot struct {
	ID        int64     `json:"id"`
	FindingID int64     `json:"finding_id"`
	Caption   string    `json:"caption"`
	Data      string    `json:"data,omitempty"` // base64 PNG; omitted in list responses
	CreatedAt time.Time `json:"created_at"`
}

// AddFindingScreenshot attaches a base64 PNG to a finding. Returns the new id.
func (d *DB) AddFindingScreenshot(findingID int64, caption, dataB64 string) (int64, error) {
	var id int64
	err := d.QueryRow(`INSERT INTO finding_screenshots(finding_id, caption, data)
		VALUES($1,$2,$3) RETURNING id`, findingID, caption, dataB64).Scan(&id)
	return id, err
}

// ListFindingScreenshots returns a finding's screenshots (data omitted unless
// withData) in order.
func (d *DB) ListFindingScreenshots(findingID int64, withData bool) ([]FindingScreenshot, error) {
	sel := "id, finding_id, caption, created_at"
	if withData {
		sel = "id, finding_id, caption, data, created_at"
	}
	rows, err := d.Query("SELECT "+sel+" FROM finding_screenshots WHERE finding_id=$1 ORDER BY id ASC", findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingScreenshot
	for rows.Next() {
		var e FindingScreenshot
		if withData {
			if err := rows.Scan(&e.ID, &e.FindingID, &e.Caption, &e.Data, &e.CreatedAt); err != nil {
				return nil, err
			}
		} else if err := rows.Scan(&e.ID, &e.FindingID, &e.Caption, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListFindingScreenshotsForFindings bulk-loads evidence screenshots (with data)
// for a set of findings, keyed by finding id. Used by the HTML/DOCX report
// export to inline screenshots. One screenshot failing to decode never breaks
// the whole batch because data is kept as an opaque base64 string here.
func (d *DB) ListFindingScreenshotsForFindings(findingIDs []int64) (map[int64][]FindingScreenshot, error) {
	out := map[int64][]FindingScreenshot{}
	if len(findingIDs) == 0 {
		return out, nil
	}
	ph := make([]string, len(findingIDs))
	args := make([]any, len(findingIDs))
	for i, id := range findingIDs {
		ph[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	rows, err := d.Query(`SELECT id, finding_id, caption, data, created_at
		FROM finding_screenshots WHERE finding_id IN (`+strings.Join(ph, ",")+`) ORDER BY finding_id ASC, id ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e FindingScreenshot
		if err := rows.Scan(&e.ID, &e.FindingID, &e.Caption, &e.Data, &e.CreatedAt); err != nil {
			return nil, err
		}
		out[e.FindingID] = append(out[e.FindingID], e)
	}
	return out, rows.Err()
}
