package db

import (
	"encoding/json"
	"strings"
	"time"
)

// 内网信息收集脚本的运行记录（F3）。脚本目录在 server 层，这里只负责落库。

type IntranetScriptRun struct {
	ID        int64          `json:"id"`
	SessionID *int64         `json:"session_id,omitempty"`
	TaskID    *int64         `json:"task_id,omitempty"`
	ScriptID  string         `json:"script_id"`
	Name      string         `json:"name"`
	OS        string         `json:"os"`
	Command   string         `json:"command"`
	ExitCode  *int           `json:"exit_code,omitempty"`
	Status    string         `json:"status"`
	Output    string         `json:"output,omitempty"`
	Parsed    map[string]any `json:"parsed"`
	CreatedAt time.Time      `json:"created_at"`
}

type IntranetScriptRunInput struct {
	SessionID int64
	TaskID    int64
	ScriptID  string
	Name      string
	OS        string
	Command   string
	ExitCode  *int
	Status    string
	Output    string
	Parsed    map[string]any
}

func nullInt64(v int64) any {
	if v <= 0 {
		return nil
	}
	return v
}

const intranetScriptRunCols = `id, session_id, task_id, script_id, name, os, command, exit_code,
       status, output, parsed::text, created_at`

func scanIntranetScriptRun(row interface{ Scan(...any) error }) (*IntranetScriptRun, error) {
	var r IntranetScriptRun
	var parsedRaw string
	if err := row.Scan(&r.ID, &r.SessionID, &r.TaskID, &r.ScriptID, &r.Name, &r.OS, &r.Command,
		&r.ExitCode, &r.Status, &r.Output, &parsedRaw, &r.CreatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(parsedRaw), &r.Parsed)
	if r.Parsed == nil {
		r.Parsed = map[string]any{}
	}
	return &r, nil
}

func (d *DB) CreateIntranetScriptRun(in IntranetScriptRunInput) (*IntranetScriptRun, error) {
	if strings.TrimSpace(in.Status) == "" {
		in.Status = "done"
	}
	parsed, _ := json.Marshal(in.Parsed)
	if parsed == nil {
		parsed = []byte("{}")
	}
	row := d.QueryRow(`INSERT INTO intranet_script_runs(session_id, task_id, script_id, name, os, command, exit_code, status, output, parsed)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
RETURNING `+intranetScriptRunCols,
		nullInt64(in.SessionID), nullInt64(in.TaskID), in.ScriptID, in.Name, in.OS, in.Command,
		in.ExitCode, in.Status, in.Output, string(parsed))
	return scanIntranetScriptRun(row)
}

func (d *DB) ListIntranetScriptRuns(sessionID int64, limit int) ([]*IntranetScriptRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.Query(`SELECT `+intranetScriptRunCols+` FROM intranet_script_runs
WHERE session_id=$1 ORDER BY id DESC LIMIT $2`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IntranetScriptRun{}
	for rows.Next() {
		r, err := scanIntranetScriptRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
