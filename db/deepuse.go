package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DeepTask kinds.
const (
	DeepTaskVerify         = "verify"
	DeepTaskExploit        = "exploit"
	DeepTaskWAFBypass      = "waf_bypass"
	DeepTaskWebshellInject = "webshell_inject"
	// DeepTaskSQLiProbe and DeepTaskXSSProbe hand the injection point to a
	// dedicated verifier (sqlmap / dalfox) instead of trusting a POC template.
	DeepTaskSQLiProbe = "sqli_probe"
	DeepTaskXSSProbe  = "xss_probe"
)

// ErrDeepTaskNotFound is returned when a deep task id does not exist.
var ErrDeepTaskNotFound = errors.New("深度利用任务不存在")

// DeepTask is one queued deep-exploitation run.
type DeepTask struct {
	ID         int64          `json:"id"`
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Target     string         `json:"target"`
	Params     map[string]any `json:"params"`
	ScanTaskID *int64         `json:"scan_task_id,omitempty"`
	AutoRun    bool           `json:"auto_run"`
	Status     string         `json:"status"`
	Stage      string         `json:"stage"`
	Progress   map[string]any `json:"progress"`
	Summary    map[string]any `json:"summary"`
	Log        string         `json:"log,omitempty"`
	Error      string         `json:"error,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
}

// DeepTaskInput is the create payload for a deep task.
type DeepTaskInput struct {
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Target     string         `json:"target"`
	Params     map[string]any `json:"params"`
	ScanTaskID *int64         `json:"scan_task_id,omitempty"`
	AutoRun    bool           `json:"auto_run"`
}

const deepTaskCols = `id, name, kind, target, params::text, scan_task_id, auto_run, status, stage,
       progress::text, summary::text, log, error,
       created_at, started_at, finished_at`

func deepOneTask(row interface{ Scan(...any) error }) (*DeepTask, error) {
	var t DeepTask
	var paramsRaw, progressRaw, summaryRaw string
	if err := row.Scan(&t.ID, &t.Name, &t.Kind, &t.Target, &paramsRaw, &t.ScanTaskID, &t.AutoRun,
		&t.Status, &t.Stage,
		&progressRaw, &summaryRaw, &t.Log, &t.Error,
		&t.CreatedAt, &t.StartedAt, &t.FinishedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(paramsRaw), &t.Params)
	_ = json.Unmarshal([]byte(progressRaw), &t.Progress)
	_ = json.Unmarshal([]byte(summaryRaw), &t.Summary)
	if t.Params == nil {
		t.Params = map[string]any{}
	}
	if t.Progress == nil {
		t.Progress = map[string]any{}
	}
	if t.Summary == nil {
		t.Summary = map[string]any{}
	}
	return &t, nil
}

// CreateDeepTask inserts a queued deep task.
func (d *DB) CreateDeepTask(in DeepTaskInput) (*DeepTask, error) {
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	switch kind {
	case DeepTaskVerify, DeepTaskExploit, DeepTaskWAFBypass, DeepTaskWebshellInject,
		DeepTaskSQLiProbe, DeepTaskXSSProbe:
	default:
		kind = DeepTaskVerify
	}
	if in.Params == nil {
		in.Params = map[string]any{}
	}
	row := d.QueryRow(`
INSERT INTO deep_tasks(name, kind, target, params, scan_task_id, auto_run)
VALUES ($1, $2, $3, $4::jsonb, $5, $6)
RETURNING `+deepTaskCols,
		strings.TrimSpace(in.Name), kind, strings.TrimSpace(in.Target), jsonObject(in.Params),
		in.ScanTaskID, in.AutoRun)
	return deepOneTask(row)
}

// ListDeepTasksByScan returns every deep task spawned by one scan, oldest first.
func (d *DB) ListDeepTasksByScan(scanTaskID int64) ([]*DeepTask, error) {
	// Auto tasks belong to one scan run: a rerun resets started_at, so older
	// tasks from a previous run are excluded while their evidence stays.
	rows, err := d.Query(`SELECT `+deepTaskCols+` FROM deep_tasks
		WHERE scan_task_id=$1
		  AND created_at >= COALESCE((SELECT started_at FROM scan_tasks WHERE id=$1), now())
		ORDER BY id ASC`, scanTaskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DeepTask{}
	for rows.Next() {
		t, err := deepOneTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListDeepTasks returns newest-first deep tasks, optionally filtered by kind.
func (d *DB) ListDeepTasks(kind string, limit, offset int) ([]*DeepTask, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	where := ""
	args := []any{}
	if k := strings.TrimSpace(kind); k != "" {
		where = " WHERE kind=$1"
		args = append(args, k)
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM deep_tasks`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	listArgs := append([]any{}, args...)
	limitIdx, offsetIdx := len(args)+1, len(args)+2
	listArgs = append(listArgs, limit, offset)
	rows, err := d.Query(`SELECT `+deepTaskCols+` FROM deep_tasks`+where+
		fmt.Sprintf(` ORDER BY id DESC LIMIT $%d OFFSET $%d`, limitIdx, offsetIdx), listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*DeepTask{}
	for rows.Next() {
		t, err := deepOneTask(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// GetDeepTask returns one deep task.
func (d *DB) GetDeepTask(id int64) (*DeepTask, error) {
	t, err := deepOneTask(d.QueryRow(`SELECT `+deepTaskCols+` FROM deep_tasks WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDeepTaskNotFound
	}
	return t, err
}

// ClaimNextDeepTask atomically claims the oldest queued deep task.
func (d *DB) ClaimNextDeepTask() (*DeepTask, error) {
	t, err := deepOneTask(d.QueryRow(`UPDATE deep_tasks
SET status='running', stage='start', started_at=now(), finished_at=NULL, error='', progress='{}'::jsonb
WHERE id=(SELECT id FROM deep_tasks WHERE status='queued' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING ` + deepTaskCols))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// UpdateDeepTaskProgress persists the current stage/counters and appends a log line.
func (d *DB) UpdateDeepTaskProgress(id int64, stage string, progress map[string]any, logLine string) error {
	line := strings.TrimSpace(logLine)
	appendLine := ""
	if line != "" {
		appendLine = line + "\n"
	}
	_, err := d.Exec(`UPDATE deep_tasks
SET stage=$2, progress=$3::jsonb,
    log=CASE WHEN $4='' THEN log ELSE left(log || $4, 131072) END
WHERE id=$1`, id, stage, jsonObject(progress), appendLine)
	return err
}

// FinishDeepTask writes a terminal state only while the task is still running.
func (d *DB) FinishDeepTask(id int64, status, stage, errMsg string, summary map[string]any) error {
	_, err := d.Exec(`UPDATE deep_tasks
SET status=$2, stage=$3, error=$4, summary=$5::jsonb, finished_at=now()
WHERE id=$1 AND status='running'`, id, status, stage, errMsg, jsonObject(summary))
	return err
}

// CancelDeepTask marks a queued/running deep task canceled.
func (d *DB) CancelDeepTask(id int64) (bool, error) {
	res, err := d.Exec(`UPDATE deep_tasks
SET status='canceled', stage='canceled', error='已手动停止', finished_at=now()
WHERE id=$1 AND status IN ('queued','running')`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RecoverInterruptedDeepTasks fails deep tasks left running by a process restart.
func (d *DB) RecoverInterruptedDeepTasks() (int64, error) {
	res, err := d.Exec(`UPDATE deep_tasks
SET status='failed', stage='failed', error='服务重启，任务中断', finished_at=now()
WHERE status='running'`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteDeepTask removes a finished deep task and its records.
func (d *DB) DeleteDeepTask(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM deep_tasks WHERE id=$1 AND status IN ('done','failed','canceled')`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ExploitRecord is one verification or exploitation outcome.
type ExploitRecord struct {
	ID         int64     `json:"id"`
	TaskID     int64     `json:"task_id"`
	Mode       string    `json:"mode"`
	TemplateID string    `json:"template_id"`
	Name       string    `json:"name"`
	Severity   string    `json:"severity"`
	Target     string    `json:"target"`
	Verdict    string    `json:"verdict"`
	StatusCode *int      `json:"status_code,omitempty"`
	Request    string    `json:"request"`
	Response   string    `json:"response"`
	Extracted  []string  `json:"extracted"`
	Curl       string    `json:"curl_command"`
	Evidence   string    `json:"evidence"`
	ElapsedMs  int       `json:"elapsed_ms"`
	CreatedAt  time.Time `json:"created_at"`
}

// AddExploitRecord stores one verification/exploitation outcome.
func (d *DB) AddExploitRecord(rec ExploitRecord) (int64, error) {
	if rec.Extracted == nil {
		rec.Extracted = []string{}
	}
	var id int64
	err := d.QueryRow(`
INSERT INTO exploit_records(task_id, mode, template_id, name, severity, target, verdict,
                            status_code, request, response, extracted, curl_command, evidence, elapsed_ms)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14)
RETURNING id`,
		rec.TaskID, rec.Mode, rec.TemplateID, rec.Name, rec.Severity, rec.Target, rec.Verdict,
		rec.StatusCode, rec.Request, rec.Response, jsonStringArray(rec.Extracted),
		rec.Curl, rec.Evidence, rec.ElapsedMs).Scan(&id)
	return id, err
}

// ListExploitRecords returns the records of one deep task.
func (d *DB) ListExploitRecords(taskID int64) ([]*ExploitRecord, error) {
	rows, err := d.Query(`
SELECT id, task_id, mode, template_id, name, severity, target, verdict, status_code,
       request, response, extracted::text, curl_command, evidence, elapsed_ms, created_at
FROM exploit_records WHERE task_id=$1 ORDER BY id ASC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ExploitRecord{}
	for rows.Next() {
		var r ExploitRecord
		var extractedRaw string
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Mode, &r.TemplateID, &r.Name, &r.Severity, &r.Target,
			&r.Verdict, &r.StatusCode, &r.Request, &r.Response, &extractedRaw, &r.Curl, &r.Evidence,
			&r.ElapsedMs, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(extractedRaw), &r.Extracted)
		if r.Extracted == nil {
			r.Extracted = []string{}
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// WAFBypassResult is one bypass attempt against a protected endpoint.
type WAFBypassResult struct {
	ID          int64     `json:"id"`
	TaskID      int64     `json:"task_id"`
	Target      string    `json:"target"`
	WAFDetected bool      `json:"waf_detected"`
	WAFVendor   string    `json:"waf_vendor"`
	Variant     string    `json:"variant"`
	VariantDesc string    `json:"variant_desc"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	StatusCode  *int      `json:"status_code,omitempty"`
	RespLength  int       `json:"resp_length"`
	Verdict     string    `json:"verdict"`
	Note        string    `json:"note"`
	CreatedAt   time.Time `json:"created_at"`
}

// AddWAFBypassResult stores one bypass attempt.
func (d *DB) AddWAFBypassResult(rec WAFBypassResult) (int64, error) {
	var id int64
	err := d.QueryRow(`
INSERT INTO waf_bypass_results(task_id, target, waf_detected, waf_vendor, variant, variant_desc,
                                method, path, status_code, resp_length, verdict, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
RETURNING id`,
		rec.TaskID, rec.Target, rec.WAFDetected, rec.WAFVendor, rec.Variant, rec.VariantDesc,
		rec.Method, rec.Path, rec.StatusCode, rec.RespLength, rec.Verdict, rec.Note).Scan(&id)
	return id, err
}

// ListWAFBypassResults returns the bypass attempts of one deep task.
func (d *DB) ListWAFBypassResults(taskID int64) ([]*WAFBypassResult, error) {
	rows, err := d.Query(`
SELECT id, task_id, target, waf_detected, waf_vendor, variant, variant_desc, method, path,
       status_code, resp_length, verdict, note, created_at
FROM waf_bypass_results WHERE task_id=$1 ORDER BY id ASC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*WAFBypassResult{}
	for rows.Next() {
		var r WAFBypassResult
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Target, &r.WAFDetected, &r.WAFVendor, &r.Variant,
			&r.VariantDesc, &r.Method, &r.Path, &r.StatusCode, &r.RespLength, &r.Verdict, &r.Note,
			&r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// Webshell is one managed webshell.
type Webshell struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	ShellType   string     `json:"shell_type"`
	Password    string     `json:"password"`
	Target      string     `json:"target"`
	Source      string     `json:"source"`
	TaskID      *int64     `json:"task_id,omitempty"`
	Status      string     `json:"status"`
	Note        string     `json:"note"`
	LastChecked *time.Time `json:"last_checked,omitempty"`
	LastOutput  string     `json:"last_output"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// WebshellInput is the create payload for a webshell.
type WebshellInput struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	ShellType string `json:"shell_type"`
	Password  string `json:"password"`
	Target    string `json:"target"`
	Source    string `json:"source"`
	TaskID    *int64 `json:"task_id"`
	Note      string `json:"note"`
}

// CreateWebshell inserts a webshell record.
func (d *DB) CreateWebshell(in WebshellInput) (*Webshell, error) {
	shellType := strings.ToLower(strings.TrimSpace(in.ShellType))
	switch shellType {
	case "php", "jsp", "aspx":
	default:
		shellType = "php"
	}
	source := strings.ToLower(strings.TrimSpace(in.Source))
	if source != "inject" {
		source = "manual"
	}
	row := d.QueryRow(`
INSERT INTO webshells(name, url, shell_type, password, target, source, task_id, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
RETURNING id, name, url, shell_type, password, target, source, task_id, status, note,
          last_checked, last_output, created_at, updated_at`,
		strings.TrimSpace(in.Name), strings.TrimSpace(in.URL), shellType, in.Password,
		strings.TrimSpace(in.Target), source, in.TaskID, in.Note)
	return d.oneWebshell(row)
}

func (d *DB) oneWebshell(row interface{ Scan(...any) error }) (*Webshell, error) {
	var w Webshell
	if err := row.Scan(&w.ID, &w.Name, &w.URL, &w.ShellType, &w.Password, &w.Target, &w.Source,
		&w.TaskID, &w.Status, &w.Note, &w.LastChecked, &w.LastOutput, &w.CreatedAt, &w.UpdatedAt); err != nil {
		return nil, err
	}
	return &w, nil
}

// GetWebshell returns one webshell.
func (d *DB) GetWebshell(id int64) (*Webshell, error) {
	return d.oneWebshell(d.QueryRow(`
SELECT id, name, url, shell_type, password, target, source, task_id, status, note,
       last_checked, last_output, created_at, updated_at
FROM webshells WHERE id=$1`, id))
}

// ListWebshells returns webshells newest-first, optionally filtered by target.
func (d *DB) ListWebshells(target string, limit, offset int) ([]*Webshell, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	where := ""
	args := []any{}
	if t := strings.TrimSpace(target); t != "" {
		where = " WHERE target=$3"
		args = append(args, t)
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM webshells`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := d.Query(`
SELECT id, name, url, shell_type, password, target, source, task_id, status, note,
       last_checked, last_output, created_at, updated_at
FROM webshells`+where+` ORDER BY id DESC LIMIT $1 OFFSET $2`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*Webshell{}
	for rows.Next() {
		w, err := d.oneWebshell(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, w)
	}
	return out, total, rows.Err()
}

// UpdateWebshellState records the liveness check result and last output.
func (d *DB) UpdateWebshellState(id int64, status, output, note string) error {
	_, err := d.Exec(`UPDATE webshells
SET status=$2, last_output=$3, note=CASE WHEN $4='' THEN note ELSE $4 END, last_checked=now()
WHERE id=$1`, id, status, output, note)
	return err
}

// UpdateWebshell updates the editable fields of a webshell.
func (d *DB) UpdateWebshell(id int64, in WebshellInput) error {
	shellType := strings.ToLower(strings.TrimSpace(in.ShellType))
	switch shellType {
	case "php", "jsp", "aspx":
	default:
		shellType = "php"
	}
	_, err := d.Exec(`UPDATE webshells
SET name=$2, url=$3, shell_type=$4, password=$5, target=$6, note=$7
WHERE id=$1`, id, strings.TrimSpace(in.Name), strings.TrimSpace(in.URL), shellType,
		in.Password, strings.TrimSpace(in.Target), in.Note)
	return err
}

// DeleteWebshell removes a webshell record.
func (d *DB) DeleteWebshell(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM webshells WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
