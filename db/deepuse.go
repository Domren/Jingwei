package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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

// ScanAutoStats aggregates the deep tasks one scan spawned in its current run.
// A rerun resets started_at, so tasks from an earlier run are excluded exactly
// like ListDeepTasksByScan.
type ScanAutoStats struct {
	Tasks     int `json:"tasks"`
	Done      int `json:"done"`
	Running   int `json:"running"`
	Failed    int `json:"failed"` // failed + canceled
	Records   int `json:"records"`
	Confirmed int `json:"confirmed"`
}

func (d *DB) ScanAutoStats(scanTaskID int64) (ScanAutoStats, error) {
	var st ScanAutoStats
	err := d.QueryRow(`
WITH dt AS (
    SELECT id, status FROM deep_tasks
    WHERE scan_task_id=$1
      AND created_at >= COALESCE((SELECT started_at FROM scan_tasks WHERE id=$1), now())
), rec AS (
    SELECT r.verdict FROM exploit_records r JOIN dt ON dt.id=r.task_id
)
SELECT (SELECT count(*) FROM dt),
       (SELECT count(*) FROM dt WHERE status='done'),
       (SELECT count(*) FROM dt WHERE status='running'),
       (SELECT count(*) FROM dt WHERE status IN ('failed','canceled')),
       (SELECT count(*) FROM rec),
       (SELECT count(*) FROM rec WHERE verdict='confirmed')`, scanTaskID).
		Scan(&st.Tasks, &st.Done, &st.Running, &st.Failed, &st.Records, &st.Confirmed)
	return st, err
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

// QueuedDeepProxies 按 FIFO 列出排队的深挖任务与它们各自的出站代理（存在 params 里）。
// 深挖任务（sqlmap/dalfox）与漏扫共用一条隧道时，两者会互相把对方挤成超时，
// 所以并发预算必须同时看得见这两类任务。
func (d *DB) QueuedDeepProxies(limit int) ([]QueuedProxyTask, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := d.Query(`SELECT id, COALESCE(params->>'proxy','') FROM deep_tasks WHERE status='queued' ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QueuedProxyTask{}
	for rows.Next() {
		var q QueuedProxyTask
		if err := rows.Scan(&q.ID, &q.Proxy); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// SetDeepTaskQueueNote 写明深挖任务为什么还在排队；认领时 progress 会整体重置。
func (d *DB) SetDeepTaskQueueNote(id int64, note string) error {
	_, err := d.Exec(`UPDATE deep_tasks
SET progress = CASE WHEN $2='' THEN progress - 'queue_note'
                    ELSE progress || jsonb_build_object('queue_note', $2) END
WHERE id=$1 AND status='queued'
      AND (progress->>'queue_note') IS DISTINCT FROM $2`, id, strings.TrimSpace(note))
	return err
}

// ClaimDeepTask 按 ID 认领一条排队任务。False 表示已被别的执行者抢走或状态已变，
// 调用方要放弃这一格名额去看下一个候选。
func (d *DB) ClaimDeepTask(id int64) (bool, error) {
	res, err := d.Exec(`UPDATE deep_tasks
SET status='running', stage='start', started_at=now(), finished_at=NULL, error='', progress='{}'::jsonb
WHERE id=$1 AND status='queued'`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// 排队深挖任务的认领只有一条路：QueuedDeepProxies 按 FIFO 取候选 + ClaimDeepTask 按 ID
// 抢占。跳过隧道并发预算的「直接认领最老的排队任务」已经被删掉——留一条近路，预算就会
// 在某个不明显的时刻被绕过。
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

// WAFBypassResult is one bypass attempt against a protected endpoint. The
// attempt/stop_reason/block_feature/final_verdict/baseline_blocked fields make
// the campaign quantifiable: the same POC against a WAF vs a non-WAF target
// yields a different Attempts/StopReason/FinalVerdict instead of just a list of
// per-variant verdicts.
type WAFBypassResult struct {
	ID             int64     `json:"id"`
	TaskID         int64     `json:"task_id"`
	Target         string    `json:"target"`
	WAFDetected    bool      `json:"waf_detected"`
	WAFVendor      string    `json:"waf_vendor"`
	Variant        string    `json:"variant"`
	VariantDesc    string    `json:"variant_desc"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	StatusCode     *int      `json:"status_code,omitempty"`
	RespLength     int       `json:"resp_length"`
	Verdict        string    `json:"verdict"`
	Note           string    `json:"note"`
	Attempt        int       `json:"attempt"`
	StopReason     string    `json:"stop_reason"`
	BlockFeature   string    `json:"block_feature"`
	FinalVerdict   string    `json:"final_verdict"`
	BaselineBlocked bool     `json:"baseline_blocked"`
	CreatedAt      time.Time `json:"created_at"`
}

// AddWAFBypassResult stores one bypass attempt.
func (d *DB) AddWAFBypassResult(rec WAFBypassResult) (int64, error) {
	var id int64
	err := d.QueryRow(`
INSERT INTO waf_bypass_results(task_id, target, waf_detected, waf_vendor, variant, variant_desc,
                                method, path, status_code, resp_length, verdict, note,
                                attempt, stop_reason, block_feature, final_verdict, baseline_blocked)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
RETURNING id`,
		rec.TaskID, rec.Target, rec.WAFDetected, rec.WAFVendor, rec.Variant, rec.VariantDesc,
		rec.Method, rec.Path, rec.StatusCode, rec.RespLength, rec.Verdict, rec.Note,
		rec.Attempt, rec.StopReason, rec.BlockFeature, rec.FinalVerdict, rec.BaselineBlocked).Scan(&id)
	return id, err
}

// ListWAFBypassResults returns the bypass attempts of one deep task.
func (d *DB) ListWAFBypassResults(taskID int64) ([]*WAFBypassResult, error) {
	rows, err := d.Query(`
SELECT id, task_id, target, waf_detected, waf_vendor, variant, variant_desc, method, path,
       status_code, resp_length, verdict, note, attempt, stop_reason, block_feature,
       final_verdict, baseline_blocked, created_at
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
			&r.Attempt, &r.StopReason, &r.BlockFeature, &r.FinalVerdict, &r.BaselineBlocked,
			&r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// Webshell is one managed webshell. Password and Secret are write-only from the
// API's perspective: responses only expose has_password/has_secret so a shell
// credential never round-trips to the browser or into logs.
type Webshell struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	ShellType     string     `json:"shell_type"`
	Protocol      string     `json:"protocol"`
	Password      string     `json:"-"`
	HasPassword   bool       `json:"has_password"`
	Secret        string     `json:"-"`
	HasSecret     bool       `json:"has_secret"`
	Carrier       string     `json:"carrier"`
	PayloadSHA256 string     `json:"payload_sha256"`
	KeyVersion    int        `json:"key_version"`
	Target        string     `json:"target"`
	Source        string     `json:"source"`
	TaskID        *int64     `json:"task_id,omitempty"`
	Status        string     `json:"status"`
	Note          string     `json:"note"`
	LastChecked   *time.Time `json:"last_checked,omitempty"`
	LastOutput    string     `json:"last_output"`
	OSKind        string     `json:"os_kind"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// WebshellInput is the create/update payload for a webshell. Secret is never
// accepted from the client; it is generated server-side and sealed at rest.
type WebshellInput struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	ShellType     string `json:"shell_type"`
	Protocol      string `json:"protocol"`
	Password      string `json:"password"`
	Secret        string `json:"-"`
	Carrier       string `json:"carrier"`
	PayloadSHA256 string `json:"payload_sha256"`
	KeyVersion    int    `json:"key_version"`
	Target        string `json:"target"`
	Source        string `json:"source"`
	TaskID        *int64 `json:"task_id"`
	Note          string `json:"note"`
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
	if source != "inject" && source != "php_prepend" {
		source = "manual"
	}
	protocol := strings.ToLower(strings.TrimSpace(in.Protocol))
	if protocol != "v2" {
		protocol = "legacy"
	}
	// A semi-persistent shell is always an encrypted PHP prepend payload; refuse
	// to mislabel legacy/JSP/ASPX records and fall back to manual.
	if source == "php_prepend" && (protocol != "v2" || shellType != "php") {
		source = "manual"
	}
	keyVersion := in.KeyVersion
	if keyVersion <= 0 {
		keyVersion = 1
	}
	row := d.QueryRow(`
INSERT INTO webshells(name, url, shell_type, protocol, password, secret, carrier,
    payload_sha256, key_version, target, source, task_id, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
RETURNING `+webshellCols,
		strings.TrimSpace(in.Name), strings.TrimSpace(in.URL), shellType, protocol,
		in.Password, in.Secret, strings.TrimSpace(in.Carrier), strings.TrimSpace(in.PayloadSHA256),
		keyVersion, strings.TrimSpace(in.Target), source, in.TaskID, in.Note)
	return d.oneWebshell(row)
}

const webshellCols = `id, name, url, shell_type, protocol, password, secret, carrier,
	payload_sha256, key_version, target, source, task_id, status, note,
	last_checked, last_output, os_kind, created_at, updated_at`

func (d *DB) oneWebshell(row interface{ Scan(...any) error }) (*Webshell, error) {
	var w Webshell
	if err := row.Scan(&w.ID, &w.Name, &w.URL, &w.ShellType, &w.Protocol, &w.Password, &w.Secret,
		&w.Carrier, &w.PayloadSHA256, &w.KeyVersion, &w.Target, &w.Source,
		&w.TaskID, &w.Status, &w.Note, &w.LastChecked, &w.LastOutput, &w.OSKind,
		&w.CreatedAt, &w.UpdatedAt); err != nil {
		return nil, err
	}
	w.HasPassword = w.Password != ""
	w.HasSecret = w.Secret != ""
	return &w, nil
}

// GetWebshell returns one webshell.
func (d *DB) GetWebshell(id int64) (*Webshell, error) {
	return d.oneWebshell(d.QueryRow(`SELECT `+webshellCols+` FROM webshells WHERE id=$1`, id))
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
	rows, err := d.Query(`SELECT `+webshellCols+` FROM webshells`+where+` ORDER BY id DESC LIMIT $1 OFFSET $2`, args...)
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

// FindWebshellByURL returns the newest record registered for exactly this land
// URL. Re-injecting onto that path replaces the file on the target, so whoever
// owns the URL has to be decided before the upload, not after: two rows for one
// path mean evacuation self-deletes a payload that no longer exists while the
// live file stays behind. sql.ErrNoRows means nothing is registered there.
func (d *DB) FindWebshellByURL(rawURL string) (*Webshell, error) {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		return nil, sql.ErrNoRows
	}
	return d.oneWebshell(d.QueryRow(`SELECT `+webshellCols+` FROM webshells
WHERE url=$1 ORDER BY id DESC LIMIT 1`, u))
}

// ReclaimWebshellForReinject re-points an existing record at the payload now
// occupying its URL, keeping the id so bound sessions and the resource ledger
// stay meaningful. Status goes back to unknown: the file was just replaced and
// nothing has spoken to it since.
func (d *DB) ReclaimWebshellForReinject(id int64, in WebshellInput) (*Webshell, error) {
	shellType := strings.ToLower(strings.TrimSpace(in.ShellType))
	switch shellType {
	case "php", "jsp", "aspx":
	default:
		shellType = "php"
	}
	source := strings.ToLower(strings.TrimSpace(in.Source))
	switch source {
	case "inject", "php_prepend", "manual":
	default:
		source = "manual"
	}
	protocol := strings.ToLower(strings.TrimSpace(in.Protocol))
	if protocol != "v2" {
		protocol = "legacy"
	}
	keyVersion := in.KeyVersion
	if keyVersion <= 0 {
		keyVersion = 1
	}
	return d.oneWebshell(d.QueryRow(`UPDATE webshells
SET name=$2, url=$3, shell_type=$4, protocol=$5, password=$6, secret=$7, carrier=$8,
    payload_sha256=$9, key_version=$10, target=$11, source=$12, task_id=$13, note=$14,
    status='unknown', last_output='', last_checked=NULL, os_kind=''
WHERE id=$1
RETURNING `+webshellCols,
		id, strings.TrimSpace(in.Name), strings.TrimSpace(in.URL), shellType, protocol,
		in.Password, in.Secret, strings.TrimSpace(in.Carrier), strings.TrimSpace(in.PayloadSHA256),
		keyVersion, strings.TrimSpace(in.Target), source, in.TaskID, in.Note))
}

// UpdateWebshellState records the liveness check result and last output.
func (d *DB) UpdateWebshellState(id int64, status, output, note string) error {
	_, err := d.Exec(`UPDATE webshells
SET status=$2, last_output=$3, note=CASE WHEN $4='' THEN note ELSE $4 END, last_checked=now()
WHERE id=$1`, id, status, output, note)
	return err
}

// UpdateWebshellTerminal caches the probed shell family alongside the result of
// one terminal turn. Empty os_kind means "this turn did not learn one" and
// leaves the stored value alone: a probe that failed because the shell was
// briefly down must not silently rewrite a Windows target as POSIX.
//
// There is deliberately no cwd here. The directory belongs to an interactive
// context, not to the landed file: one webshell can carry any number of intranet
// sessions (intranet_sessions.webshell_id is not unique) and each already keeps
// its own cwd. A second copy on this row would be a second truth for the same
// target, and the two would disagree in silence.
func (d *DB) UpdateWebshellTerminal(id int64, osKind, status, output string) error {
	_, err := d.Exec(`UPDATE webshells
SET os_kind=CASE WHEN $2='' THEN os_kind ELSE $2 END,
    status=$3, last_output=$4, last_checked=now()
WHERE id=$1`, id, osKind, status, output)
	return err
}

// UpdateWebshell updates the editable fields of a webshell. An empty password
// keeps the stored one; protocol/secret/carrier are managed by the server.
// os_kind describes the machine behind one specific URL, so it only survives an
// edit that left both the address and the shell family alone.
func (d *DB) UpdateWebshell(id int64, in WebshellInput) error {
	shellType := strings.ToLower(strings.TrimSpace(in.ShellType))
	switch shellType {
	case "php", "jsp", "aspx":
	default:
		shellType = "php"
	}
	_, err := d.Exec(`UPDATE webshells
SET name=$2, url=$3, shell_type=$4, target=$5, note=$6,
    password=CASE WHEN $7='' THEN password ELSE $7 END,
    os_kind=CASE WHEN url=$3 AND shell_type=$4 THEN os_kind ELSE '' END
WHERE id=$1`, id, strings.TrimSpace(in.Name), strings.TrimSpace(in.URL), shellType,
		strings.TrimSpace(in.Target), in.Note, in.Password)
	return err
}

// UpdateWebshellSecret stores a new v2 secret/carrier/fingerprint after creation
// or key rotation. The caller seals the secret before handing it over.
func (d *DB) UpdateWebshellSecret(id int64, secret, carrier, payloadSHA256 string, keyVersion int) error {
	if keyVersion <= 0 {
		keyVersion = 1
	}
	_, err := d.Exec(`UPDATE webshells
SET secret=$2, carrier=$3, payload_sha256=$4, key_version=$5
WHERE id=$1`, id, secret, strings.TrimSpace(carrier), strings.TrimSpace(payloadSHA256), keyVersion)
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

// JavaMemshell is one in-memory endpoint injected through a v2 webshell. The
// key is sealed at rest and never serialized to API clients.
type JavaMemshell struct {
	ID          int64      `json:"id"`
	WebshellID  *int64     `json:"webshell_id,omitempty"`
	TaskID      *int64     `json:"task_id,omitempty"`
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	Path        string     `json:"path"`
	URL         string     `json:"url"`
	Port        int        `json:"port"`
	Secret      string     `json:"-"`
	HasSecret   bool       `json:"has_secret"`
	Carrier     string     `json:"carrier"`
	Target      string     `json:"target"`
	Container   string     `json:"container"`
	ServletAPI  string     `json:"servlet_api"`
	Status      string     `json:"status"`
	Note        string     `json:"note"`
	LastChecked *time.Time `json:"last_checked,omitempty"`
	LastOutput  string     `json:"last_output"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// JavaMemshellInput is the server-side insert payload. Secret is sealed by the
// caller; the client never supplies it.
type JavaMemshellInput struct {
	WebshellID *int64
	TaskID     *int64
	Type       string
	Name       string
	Path       string
	URL        string
	Port       int
	Secret     string
	Carrier    string
	Target     string
	Container  string
	ServletAPI string
	Status     string
	Note       string
}

const javaMemshellCols = `id, webshell_id, task_id, type, name, path, url, port, secret,
	carrier, target, container, servlet_api, status, note, last_checked, last_output,
	created_at, updated_at`

func scanJavaMemshell(row interface{ Scan(...any) error }) (*JavaMemshell, error) {
	var m JavaMemshell
	if err := row.Scan(&m.ID, &m.WebshellID, &m.TaskID, &m.Type, &m.Name, &m.Path, &m.URL,
		&m.Port, &m.Secret, &m.Carrier, &m.Target, &m.Container, &m.ServletAPI,
		&m.Status, &m.Note, &m.LastChecked, &m.LastOutput, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return nil, err
	}
	m.HasSecret = m.Secret != ""
	return &m, nil
}

// CreateJavaMemshell inserts a memory-shell record.
func (d *DB) CreateJavaMemshell(in JavaMemshellInput) (*JavaMemshell, error) {
	status := strings.ToLower(strings.TrimSpace(in.Status))
	switch status {
	case "alive", "dead", "removed":
	default:
		status = "unknown"
	}
	if in.Port < 0 || in.Port > 65535 {
		in.Port = 0
	}
	return scanJavaMemshell(d.QueryRow(`
INSERT INTO java_memshells(webshell_id, task_id, type, name, path, url, port, secret,
    carrier, target, container, servlet_api, status, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
RETURNING `+javaMemshellCols,
		in.WebshellID, in.TaskID, strings.ToLower(strings.TrimSpace(in.Type)),
		strings.TrimSpace(in.Name), strings.TrimSpace(in.Path), strings.TrimSpace(in.URL),
		in.Port, in.Secret, strings.TrimSpace(in.Carrier), strings.TrimSpace(in.Target),
		strings.TrimSpace(in.Container), strings.TrimSpace(in.ServletAPI), status, in.Note))
}

// GetJavaMemshell returns one memory-shell record.
func (d *DB) GetJavaMemshell(id int64) (*JavaMemshell, error) {
	return scanJavaMemshell(d.QueryRow(`SELECT `+javaMemshellCols+` FROM java_memshells WHERE id=$1`, id))
}

// JavaMemshellFilter selects memory shells for listing.
type JavaMemshellFilter struct {
	WebshellID int64
	TaskID     int64
	Status     string
	Target     string
	Limit      int
	Offset     int
}

// ListJavaMemshells returns records newest-first with optional filters.
func (d *DB) ListJavaMemshells(f JavaMemshellFilter) ([]*JavaMemshell, int, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where := []string{}
	args := []any{}
	add := func(expr string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(expr, "?", "$"+strconv.Itoa(len(args))))
	}
	if f.WebshellID > 0 {
		add("webshell_id=?", f.WebshellID)
	}
	if f.TaskID > 0 {
		add("task_id=?", f.TaskID)
	}
	if s := strings.ToLower(strings.TrimSpace(f.Status)); s != "" {
		switch s {
		case "active":
			where = append(where, "status IN ('alive','unknown')")
		default:
			add("status=?", s)
		}
	}
	if t := strings.TrimSpace(f.Target); t != "" {
		add("target=?", t)
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM java_memshells`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := d.Query(`SELECT `+javaMemshellCols+` FROM java_memshells`+clause+
		` ORDER BY id DESC LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*JavaMemshell{}
	for rows.Next() {
		m, err := scanJavaMemshell(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	return out, total, rows.Err()
}

// UpdateJavaMemshellState records a liveness/probe result.
func (d *DB) UpdateJavaMemshellState(id int64, status, output, note string) error {
	_, err := d.Exec(`UPDATE java_memshells
SET status=$2, last_output=$3, note=CASE WHEN $4='' THEN note ELSE $4 END,
    last_checked=now()
WHERE id=$1`, id, status, output, note)
	return err
}

// UpdateJavaMemshellProbe refreshes status plus the container signature found
// by a probe. Empty container/api values keep the previous ones.
func (d *DB) UpdateJavaMemshellProbe(id int64, status, container, servletAPI, note string) error {
	_, err := d.Exec(`UPDATE java_memshells
SET status=$2,
    container=CASE WHEN $3='' THEN container ELSE $3 END,
    servlet_api=CASE WHEN $4='' THEN servlet_api ELSE $4 END,
    note=CASE WHEN $5='' THEN note ELSE $5 END,
    last_checked=now()
WHERE id=$1`, id, status, strings.TrimSpace(container), strings.TrimSpace(servletAPI), note)
	return err
}

// CountJavaMemshellsByWebshell counts rows derived from a parent webshell.
func (d *DB) CountJavaMemshellsByWebshell(webshellID int64) (int, error) {
	var n int
	err := d.QueryRow(`SELECT count(*) FROM java_memshells WHERE webshell_id=$1`, webshellID).Scan(&n)
	return n, err
}

// ListJavaMemshellsByWebshells returns every memory shell whose parent is one
// of the given webshell ids. Used by evacuation to clean children first.
func (d *DB) ListJavaMemshellsByWebshells(webshellIDs []int64) ([]*JavaMemshell, error) {
	if len(webshellIDs) == 0 {
		return []*JavaMemshell{}, nil
	}
	placeholders := make([]string, len(webshellIDs))
	args := make([]any, len(webshellIDs))
	for i, id := range webshellIDs {
		placeholders[i] = "$" + strconv.Itoa(i+1)
		args[i] = id
	}
	rows, err := d.Query(`SELECT `+javaMemshellCols+` FROM java_memshells
WHERE webshell_id IN (`+strings.Join(placeholders, ",")+`) ORDER BY id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*JavaMemshell{}
	for rows.Next() {
		m, err := scanJavaMemshell(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteJavaMemshell removes a memory-shell record.
func (d *DB) DeleteJavaMemshell(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM java_memshells WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
