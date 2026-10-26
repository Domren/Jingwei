package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrScanTaskNotFound = errors.New("scan task not found")

// ScanTask is one LLM-free automated scan run.
type ScanTask struct {
	ID             int64          `json:"id"`
	Name           string         `json:"name"`
	Targets        []string       `json:"targets"`
	Mode           string         `json:"mode"` // auto | selected | full
	POCIDs         []int64        `json:"poc_ids"`
	Ports          string         `json:"ports"` // web | top100 | full | custom spec
	MinSeverity    string         `json:"min_severity"`
	Fingerprint    bool           `json:"fingerprint"`
	CreateFindings bool           `json:"create_findings"`
	WebshellInject bool           `json:"webshell_inject"`
	WebshellParams map[string]any `json:"webshell_params"`
	RateLimit      int            `json:"rate_limit"`
	Concurrency    int            `json:"concurrency"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	Status         string         `json:"status"` // queued | running | done | failed | canceled
	Stage          string         `json:"stage"`  // queued | discover | fingerprint | match | scan | done | failed | canceled
	Progress       map[string]any `json:"progress"`
	Summary        map[string]any `json:"summary"`
	Log            string         `json:"log,omitempty"`
	Error          string         `json:"error,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	FinishedAt     *time.Time     `json:"finished_at,omitempty"`
}

// ScanTaskInput is the create payload for a scan task.
type ScanTaskInput struct {
	Name           string         `json:"name"`
	Targets        []string       `json:"targets"`
	Mode           string         `json:"mode"`
	POCIDs         []int64        `json:"poc_ids"`
	Ports          string         `json:"ports"`
	MinSeverity    string         `json:"min_severity"`
	Fingerprint    bool           `json:"fingerprint"`
	CreateFindings bool           `json:"create_findings"`
	WebshellInject bool           `json:"webshell_inject"`
	WebshellParams map[string]any `json:"webshell_params"`
	RateLimit      int            `json:"rate_limit"`
	Concurrency    int            `json:"concurrency"`
	TimeoutSeconds int            `json:"timeout_seconds"`
}

// ScanTaskAsset links one discovered asset to a scan task and keeps the
// presentation fields captured at discovery time.
type ScanTaskAsset struct {
	AssetID      int64     `json:"asset_id"`
	AssetType    string    `json:"asset_type"`
	Host         string    `json:"host"`
	URL          string    `json:"url"`
	Note         string    `json:"note"`
	StatusCode   *int      `json:"status_code,omitempty"`
	PageTitle    string    `json:"page_title"`
	Technologies []string  `json:"technologies"`
	CreatedAt    time.Time `json:"created_at"`
}

// ScanTaskResult stores one nuclei match.
type ScanTaskResult struct {
	ID            int64          `json:"id"`
	FindingID     *int64         `json:"finding_id,omitempty"`
	TemplateID    string         `json:"template_id"`
	Name          string         `json:"name"`
	Severity      string         `json:"severity"`
	Host          string         `json:"host"`
	MatchedAt     string         `json:"matched_at"`
	Type          string         `json:"type"`
	Curl          string         `json:"curl_command,omitempty"`
	Extracted     []string       `json:"extracted"`
	Raw           map[string]any `json:"raw,omitempty"`
	FindingStatus string         `json:"finding_status,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

const scanTaskCols = `id, name, targets::text, mode, poc_ids::text, ports, min_severity,
       fingerprint, create_findings, webshell_inject, webshell_params::text,
       rate_limit, concurrency, timeout_seconds,
       status, stage, progress::text, summary::text, log, error,
       created_at, started_at, finished_at`

func scanOneScanTask(row interface{ Scan(...any) error }) (*ScanTask, error) {
	var t ScanTask
	var targetsRaw, pocRaw, webshellRaw, progressRaw, summaryRaw string
	if err := row.Scan(&t.ID, &t.Name, &targetsRaw, &t.Mode, &pocRaw, &t.Ports, &t.MinSeverity,
		&t.Fingerprint, &t.CreateFindings, &t.WebshellInject, &webshellRaw,
		&t.RateLimit, &t.Concurrency, &t.TimeoutSeconds,
		&t.Status, &t.Stage, &progressRaw, &summaryRaw, &t.Log, &t.Error,
		&t.CreatedAt, &t.StartedAt, &t.FinishedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(targetsRaw), &t.Targets)
	_ = json.Unmarshal([]byte(pocRaw), &t.POCIDs)
	_ = json.Unmarshal([]byte(webshellRaw), &t.WebshellParams)
	_ = json.Unmarshal([]byte(progressRaw), &t.Progress)
	_ = json.Unmarshal([]byte(summaryRaw), &t.Summary)
	if t.WebshellParams == nil {
		t.WebshellParams = map[string]any{}
	}
	if t.Targets == nil {
		t.Targets = []string{}
	}
	if t.POCIDs == nil {
		t.POCIDs = []int64{}
	}
	if t.Progress == nil {
		t.Progress = map[string]any{}
	}
	if t.Summary == nil {
		t.Summary = map[string]any{}
	}
	return &t, nil
}

func jsonStringArray(items []string) string {
	if items == nil {
		items = []string{}
	}
	b, _ := json.Marshal(items)
	return string(b)
}

func jsonInt64Array(items []int64) string {
	if items == nil {
		items = []int64{}
	}
	b, _ := json.Marshal(items)
	return string(b)
}

func jsonObject(v map[string]any) string {
	if v == nil {
		v = map[string]any{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// CreateScanTask inserts a queued scan task.
func (d *DB) CreateScanTask(in ScanTaskInput) (*ScanTask, error) {
	if in.RateLimit <= 0 {
		in.RateLimit = 50
	}
	if in.Concurrency <= 0 {
		in.Concurrency = 25
	}
	if in.TimeoutSeconds <= 0 {
		in.TimeoutSeconds = 600
	}
	row := d.QueryRow(`
INSERT INTO scan_tasks(name, targets, mode, poc_ids, ports, min_severity, fingerprint,
                       create_findings, webshell_inject, webshell_params,
                       rate_limit, concurrency, timeout_seconds)
VALUES ($1, $2::jsonb, $3, $4::jsonb, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13)
RETURNING `+scanTaskCols,
		strings.TrimSpace(in.Name), jsonStringArray(in.Targets), in.Mode, jsonInt64Array(in.POCIDs),
		in.Ports, in.MinSeverity, in.Fingerprint, in.CreateFindings,
		in.WebshellInject, jsonObject(in.WebshellParams),
		in.RateLimit, in.Concurrency, in.TimeoutSeconds)
	return scanOneScanTask(row)
}

// ListScanTasks returns newest-first scan tasks.
func (d *DB) ListScanTasks(limit, offset int) ([]*ScanTask, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM scan_tasks`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.Query(`SELECT `+scanTaskCols+` FROM scan_tasks ORDER BY id DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*ScanTask{}
	for rows.Next() {
		t, err := scanOneScanTask(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// GetScanTask returns one scan task.
func (d *DB) GetScanTask(id int64) (*ScanTask, error) {
	t, err := scanOneScanTask(d.QueryRow(`SELECT `+scanTaskCols+` FROM scan_tasks WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrScanTaskNotFound
	}
	return t, err
}

// ClaimNextScanTask atomically claims the oldest queued task for execution.
// It returns (nil, nil) when the queue is empty.
func (d *DB) ClaimNextScanTask() (*ScanTask, error) {
	t, err := scanOneScanTask(d.QueryRow(`UPDATE scan_tasks
SET status='running', stage='discover', started_at=now(), finished_at=NULL, error='', progress='{}'::jsonb
WHERE id=(SELECT id FROM scan_tasks WHERE status='queued' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING ` + scanTaskCols))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// ClaimScanTask atomically moves a queued task to running. False means another
// worker claimed it or it was canceled.
func (d *DB) ClaimScanTask(id int64) (bool, error) {
	res, err := d.Exec(`UPDATE scan_tasks
SET status='running', stage='discover', started_at=now(), finished_at=NULL, error='', progress='{}'::jsonb
WHERE id=$1 AND status='queued'`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// UpdateScanProgress persists the current stage/counters and appends a log line.
func (d *DB) UpdateScanProgress(id int64, stage string, progress map[string]any, logLine string) error {
	line := strings.TrimSpace(logLine)
	appendLine := ""
	if line != "" {
		appendLine = line + "\n"
	}
	_, err := d.Exec(`UPDATE scan_tasks
SET stage=$2, progress=$3::jsonb,
    log=CASE WHEN $4='' THEN log ELSE left(log || $4, 131072) END
WHERE id=$1`, id, stage, jsonObject(progress), appendLine)
	return err
}

// AppendScanLog appends a line without changing stage/progress.
func (d *DB) AppendScanLog(id int64, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	_, err := d.Exec(`UPDATE scan_tasks SET log=left(log || $2, 131072) WHERE id=$1`, id, line+"\n")
	return err
}

// FinishScanTask writes a terminal state only while the task is still running.
// A manual cancel sets status=canceled first and is therefore never overwritten.
func (d *DB) FinishScanTask(id int64, status, stage, errMsg string, summary map[string]any) error {
	_, err := d.Exec(`UPDATE scan_tasks
SET status=$2, stage=$3, error=$4, summary=$5::jsonb, finished_at=now()
WHERE id=$1 AND status='running'`,
		id, status, stage, errMsg, jsonObject(summary))
	return err
}

// CancelScanTask marks a queued/running task canceled. The executor's context
// is canceled separately by the manager.
func (d *DB) CancelScanTask(id int64) (bool, error) {
	res, err := d.Exec(`UPDATE scan_tasks
SET status='canceled', stage='canceled', error='已手动停止', finished_at=now()
WHERE id=$1 AND status IN ('queued','running')`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RecoverInterruptedScanTasks fails tasks left running by a process restart.
func (d *DB) RecoverInterruptedScanTasks() (int64, error) {
	res, err := d.Exec(`UPDATE scan_tasks
SET status='failed', stage='failed', error='服务重启，扫描中断', finished_at=now()
WHERE status='running'`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteScanTask removes a finished task and its results/links.
func (d *DB) DeleteScanTask(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM scan_tasks WHERE id=$1 AND status IN ('done','failed','canceled')`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// QueueScanTask resets a finished task for another run, clearing prior
// asset links and results in the same transaction so a fast worker can never
// pick it up before the old output is gone.
func (d *DB) QueueScanTask(id int64) (bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM scan_task_results WHERE scan_task_id=$1`, id); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM scan_task_assets WHERE scan_task_id=$1`, id); err != nil {
		return false, err
	}
	res, err := tx.Exec(`UPDATE scan_tasks
SET status='queued', stage='queued', progress='{}'::jsonb, summary='{}'::jsonb,
    log='', error='', started_at=NULL, finished_at=NULL
WHERE id=$1 AND status IN ('done','failed','canceled')`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// AddScanTaskAsset upserts one asset link.
func (d *DB) AddScanTaskAsset(taskID int64, a ScanTaskAsset) error {
	techs := a.Technologies
	if techs == nil {
		techs = []string{}
	}
	raw, _ := json.Marshal(techs)
	_, err := d.Exec(`
INSERT INTO scan_task_assets(scan_task_id, asset_id, asset_type, host, url, note, status_code, page_title, technologies)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
ON CONFLICT (scan_task_id, asset_id) DO UPDATE SET
    asset_type=EXCLUDED.asset_type,
    host=EXCLUDED.host,
    url=EXCLUDED.url,
    note=EXCLUDED.note,
    status_code=COALESCE(EXCLUDED.status_code, scan_task_assets.status_code),
    page_title=EXCLUDED.page_title,
    technologies=EXCLUDED.technologies
`, taskID, a.AssetID, a.AssetType, a.Host, a.URL, a.Note, a.StatusCode, a.PageTitle, string(raw))
	return err
}

// ListScanTaskAssets returns the assets captured by one scan.
func (d *DB) ListScanTaskAssets(taskID int64, limit int) ([]ScanTaskAsset, error) {
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	rows, err := d.Query(`SELECT asset_id, asset_type, host, url, note, status_code, page_title, technologies::text, created_at
FROM scan_task_assets WHERE scan_task_id=$1 ORDER BY asset_type, asset_id LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanTaskAsset{}
	for rows.Next() {
		var a ScanTaskAsset
		var techsRaw string
		if err := rows.Scan(&a.AssetID, &a.AssetType, &a.Host, &a.URL, &a.Note, &a.StatusCode, &a.PageTitle, &techsRaw, &a.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(techsRaw), &a.Technologies)
		if a.Technologies == nil {
			a.Technologies = []string{}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddScanTaskResult inserts a nuclei match; a duplicate returns id=0.
func (d *DB) AddScanTaskResult(taskID int64, findingID int64, r ScanTaskResult) (int64, error) {
	extracted := r.Extracted
	if extracted == nil {
		extracted = []string{}
	}
	extJSON, _ := json.Marshal(extracted)
	rawJSON, _ := json.Marshal(r.Raw)
	if len(rawJSON) == 0 || string(rawJSON) == "null" {
		rawJSON = []byte("{}")
	}
	var fid any
	if findingID > 0 {
		fid = findingID
	}
	var id int64
	err := d.QueryRow(`
INSERT INTO scan_task_results(scan_task_id, finding_id, template_id, name, severity, host, matched_at, type, curl_command, extracted, raw)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb)
ON CONFLICT (scan_task_id, template_id, matched_at) DO NOTHING
RETURNING id`,
		taskID, fid, r.TemplateID, r.Name, r.Severity, r.Host, r.MatchedAt, r.Type, r.Curl, string(extJSON), string(rawJSON)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// ListScanTaskResults returns matches newest-first with finding triage state.
func (d *DB) ListScanTaskResults(taskID int64, limit int) ([]ScanTaskResult, error) {
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	rows, err := d.Query(`SELECT r.id, r.finding_id, r.template_id, r.name, r.severity, r.host, r.matched_at,
       r.type, r.curl_command, r.extracted::text, r.raw::text, COALESCE(f.status,''), r.created_at
FROM scan_task_results r LEFT JOIN findings f ON f.id=r.finding_id
WHERE r.scan_task_id=$1 ORDER BY r.id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanTaskResult{}
	for rows.Next() {
		var r ScanTaskResult
		var extractedRaw, rawRaw string
		if err := rows.Scan(&r.ID, &r.FindingID, &r.TemplateID, &r.Name, &r.Severity, &r.Host, &r.MatchedAt,
			&r.Type, &r.Curl, &extractedRaw, &rawRaw, &r.FindingStatus, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(extractedRaw), &r.Extracted)
		_ = json.Unmarshal([]byte(rawRaw), &r.Raw)
		if r.Extracted == nil {
			r.Extracted = []string{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListEnabledPOCMetadata returns enabled templates without their YAML bodies,
// used to match fingerprints before loading only the selected templates.
func (d *DB) ListEnabledPOCMetadata() ([]POCTemplate, error) {
	rows, err := d.Query(`SELECT ` + pocCols + ` FROM poc_templates WHERE enabled ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []POCTemplate{}
	for rows.Next() {
		p, err := scanPOC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListEnabledPOCContents returns enabled templates with bodies for a full scan,
// most dangerous severity first, plus the total enabled count so the caller can
// log how many low-severity templates the limit dropped. Ordering by id (the old
// behaviour) silently cut the newest templates whenever the library grew past
// the cap — exactly the ones a lab backfill adds — so a full scan could lose a
// whole target's coverage without any trace in the log.
func (d *DB) ListEnabledPOCContents(limit int) ([]POCTemplate, int, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := d.Query(`SELECT `+pocCols+`, content, count(*) OVER () AS total_enabled
FROM poc_templates WHERE enabled
ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, id
LIMIT $1`, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []POCTemplate{}
	total := 0
	for rows.Next() {
		var p POCTemplate
		var tags, refs string
		var cvss sql.NullFloat64
		if err := rows.Scan(&p.ID, &p.TemplateID, &p.Name, &p.Severity, &p.Protocol, &p.CVEID, &p.CWEID,
			&cvss, &tags, &p.Author, &p.Description, &refs, &p.Source, &p.SourceURL, &p.Digest,
			&p.Enabled, &p.CreatedAt, &p.UpdatedAt, &p.SizeBytes, &p.Content, &total); err != nil {
			return nil, 0, err
		}
		if cvss.Valid {
			p.CVSSScore = &cvss.Float64
		}
		p.Tags = decodeStringList(tags)
		p.References = decodeStringList(refs)
		out = append(out, p)
	}
	return out, total, rows.Err()
}
