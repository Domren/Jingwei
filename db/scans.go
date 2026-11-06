package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	Proxy          string         `json:"proxy"`
	RateLimit      int            `json:"rate_limit"`
	Concurrency    int            `json:"concurrency"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	Status         string         `json:"status"` // queued | running | done | failed | canceled
	Stage          string         `json:"stage"`  // queued | discover | fingerprint | match | scan | done | failed | canceled
	Progress       map[string]any `json:"progress"`
	Summary        map[string]any `json:"summary"`
	// Plan 是续扫计划（JSON 原文）：目标、模板 ID 与发现阶段上下文。只在服务端解析。
	Plan string `json:"-"`
	// ResumeRequested 表示这条任务是被「续扫」重新入队的，执行器会跳过已完成的阶段。
	ResumeRequested bool       `json:"resume_requested,omitempty"`
	CanResume       bool       `json:"can_resume"`
	Log             string     `json:"log,omitempty"`
	Error           string     `json:"error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
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
	Proxy          string         `json:"proxy"`
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
       fingerprint, create_findings, webshell_inject, webshell_params::text, proxy,
       rate_limit, concurrency, timeout_seconds,
       status, stage, progress::text, summary::text, log, error,
       plan::text, resume_requested, created_at, started_at, finished_at`

func scanOneScanTask(row interface{ Scan(...any) error }) (*ScanTask, error) {
	var t ScanTask
	var targetsRaw, pocRaw, webshellRaw, progressRaw, summaryRaw, planRaw string
	if err := row.Scan(&t.ID, &t.Name, &targetsRaw, &t.Mode, &pocRaw, &t.Ports, &t.MinSeverity,
		&t.Fingerprint, &t.CreateFindings, &t.WebshellInject, &webshellRaw, &t.Proxy,
		&t.RateLimit, &t.Concurrency, &t.TimeoutSeconds,
		&t.Status, &t.Stage, &progressRaw, &summaryRaw, &t.Log, &t.Error,
		&planRaw, &t.ResumeRequested, &t.CreatedAt, &t.StartedAt, &t.FinishedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(targetsRaw), &t.Targets)
	_ = json.Unmarshal([]byte(pocRaw), &t.POCIDs)
	_ = json.Unmarshal([]byte(webshellRaw), &t.WebshellParams)
	_ = json.Unmarshal([]byte(progressRaw), &t.Progress)
	_ = json.Unmarshal([]byte(summaryRaw), &t.Summary)
	if planRaw != "" && planRaw != "{}" {
		t.Plan = planRaw
	}
	var plan struct {
		Phase string `json:"phase"`
	}
	// CanResume 只是给界面上的「续扫」按钮做参考；能不能真续，以 RequestScanResume
	// 的 SQL 条件为准（它额外要求分片行还在）。
	if json.Unmarshal([]byte(planRaw), &plan) == nil {
		t.CanResume = (t.Status == "failed" || t.Status == "canceled") && plan.Phase == "poc"
	}
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
                       create_findings, webshell_inject, webshell_params, proxy,
                       rate_limit, concurrency, timeout_seconds)
VALUES ($1, $2::jsonb, $3, $4::jsonb, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14)
RETURNING `+scanTaskCols,
		strings.TrimSpace(in.Name), jsonStringArray(in.Targets), in.Mode, jsonInt64Array(in.POCIDs),
		in.Ports, in.MinSeverity, in.Fingerprint, in.CreateFindings,
		in.WebshellInject, jsonObject(in.WebshellParams), strings.TrimSpace(in.Proxy),
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

// 排队任务的认领只有一条路：QueuedScanProxies 按 FIFO 取候选，ClaimScanTask 按 ID 抢占。
// 没有「直接认领最老的排队任务」那种便捷写法了——要不要开工现在取决于隧道并发预算，
// 留一个跳过预算的认领方式等于给它一条近路。
//
// QueuedScanProxies 列出排队任务与各自要走的代理串。代理原样返回、只用于算端点：
// 它可能带凭据，因此绝不写进日志或接口（见 server.proxyEndpoint）。
type QueuedProxyTask struct {
	ID    int64
	Proxy string
}

func (d *DB) QueuedScanProxies(limit int) ([]QueuedProxyTask, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := d.Query(`SELECT id, proxy FROM scan_tasks WHERE status='queued' ORDER BY id LIMIT $1`, limit)
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

// SetScanTaskQueueNote 把「为什么还在排队」写进进度里。排队不动的原因是隧道忙，
// 不是任务坏了——不写出来，运维只能猜，而猜的方向通常是「平台卡死了」。
// note 为空表示清除（任务被认领时 progress 也会整体重置）。
func (d *DB) SetScanTaskQueueNote(id int64, note string) error {
	_, err := d.Exec(`UPDATE scan_tasks
SET progress = CASE WHEN $2='' THEN progress - 'queue_note'
                    ELSE progress || jsonb_build_object('queue_note', $2) END
WHERE id=$1 AND status='queued'
      AND (progress->>'queue_note') IS DISTINCT FROM $2`, id, strings.TrimSpace(note))
	return err
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

// MergeScanTaskSummary adds fields to a finished scan's summary. Automatic
// deep-dive results land after the scan itself is done, so the scan list would
// otherwise keep showing the snapshot taken at completion.
func (d *DB) MergeScanTaskSummary(id int64, fields map[string]any) error {
	_, err := d.Exec(`UPDATE scan_tasks
SET summary = COALESCE(summary, '{}'::jsonb) || $2::jsonb
WHERE id=$1`, id, jsonObject(fields))
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
// The message must not promise more than the checkpoint can deliver: only a run
// interrupted inside the sharded POC stage can be resumed, so the wording is
// picked from the plan's phase instead of being asserted for every task.
func (d *DB) RecoverInterruptedScanTasks() (int64, error) {
	res, err := d.Exec(`UPDATE scan_tasks
SET status='failed', stage='failed',
    error=CASE
        WHEN plan->>'phase'='poc' AND EXISTS (SELECT 1 FROM scan_task_shards s WHERE s.scan_task_id=scan_tasks.id)
            THEN '服务重启，POC 分片扫描中断：已完成分片已记录，可用「续扫」只跑未完成分片'
        WHEN plan->>'phase' IN ('postprocess','done')
            THEN '服务重启，POC 已全部扫完、中断发生在深挖/基线阶段：该阶段不支持续跑，请用「重跑」重新开始'
        ELSE '服务重启，扫描中断（中断时尚未建立 POC 分片检查点），请用「重跑」重新开始'
    END,
    finished_at=now()
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

// QueueScanTask resets a finished task for another run. The row is locked and
// checked first: deleting output before knowing the task is actually eligible
// would leave a running executor writing results into a task whose rows are
// already gone. Plan and shards are reset too, otherwise a rerun would inherit
// the previous run's checkpoint and skip half of its own POC stage.
func (d *DB) QueueScanTask(id int64) (bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var eligible bool
	err = tx.QueryRow(`SELECT COALESCE(status IN ('done','failed','canceled'), false)
FROM scan_tasks WHERE id=$1 FOR UPDATE`, id).Scan(&eligible)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !eligible {
		return false, nil
	}
	if _, err := tx.Exec(`DELETE FROM scan_task_results WHERE scan_task_id=$1`, id); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM scan_task_assets WHERE scan_task_id=$1`, id); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM scan_task_shards WHERE scan_task_id=$1`, id); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`UPDATE scan_tasks
SET status='queued', stage='queued', progress='{}'::jsonb, summary='{}'::jsonb,
    log='', error='', plan='{}'::jsonb, resume_requested=false, started_at=NULL, finished_at=NULL
WHERE id=$1`, id); err != nil {
		return false, err
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

func scanTaskResultJSON(r ScanTaskResult) (extracted, raw string) {
	if r.Extracted == nil {
		r.Extracted = []string{}
	}
	extJSON, _ := json.Marshal(r.Extracted)
	rawJSON, _ := json.Marshal(r.Raw)
	if len(rawJSON) == 0 || string(rawJSON) == "null" {
		rawJSON = []byte("{}")
	}
	return string(extJSON), string(rawJSON)
}

// AddScanTaskResult inserts a nuclei match; a duplicate returns id=0.
func (d *DB) AddScanTaskResult(taskID int64, findingID int64, r ScanTaskResult) (int64, error) {
	extracted, raw := scanTaskResultJSON(r)
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
		taskID, fid, r.TemplateID, r.Name, r.Severity, r.Host, r.MatchedAt, r.Type, r.Curl, extracted, raw).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// LinkScanTaskResult binds a finding to the result row for the same template
// and match location. A deep-dive task runs after the scan finished and often
// proves an issue the POC pass could not (SQLi/XSS by sqlmap/dalfox), so the row
// may not exist yet; in that case it is inserted. When the scan already stored
// the same match without a finding, the finding is attached to that row instead
// of creating a duplicate.
func (d *DB) LinkScanTaskResult(taskID, findingID int64, r ScanTaskResult) error {
	if taskID <= 0 || findingID <= 0 || strings.TrimSpace(r.TemplateID) == "" {
		return nil
	}
	extracted, raw := scanTaskResultJSON(r)
	_, err := d.Exec(`
INSERT INTO scan_task_results(scan_task_id, finding_id, template_id, name, severity, host, matched_at, type, curl_command, extracted, raw)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb)
ON CONFLICT (scan_task_id, template_id, matched_at) DO UPDATE
SET finding_id = COALESCE(scan_task_results.finding_id, EXCLUDED.finding_id)`,
		taskID, findingID, r.TemplateID, r.Name, r.Severity, r.Host, r.MatchedAt, r.Type, r.Curl, extracted, raw)
	return err
}

// ScanTaskResultCounts reports how many results a scan has stored and how many
// of them are bound to a finding. Deep-dive tasks append rows after the scan
// finished, so the completion-time summary snapshot needs recomputing.
func (d *DB) ScanTaskResultCounts(taskID int64) (results, findings int, err error) {
	err = d.QueryRow(`SELECT count(*), count(*) FILTER (WHERE finding_id IS NOT NULL)
FROM scan_task_results WHERE scan_task_id=$1`, taskID).Scan(&results, &findings)
	return results, findings, err
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

// ListScanTaskResultsForDiff 取一次扫描的全部结果行，供两次扫描的增量对比使用。
// 与列表接口不同，这里不设上限：diff 少一条就会把「还在」误报成「消失」。
func (d *DB) ListScanTaskResultsForDiff(taskID int64) ([]ScanTaskResult, error) {
	rows, err := d.Query(`SELECT id, finding_id, template_id, name, severity, host, matched_at, type,
       curl_command, extracted::text, raw::text, created_at
FROM scan_task_results WHERE scan_task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanTaskResult{}
	for rows.Next() {
		var r ScanTaskResult
		var extractedRaw, rawRaw string
		if err := rows.Scan(&r.ID, &r.FindingID, &r.TemplateID, &r.Name, &r.Severity, &r.Host,
			&r.MatchedAt, &r.Type, &r.Curl, &extractedRaw, &rawRaw, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(extractedRaw), &r.Extracted)
		_ = json.Unmarshal([]byte(rawRaw), &r.Raw)
		out = append(out, r)
	}
	return out, rows.Err()
}

// PreviousDoneScanTask 取编号小于 id 的最近一个已完成扫描，作为增量对比的默认基线。
func (d *DB) PreviousDoneScanTask(id int64) (*ScanTask, error) {
	t, err := scanOneScanTask(d.QueryRow(`SELECT `+scanTaskCols+` FROM scan_tasks
WHERE id < $1 AND status = 'done' ORDER BY id DESC LIMIT 1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// ScanShardSpec 是分片布局里的一格：槽位号、模板分片编号、这一片打哪个目标、几
// 条模板。布局完全由计划里的「模板顺序 × 目标顺序 × 分片参数」算出来，所以续扫时
// 可以重算一遍再与库内比对，对不上就是中途有人改了 POC 库或目标清单。
type ScanShardSpec struct {
	Ordinal   int
	Chunk     int
	Target    string
	Templates int
}

// ScanShard 是一格分片的布局加进度。done 的不再执行；failed / pending 在续扫时
// 重试，skipped 是策略拒绝（目标被移出授权），不算失败但结果不完整。
type ScanShard struct {
	ScanShardSpec
	Status  string
	Results int
	Error   string
}

// ErrScanLayoutChanged 表示库里的分片行与计划算出的布局不一致。续扫遇到它只能拒绝：
// 半旧半新的「已完成」拼起来会谎报覆盖面。
var ErrScanLayoutChanged = errors.New("分片布局与续扫计划不一致")

type shardQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func scanShardRows(q shardQuerier, taskID int64, lock bool) ([]ScanShard, error) {
	// 普通读不能加 FOR UPDATE，锁读只在校验/补齐时用一个事务内的行锁。
	stmt := `SELECT ordinal, chunk, target, templates, status, results, error
FROM scan_task_shards WHERE scan_task_id=$1 ORDER BY ordinal`
	if lock {
		stmt += " FOR UPDATE"
	}
	rows, err := q.Query(stmt, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanShard{}
	for rows.Next() {
		var s ScanShard
		if err := rows.Scan(&s.Ordinal, &s.Chunk, &s.Target, &s.Templates, &s.Status, &s.Results, &s.Error); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SaveScanPlan 在一个事务里写入续扫计划并对齐分片行：已有行必须逐格与布局一致
// （不一致就报错，绝不就地压缩或改写历史进度），缺的补上。
// POC 阶段开始前写一次，续扫时再写一次当作校验。
func (d *DB) SaveScanPlan(taskID int64, plan string, layout []ScanShardSpec) ([]ScanShard, error) {
	if len(layout) == 0 {
		return nil, fmt.Errorf("分片布局为空，无法建立续扫检查点")
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var one int
	if err := tx.QueryRow(`SELECT 1 FROM scan_tasks WHERE id=$1 FOR UPDATE`, taskID).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("扫描任务 %d 不存在", taskID)
		}
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE scan_tasks SET plan=$2::jsonb WHERE id=$1`, taskID, plan); err != nil {
		return nil, err
	}
	existing, err := scanShardRows(tx, taskID, true)
	if err != nil {
		return nil, err
	}
	byOrdinal := make(map[int]ScanShard, len(existing))
	for _, s := range existing {
		byOrdinal[s.Ordinal] = s
	}
	if len(existing) > 0 {
		if len(existing) != len(layout) {
			return nil, fmt.Errorf("%w：计划 %d 片，库内 %d 片（目标数或模板数变了），请用「重跑」重新开始",
				ErrScanLayoutChanged, len(layout), len(existing))
		}
		for _, want := range layout {
			got, ok := byOrdinal[want.Ordinal]
			if !ok {
				return nil, fmt.Errorf("%w：库内缺少第 %d 片（应为 目标 %q × 模板 %d），分片进度被人为动过，请用「重跑」重新开始",
					ErrScanLayoutChanged, want.Ordinal+1, want.Target, want.Templates)
			}
			if got.Chunk != want.Chunk || got.Target != want.Target || got.Templates != want.Templates {
				return nil, fmt.Errorf("%w：第 %d 片应为 目标 %q × 模板 %d，库内记的是 目标 %q × 模板 %d，请用「重跑」重新开始",
					ErrScanLayoutChanged, want.Ordinal+1, want.Target, want.Templates, got.Target, got.Templates)
			}
		}
	}
	for _, want := range layout {
		if _, ok := byOrdinal[want.Ordinal]; ok {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO scan_task_shards(scan_task_id, ordinal, chunk, target, templates, status)
VALUES ($1,$2,$3,$4,$5,'pending')`, taskID, want.Ordinal, want.Chunk, want.Target, want.Templates); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// 返回值用布局 + 已读到的状态拼，省掉提交后再查一遍（期间无人能改这些行，
	// 行锁一直在事务里拿着）。
	out := make([]ScanShard, 0, len(layout))
	for _, want := range layout {
		s := ScanShard{ScanShardSpec: want, Status: "pending"}
		if got, ok := byOrdinal[want.Ordinal]; ok {
			s.Status, s.Results, s.Error = got.Status, got.Results, got.Error
		}
		out = append(out, s)
	}
	return out, nil
}

func (d *DB) ListScanShards(taskID int64) ([]ScanShard, error) {
	return scanShardRows(d, taskID, false)
}

func (d *DB) StartScanShard(taskID int64, ordinal int) error {
	_, err := d.Exec(`UPDATE scan_task_shards SET started_at=now() WHERE scan_task_id=$1 AND ordinal=$2`, taskID, ordinal)
	return err
}

// FinishScanShard 记录分片终态（done / failed / skipped）。done 只在「这一片真的
// 跑完且结果已落库」之后由调用方写入，失败与中断都必须留下可重跑的痕迹。
func (d *DB) FinishScanShard(taskID int64, ordinal int, status string, results int, errMsg string) error {
	_, err := d.Exec(`UPDATE scan_task_shards
SET status=$3, results=$4, error=$5, finished_at=now() WHERE scan_task_id=$1 AND ordinal=$2`,
		taskID, ordinal, status, results, errMsg)
	return err
}

// SetScanPlanPhase 推进续扫计划的 phase（poc → postprocess → done）。phase 是续扫
// 的唯一判据：只有停在 poc 的任务可以续，跑到 postprocess 说明深挖/基线已经动过，
// 重放会重复排队深挖任务。到 done 时顺带清掉续扫标记——标记只在确认成功时清。
func (d *DB) SetScanPlanPhase(taskID int64, phase string) error {
	_, err := d.Exec(`UPDATE scan_tasks
SET plan = jsonb_set(plan, '{phase}', to_jsonb($2::text)),
    resume_requested = CASE WHEN $2='done' THEN false ELSE resume_requested END
WHERE id=$1`, taskID, phase)
	return err
}

// ScanPOCResultCounts 按库内实际行数统计 POC 阶段的结果与发现：分片重跑时唯一键会
// 吃掉重复行，用「本轮 persistResults 的返回值」累加会少算，只有数库才对得上。
// 两个过滤条件都不能省：template_id 把目录枚举（dir-enum:…）等同样写这张表的功能排除，
// raw 里有没有 template-id 把深挖任务回填的行（source=deep）排除——它们不是 POC 命中，
// 算进覆盖率就是谎报。
func (d *DB) ScanPOCResultCounts(taskID int64, templateIDs []string) (results, findings int, err error) {
	if len(templateIDs) == 0 {
		return 0, 0, nil
	}
	err = d.QueryRow(`SELECT count(*), count(*) FILTER (WHERE finding_id IS NOT NULL)
FROM scan_task_results
WHERE scan_task_id=$1 AND template_id = ANY($2) AND raw ? 'template-id'`, taskID, templateIDs).
		Scan(&results, &findings)
	return results, findings, err
}

// ListScanTaskPOCHits 取 POC 阶段写入的命中（带原始 nuclei 事件），供续扫之后的深挖
// 与专项基线重建结果集。过滤条件与 ScanPOCResultCounts 完全一致，两处数字才对得上。
// 不分页：漏掉尾部等于漏掉高危命中，深挖任务就不会被排上。
func (d *DB) ListScanTaskPOCHits(taskID int64, templateIDs []string) ([]ScanTaskResult, error) {
	if len(templateIDs) == 0 {
		return nil, nil
	}
	rows, err := d.Query(`SELECT id, finding_id, template_id, name, severity, host, matched_at, type,
	       curl_command, extracted::text, raw::text, created_at
FROM scan_task_results
WHERE scan_task_id=$1 AND template_id = ANY($2) AND raw ? 'template-id' ORDER BY id`, taskID, templateIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanTaskResult{}
	for rows.Next() {
		var r ScanTaskResult
		var extractedRaw, rawRaw string
		if err := rows.Scan(&r.ID, &r.FindingID, &r.TemplateID, &r.Name, &r.Severity, &r.Host,
			&r.MatchedAt, &r.Type, &r.Curl, &extractedRaw, &rawRaw, &r.CreatedAt); err != nil {
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

// RequestScanResume 把一条停在 POC 分片阶段的失败/已取消任务重新排队。条件比旧版
// 严格：必须有 poc 阶段的计划和对应分片行，否则执行器只会拿着一个无法续跑的计划
// 起来再失败一次。
func (d *DB) RequestScanResume(taskID int64) (bool, error) {
	res, err := d.Exec(`UPDATE scan_tasks
SET status='queued', stage='queued', error='', resume_requested=true, started_at=NULL, finished_at=NULL
WHERE id=$1 AND status IN ('failed','canceled')
  AND plan->>'phase'='poc'
  AND EXISTS (SELECT 1 FROM scan_task_shards s WHERE s.scan_task_id=scan_tasks.id)`, taskID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
