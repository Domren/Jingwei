package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// 子域名枚举（C3）的任务与结果存储。
//
// 与弱口令检测同一套纪律：存储层只记输入、运行状态与引擎给出的每一条结论，不决定
// 枚举什么、不合并去重、不替引擎判断泛解析。引擎说「未判定」，这里就写未判定；
// 存储层把一条结果圆成「没有」，报告里就少一句真话。

const (
	SubdomainTaskQueued   = "queued"
	SubdomainTaskRunning  = "running"
	SubdomainTaskDone     = "done"
	SubdomainTaskFailed   = "failed"
	SubdomainTaskCanceled = "canceled"
)

// ErrSubdomainTaskNotFound 表示任务编号不存在。
var ErrSubdomainTaskNotFound = errors.New("子域名枚举任务不存在")

// SubdomainTask 是一次枚举任务。Options 里存的是操作员填的东西（字典、并发、预算、
// 是否用公开接口、是否顺带探测端口），不是引擎算出来的结论——结论在 Summary。
type SubdomainTask struct {
	ID         int64          `json:"id"`
	Name       string         `json:"name"`
	Targets    []string       `json:"targets"`
	Options    map[string]any `json:"options"`
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

type SubdomainTaskInput struct {
	Name    string
	Targets []string
	Options map[string]any
}

// SubdomainResult 是一条「某个名字解析出了什么」。
type SubdomainResult struct {
	ID        int64             `json:"id"`
	TaskID    int64             `json:"task_id"`
	Name      string            `json:"name"`
	Root      string            `json:"root"`
	Source    string            `json:"source"`
	Records   []SubdomainRecord `json:"records"`
	IPs       []string          `json:"ips"`
	Wildcard  bool              `json:"wildcard"`
	AssetID   *int64            `json:"asset_id,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// SubdomainRecord 是结果表里的记录形态（与 scanner 的同名结构各自定义：
// db 不依赖 scanner，避免存储层被引擎的改动牵着走）。
type SubdomainRecord struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

const subdomainTaskCols = `id, name, targets::text, options::text,
       status, stage, progress::text, summary::text, log, error,
       created_at, started_at, finished_at`

func oneSubdomainTask(row interface{ Scan(...any) error }) (*SubdomainTask, error) {
	var t SubdomainTask
	var targetsRaw, optionsRaw, progressRaw, summaryRaw string
	if err := row.Scan(&t.ID, &t.Name, &targetsRaw, &optionsRaw,
		&t.Status, &t.Stage, &progressRaw, &summaryRaw, &t.Log, &t.Error,
		&t.CreatedAt, &t.StartedAt, &t.FinishedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSubdomainTaskNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(targetsRaw), &t.Targets)
	_ = json.Unmarshal([]byte(optionsRaw), &t.Options)
	_ = json.Unmarshal([]byte(progressRaw), &t.Progress)
	_ = json.Unmarshal([]byte(summaryRaw), &t.Summary)
	if t.Targets == nil {
		t.Targets = []string{}
	}
	if t.Options == nil {
		t.Options = map[string]any{}
	}
	if t.Progress == nil {
		t.Progress = map[string]any{}
	}
	if t.Summary == nil {
		t.Summary = map[string]any{}
	}
	return &t, nil
}

// CreateSubdomainTask 建一条排队中的任务。Targets 去重但保序：同一个根写两遍是输入错误，
// 不该在报告里变成两轮查询。
func (d *DB) CreateSubdomainTask(in SubdomainTaskInput) (*SubdomainTask, error) {
	targets := make([]string, 0, len(in.Targets))
	seen := map[string]bool{}
	for _, t := range in.Targets {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		targets = append(targets, t)
	}
	b, _ := json.Marshal(targets)
	row := d.QueryRow(`
INSERT INTO subdomain_tasks(name, targets, options)
VALUES ($1, $2::jsonb, $3::jsonb)
RETURNING `+subdomainTaskCols, strings.TrimSpace(in.Name), string(b), jsonObject(in.Options))
	return oneSubdomainTask(row)
}

func (d *DB) GetSubdomainTask(id int64) (*SubdomainTask, error) {
	return oneSubdomainTask(d.QueryRow(`SELECT `+subdomainTaskCols+` FROM subdomain_tasks WHERE id=$1`, id))
}

func (d *DB) ListSubdomainTasks(limit int) ([]*SubdomainTask, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.Query(`SELECT `+subdomainTaskCols+` FROM subdomain_tasks ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*SubdomainTask{}
	for rows.Next() {
		t, err := oneSubdomainTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ClaimNextSubdomainTask 抢占最早的排队任务。没有可抢的任务时返回 (nil, nil)——
// 调度循环靠它与「数据库出错」区分开。
func (d *DB) ClaimNextSubdomainTask() (*SubdomainTask, error) {
	t, err := oneSubdomainTask(d.QueryRow(`UPDATE subdomain_tasks
SET status='running', stage='planning', started_at=now(), finished_at=NULL, error='', progress='{}'::jsonb
WHERE id=(SELECT id FROM subdomain_tasks WHERE status='queued' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING ` + subdomainTaskCols))
	if errors.Is(err, ErrSubdomainTaskNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (d *DB) SetSubdomainTaskStage(id int64, stage string, progress map[string]any) error {
	_, err := d.Exec(`UPDATE subdomain_tasks SET stage=$2, progress=$3::jsonb WHERE id=$1`,
		id, stage, jsonObject(progress))
	return err
}

func (d *DB) AppendSubdomainTaskLog(id int64, line string) error {
	line = strings.TrimRight(line, "\n")
	if line == "" {
		return nil
	}
	_, err := d.Exec(`UPDATE subdomain_tasks
SET log = CASE WHEN log = '' THEN $2 ELSE log || E'\n' || $2 END
WHERE id=$1`, id, line)
	return err
}

// FinishSubdomainTask 收尾。status 只接受 done/failed/canceled，其余按 failed 处理，
// 免得一个手误把任务永久留在 running 上。
func (d *DB) FinishSubdomainTask(id int64, status string, summary map[string]any, errMsg string) error {
	switch status {
	case SubdomainTaskDone, SubdomainTaskFailed, SubdomainTaskCanceled:
	default:
		status = SubdomainTaskFailed
	}
	_, err := d.Exec(`UPDATE subdomain_tasks
SET status=$2, summary=$3::jsonb, error=$4, finished_at=now(),
    stage = CASE WHEN $2='done' THEN 'done' ELSE $2 END
WHERE id=$1`, id, status, jsonObject(summary), strings.TrimSpace(errMsg))
	return err
}

func (d *DB) CancelSubdomainTask(id int64) (bool, error) {
	res, err := d.Exec(`UPDATE subdomain_tasks
SET status='canceled', stage='canceled', error='已手动停止', finished_at=now()
WHERE id=$1 AND status IN ('queued','running')`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RecoverInterruptedSubdomainTasks 把进程重启前遗留的运行中任务标成失败。
func (d *DB) RecoverInterruptedSubdomainTasks() (int64, error) {
	res, err := d.Exec(`UPDATE subdomain_tasks
SET status='failed', stage='failed', error='服务重启，任务中断', finished_at=now()
WHERE status='running'`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteSubdomainTasks 批量删除已结束的任务（结果随外键级联删除）。运行中的任务不删。
func (d *DB) DeleteSubdomainTasks(ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	b, _ := json.Marshal(ids)
	res, err := d.Exec(`DELETE FROM subdomain_tasks
WHERE id IN (SELECT jsonb_array_elements_text($1::jsonb)::bigint)
  AND status IN ('done','failed','canceled')`, string(b))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InsertSubdomainResults 整批落库。半批入库会让「台账条数」与「任务结论」对不上，
// 所以要么全成要么全不成；同名重复按最新一次答复覆盖（重跑同一任务时是幂等的）。
func (d *DB) InsertSubdomainResults(taskID int64, results []SubdomainResult) error {
	if len(results) == 0 {
		return nil
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, r := range results {
		records, _ := json.Marshal(r.Records)
		if r.Records == nil {
			records = []byte("[]")
		}
		ips, _ := json.Marshal(r.IPs)
		if r.IPs == nil {
			ips = []byte("[]")
		}
		if _, err := tx.Exec(`
INSERT INTO subdomain_results(task_id, name, root, source, records, ips, wildcard, asset_id)
VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8)
ON CONFLICT (task_id, name) DO UPDATE SET
    root=EXCLUDED.root, source=EXCLUDED.source, records=EXCLUDED.records,
    ips=EXCLUDED.ips, wildcard=EXCLUDED.wildcard,
    asset_id=COALESCE(EXCLUDED.asset_id, subdomain_results.asset_id)`,
			taskID, strings.TrimSpace(r.Name), r.Root, r.Source,
			string(records), string(ips), r.Wildcard, r.AssetID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetSubdomainResultAsset 把结果行与写成的资产编号关联起来。
// 单独一步是因为资产写入在引擎之外（要过公司归属与范围合并），失败时结果仍然留得住。
func (d *DB) SetSubdomainResultAsset(taskID int64, name string, assetID int64) error {
	_, err := d.Exec(`UPDATE subdomain_results SET asset_id=$3 WHERE task_id=$1 AND name=$2`,
		taskID, strings.TrimSpace(name), assetID)
	return err
}

// ListSubdomainResults 按新到旧列出一次任务的结果。Root/Source 为空表示不加该条件。
func (d *DB) ListSubdomainResults(taskID int64, root, source string, limit int) ([]SubdomainResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	rows, err := d.Query(`SELECT id, task_id, name, root, source, records::text, ips::text,
       wildcard, asset_id, created_at
FROM subdomain_results
WHERE task_id=$1 AND ($2='' OR root=$2) AND ($3='' OR source=$3)
ORDER BY wildcard, name LIMIT $4`, taskID, strings.TrimSpace(root), strings.TrimSpace(source), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SubdomainResult{}
	for rows.Next() {
		var r SubdomainResult
		var recordsRaw, ipsRaw string
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Name, &r.Root, &r.Source, &recordsRaw, &ipsRaw,
			&r.Wildcard, &r.AssetID, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(recordsRaw), &r.Records)
		_ = json.Unmarshal([]byte(ipsRaw), &r.IPs)
		if r.Records == nil {
			r.Records = []SubdomainRecord{}
		}
		if r.IPs == nil {
			r.IPs = []string{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SubdomainResultCount 给任务列表用：一次任务记了多少条结果。
func (d *DB) SubdomainResultCount(taskID int64) (int, error) {
	var n int
	err := d.QueryRow(`SELECT count(*) FROM subdomain_results WHERE task_id=$1`, taskID).Scan(&n)
	return n, err
}
