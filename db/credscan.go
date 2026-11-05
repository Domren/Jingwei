package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 弱口令检测任务与结果（界面名「弱口令检测」，内部标识保持 credscan）。
//
// 存储层只做两件事：把一次任务的输入与运行状态记全，把引擎吐出的每一行结果
// 原样落库。它不决定测什么、不合并去重——「每个端点×凭据一行」是引擎给出的
// 结论形态，存储层改一行就等于让报告少说一句话。

const (
	CredTaskQueued   = "queued"
	CredTaskRunning  = "running"
	CredTaskDone     = "done"
	CredTaskFailed   = "failed"
	CredTaskCanceled = "canceled"
)

// CredTaskOutcomes 是引擎的六种结论。存储层不校验取值（协议适配器可能先于
// 这里新增），但提供这份清单给筛选器与统计使用。
var CredTaskOutcomes = []string{"hit", "deny", "unreachable", "locked", "inconclusive", "unsupported"}

// ErrCredTaskNotFound 表示任务编号不存在。
var ErrCredTaskNotFound = errors.New("弱口令检测任务不存在")

type CredTask struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	Targets     []string       `json:"targets"`
	Protocols   []string       `json:"protocols"`
	Options     map[string]any `json:"options"`
	DictProfile string         `json:"dict_profile"`
	Status      string         `json:"status"`
	Stage       string         `json:"stage"`
	Progress    map[string]any `json:"progress"`
	Summary     map[string]any `json:"summary"`
	Log         string         `json:"log,omitempty"`
	Error       string         `json:"error,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	FinishedAt  *time.Time     `json:"finished_at,omitempty"`
}

type CredTaskInput struct {
	Name        string         `json:"name"`
	Targets     []string       `json:"targets"`
	Protocols   []string       `json:"protocols"`
	Options     map[string]any `json:"options"`
	DictProfile string         `json:"dict_profile"`
}

// CredResult 是一行「某端点的某组凭据试出了什么」。
// Password 与 Evidence 都是明文：它们就是这份发现的内容，报告要逐字节复现。
// 需要密封复用的凭据另存 intranet_credentials，两处用途不同，别把这里也封上
// ——封了口令却把证据里的明文留着，只是看起来安全。
type CredResult struct {
	ID                int64             `json:"id"`
	TaskID            int64             `json:"task_id"`
	Host              string            `json:"host"`
	Port              int               `json:"port"`
	Protocol          string            `json:"protocol"`
	ProtocolSource    string            `json:"protocol_source"`
	ProtocolConfirmed bool              `json:"protocol_confirmed"`
	Params            map[string]string `json:"params,omitempty"`
	Username          string            `json:"username"`
	Password          string            `json:"password"`
	Outcome           string            `json:"outcome"`
	Banner            string            `json:"banner,omitempty"`
	Evidence          string            `json:"evidence,omitempty"`
	TLS               bool              `json:"tls,omitempty"`
	Reason            string            `json:"reason,omitempty"`
	Attempts          int               `json:"attempts"`
	ElapsedMS         int64             `json:"elapsed_ms"`
	CreatedAt         time.Time         `json:"created_at"`
}

// CredResultFilter 是结果列表的筛选条件。Outcome 为空表示全部；
// Host 非空时只出该主机的行（内网横向时按主机看更顺手）。
type CredResultFilter struct {
	Outcome string
	Host    string
	Offset  int
	Limit   int
}

const credTaskCols = `id, name, targets::text, protocols::text, options::text, dict_profile,
       status, stage, progress::text, summary::text, log, error,
       created_at, started_at, finished_at`

func credOneTask(row interface{ Scan(...any) error }) (*CredTask, error) {
	var t CredTask
	var targetsRaw, protocolsRaw, optionsRaw, progressRaw, summaryRaw string
	if err := row.Scan(&t.ID, &t.Name, &targetsRaw, &protocolsRaw, &optionsRaw, &t.DictProfile,
		&t.Status, &t.Stage, &progressRaw, &summaryRaw, &t.Log, &t.Error,
		&t.CreatedAt, &t.StartedAt, &t.FinishedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCredTaskNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(targetsRaw), &t.Targets)
	_ = json.Unmarshal([]byte(protocolsRaw), &t.Protocols)
	_ = json.Unmarshal([]byte(optionsRaw), &t.Options)
	_ = json.Unmarshal([]byte(progressRaw), &t.Progress)
	_ = json.Unmarshal([]byte(summaryRaw), &t.Summary)
	if t.Targets == nil {
		t.Targets = []string{}
	}
	if t.Protocols == nil {
		t.Protocols = []string{}
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

func credStringList(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// CreateCredTask 建一条排队中的任务。Targets 去重但保序：同一目标写两遍是
// 输入错误，不该让它在报告里变成两个端点。
func (d *DB) CreateCredTask(in CredTaskInput) (*CredTask, error) {
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
	protocols := make([]string, 0, len(in.Protocols))
	for _, p := range in.Protocols {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			protocols = append(protocols, p)
		}
	}
	row := d.QueryRow(`
INSERT INTO cred_tasks(name, targets, protocols, options, dict_profile)
VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb, $5)
RETURNING `+credTaskCols,
		strings.TrimSpace(in.Name), credStringList(targets), credStringList(protocols),
		jsonObject(in.Options), strings.TrimSpace(in.DictProfile))
	return credOneTask(row)
}

// GetCredTask 取一个任务；不存在时返回 ErrCredTaskNotFound。
func (d *DB) GetCredTask(id int64) (*CredTask, error) {
	return credOneTask(d.QueryRow(`SELECT `+credTaskCols+` FROM cred_tasks WHERE id=$1`, id))
}

// ListCredTasks 按新到旧列出任务。
func (d *DB) ListCredTasks(limit int) ([]*CredTask, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.Query(`SELECT `+credTaskCols+` FROM cred_tasks ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CredTask{}
	for rows.Next() {
		t, err := credOneTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ClaimNextCredTask 抢占最早的排队任务。没有可抢的任务时返回 (nil, nil)——
// 调度循环靠它与「数据库出错」区分开，出错要打日志，空队列是常态。
func (d *DB) ClaimNextCredTask() (*CredTask, error) {
	t, err := credOneTask(d.QueryRow(`UPDATE cred_tasks
SET status='running', stage='planning', started_at=now(), finished_at=NULL, error='', progress='{}'::jsonb
WHERE id=(SELECT id FROM cred_tasks WHERE status='queued' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING ` + credTaskCols))
	if errors.Is(err, ErrCredTaskNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// StartCredTask 抢占排队任务：只有 queued → running 算抢到，重复调用是安全的。
func (d *DB) StartCredTask(id int64) (bool, error) {
	res, err := d.Exec(`UPDATE cred_tasks SET status='running', stage='planning', started_at=now()
		WHERE id=$1 AND status='queued'`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetCredTaskStage 更新阶段与进度快照。进度是给人看的一句话+计数，不是状态机。
func (d *DB) SetCredTaskStage(id int64, stage string, progress map[string]any) error {
	_, err := d.Exec(`UPDATE cred_tasks SET stage=$2, progress=$3::jsonb WHERE id=$1`,
		id, stage, jsonObject(progress))
	return err
}

// AppendCredTaskLog 追加一行任务日志。
func (d *DB) AppendCredTaskLog(id int64, line string) error {
	line = strings.TrimRight(line, "\n")
	if line == "" {
		return nil
	}
	_, err := d.Exec(`UPDATE cred_tasks
SET log = CASE WHEN log = '' THEN $2 ELSE log || E'\n' || $2 END
WHERE id=$1`, id, line)
	return err
}

// FinishCredTask 收尾。status 只接受 done/failed/canceled 三种，其余按 failed 处理，
// 免得一个手误把任务永久留在 running 上。
func (d *DB) FinishCredTask(id int64, status string, summary map[string]any, errMsg string) error {
	switch status {
	case CredTaskDone, CredTaskFailed, CredTaskCanceled:
	default:
		status = CredTaskFailed
	}
	_, err := d.Exec(`UPDATE cred_tasks
SET status=$2, summary=$3::jsonb, error=$4, finished_at=now(),
    stage = CASE WHEN $2='done' THEN 'done' ELSE $2 END
WHERE id=$1`, id, status, jsonObject(summary), strings.TrimSpace(errMsg))
	return err
}

// CancelCredTask 把排队/运行中的任务标成已取消。运行中的任务由调用方同时取消 context。
func (d *DB) CancelCredTask(id int64) (bool, error) {
	res, err := d.Exec(`UPDATE cred_tasks
SET status='canceled', stage='canceled', error='已手动停止', finished_at=now()
WHERE id=$1 AND status IN ('queued','running')`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RecoverInterruptedCredTasks 把进程重启前遗留的运行中任务标成失败。
func (d *DB) RecoverInterruptedCredTasks() (int64, error) {
	res, err := d.Exec(`UPDATE cred_tasks
SET status='failed', stage='failed', error='服务重启，任务中断', finished_at=now()
WHERE status='running'`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteCredTasks 批量删除已结束的任务与其结果（外键级联）。运行中的任务不删。
func (d *DB) DeleteCredTasks(ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	b, _ := json.Marshal(ids)
	res, err := d.Exec(`DELETE FROM cred_tasks
WHERE id IN (SELECT jsonb_array_elements_text($1::jsonb)::bigint)
  AND status IN ('done','failed','canceled')`, string(b))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InsertCredResults 批量落一行行结论。整批一个事务：半批入库会让报告与任务状态对不上。
func (d *DB) InsertCredResults(taskID int64, results []CredResult) error {
	if len(results) == 0 {
		return nil
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	const cols = 16
	chunk := 200
	for start := 0; start < len(results); start += chunk {
		end := start + chunk
		if end > len(results) {
			end = len(results)
		}
		batch := results[start:end]
		sb := strings.Builder{}
		sb.WriteString(`INSERT INTO cred_results(task_id, host, port, protocol, protocol_source,
protocol_confirmed, params, username, password, outcome, banner, evidence, tls, reason, attempts, elapsed_ms) VALUES `)
		args := make([]any, 0, len(batch)*cols)
		for i, r := range batch {
			if i > 0 {
				sb.WriteString(",")
			}
			base := i * cols
			params := map[string]string{}
			for k, v := range r.Params {
				params[k] = v
			}
			pb, _ := json.Marshal(params)
			fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d::jsonb,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
				base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8,
				base+9, base+10, base+11, base+12, base+13, base+14, base+15, base+16)
			args = append(args, taskID, r.Host, r.Port, r.Protocol, r.ProtocolSource,
				r.ProtocolConfirmed, string(pb), r.Username, r.Password, r.Outcome,
				r.Banner, r.Evidence, r.TLS, r.Reason, r.Attempts, r.ElapsedMS)
		}
		if _, err := tx.Exec(sb.String(), args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const credResultCols = `id, task_id, host, port, protocol, protocol_source, protocol_confirmed,
       params::text, username, password, outcome, banner, evidence, tls, reason, attempts, elapsed_ms, created_at`

func credScanResult(rows interface{ Scan(...any) error }) (*CredResult, error) {
	var r CredResult
	var paramsRaw string
	if err := rows.Scan(&r.ID, &r.TaskID, &r.Host, &r.Port, &r.Protocol, &r.ProtocolSource,
		&r.ProtocolConfirmed, &paramsRaw, &r.Username, &r.Password, &r.Outcome, &r.Banner,
		&r.Evidence, &r.TLS, &r.Reason, &r.Attempts, &r.ElapsedMS, &r.CreatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(paramsRaw), &r.Params)
	if r.Params == nil {
		r.Params = map[string]string{}
	}
	return &r, nil
}

// ListCredResults 分页列出结果，返回本页行与符合条件的总数。
// 默认按 id 升序：报告里「先测的端点先出现」比「最新的先出现」好读。
func (d *DB) ListCredResults(taskID int64, f CredResultFilter) ([]*CredResult, int, error) {
	where := []string{"task_id=$1"}
	args := []any{taskID}
	if f.Outcome != "" {
		args = append(args, f.Outcome)
		where = append(where, fmt.Sprintf("outcome=$%d", len(args)))
	}
	if f.Host != "" {
		args = append(args, f.Host)
		where = append(where, fmt.Sprintf("host=$%d", len(args)))
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM cred_results WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	rows, err := d.Query(`SELECT `+credResultCols+` FROM cred_results WHERE `+cond+
		fmt.Sprintf(` ORDER BY id ASC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*CredResult{}
	for rows.Next() {
		r, err := credScanResult(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// CredTaskOutcomeCounts 按结论计数。任务列表与摘要都用它，避免两处各算一遍。
func (d *DB) CredTaskOutcomeCounts(taskID int64) (map[string]int, error) {
	rows, err := d.Query(`SELECT outcome, count(*) FROM cred_results WHERE task_id=$1 GROUP BY outcome`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			return nil, err
		}
		out[name] = n
	}
	return out, rows.Err()
}
