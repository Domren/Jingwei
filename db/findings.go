package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DBFinding is a row in the standalone findings table. It persists across task
// deletion unless the caller explicitly requests related finding cleanup.
type DBFinding struct {
	ExportCaseID    int64 // transient unified-export identity, never a finding handle
	ExportMemberIDs []int64

	TrafficCount          int
	EvidenceVersion       int64
	ReportEvidenceVersion int64
	TrafficBindings       []FindingTrafficBinding // populated only for export
	EvidencePackets       []FindingEvidencePacket // hydrated raw exchanges, populated only for export
	EvidencePacketOmitted int                     // exchanges merged or dropped so the report stays readable
	Screenshots           []FindingScreenshot     // evidence screenshots, populated only for export

	ID              int64
	TaskID          *int64
	NodeID          *int64
	VulnClass       string
	Name            string // 漏洞名称(可读标题);为空时前端回退展示 VulnClass
	Severity        string
	Summary         string
	Evidence        string
	Worker          string
	AssetIDs        []int64
	Status          string
	CVSS            *float64      // CVSS v3.1 基础分,0.0-10.0
	Reproduction    *Reproduction // 结构化复现过程(agent 记录时就地落库);nil=未记录,报告回退到重构的验证步骤
	Report          string        // 详细报告(Markdown);仅 GetFinding 填充,列表查询不带
	HTTPRequest     string        // 原始 HTTP 请求报文;扫描/深度利用/自定义请求产生
	HTTPResponse    string        // 原始 HTTP 响应报文
	CreatedAt       time.Time
	TaskDescription string // populated via LEFT JOIN on tasks
	// ScanTaskID/ScanTaskName 是无 LLM 漏扫来源(f.task_id 为空时按最早一轮归属);
	// 导出报告时用于按漏扫任务分组,而不是落到「未关联任务」。
	ScanTaskID   *int64
	ScanTaskName string
}

// FindingEvidencePacket is a hydrated raw exchange bound to a finding. It is a
// transient export view: the heads come from the snapshot row and the bodies
// from the evidence blob store.
type FindingEvidencePacket struct {
	BindingID    int64
	Role         string
	Note         string
	Snapshot     TrafficEvidenceSnapshot
	HTTPRequest  string
	HTTPResponse string
	Primary      bool
	// Repeated counts the extra bindings merged into this exchange because they
	// captured the same step in later rounds; the report says so instead of
	// silently hiding them.
	Repeated int
}

// AutoReportMarker marks a report generated deterministically from evidence
// without an LLM. Such reports may be regenerated/overwritten; a report without
// the marker is treated as user/LLM-authored and is never replaced automatically.
const AutoReportMarker = "<!-- jingwei:auto-report -->"

// IsAutoReport reports whether a report was produced by the deterministic
// template rather than by an LLM or a human.
func IsAutoReport(report string) bool { return strings.Contains(report, AutoReportMarker) }

// Finding triage states (findings.status).
const (
	FindingPending       = "pending"        // 待处理
	FindingInProgress    = "in_progress"    // 处理中
	FindingConfirmed     = "confirmed"      // 已确认(真实漏洞,未修复)
	FindingResolved      = "resolved"       // 已处理
	FindingFixed         = "fixed"          // 已修复
	FindingFalsePositive = "false_positive" // 误报
	FindingIgnored       = "ignored"        // 忽略
	FindingDuplicate     = "duplicate"      // 重复
	FindingRiskAccepted  = "risk_accepted"  // 风险接受
)

// ValidFindingStatus reports whether s is a known triage state.
func ValidFindingStatus(s string) bool {
	switch s {
	case FindingPending, FindingInProgress, FindingConfirmed, FindingResolved, FindingFixed,
		FindingFalsePositive, FindingIgnored, FindingDuplicate, FindingRiskAccepted:
		return true
	}
	return false
}

// Finding severity levels (findings.severity).
const (
	SeverityCritical = "critical" // 严重
	SeverityHigh     = "high"     // 高
	SeverityMedium   = "medium"   // 中
	SeverityLow      = "low"      // 低
)

// ValidSeverity reports whether s is a known severity level.
func ValidSeverity(s string) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	}
	return false
}

// AddFinding inserts a finding into the standalone findings table. taskID and
// nodeID may be 0 (stored as NULL). name may be "" (frontend falls back to
// vulnclass). Returns the new finding id.
func (d *DB) AddFinding(taskID, nodeID int64, vulnclass, name, severity, summary, evidence, worker string, assetIDs []int64) (int64, error) {
	id, _, err := d.UpsertFinding(taskID, nodeID, vulnclass, name, severity, summary, evidence, worker, assetIDs, "")
	return id, err
}

// UpsertFinding inserts a finding, or merges it into the row carrying the same
// dedupeKey. A non-empty key is the canonical identity of a machine-produced
// finding (template + origin + path), so repeated scans update evidence instead
// of piling up duplicates. The existing triage status is never overwritten.
// Returns created=false when an existing row was updated.
func (d *DB) UpsertFinding(taskID, nodeID int64, vulnclass, name, severity, summary, evidence, worker string, assetIDs []int64, dedupeKey string) (id int64, created bool, err error) {
	aidsJSON, _ := json.Marshal(assetIDs)
	if assetIDs == nil {
		aidsJSON = []byte("[]")
	}
	var tid, nid *int64
	if taskID > 0 {
		tid = &taskID
	}
	if nodeID > 0 {
		nid = &nodeID
	}
	dedupeKey = strings.TrimSpace(dedupeKey)
	if dedupeKey == "" {
		err = d.QueryRow(
			`INSERT INTO findings (task_id, node_id, vulnclass, name, severity, summary, evidence, worker, asset_ids)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
			tid, nid, vulnclass, name, severity, summary, evidence, worker, string(aidsJSON),
		).Scan(&id)
		return id, err == nil, err
	}
	err = d.QueryRow(
		`INSERT INTO findings (task_id, node_id, vulnclass, name, severity, summary, evidence, worker, asset_ids, dedupe_key)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (dedupe_key) DO UPDATE SET
		     name      = CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE findings.name END,
		     severity  = CASE WHEN EXCLUDED.severity <> '' THEN EXCLUDED.severity ELSE findings.severity END,
		     summary   = EXCLUDED.summary,
		     evidence  = EXCLUDED.evidence,
		     worker    = EXCLUDED.worker,
		     asset_ids = EXCLUDED.asset_ids
		 RETURNING id, (xmax = 0)`,
		tid, nid, vulnclass, name, severity, summary, evidence, worker, string(aidsJSON), dedupeKey,
	).Scan(&id, &created)
	return id, created, err
}

// ConfirmFinding appends a verification note to the finding evidence and moves
// it to confirmed through SetFindingStatusTx, so status-change notifications
// fire exactly as they do for a manual triage update. The note is only
// appended once per caller-supplied chunk; pass "" to change status only.
func (d *DB) ConfirmFinding(ctx context.Context, id int64, note string) (from string, found bool, changed bool, err error) {
	return d.setFindingVerdict(ctx, id, note, FindingConfirmed)
}

// ReopenFinding sends a finding back to 待处理 with the reason recorded. It is
// the mirror image of ConfirmFinding: when a specialized tool (sqlmap, dalfox)
// cannot reproduce what a POC template had asserted, the finding must leave the
// confirmed set instead of keeping a verdict the platform now doubts.
func (d *DB) ReopenFinding(ctx context.Context, id int64, note string) (from string, found bool, changed bool, err error) {
	return d.setFindingVerdict(ctx, id, note, FindingPending)
}

func (d *DB) setFindingVerdict(ctx context.Context, id int64, note, to string) (from string, found bool, changed bool, err error) {
	note = strings.TrimSpace(note)
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, id, nil); err != nil {
			if errors.Is(err, ErrFindingNotFound) {
				return nil
			}
			return err
		}
		found = true
		if note != "" {
			var existing string
			if err := tx.QueryRowContext(ctx, `SELECT evidence FROM findings WHERE id=$1`, id).Scan(&existing); err != nil {
				return err
			}
			if !strings.Contains(existing, note) {
				if _, err := tx.ExecContext(ctx,
					`UPDATE findings SET evidence = CASE WHEN evidence = '' THEN $2 ELSE evidence || E'\n\n' || $2 END WHERE id=$1`,
					id, note); err != nil {
					return err
				}
				if err := bumpEvidenceVersionTx(tx, id); err != nil {
					return err
				}
			}
		}
		from, _, changed, _, err = SetFindingStatusTx(ctx, tx, id, to)
		return err
	})
	return from, found, changed, err
}

// findingSelectCols is the column list (with task_description join) every finding
// list query selects, so scanFinding stays in sync across callers.
const findingSelectCols = `f.id, f.task_id, f.node_id, f.vulnclass, COALESCE(f.name, ''), f.severity, f.summary,
	       f.evidence, f.worker, f.asset_ids, COALESCE(f.status, 'pending'), f.created_at,
	       COALESCE(t.description, '') AS task_description, f.evidence_version, f.report_evidence_version, f.cvss,
 (SELECT count(*) FROM finding_traffic_bindings b WHERE b.finding_id=f.id),
 COALESCE(f.reproduction::text, '')`

// scanFindings materializes rows selected via findingSelectCols.
func scanFindings(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*DBFinding, error) {
	var out []*DBFinding
	for rows.Next() {
		f := &DBFinding{}
		var aidsJSON string
		var cvss sql.NullFloat64
		var reproText string
		if err := rows.Scan(&f.ID, &f.TaskID, &f.NodeID, &f.VulnClass, &f.Name, &f.Severity,
			&f.Summary, &f.Evidence, &f.Worker, &aidsJSON, &f.Status, &f.CreatedAt, &f.TaskDescription, &f.EvidenceVersion, &f.ReportEvidenceVersion, &cvss, &f.TrafficCount, &reproText); err != nil {
			return nil, err
		}
		if cvss.Valid {
			f.CVSS = &cvss.Float64
		}
		f.Reproduction = ParseReproduction(reproText)
		_ = json.Unmarshal([]byte(aidsJSON), &f.AssetIDs)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListFindings returns all findings (newest first), joined with task description.
// Kept for the dashboard's summary; the paginated 发现 page uses ListFindingsPage.
func (d *DB) ListFindings(limit int) ([]*DBFinding, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := d.Query(`
		SELECT `+findingSelectCols+`
		FROM findings f
		LEFT JOIN tasks t ON f.task_id = t.id
		ORDER BY f.created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// FindingFilter narrows a paginated findings query. Empty-string fields mean "no
// filter on that column". Sort is "severity" (severity desc, then newest) or
// anything else (newest first).
type FindingFilter struct {
	Severity  string // high | medium | low
	Status    string // pending | false_positive | ignored | resolved
	VulnClass string
	TaskID    string // 任务 id(字符串形式;空/非法 = 不按任务筛选)
	// ScanTaskID 按无 LLM 漏扫任务筛选:命中的 finding 通过 scan_task_results
	// 关联(一条 finding 可被多轮扫描重复命中)。空/非法 = 不按漏扫任务筛选。
	ScanTaskID string
	Query      string // 名称/类型/摘要/证据/报告正文的模糊检索关键词
	Sort       string // "severity" | "time"
	// AssetScope 是资产树的节点 key(a:<id> / c:<id> / r:<domain> / __none__),
	// 选中一个节点等于选中它的整棵子树。空 = 不按资产筛选。
	AssetScope string
	// System 是系统(host:port / host / __none__)的 key,对应「按任务 → 系统」
	// 视图的叶子;空 = 不按系统筛选。
	System string

	// 下面几个由 applyAssetScope / applySystemScope 解析而来,调用方不用设置。
	assetIDs     []int64 // 子树里所有资产 id
	assetNone    bool    // 只要「未关联资产」的发现
	assetMiss    bool    // 选中的节点在当前筛选下不存在 → 结果恒空
	systemIDs    []int64 // 主系统命中的发现 id
	systemFilter bool    // System 已解析(即使命中为空也要过滤)
}

// FindingUnassignedTask is the task filter sentinel for findings whose task is
// absent. That includes rows created without a task and rows retained after their
// originating task was deleted (the findings FK is ON DELETE SET NULL).
const FindingUnassignedTask = "__unassigned__"

// where builds the WHERE clause (shared by the page and count queries) plus its
// positional args. All values are parameterized; Query also escapes ILIKE
// wildcards so user input is always matched literally.
func (f FindingFilter) where() (string, []any) {
	var conds []string
	var args []any
	add := func(col, val string) {
		if val == "" {
			return
		}
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("f.%s = $%d", col, len(args)))
	}
	add("severity", f.Severity)
	add("status", f.Status)
	add("vulnclass", f.VulnClass)
	// task_id 是 bigint 列,按整数比较(不能走上面的文本 add);空/非法值忽略。
	if f.TaskID == FindingUnassignedTask {
		// 「未关联」只收既没有 Agent 任务、也没有漏扫任务来源的 finding;
		// 漏扫发现有自己的任务分组,不能混进这个桶。
		conds = append(conds, `((f.task_id IS NULL AND NOT EXISTS (
			SELECT 1 FROM scan_task_results sr WHERE sr.finding_id = f.id
		)) OR (f.task_id IS NOT NULL AND t.id IS NULL))`)
	} else if tid, err := strconv.ParseInt(f.TaskID, 10, 64); err == nil && tid > 0 {
		args = append(args, tid)
		conds = append(conds, fmt.Sprintf("f.task_id = $%d", len(args)))
	}
	if sid, err := strconv.ParseInt(strings.TrimSpace(f.ScanTaskID), 10, 64); err == nil && sid > 0 {
		args = append(args, sid)
		conds = append(conds, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM scan_task_results sr
			WHERE sr.finding_id = f.id AND sr.scan_task_id = $%d
		)`, len(args)))
	}
	// 资产筛选:asset_ids 是 jsonb 数组,@> ANY(...) 能走 idx_findings_asset_ids。
	switch {
	case f.assetMiss:
		conds = append(conds, "FALSE")
	case f.assetNone:
		// 「未关联资产」= asset_ids 为空,或者里面的 id 一个都不在 assets 表里
		// (资产已被删除)。两类都进资产树的未关联桶,这里必须同样收下,否则桶上
		// 的计数会大于点开后能查到的条数。
		conds = append(conds, `(
			jsonb_array_length(COALESCE(f.asset_ids, '[]'::jsonb)) = 0
			OR NOT EXISTS (
				SELECT 1 FROM jsonb_array_elements_text(f.asset_ids) e(v)
				JOIN assets a ON a.id = e.v::bigint
			)
		)`)
	case len(f.assetIDs) > 0:
		args = append(args, assetIDContainments(f.assetIDs))
		conds = append(conds, fmt.Sprintf("f.asset_ids @> ANY($%d::jsonb[])", len(args)))
	}
	// 系统筛选解析成精确的发现 id 集合(主系统规则见 finding_systems.go)。
	if f.systemFilter {
		if len(f.systemIDs) == 0 {
			conds = append(conds, "FALSE")
		} else {
			args = append(args, f.systemIDs)
			conds = append(conds, fmt.Sprintf("f.id = ANY($%d::bigint[])", len(args)))
		}
	}
	if query := strings.TrimSpace(f.Query); query != "" {
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(query)
		args = append(args, "%"+escaped+"%")
		placeholder := fmt.Sprintf("$%d", len(args))
		conds = append(conds, fmt.Sprintf(`(
			COALESCE(f.name, '') ILIKE %s ESCAPE '\' OR
			f.vulnclass ILIKE %s ESCAPE '\' OR
			f.summary ILIKE %s ESCAPE '\' OR
			f.evidence ILIKE %s ESCAPE '\' OR
			COALESCE(f.report, '') ILIKE %s ESCAPE '\'
		)`, placeholder, placeholder, placeholder, placeholder, placeholder))
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// ListFindingsPage returns one page of findings matching the filter, plus the
// total count of matching rows (for the frontend pager). page is 1-based.
func (d *DB) ListFindingsPage(f FindingFilter, page, pageSize int) ([]*DBFinding, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	f, err := d.applyFindingScopes(f)
	if err != nil {
		return nil, 0, err
	}
	where, args := f.where()

	var total int
	if err := d.QueryRow(`SELECT COUNT(*) FROM findings f LEFT JOIN tasks t ON f.task_id=t.id`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	// Avoid overflowing (page-1)*pageSize for an arbitrarily large page number.
	// Once the requested page is beyond the exact count, no data query is needed.
	if total == 0 || page > (total-1)/pageSize+1 {
		return []*DBFinding{}, total, nil
	}

	order := "f.created_at DESC, f.id DESC"
	if f.Sort == "severity" {
		// critical > high > medium > low > 其它, then newest first.
		order = `CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, f.created_at DESC, f.id DESC`
	}
	pageArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	q := fmt.Sprintf(`
		SELECT %s
		FROM findings f
		LEFT JOIN tasks t ON f.task_id = t.id%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d`, findingSelectCols, where, order, len(args)+1, len(args)+2)
	rows, err := d.Query(q, pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out, err := scanFindings(rows)
	return out, total, err
}

// ListFindingIDs 返回匹配 filter 的全部 finding id（上限 limit），供「全选所有」批量
// 操作使用。复用与 ListFindingsPage 相同的筛选/排序，但不取字段、不分页。
func (d *DB) ListFindingIDs(f FindingFilter, limit int) ([]int64, error) {
	if limit <= 0 {
		limit = 500
	}
	f, err := d.applyFindingScopes(f)
	if err != nil {
		return nil, err
	}
	where, args := f.where()
	order := "f.created_at DESC, f.id DESC"
	if f.Sort == "severity" {
		order = `CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, f.created_at DESC, f.id DESC`
	}
	args = append(args, limit)
	q := fmt.Sprintf(`
		SELECT f.id
		FROM findings f
		LEFT JOIN tasks t ON f.task_id = t.id%s
		ORDER BY %s
		LIMIT $%d`, where, order, len(args))
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// FindingGroup is one task-level bucket in the global findings view. TaskID is
// nil for both findings that never had a task and findings retained after task
// deletion; those records intentionally share one "unassigned/deleted" bucket.
type FindingGroup struct {
	TaskID          *int64    `json:"task_id"`
	TaskName        string    `json:"task_name"` // 可选任务名称;空=未命名
	TaskDescription string    `json:"task_description"`
	TaskStatus      string    `json:"task_status"`
	ScanTaskID      *int64    `json:"scan_task_id"`
	ScanTaskName    string    `json:"scan_task_name"`
	Count           int       `json:"count"`
	Critical        int       `json:"critical"`
	High            int       `json:"high"`
	Medium          int       `json:"medium"`
	Low             int       `json:"low"`
	LastFoundAt     time.Time `json:"last_found_at"`
}

// ListFindingGroups returns a page of task groups matching the same filters as
// ListFindingsPage. The group count and finding count are independent totals so
// clients can page groups without losing the exact export/selection count.
// Findings without an Agent task are attributed to the earliest scan task that
// linked them (scan_task_results), so one finding is listed under exactly one
// group while a scan_task_id filter can still export every finding that scan hit.
func (d *DB) ListFindingGroups(f FindingFilter, page, pageSize int) ([]FindingGroup, int, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}
	f, err := d.applyFindingScopes(f)
	if err != nil {
		return nil, 0, 0, err
	}
	where, args := f.where()
	scanPick := ""
	if sid, err := strconv.ParseInt(strings.TrimSpace(f.ScanTaskID), 10, 64); err == nil && sid > 0 {
		scanPick = fmt.Sprintf(" AND st.id = %d", sid)
	}
	scanJoin := ` LEFT JOIN LATERAL (
		SELECT st.id, st.name, st.status
		FROM scan_task_results r
		JOIN scan_tasks st ON st.id = r.scan_task_id
		WHERE f.task_id IS NULL AND r.finding_id = f.id` + scanPick + `
		ORDER BY st.id
		LIMIT 1
	) st ON true`
	groupBy := ` GROUP BY t.id, t.name, t.description, t.status, t.paused, t.queued,
		st.id, st.name, st.status`
	grouped := ` FROM findings f LEFT JOIN tasks t ON f.task_id=t.id` + scanJoin + where + groupBy

	var groupTotal, findingTotal int
	countQuery := `SELECT COUNT(*), COALESCE(SUM(finding_count),0) FROM (` +
		`SELECT COUNT(*) AS finding_count` + grouped + `) grouped_findings`
	if err := d.QueryRow(countQuery, args...).Scan(&groupTotal, &findingTotal); err != nil {
		return nil, 0, 0, err
	}
	if groupTotal == 0 || page > (groupTotal-1)/pageSize+1 {
		return []FindingGroup{}, groupTotal, findingTotal, nil
	}

	order := "MAX(f.created_at) DESC, t.id DESC NULLS LAST, st.id DESC NULLS LAST"
	if f.Sort == "severity" {
		order = `MAX(CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) DESC, MAX(f.created_at) DESC, t.id DESC NULLS LAST, st.id DESC NULLS LAST`
	}
	pageArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	query := fmt.Sprintf(`SELECT t.id, COALESCE(t.name,''), COALESCE(t.description,''), COALESCE(
		CASE
			WHEN t.status IN ('done','failed','timeout') THEN t.status
			WHEN t.queued THEN 'queued'
			WHEN t.paused THEN 'paused'
			ELSE t.status
		END, ''),
		st.id, COALESCE(st.name,''), COALESCE(st.status,''),
		COUNT(*),
		COUNT(*) FILTER (WHERE f.severity='critical'),
		COUNT(*) FILTER (WHERE f.severity='high'),
		COUNT(*) FILTER (WHERE f.severity='medium'),
		COUNT(*) FILTER (WHERE f.severity='low'),
		MAX(f.created_at)%s
		ORDER BY %s LIMIT $%d OFFSET $%d`, grouped, order, len(args)+1, len(args)+2)
	rows, err := d.Query(query, pageArgs...)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	groups := []FindingGroup{}
	for rows.Next() {
		var group FindingGroup
		var taskID, scanTaskID sql.NullInt64
		var scanStatus string
		if err := rows.Scan(&taskID, &group.TaskName, &group.TaskDescription, &group.TaskStatus,
			&scanTaskID, &group.ScanTaskName, &scanStatus,
			&group.Count, &group.Critical, &group.High, &group.Medium, &group.Low, &group.LastFoundAt); err != nil {
			return nil, 0, 0, err
		}
		if taskID.Valid {
			id := taskID.Int64
			group.TaskID = &id
		}
		if scanTaskID.Valid {
			id := scanTaskID.Int64
			group.ScanTaskID = &id
			group.TaskStatus = scanStatus
		}
		groups = append(groups, group)
	}
	return groups, groupTotal, findingTotal, rows.Err()
}

// ErrFindingOriginUnavailable means a retained finding no longer has a live
// owning task and finding node from which a follow-up intent can be derived.
var ErrFindingOriginUnavailable = errors.New("finding origin is no longer available")

// AddFindingFollowUpIntent atomically creates a priority-10 human intent from a
// live finding node, copies that finding's asset anchors, records the
// finding --derived_from--> intent lineage edge, and persists its audit activity.
// The returned activity is the committed row and can be broadcast as-is without
// calling AppendActivity again.
func (s *ExplorationStore) AddFindingFollowUpIntent(findingID, findingNodeID int64, description string, audit Activity) (int64, Activity, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, Activity{}, err
	}
	defer tx.Rollback()

	var liveNodeID int64
	err = tx.QueryRow(`SELECT n.id
		FROM findings f
		JOIN tasks t ON t.id=f.task_id
		JOIN exploration_nodes n ON n.id=f.node_id AND n.exploration_id=t.exploration_id
		WHERE f.id=$1 AND f.node_id=$2 AND t.exploration_id=$3 AND n.kind='finding'
		FOR SHARE OF f, t, n`, findingID, findingNodeID, s.expID).Scan(&liveNodeID)
	if err == sql.ErrNoRows {
		return 0, Activity{}, ErrFindingOriginUnavailable
	}
	if err != nil {
		return 0, Activity{}, err
	}

	anchors := []int64{}
	anchorRows, err := tx.Query(`SELECT asset_id FROM exploration_anchors WHERE node_id=$1 ORDER BY asset_id`, liveNodeID)
	if err != nil {
		return 0, Activity{}, err
	}
	for anchorRows.Next() {
		var assetID int64
		if err := anchorRows.Scan(&assetID); err != nil {
			anchorRows.Close()
			return 0, Activity{}, err
		}
		anchors = append(anchors, assetID)
	}
	if err := anchorRows.Err(); err != nil {
		anchorRows.Close()
		return 0, Activity{}, err
	}
	if err := anchorRows.Close(); err != nil {
		return 0, Activity{}, err
	}

	payload := map[string]any{
		"summary":                description,
		"source_finding_id":      findingID,
		"source_finding_node_id": liveNodeID,
	}
	if len(anchors) > 0 {
		payload["asset_ids"] = anchors
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, Activity{}, err
	}
	var intentID int64
	if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
		VALUES ($1,'intent',$2,10,'open','human') RETURNING id`, s.expID, raw).Scan(&intentID); err != nil {
		return 0, Activity{}, err
	}
	if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id)
		SELECT $1, asset_id FROM exploration_anchors WHERE node_id=$2
		ON CONFLICT DO NOTHING`, intentID, liveNodeID); err != nil {
		return 0, Activity{}, err
	}
	if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
		VALUES ($1,$2,$3,$4)`, s.expID, liveNodeID, RelDerivedFrom, intentID); err != nil {
		return 0, Activity{}, err
	}

	audit.NodeID = &intentID
	if summary := strings.TrimSpace(audit.Summary); summary != "" {
		audit.Summary = fmt.Sprintf("%s #%d", summary, intentID)
	} else {
		audit.Summary = ""
	}
	metadata := audit.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	if err := tx.QueryRow(`
INSERT INTO activity(exploration_id, node_id, worker, kind, tool, tool_use_id, is_error, summary, detail, metadata, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens)
VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),$7,NULLIF($8,''),NULLIF($9,''),$10,$11,$12,$13,$14)
RETURNING id, created_at`, s.expID, audit.NodeID, utf8Clean(audit.Worker), utf8Clean(audit.Kind), utf8Clean(audit.Tool), utf8Clean(audit.ToolUseID), audit.IsError,
		utf8Clean(audit.Summary), utf8Clean(audit.Detail), metadata, audit.InputTokens, audit.OutputTokens, audit.CacheReadTokens, audit.CacheWriteTokens).
		Scan(&audit.ID, &audit.CreatedAt); err != nil {
		return 0, Activity{}, err
	}
	audit.Metadata = metadata
	if err := tx.Commit(); err != nil {
		return 0, Activity{}, err
	}
	return intentID, audit, nil
}

// ListFindingsForExport returns findings for the 发现 page 导出功能，携带完整
// report 字段、不分页。ids 非空时按这批 finding id 精确导出(勾选导出),忽略
// filter;ids 为空时按 filter 导出(导出当前筛选/全部)。结果按严重等级降序、
// 再按时间倒序,与「导出汇总报告」的分组顺序一致。
func (d *DB) ListFindingsForExport(f FindingFilter, ids []int64) ([]*DBFinding, error) {
	const order = `ORDER BY CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, f.created_at DESC`
	cols := findingSelectCols + `, COALESCE(f.report, ''), COALESCE(f.http_request, ''), COALESCE(f.http_response, ''), st.id, COALESCE(st.name, '')`
	scanJoin := func(pick string) string {
		return ` LEFT JOIN LATERAL (
			SELECT st.id, st.name
			FROM scan_task_results r
			JOIN scan_tasks st ON st.id = r.scan_task_id
			WHERE f.task_id IS NULL AND r.finding_id = f.id` + pick + `
			ORDER BY st.id LIMIT 1
		) st ON true`
	}

	var q string
	var args []any
	scanPick := ""
	if len(ids) > 0 {
		ph := make([]string, len(ids))
		for i, id := range ids {
			ph[i] = fmt.Sprintf("$%d", i+1)
			args = append(args, id)
		}
		q = `SELECT ` + cols + `
			FROM findings f
			LEFT JOIN tasks t ON f.task_id = t.id` + scanJoin(scanPick) + `
			WHERE f.id IN (` + strings.Join(ph, ",") + `)
			` + order
	} else {
		scoped, err := d.applyFindingScopes(f)
		if err != nil {
			return nil, err
		}
		where, wargs := scoped.where()
		if sid, err := strconv.ParseInt(strings.TrimSpace(scoped.ScanTaskID), 10, 64); err == nil && sid > 0 {
			// 按漏扫任务导出时,报告里的「所属任务」必须是这一轮,而不是最早一轮。
			scanPick = fmt.Sprintf(" AND st.id = %d", sid)
		}
		q = `SELECT ` + cols + `
			FROM findings f
			LEFT JOIN tasks t ON f.task_id = t.id` + scanJoin(scanPick) + where + `
			` + order
		args = wargs
	}

	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*DBFinding
	for rows.Next() {
		f := &DBFinding{}
		var aidsJSON string
		var cvss sql.NullFloat64
		var reproText string
		if err := rows.Scan(&f.ID, &f.TaskID, &f.NodeID, &f.VulnClass, &f.Name, &f.Severity,
			&f.Summary, &f.Evidence, &f.Worker, &aidsJSON, &f.Status, &f.CreatedAt,
			&f.TaskDescription, &f.EvidenceVersion, &f.ReportEvidenceVersion, &cvss, &f.TrafficCount, &reproText, &f.Report,
			&f.HTTPRequest, &f.HTTPResponse, &f.ScanTaskID, &f.ScanTaskName); err != nil {
			return nil, err
		}
		if cvss.Valid {
			f.CVSS = &cvss.Float64
		}
		f.Reproduction = ParseReproduction(reproText)
		_ = json.Unmarshal([]byte(aidsJSON), &f.AssetIDs)
		out = append(out, f)
	}
	return out, rows.Err()
}

// FindingStats is the whole-table aggregate powering the 发现 page's stat cards
// and vuln-class filter — computed server-side so it stays exact regardless of
// pagination.
type FindingStats struct {
	Distinct *FindingDistinctStats `json:"distinct,omitempty"`

	Total       int                 `json:"total"`
	Pending     int                 `json:"pending"`
	Critical    int                 `json:"critical"`
	High        int                 `json:"high"`
	Medium      int                 `json:"medium"`
	Low         int                 `json:"low"`
	VulnClasses []string            `json:"vulnclasses"`
	Tasks       []FindingTaskOption `json:"tasks"` // 有漏洞的任务(供「按任务」下拉)
}

// FindingTaskOption is one entry in the 发现 page's 任务 filter: a task that has at
// least one finding, with its description and finding count. Description is empty when
// the task has since been deleted (finding rows persist), so the frontend falls back to
// the id.
type FindingTaskOption struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"` // 可选任务名称;空=未命名
	Description string `json:"description"`
	Count       int    `json:"count"`
}

// FindingStats returns whole-table counts (by severity + pending) and the sorted
// set of distinct vuln classes.
func (d *DB) FindingStats() (*FindingStats, error) {
	st := &FindingStats{VulnClasses: []string{}, Tasks: []FindingTaskOption{}}
	err := d.QueryRow(`SELECT
		COUNT(*),
		COUNT(*) FILTER (WHERE status = 'pending'),
		COUNT(*) FILTER (WHERE severity = 'critical'),
		COUNT(*) FILTER (WHERE severity = 'high'),
		COUNT(*) FILTER (WHERE severity = 'medium'),
		COUNT(*) FILTER (WHERE severity = 'low')
		FROM findings`).Scan(&st.Total, &st.Pending, &st.Critical, &st.High, &st.Medium, &st.Low)
	if err != nil {
		return nil, err
	}
	rows, err := d.Query(`SELECT DISTINCT vulnclass FROM findings WHERE vulnclass <> '' ORDER BY vulnclass`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var vc string
		if err := rows.Scan(&vc); err != nil {
			return nil, err
		}
		st.VulnClasses = append(st.VulnClasses, vc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 任务下拉:有漏洞的任务,带描述(任务删除后为空,前端回退 id)和条数,最新有漏洞的排前。
	trows, err := d.Query(`SELECT f.task_id, COALESCE(t.name, ''), COALESCE(t.description, ''), COUNT(*)
		FROM findings f
		LEFT JOIN tasks t ON f.task_id = t.id
		WHERE f.task_id IS NOT NULL
		GROUP BY f.task_id, t.name, t.description
		ORDER BY MAX(f.created_at) DESC`)
	if err != nil {
		return nil, err
	}
	defer trows.Close()
	for trows.Next() {
		var opt FindingTaskOption
		if err := trows.Scan(&opt.ID, &opt.Name, &opt.Description, &opt.Count); err != nil {
			return nil, err
		}
		st.Tasks = append(st.Tasks, opt)
	}
	if err := trows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	vulnclasses := make(map[string]bool, len(st.VulnClasses))
	for _, vulnclass := range st.VulnClasses {
		vulnclasses[vulnclass] = true
	}
	for _, aggregate := range archived {
		cold := aggregate.FindingStats
		st.Total += cold.Total
		st.Pending += cold.Pending
		st.Critical += cold.Critical
		st.High += cold.High
		st.Medium += cold.Medium
		st.Low += cold.Low
		for _, vulnclass := range cold.VulnClasses {
			if vulnclass != "" {
				vulnclasses[vulnclass] = true
			}
		}
	}
	st.VulnClasses = st.VulnClasses[:0]
	for vulnclass := range vulnclasses {
		st.VulnClasses = append(st.VulnClasses, vulnclass)
	}
	sort.Strings(st.VulnClasses)
	return st, nil
}

// GetFinding returns a single finding row (with task_description joined and the
// full Markdown report), or nil when no row has that id. Unlike the list queries
// it also selects `report` — that column is only needed on the detail page.
func (d *DB) GetFinding(id int64) (*DBFinding, error) {
	f := &DBFinding{}
	var aidsJSON string
	var cvss sql.NullFloat64
	var reproText string
	err := d.QueryRow(`SELECT `+findingSelectCols+`, COALESCE(f.report, ''), COALESCE(f.http_request, ''), COALESCE(f.http_response, '')
		FROM findings f
		LEFT JOIN tasks t ON f.task_id = t.id
		WHERE f.id = $1`, id).Scan(
		&f.ID, &f.TaskID, &f.NodeID, &f.VulnClass, &f.Name, &f.Severity,
		&f.Summary, &f.Evidence, &f.Worker, &aidsJSON, &f.Status, &f.CreatedAt,
		&f.TaskDescription, &f.EvidenceVersion, &f.ReportEvidenceVersion, &cvss, &f.TrafficCount, &reproText, &f.Report,
		&f.HTTPRequest, &f.HTTPResponse)
	if cvss.Valid {
		f.CVSS = &cvss.Float64
	}
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(aidsJSON), &f.AssetIDs)
	f.Reproduction = ParseReproduction(reproText)
	return f, nil
}

// DeleteFinding removes a finding entirely: the standalone findings row and its
// originating exploration node (kind='finding'), so it disappears from the findings
// list, the per-task 发现 Tab, and the exploration graph alike. Deleting the node
// cascades its edges + node_assets and nulls any activity referencing it. Returns
// rows affected (0 = no finding with that id).
func (d *DB) DeleteFinding(id int64) (n int64, err error) {
	err = d.WithEvidenceTx(context.Background(), func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, id, nil); err != nil {
			if errors.Is(err, ErrFindingNotFound) {
				return nil
			}
			return err
		}
		var nodeID sql.NullInt64
		if err := tx.QueryRow(`DELETE FROM findings WHERE id=$1 RETURNING node_id`, id).Scan(&nodeID); err != nil {
			return err
		}
		if nodeID.Valid {
			if _, err := tx.Exec(`DELETE FROM exploration_nodes WHERE id=$1 AND kind='finding'`, nodeID.Int64); err != nil {
				return err
			}
		}
		n = 1
		return nil
	})
	return
}

// DeleteFindings removes many findings with the same cleanup as DeleteFinding, in
// one transaction: either every listed finding (plus its exploration node) is gone
// or nothing changed. Ids are locked in ascending order so concurrent batches taken
// in different submission orders cannot deadlock each other. Ids that no longer
// exist are skipped, and the return value counts only the rows actually deleted.
func (d *DB) DeleteFindings(ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	unique := slices.Sorted(slices.Values(ids))
	unique = slices.Compact(unique)
	var deleted int64
	err := d.WithEvidenceTx(context.Background(), func(tx *sql.Tx) error {
		var nodeIDs []int64
		for _, id := range unique {
			if err := LockFindingEvidenceTx(tx, id, nil); err != nil {
				if errors.Is(err, ErrFindingNotFound) {
					continue
				}
				return err
			}
			var nodeID sql.NullInt64
			if err := tx.QueryRow(`DELETE FROM findings WHERE id=$1 RETURNING node_id`, id).Scan(&nodeID); err != nil {
				return err
			}
			if nodeID.Valid {
				nodeIDs = append(nodeIDs, nodeID.Int64)
			}
			deleted++
		}
		if len(nodeIDs) > 0 {
			placeholders := make([]string, len(nodeIDs))
			args := make([]any, len(nodeIDs))
			for i, nodeID := range nodeIDs {
				placeholders[i] = "$" + strconv.Itoa(i+1)
				args[i] = nodeID
			}
			if _, err := tx.Exec(
				"DELETE FROM exploration_nodes WHERE kind='finding' AND id IN ("+strings.Join(placeholders, ",")+")",
				args...,
			); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// DeleteFindingsByTask removes all findings rows of a task. The originating
// exploration finding nodes are cascade-deleted separately when the task's
// exploration subgraph is dropped. Returns rows deleted.
func (d *DB) DeleteFindingsByTask(taskID int64) (int64, error) {
	res, err := d.Exec(`DELETE FROM findings WHERE task_id=$1`, taskID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetFindingStatus updates one finding's triage state. Returns rows affected.
//
// 底层 setter：只改状态、不登记推送事件。生产代码改状态请走
// SetFindingStatusWithNotify —— 直接调本函数会让「状态变更推送」静默失效。
// 保留它是为了让不关心通知的用例（参数校验、复测流程）能单独驱动状态。
func (d *DB) SetFindingStatus(id int64, status string) (int64, error) {
	res, err := d.Exec(`UPDATE findings SET status=$1 WHERE id=$2`, status, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetFindingReportByNodeID sets the Markdown report on the standalone finding row
// whose node_id matches — report_finding returns that node id, so an agent tool
// can address the finding it just created. Returns rows affected (0 when no row).
func (d *DB) SetFindingReportByNodeID(nodeID int64, report string) (int64, error) {
	return d.SetFindingReportVersionByNodeID(context.Background(), nodeID, report, nil)
}

// SetFindingHTTPArtifactsAndAutoReport stores the captured raw HTTP exchange and
// installs the deterministic report. A report authored by an LLM/human (no
// AutoReportMarker) is preserved; only empty or previously auto-generated reports
// are refreshed. Raw fields are only replaced when non-empty.
func (d *DB) SetFindingHTTPArtifactsAndAutoReport(id int64, request, response, report string) error {
	if id <= 0 {
		return nil
	}
	// 扫描到的报文可能带非 UTF-8 字节（GBK 页面、MySQL/Redis 等二进制协议响应），
	// Postgres 会直接拒绝整行写入并丢掉这条发现，所以入库前统一过一遍文本安全。
	request = safePacketText(request, maxRawPacketRequest)
	response = safePacketText(response, maxRawPacketResponse)
	report = safePacketText(report, 0)
	_, err := d.Exec(`UPDATE findings SET
		http_request  = CASE WHEN $2 <> '' THEN $2 ELSE http_request END,
		http_response = CASE WHEN $3 <> '' THEN $3 ELSE http_response END,
		report = CASE WHEN report = '' OR position($4 in report) > 0 THEN $5 ELSE report END,
		report_evidence_version = CASE WHEN report = '' OR position($4 in report) > 0 THEN evidence_version ELSE report_evidence_version END
		WHERE id=$1`, id, request, response, AutoReportMarker, report)
	return err
}

// SetFindingAutoReport installs a deterministic report but never replaces a
// report authored by an LLM/human.
func (d *DB) SetFindingAutoReport(id int64, report string) error {
	if id <= 0 {
		return nil
	}
	report = safePacketText(report, 0)
	_, err := d.Exec(`UPDATE findings SET report=$2, report_evidence_version=evidence_version
		WHERE id=$1 AND (report = '' OR position($3 in report) > 0)`, id, report, AutoReportMarker)
	return err
}

// setFindingCol updates one text column on the standalone finding row AND mirrors
// the new value into the originating exploration node's payload under jsonKey, so the
// per-task 发现 Tab (which reads the node payload, not this table) stays in sync.
// Returns rows affected (0 when no finding has that id); the node sync is best-effort.
// col and jsonKey MUST be trusted constants (they are interpolated into SQL) — never
// pass user input.
func (d *DB) setFindingCol(id int64, col, jsonKey, val string) (int64, error) {
	var nodeID *int64
	err := d.QueryRow(`UPDATE findings SET `+col+`=$1 WHERE id=$2 RETURNING node_id`, val, id).Scan(&nodeID)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if nodeID != nil {
		_, _ = d.Exec(`UPDATE exploration_nodes
			SET payload = jsonb_set(payload, '{`+jsonKey+`}', to_jsonb($1::text))
			WHERE id = $2`, val, *nodeID)
	}
	return 1, nil
}

// SetFindingCVSS updates one finding's CVSS base score (+ node payload sync). Returns
// rows affected (0 when no finding has that id).
func (d *DB) SetFindingCVSS(id int64, cvss float64) (int64, error) {
	var nodeID *int64
	err := d.QueryRow(`UPDATE findings SET cvss=$1 WHERE id=$2 RETURNING node_id`, cvss, id).Scan(&nodeID)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if nodeID != nil {
		_, _ = d.Exec(`UPDATE exploration_nodes SET payload = jsonb_set(payload, '{cvss}', to_jsonb($1::float8)) WHERE id = $2`, cvss, *nodeID)
	}
	return 1, nil
}

// SetFindingSeverity updates one finding's severity (+ node payload sync). Returns
// rows affected (0 when no finding has that id).
func (d *DB) SetFindingSeverity(id int64, severity string) (int64, error) {
	return d.setFindingCol(id, "severity", "severity", severity)
}

// SetFindingName updates one finding's 漏洞名称 (+ node payload sync). Empty name is
// allowed — the frontend falls back to the vuln class for display.
func (d *DB) SetFindingName(id int64, name string) (int64, error) {
	return d.setFindingCol(id, "name", "name", name)
}

// SetFindingVulnClass updates one finding's 漏洞类别 (+ node payload sync).
func (d *DB) SetFindingVulnClass(id int64, vulnclass string) (int64, error) {
	return d.setFindingCol(id, "vulnclass", "vulnclass", vulnclass)
}

// FindingMeta is the standalone-row data (id, triage state, anchored assets) the
// per-task view grafts onto its exploration-node findings.
type FindingMeta struct {
	TrafficCount int

	ID       int64
	Status   string
	AssetIDs []int64
}

// FindingMetaByNodeID maps a task's finding node ids to their standalone-row
// metadata (status + anchored asset ids) via the asset store, so callers holding
// only an AssetStore (e.g. the agent ToolSet) can reach it without a raw *DB.
func (a *AssetStore) FindingMetaByNodeID(taskID int64) (map[int64]FindingMeta, error) {
	return a.db.FindingMetaByNodeID(taskID)
}

// FindingMetaByNodeID maps a task's finding node ids to their standalone-row
// metadata, so the per-task view (which reads exploration nodes) can show and
// edit the same status — and the same anchored assets — as the global 发现 page.
func (d *DB) FindingMetaByNodeID(taskID int64) (map[int64]FindingMeta, error) {
	out := map[int64]FindingMeta{}
	if taskID <= 0 {
		return out, nil
	}
	rows, err := d.Query(`SELECT node_id, id, COALESCE(status,'pending'), asset_ids, (SELECT count(*) FROM finding_traffic_bindings b WHERE b.finding_id=findings.id) FROM findings
		WHERE task_id=$1 AND node_id IS NOT NULL`, taskID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var nid int64
		var m FindingMeta
		var aidsJSON string
		if err := rows.Scan(&nid, &m.ID, &m.Status, &aidsJSON, &m.TrafficCount); err != nil {
			return out, err
		}
		_ = json.Unmarshal([]byte(aidsJSON), &m.AssetIDs)
		out[nid] = m
	}
	return out, rows.Err()
}
