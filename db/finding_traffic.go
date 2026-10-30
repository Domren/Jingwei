package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/notify"
)

var (
	ErrEvidenceConflict = errors.New("流量证据已变更，请刷新后重试")
	ErrFindingNotFound  = errors.New("漏洞不存在")
	ErrEvidenceNotFound = errors.New("流量证据不存在")
)

// This lock covers the evidence filesystem as well as its SQL references. All
// processes sharing the database use it, including readers, exports and GC.
const findingEvidenceLockKey int64 = 7337741004

func (d *DB) WithEvidenceTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, findingEvidenceLockKey); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type TrafficRef struct {
	TrafficID string `json:"traffic_id"`
	Role      string `json:"role"`
	Note      string `json:"note"`
}

func NormalizeTrafficRefs(refs []TrafficRef) ([]TrafficRef, error) {
	out := make([]TrafficRef, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		ref.TrafficID = strings.TrimSpace(ref.TrafficID)
		if ref.TrafficID == "" {
			return nil, errors.New("traffic_id 不能为空")
		}
		if ref.Role == "" {
			ref.Role = "supporting"
		}
		if !ValidTrafficRole(ref.Role) {
			return nil, fmt.Errorf("无效的流量用途 %q", ref.Role)
		}
		if !seen[ref.TrafficID] {
			out = append(out, ref)
			seen[ref.TrafficID] = true
		}
	}
	return out, nil
}

func ValidTrafficRole(role string) bool {
	return role == "baseline" || role == "proof" || role == "verification" || role == "supporting"
}

type TrafficEvidenceSnapshot struct {
	ID              string    `json:"id"`
	SourceTrafficID string    `json:"source_traffic_id"`
	CapturedAt      int64     `json:"captured_at"`
	URL             string    `json:"url"`
	Method          string    `json:"method"`
	Status          int       `json:"status"`
	ContentType     string    `json:"content_type"`
	ReqHead         string    `json:"req_head,omitempty"`
	RespHead        string    `json:"resp_head,omitempty"`
	ReqHash         string    `json:"req_hash"`
	RespHash        string    `json:"resp_hash"`
	ReqLen          int64     `json:"req_len"`
	RespLen         int64     `json:"resp_len"`
	CreatedAt       time.Time `json:"created_at"`
}

type FindingTrafficBinding struct {
	ID         int64                   `json:"id,string"`
	FindingID  int64                   `json:"finding_id,string"`
	SnapshotID string                  `json:"snapshot_id"`
	Role       string                  `json:"role"`
	Note       string                  `json:"note"`
	Position   int                     `json:"position"`
	CreatedAt  time.Time               `json:"created_at"`
	Snapshot   TrafficEvidenceSnapshot `json:"snapshot"`
}

type FindingTraffic struct {
	FindingID     int64                   `json:"finding_id,string"`
	Version       int64                   `json:"version"`
	ReportVersion int64                   `json:"report_version"`
	Bindings      []FindingTrafficBinding `json:"bindings"`
}

type PreparedTrafficEvidence struct {
	Ref      TrafficRef
	Snapshot TrafficEvidenceSnapshot
}

// Normalize makes the snapshot's text columns safe for PostgreSQL. URL and the
// head blocks come straight off the wire, so a target answering with a non-UTF-8
// header (a GBK `Content-Disposition: filename=…`, a NUL byte) would otherwise
// abort the INSERT and roll back the whole finding — losing a confirmed finding
// over a malformed response header. Applied before hashing so the ID always
// matches the bytes that actually land in the table.
func (s TrafficEvidenceSnapshot) Normalize() TrafficEvidenceSnapshot {
	s.SourceTrafficID = utf8Clean(s.SourceTrafficID)
	s.URL = utf8Clean(s.URL)
	s.Method = utf8Clean(s.Method)
	s.ContentType = utf8Clean(s.ContentType)
	s.ReqHead = utf8Clean(s.ReqHead)
	s.RespHead = utf8Clean(s.RespHead)
	return s
}

func TrafficSnapshotID(snapshot TrafficEvidenceSnapshot) string {
	snapshot = snapshot.Normalize()
	snapshot.ID = ""
	snapshot.CreatedAt = time.Time{}
	raw, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// LockTaskEvidenceTx serializes writes with archive queueing (which locks the
// same task row). Once queued, its snapshot must not acquire new evidence.
func LockTaskEvidenceTx(tx *sql.Tx, taskID int64) error {
	if taskID == 0 {
		return nil
	}
	var deleted sql.NullTime
	if err := tx.QueryRow(`SELECT deleted_at FROM tasks WHERE id=$1 FOR UPDATE`, taskID).Scan(&deleted); err != nil {
		return err
	}
	if deleted.Valid {
		return ErrTaskArchiveState
	}
	var state string
	err := tx.QueryRow(`SELECT state FROM task_archives WHERE task_id=$1`, taskID).Scan(&state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && state != ArchiveFailed {
		return ErrTaskArchiveState
	}
	return nil
}

func LockFindingEvidenceTx(tx *sql.Tx, findingID int64, version *int64) error {
	var taskID sql.NullInt64
	if err := tx.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, findingID).Scan(&taskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if err := LockTaskEvidenceTx(tx, taskID.Int64); err != nil {
		return err
	}
	var current int64
	if err := tx.QueryRow(`SELECT evidence_version FROM findings WHERE id=$1 FOR UPDATE`, findingID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if version != nil && *version != current {
		return ErrEvidenceConflict
	}
	return nil
}

func InsertEvidenceSnapshotTx(tx *sql.Tx, s TrafficEvidenceSnapshot) error {
	if s.ID != TrafficSnapshotID(s) {
		return errors.New("证据快照元数据哈希不匹配")
	}
	// The ID was computed over the normalized form; store those same bytes.
	id := s.ID
	s = s.Normalize()
	s.ID = id
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	_, err := tx.Exec(`INSERT INTO traffic_evidence_snapshots
(id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO NOTHING`,
		s.ID, s.SourceTrafficID, s.CapturedAt, s.URL, s.Method, s.Status, s.ContentType, s.ReqHead, s.RespHead, s.ReqHash, s.RespHash, s.ReqLen, s.RespLen, s.CreatedAt)
	return err
}

func AddFindingTrafficTx(tx *sql.Tx, findingID int64, prepared []PreparedTrafficEvidence) error {
	var position int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(position)+1,0) FROM finding_traffic_bindings WHERE finding_id=$1`, findingID).Scan(&position); err != nil {
		return err
	}
	changed := false
	for _, item := range prepared {
		if err := InsertEvidenceSnapshotTx(tx, item.Snapshot); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE traffic_evidence_snapshots SET unreferenced_at=NULL WHERE id=$1`, item.Snapshot.ID); err != nil {
			return err
		}
		res, err := tx.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(finding_id,snapshot_id) DO NOTHING`, findingID, item.Snapshot.ID, item.Ref.Role, item.Ref.Note, position)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n > 0 {
			changed = true
			position++
		}
	}
	if changed {
		return bumpEvidenceVersionTx(tx, findingID)
	}
	return nil
}

func bumpEvidenceVersionTx(tx *sql.Tx, findingID int64) error {
	_, err := tx.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, findingID)
	return err
}

func FindingTrafficTx(tx *sql.Tx, findingID int64) (*FindingTraffic, error) {
	out := &FindingTraffic{FindingID: findingID, Bindings: []FindingTrafficBinding{}}
	if err := tx.QueryRow(`SELECT evidence_version,report_evidence_version FROM findings WHERE id=$1`, findingID).Scan(&out.Version, &out.ReportVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	rows, err := tx.Query(`SELECT b.id,b.finding_id,b.snapshot_id,b.role,b.note,b.position,b.created_at,to_jsonb(s)
FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id WHERE b.finding_id=$1 ORDER BY b.position,b.id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b FindingTrafficBinding
		var raw []byte
		if err := rows.Scan(&b.ID, &b.FindingID, &b.SnapshotID, &b.Role, &b.Note, &b.Position, &b.CreatedAt, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &b.Snapshot); err != nil {
			return nil, err
		}
		out.Bindings = append(out.Bindings, b)
	}
	return out, rows.Err()
}

func (d *DB) GetFindingTraffic(ctx context.Context, findingID int64) (out *FindingTraffic, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = FindingTrafficTx(tx, findingID); return e })
	return
}

func (d *DB) EditFindingTraffic(ctx context.Context, findingID, bindingID, version int64, role, note *string, remove bool, order []int64) error {
	if role != nil && !ValidTrafficRole(*role) {
		return errors.New("无效的流量用途")
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, &version); err != nil {
			return err
		}
		if order != nil {
			current, err := FindingTrafficTx(tx, findingID)
			if err != nil {
				return err
			}
			if len(order) != len(current.Bindings) {
				return ErrEvidenceConflict
			}
			ids := map[int64]bool{}
			for _, b := range current.Bindings {
				ids[b.ID] = true
			}
			for position, id := range order {
				if !ids[id] {
					return ErrEvidenceConflict
				}
				delete(ids, id)
				if _, err := tx.Exec(`UPDATE finding_traffic_bindings SET position=$1 WHERE finding_id=$2 AND id=$3`, position, findingID, id); err != nil {
					return err
				}
			}
		} else {
			var res sql.Result
			var err error
			if remove {
				res, err = tx.Exec(`DELETE FROM finding_traffic_bindings WHERE finding_id=$1 AND id=$2`, findingID, bindingID)
			} else {
				res, err = tx.Exec(`UPDATE finding_traffic_bindings SET role=COALESCE($3,role),note=COALESCE($4,note) WHERE finding_id=$1 AND id=$2`, findingID, bindingID, role, note)
			}
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrEvidenceNotFound
			}
		}
		return bumpEvidenceVersionTx(tx, findingID)
	})
}

type RecordFindingInput struct {
	TaskID, ExplorationID, IntentID                      int64
	VulnClass, Name, Severity, Summary, Evidence, Worker string
	CVSS                                                 *float64 // 提交时强制填写的 CVSS 基础分
	AssetIDs                                             []int64
	// RawRequest/RawResponse carry byte-exact non-HTTP protocol data (RESP,
	// MySQL, SSH banners…) that the proxy cannot capture; Protocol names it so
	// reports label the capture as raw data instead of HTTP packets.
	Protocol    string
	RawRequest  string
	RawResponse string
	// Reproduction is the structured recipe the agent records at confirm time
	// (entry point / prerequisites / ordered verbatim steps / provenance). Its
	// steps are resolved onto the bound snapshots inside the recording
	// transaction, so the report can print each step next to its own packet.
	Reproduction *Reproduction
}

// storeRawPacketsTx writes agent-supplied raw protocol bytes onto a finding.
// Existing packets are kept when the new value is empty.
func storeRawPacketsTx(tx *sql.Tx, findingID int64, in RecordFindingInput) (bool, error) {
	req := safePacketText(in.RawRequest, maxRawPacketRequest)
	resp := safePacketText(in.RawResponse, maxRawPacketResponse)
	if req == "" && resp == "" {
		return false, nil
	}
	res, err := tx.Exec(`UPDATE findings SET
		http_request  = CASE WHEN $2 <> '' THEN $2 ELSE http_request END,
		http_response = CASE WHEN $3 <> '' THEN $3 ELSE http_response END
		WHERE id=$1`, findingID, req, resp)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

const (
	maxRawPacketRequest  = 64 << 10
	maxRawPacketResponse = 128 << 10
)

// safePacketText drops only the bytes a Postgres text column cannot store (NUL,
// invalid UTF-8). Line terminators and trailing CRLF are kept because the saved
// bytes must replay identically on the wire.
func safePacketText(s string, limit int) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ToValidUTF8(s, "\uFFFD")
	if limit > 0 && len(s) > limit {
		s = strings.ToValidUTF8(s[:limit], "") + "\n\n[报文过长，已截断]"
	}
	return s
}

type RecordedFinding struct {
	FindingID int64           `json:"finding_id,string"`
	NodeID    int64           `json:"finding_node_id,string"`
	Traffic   *FindingTraffic `json:"traffic"`
}

// ctx 由调用方传入本次事务所用的上下文（而非在内部取 context.Background）：
// 事务内新加的推送事件写入同样应受调用方的取消与超时约束。
func RecordFindingTx(ctx context.Context, tx *sql.Tx, in RecordFindingInput, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	if err := LockTaskEvidenceTx(tx, in.TaskID); err != nil {
		return nil, err
	}
	if in.TaskID > 0 {
		var expID int64
		if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, in.TaskID).Scan(&expID); err != nil {
			return nil, err
		}
		if expID != in.ExplorationID {
			return nil, errors.New("漏洞所属任务与探索记录不匹配")
		}
	}
	if in.IntentID > 0 {
		var ok bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent')`, in.IntentID, in.ExplorationID).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("intent_id 必须是本任务的意图（关联任务意图只读）")
		}
	}
	identity := agentFindingIdentity(in, prepared)
	if identity != "" {
		var existingID, existingNode int64
		err := tx.QueryRow(`SELECT id, COALESCE(node_id, 0) FROM findings WHERE dedupe_key=$1`, identity).Scan(&existingID, &existingNode)
		if err == nil {
			return mergeAgentFindingTx(ctx, tx, existingID, existingNode, in, prepared)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	payload, _ := json.Marshal(map[string]any{"vulnclass": in.VulnClass, "name": in.Name, "severity": in.Severity, "summary": in.Summary, "evidence": map[string]any{"by": in.Worker, "poc": in.Evidence}})
	out := &RecordedFinding{}
	if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
VALUES($1,'finding',$2,9,'confirmed',$3) RETURNING id`, in.ExplorationID, string(payload), in.Worker).Scan(&out.NodeID); err != nil {
		return nil, err
	}
	for _, asset := range in.AssetIDs {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, out.NodeID, asset); err != nil {
			return nil, err
		}
	}
	if in.IntentID > 0 {
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4)`, in.ExplorationID, in.IntentID, RelYields, out.NodeID); err != nil {
			return nil, err
		}
	}
	assets := in.AssetIDs
	if assets == nil {
		assets = []int64{}
	}
	raw, _ := json.Marshal(assets)
	if err := tx.QueryRow(`INSERT INTO findings(task_id,node_id,vulnclass,name,severity,summary,evidence,worker,asset_ids,dedupe_key,cvss)
VALUES(NULLIF($1,0),$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,''),$11) RETURNING id`, in.TaskID, out.NodeID, in.VulnClass, in.Name, in.Severity, in.Summary, in.Evidence, in.Worker, string(raw), identity, in.CVSS).Scan(&out.FindingID); err != nil {
		return nil, err
	}
	if _, err := storeRawPacketsTx(tx, out.FindingID, in); err != nil {
		return nil, err
	}
	// 在**同一事务**里登记一条推送事件：提交即保证「漏洞落库」与「推送任务存在」
	// 原子一致，不存在提交成功却没入队、消息永久丢失的窗口。
	// 这里的失败被隔离在保存点上、不影响漏洞写入（见函数注释），因此忽略返回值。
	RecordNotificationEventTx(ctx, tx, notify.EventFindingCreated, out.FindingID, notify.Snapshot{
		Kind:      notify.EventFindingCreated,
		FindingID: out.FindingID,
		TaskID:    in.TaskID,
		VulnClass: in.VulnClass,
		Name:      in.Name,
		Severity:  in.Severity,
		Summary:   in.Summary,
		AssetIDs:  assets,
	})
	if err := AddFindingTrafficTx(tx, out.FindingID, prepared); err != nil {
		return nil, err
	}
	var err error
	out.Traffic, err = FindingTrafficTx(tx, out.FindingID)
	if err != nil {
		return nil, err
	}
	// 复现过程与流量绑定在同一事务里完成：步骤要落到刚绑定好的快照上，
	// 拆开就会有一段时间报告里「步骤有、报文没有」。
	if _, err := storeReproductionTx(tx, out.FindingID, in.Reproduction, out.Traffic.Bindings); err != nil {
		return nil, err
	}
	return out, nil
}

// findingClassKey folds the free-form vulnclass/name an LLM writes into a
// stable family, so two workers describing the same weakness with different
// wording still dedupe.
func findingClassKey(vulnclass, name string) string {
	text := strings.ToLower(vulnclass + " " + name)
	has := func(terms ...string) bool {
		for _, term := range terms {
			if strings.Contains(text, term) {
				return true
			}
		}
		return false
	}
	switch {
	// Weak credentials and CSRF are checked before XSS: a name such as
	// "pkxss 后台弱口令" contains the substring "xss" but is not XSS.
	case has("weak password", "weak credential", "default credential", "弱口令"):
		return "weak-password"
	case has("csrf", "cross-site request forgery", "跨站请求伪造"):
		return "csrf"
	case has("sql injection", "sqli", "sql 注入", "sql注入"):
		return "sqli"
	case has("command injection", "rce", "命令注入", "命令执行", "代码执行"):
		return "rce"
	case has("file inclusion", "lfi", "文件包含"):
		return "lfi"
	case has("path traversal", "directory traversal", "路径穿越", "目录穿越", "目录遍历"):
		return "traversal"
	case has("upload", "文件上传"):
		return "upload"
	case has("ssrf", "服务端请求伪造"):
		return "ssrf"
	case has("xxe", "xml external"):
		return "xxe"
	case has("idor", "越权", "insecure direct object"):
		return "idor"
	case has("xss", "跨站脚本"):
		return "xss"
	case has("sensitive information", "information disclosure", "信息泄露", "敏感信息"):
		return "info-disclosure"
	}
	return ""
}

// agentFindingTargetKey identifies the verified location from captured traffic:
// host + path + parameter names + method. Payload values are deliberately
// excluded so a second worker proving the same sink with a different payload
// merges into the existing finding instead of creating a duplicate.
func agentFindingTargetKey(prepared []PreparedTrafficEvidence) string {
	pick := func(p PreparedTrafficEvidence) string {
		u, err := url.Parse(p.Snapshot.URL)
		if err != nil || u.Host == "" {
			return ""
		}
		target := strings.ToLower(u.Scheme + "://" + u.Host + u.Path)
		keys := make([]string, 0, 4)
		for key := range u.Query() {
			keys = append(keys, strings.ToLower(key))
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			target += "?" + strings.Join(keys, "&")
		}
		if method := strings.ToUpper(strings.TrimSpace(p.Snapshot.Method)); method != "" {
			target += "#" + method
		}
		return target
	}
	for _, p := range prepared {
		if p.Ref.Role == "proof" {
			if target := pick(p); target != "" {
				return target
			}
		}
	}
	for _, p := range prepared {
		if target := pick(p); target != "" {
			return target
		}
	}
	return ""
}

func normalizeIdentityText(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r > 0x7f {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 96 {
		out = out[:96]
	}
	return out
}

// agentFindingIdentity returns the dedupe key for an agent-recorded finding.
// A finding is keyed by task + weakness family + verified location; without
// packets it falls back to the normalized name within the same family.
func agentFindingIdentity(in RecordFindingInput, prepared []PreparedTrafficEvidence) string {
	if in.TaskID <= 0 {
		return ""
	}
	class := findingClassKey(in.VulnClass, in.Name)
	if class == "" {
		return ""
	}
	target := agentFindingTargetKey(prepared)
	if target == "" {
		target = normalizeIdentityText(in.Name)
	}
	if target == "" {
		return ""
	}
	return fmt.Sprintf("agent:%d:%s:%s", in.TaskID, class, target)
}

func severityWeight(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// mergeAgentFindingTx folds a repeated observation into the existing finding:
// the richest text wins, the highest severity wins, the triage status is left
// untouched, and newly verified packets are appended to the binding list.
func mergeAgentFindingTx(ctx context.Context, tx *sql.Tx, findingID, nodeID int64, in RecordFindingInput, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	var name, severity, summary, evidence string
	if err := tx.QueryRowContext(ctx, `SELECT name, severity, summary, evidence FROM findings WHERE id=$1`, findingID).
		Scan(&name, &severity, &summary, &evidence); err != nil {
		return nil, err
	}
	if len(in.Name) > len(name) {
		name = in.Name
	}
	if severityWeight(in.Severity) > severityWeight(severity) {
		severity = in.Severity
	}
	changed := false
	if len(in.Summary) > len(summary) {
		summary = in.Summary
		changed = true
	}
	if len(in.Evidence) > len(evidence) {
		evidence = in.Evidence
		changed = true
	}
	if in.CVSS != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET cvss=$2 WHERE id=$1 AND cvss IS NULL`, findingID, *in.CVSS); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET name=$2, severity=$3, summary=$4, evidence=$5 WHERE id=$1`,
		findingID, name, severity, summary, evidence); err != nil {
		return nil, err
	}
	stored, err := storeRawPacketsTx(tx, findingID, in)
	if err != nil {
		return nil, err
	}
	if changed || stored {
		if err := bumpEvidenceVersionTx(tx, findingID); err != nil {
			return nil, err
		}
	}
	if err := AddFindingTrafficTx(tx, findingID, prepared); err != nil {
		return nil, err
	}
	traffic, err := FindingTrafficTx(tx, findingID)
	if err != nil {
		return nil, err
	}
	// 合并时用最新一次记录覆盖复现过程——重复上报的通常是对同一漏洞更完整的
	// 复现链条；空值不覆盖已有内容（见 storeReproductionTx）。
	reproStored, err := storeReproductionTx(tx, findingID, in.Reproduction, traffic.Bindings)
	if err != nil {
		return nil, err
	}
	if reproStored && !changed && !stored {
		// 复现过程变了同样意味着报告要重出，否则详情页/报告会停在旧版本。
		if err := bumpEvidenceVersionTx(tx, findingID); err != nil {
			return nil, err
		}
	}
	return &RecordedFinding{FindingID: findingID, NodeID: nodeID, Traffic: traffic}, nil
}

// RecordFinding is the atomic legacy/no-recorder path used by tools and tests.
func (s *ExplorationStore) RecordFinding(ctx context.Context, in RecordFindingInput) (out *RecordedFinding, err error) {
	in.ExplorationID = s.expID
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = RecordFindingTx(ctx, tx, in, nil); return e })
	return
}

func (d *DB) FindingIDByNodeID(nodeID int64) (id int64, err error) {
	err = d.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&id)
	return
}

// PopulateFindingTrafficIDs only enriches already-visible nodes. It performs no
// discovery or ID guessing, and leaves the legacy node ID unchanged.
func (s *ExplorationStore) PopulateFindingTrafficIDs(nodes []*Node) error {
	byID := map[int64]*Node{}
	var args []any
	var placeholders []string
	for _, n := range nodes {
		if n == nil || n.Kind != KindFinding || byID[n.ID] != nil {
			continue
		}
		byID[n.ID] = n
		args = append(args, n.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	if len(args) == 0 {
		return nil
	}
	rows, err := s.db.Query(`SELECT f.id,f.node_id,(SELECT count(*) FROM finding_traffic_bindings b WHERE b.finding_id=f.id) FROM findings f WHERE f.node_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var findingID, nodeID int64
		var count int
		if err := rows.Scan(&findingID, &nodeID, &count); err != nil {
			return err
		}
		n := byID[nodeID]
		n.FindingID, n.FindingNodeID, n.TrafficCount = findingID, nodeID, count
	}
	return rows.Err()
}

func (d *DB) SetFindingReportVersionByNodeID(ctx context.Context, nodeID int64, report string, version *int64) (n int64, err error) {
	report = safePacketText(report, 0)
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var id int64
		if err := tx.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if err := LockFindingEvidenceTx(tx, id, version); err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE findings SET report=$2,report_evidence_version=COALESCE($3::bigint,CASE WHEN evidence_version=0 THEN 0 ELSE -1 END) WHERE id=$1`, id, report, version)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return
}
