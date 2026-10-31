package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// 内网落地物台账：目标侧文件、计划任务、systemd 服务、SSH 公钥等持久化痕迹。
// 每条记录保存部署/撤销/验证命令，撤离时按 id 逆序执行撤销并核验。
// ---------------------------------------------------------------------------

const (
	IntranetArtifactActive  = "active"
	IntranetArtifactRevoked = "revoked"

	IntranetArtifactFile     = "file"
	IntranetArtifactCron     = "cron"
	IntranetArtifactSystemd  = "systemd"
	IntranetArtifactSSHKey   = "ssh_key"
	IntranetArtifactSchtasks = "schtasks"
	IntranetArtifactRegistry = "registry"
	IntranetArtifactOther    = "other"
)

var ErrIntranetArtifactNotFound = errors.New("intranet artifact not found")

type IntranetArtifact struct {
	ID            int64          `json:"id"`
	TaskID        *int64         `json:"task_id,omitempty"`
	SessionID     *int64         `json:"session_id,omitempty"`
	Host          string         `json:"host"`
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	Path          string         `json:"path"`
	Description   string         `json:"description"`
	DeployCommand string         `json:"deploy_command"`
	RevokeCommand string         `json:"revoke_command"`
	VerifyCommand string         `json:"verify_command"`
	Status        string         `json:"status"`
	Evidence      string         `json:"evidence"`
	Metadata      map[string]any `json:"metadata"`
	RevokedAt     *time.Time     `json:"revoked_at,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type IntranetArtifactInput struct {
	TaskID        int64
	SessionID     int64
	Host          string
	Kind          string
	Name          string
	Path          string
	Description   string
	DeployCommand string
	RevokeCommand string
	VerifyCommand string
	Evidence      string
	Metadata      map[string]any
}

type IntranetArtifactFilter struct {
	TaskID    int64
	SessionID int64
	Host      string
	Kind      string
	Status    string
	Limit     int
	Offset    int
}

const intranetArtifactCols = `id, task_id, session_id, host, kind, name, path, description,
	deploy_command, revoke_command, verify_command, status, evidence, metadata,
	revoked_at, created_at, updated_at`

func scanIntranetArtifact(row interface{ Scan(...any) error }) (*IntranetArtifact, error) {
	var a IntranetArtifact
	var raw []byte
	if err := row.Scan(&a.ID, &a.TaskID, &a.SessionID, &a.Host, &a.Kind, &a.Name, &a.Path,
		&a.Description, &a.DeployCommand, &a.RevokeCommand, &a.VerifyCommand, &a.Status,
		&a.Evidence, &raw, &a.RevokedAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return nil, err
	}
	a.Metadata = map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &a.Metadata)
	}
	return &a, nil
}

func validIntranetArtifactKind(kind string) bool {
	switch kind {
	case IntranetArtifactFile, IntranetArtifactCron, IntranetArtifactSystemd,
		IntranetArtifactSSHKey, IntranetArtifactSchtasks, IntranetArtifactRegistry, IntranetArtifactOther:
		return true
	}
	return false
}

// AddIntranetArtifact records one deployed artifact. Every row must carry a
// revoke command: an artifact the platform cannot remove is not allowed into
// the ledger.
func (d *DB) AddIntranetArtifact(in IntranetArtifactInput) (*IntranetArtifact, error) {
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	if !validIntranetArtifactKind(kind) {
		return nil, errors.New("kind 必须是 file/cron/systemd/ssh_key/schtasks/registry/other")
	}
	revoke := strings.TrimSpace(in.RevokeCommand)
	if revoke == "" {
		return nil, errors.New("撤销命令不能为空")
	}
	var taskID, sessionID any
	if in.TaskID > 0 {
		taskID = in.TaskID
	}
	if in.SessionID > 0 {
		sessionID = in.SessionID
	}
	meta, _ := json.Marshal(in.Metadata)
	if in.Metadata == nil {
		meta = []byte("{}")
	}
	return scanIntranetArtifact(d.QueryRow(`
INSERT INTO intranet_artifacts(task_id, session_id, host, kind, name, path, description,
    deploy_command, revoke_command, verify_command, evidence, metadata)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
RETURNING `+intranetArtifactCols,
		taskID, sessionID, strings.ToLower(strings.TrimSpace(in.Host)), kind,
		strings.TrimSpace(in.Name), strings.TrimSpace(in.Path), strings.TrimSpace(in.Description),
		strings.TrimSpace(in.DeployCommand), revoke, strings.TrimSpace(in.VerifyCommand),
		strings.TrimSpace(in.Evidence), string(meta)))
}

// ListIntranetArtifacts returns artifacts newest-first with optional filters.
func (d *DB) ListIntranetArtifacts(f IntranetArtifactFilter) ([]*IntranetArtifact, int, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where := []string{}
	args := []any{}
	if f.TaskID > 0 {
		args = append(args, f.TaskID)
		where = append(where, "task_id=$"+strconv.Itoa(len(args)))
	}
	if f.SessionID > 0 {
		args = append(args, f.SessionID)
		where = append(where, "session_id=$"+strconv.Itoa(len(args)))
	}
	if v := strings.ToLower(strings.TrimSpace(f.Host)); v != "" {
		args = append(args, v)
		where = append(where, "host=$"+strconv.Itoa(len(args)))
	}
	if v := strings.ToLower(strings.TrimSpace(f.Kind)); v != "" {
		args = append(args, v)
		where = append(where, "kind=$"+strconv.Itoa(len(args)))
	}
	if v := strings.ToLower(strings.TrimSpace(f.Status)); v != "" {
		args = append(args, v)
		where = append(where, "status=$"+strconv.Itoa(len(args)))
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM intranet_artifacts`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, f.Offset)
	rows, err := d.Query(`SELECT `+intranetArtifactCols+` FROM intranet_artifacts`+clause+
		` ORDER BY id DESC LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*IntranetArtifact{}
	for rows.Next() {
		a, err := scanIntranetArtifact(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (d *DB) GetIntranetArtifact(id int64) (*IntranetArtifact, error) {
	a, err := scanIntranetArtifact(d.QueryRow(`SELECT `+intranetArtifactCols+`
FROM intranet_artifacts WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIntranetArtifactNotFound
	}
	return a, err
}

// ListActiveIntranetArtifactsByTask returns still-deployed artifacts newest-first,
// i.e. the reverse order of deployment. The evacuation path walks this order.
func (d *DB) ListActiveIntranetArtifactsByTask(taskID int64) ([]*IntranetArtifact, error) {
	if taskID <= 0 {
		return []*IntranetArtifact{}, nil
	}
	rows, err := d.Query(`SELECT `+intranetArtifactCols+`
FROM intranet_artifacts WHERE task_id=$1 AND status='active' ORDER BY id DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IntranetArtifact{}
	for rows.Next() {
		a, err := scanIntranetArtifact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// MarkIntranetArtifactRevoked settles an artifact after its revoke command ran
// and the follow-up verification confirmed it is gone.
func (d *DB) MarkIntranetArtifactRevoked(id int64, evidence string) (*IntranetArtifact, error) {
	a, err := scanIntranetArtifact(d.QueryRow(`
UPDATE intranet_artifacts SET status='revoked', revoked_at=now(),
    evidence = CASE WHEN $2='' THEN evidence ELSE $2 END
WHERE id=$1
RETURNING `+intranetArtifactCols, id, strings.TrimSpace(evidence)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIntranetArtifactNotFound
	}
	return a, err
}

// UpdateIntranetArtifactEvidence records a held-over revoke attempt without
// changing status, so an artifact that failed to verify stays active for retry.
func (d *DB) UpdateIntranetArtifactEvidence(id int64, evidence string) (*IntranetArtifact, error) {
	a, err := scanIntranetArtifact(d.QueryRow(`
UPDATE intranet_artifacts SET evidence=$2 WHERE id=$1
RETURNING `+intranetArtifactCols, id, strings.TrimSpace(evidence)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIntranetArtifactNotFound
	}
	return a, err
}
