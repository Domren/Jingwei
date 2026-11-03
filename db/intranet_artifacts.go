package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// ---------------------------------------------------------------------------
// 内网落地物台账：目标侧文件、计划任务、systemd 服务、SSH 公钥等持久化痕迹。
// 每条记录保存部署/撤销/验证命令，撤离时按 id 逆序执行撤销并核验。
// ---------------------------------------------------------------------------

const (
	IntranetArtifactActive  = "active"
	IntranetArtifactRevoked = "revoked"

	IntranetArtifactFile        = "file"
	IntranetArtifactCron        = "cron"
	IntranetArtifactSystemd     = "systemd"
	IntranetArtifactUserSystemd = "user_systemd"
	IntranetArtifactAt          = "at"
	IntranetArtifactProfile     = "profile"
	IntranetArtifactSSHKey      = "ssh_key"
	IntranetArtifactSchtasks    = "schtasks"
	IntranetArtifactRegistry    = "registry"
	IntranetArtifactService     = "service"
	IntranetArtifactWMI         = "wmi"
	IntranetArtifactStartup     = "startup"
	IntranetArtifactPHPUserINI  = "php_user_ini"
	IntranetArtifactPHPHtaccess = "php_htaccess"
	IntranetArtifactOther       = "other"
)

var (
	ErrIntranetArtifactNotFound  = errors.New("intranet artifact not found")
	ErrIntranetArtifactDuplicate = errors.New("an active intranet artifact with the same fingerprint already exists")
)

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
	Fingerprint   string         `json:"fingerprint"`
	Evidence      string         `json:"evidence"`
	Metadata      map[string]any `json:"metadata"`
	ExpiresAt     *time.Time     `json:"expires_at,omitempty"`
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
	Fingerprint   string
	Evidence      string
	ExpiresAt     *time.Time
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
	deploy_command, revoke_command, verify_command, status, fingerprint, evidence, metadata,
	expires_at, revoked_at, created_at, updated_at`

func scanIntranetArtifact(row interface{ Scan(...any) error }) (*IntranetArtifact, error) {
	var a IntranetArtifact
	var raw []byte
	if err := row.Scan(&a.ID, &a.TaskID, &a.SessionID, &a.Host, &a.Kind, &a.Name, &a.Path,
		&a.Description, &a.DeployCommand, &a.RevokeCommand, &a.VerifyCommand, &a.Status,
		&a.Fingerprint, &a.Evidence, &raw, &a.ExpiresAt, &a.RevokedAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
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
		IntranetArtifactUserSystemd, IntranetArtifactAt, IntranetArtifactProfile,
		IntranetArtifactSSHKey, IntranetArtifactSchtasks, IntranetArtifactRegistry,
		IntranetArtifactService, IntranetArtifactWMI, IntranetArtifactStartup,
		IntranetArtifactPHPUserINI, IntranetArtifactPHPHtaccess,
		IntranetArtifactOther:
		return true
	}
	return false
}

// PHPPersistArtifactKinds are the ledger kinds that describe a PHP
// auto_prepend_file persistence config. They are deployed from a webshell
// instead of an intranet session, so revocation may have to run through that
// webshell (metadata webshell_id / parent_webshell_id).
func PHPPersistArtifactKinds() []string {
	return []string{IntranetArtifactPHPUserINI, IntranetArtifactPHPHtaccess}
}

func IsPHPPersistArtifactKind(kind string) bool {
	kind = strings.ToLower(strings.TrimSpace(kind))
	return kind == IntranetArtifactPHPUserINI || kind == IntranetArtifactPHPHtaccess
}

// AddIntranetArtifact records one deployed artifact. Every row must carry a
// revoke command: an artifact the platform cannot remove is not allowed into
// the ledger.
func (d *DB) AddIntranetArtifact(in IntranetArtifactInput) (*IntranetArtifact, error) {
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	if !validIntranetArtifactKind(kind) {
		return nil, errors.New("kind 必须是 file/cron/systemd/user_systemd/at/profile/ssh_key/schtasks/registry/service/wmi/startup/php_user_ini/php_htaccess/other")
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
	art, err := scanIntranetArtifact(d.QueryRow(`
INSERT INTO intranet_artifacts(task_id, session_id, host, kind, name, path, description,
    deploy_command, revoke_command, verify_command, fingerprint, evidence, metadata, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
RETURNING `+intranetArtifactCols,
		taskID, sessionID, strings.ToLower(strings.TrimSpace(in.Host)), kind,
		strings.TrimSpace(in.Name), strings.TrimSpace(in.Path), strings.TrimSpace(in.Description),
		strings.TrimSpace(in.DeployCommand), revoke, strings.TrimSpace(in.VerifyCommand),
		strings.TrimSpace(in.Fingerprint), strings.TrimSpace(in.Evidence), string(meta), in.ExpiresAt))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, ErrIntranetArtifactDuplicate
	}
	return art, err
}

// FindActiveIntranetArtifactByFingerprint powers idempotent reinstall: the same
// module identity on the same host reuses its active ledger row instead of
// planting a second copy.
func (d *DB) FindActiveIntranetArtifactByFingerprint(fingerprint string) (*IntranetArtifact, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return nil, ErrIntranetArtifactNotFound
	}
	a, err := scanIntranetArtifact(d.QueryRow(`SELECT `+intranetArtifactCols+`
FROM intranet_artifacts WHERE fingerprint=$1 AND status='active' ORDER BY id DESC LIMIT 1`, fingerprint))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIntranetArtifactNotFound
	}
	return a, err
}

// ListExpiredIntranetArtifacts returns active rows whose TTL has elapsed,
// oldest expiry first, for the automatic cleanup worker.
func (d *DB) ListExpiredIntranetArtifacts(now time.Time, limit int) ([]*IntranetArtifact, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := d.Query(`SELECT `+intranetArtifactCols+`
FROM intranet_artifacts
WHERE status='active' AND expires_at IS NOT NULL AND expires_at <= $1
ORDER BY expires_at ASC, id ASC LIMIT $2`, now, limit)
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

// ListActivePHPPersistArtifactsByWebshell returns active PHP auto_prepend
// artifacts whose metadata points at the given webshell, either as the
// deployed prepend shell or as its parent controller. Webshell deletion is
// blocked while any of these rows is active, otherwise the .user.ini/.htaccess
// block would outlive the platform record that knows how to remove it.
func (d *DB) ListActivePHPPersistArtifactsByWebshell(webshellID int64) ([]*IntranetArtifact, error) {
	if webshellID <= 0 {
		return []*IntranetArtifact{}, nil
	}
	id := strconv.FormatInt(webshellID, 10)
	rows, err := d.Query(`SELECT `+intranetArtifactCols+`
FROM intranet_artifacts
WHERE status='active' AND kind IN ('`+IntranetArtifactPHPUserINI+`','`+IntranetArtifactPHPHtaccess+`')
  AND (metadata->>'webshell_id'=$1 OR metadata->>'parent_webshell_id'=$1)
ORDER BY id DESC`, id)
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
