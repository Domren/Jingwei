package db

import (
	"database/sql"
	"errors"
	"log"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// 凭据复用台账：弱口令命中 / 横向验证过的凭据统一登记，供内网任务挑选复用。
// 凭据属于攻击面证据，按目标去重；同一 host+username+password 只保留一行。
// ---------------------------------------------------------------------------

const (
	IntranetCredUntested = "untested"
	IntranetCredValid    = "valid"
	IntranetCredInvalid  = "invalid"
)

var ErrIntranetCredentialNotFound = errors.New("intranet credential not found")

// IntranetCredential is one ledger entry. Password is write-only from the API's
// perspective, like a webshell key: REST responses only carry has_password, so a
// plaintext credential never round-trips to the browser or into a proxy log. The
// agent-facing tool re-attaches the value deliberately (the server package
// wraps rows in `intranetAgentCredential` and unwraps them again with
// `revealCredential`) because assembling raw requests needs the plaintext.
type IntranetCredential struct {
	ID          int64  `json:"id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	URL         string `json:"url"`
	Username    string `json:"username"`
	Password    string `json:"-"`
	HasPassword bool   `json:"has_password"`
	// SealBroken marks a row whose sealed password could not be opened with this
	// platform's signing root. It is never serialized: callers must fail loudly
	// rather than dial with an empty or ciphertext password.
	SealBroken bool       `json:"-"`
	Source     string     `json:"source"`
	TaskID     *int64     `json:"task_id,omitempty"`
	ScanTaskID *int64     `json:"scan_task_id,omitempty"`
	FindingID  *int64     `json:"finding_id,omitempty"`
	Status     string     `json:"status"`
	Evidence   string     `json:"evidence"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type IntranetCredentialInput struct {
	Host       string
	Port       int
	Protocol   string
	URL        string
	Username   string
	Password   string
	Source     string
	TaskID     int64
	ScanTaskID int64
	FindingID  int64
	Evidence   string
}

type IntranetCredentialFilter struct {
	Host       string
	Status     string
	TaskID     int64
	ScanTaskID int64
	Limit      int
}

const intranetCredentialCols = `id, host, port, protocol, url, username, password, source,
	task_id, scan_task_id, finding_id, status, evidence, last_used_at, created_at, updated_at`

// scanIntranetCredential reads one ledger row. The password column is stored
// sealed; a row the startup migration has not reached is still plaintext and is
// returned as-is. A row that looks sealed but will not open keeps Password empty
// and sets SealBroken: the list must not fail because of one bad row, but a
// caller about to dial SSH has to be able to tell "no password recorded" from
// "the password is there and I cannot read it".
func (d *DB) scanIntranetCredential(row interface{ Scan(...any) error }) (*IntranetCredential, error) {
	var c IntranetCredential
	if err := row.Scan(&c.ID, &c.Host, &c.Port, &c.Protocol, &c.URL, &c.Username, &c.Password,
		&c.Source, &c.TaskID, &c.ScanTaskID, &c.FindingID, &c.Status, &c.Evidence,
		&c.LastUsedAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	c.HasPassword = c.Password != ""
	if sealed := c.Password; sealed != "" {
		plain, err := d.openCredential(sealed)
		if err != nil {
			log.Printf("[seal] 凭据 #%d (%s@%s) 解封失败：%v", c.ID, c.Username, c.Host, err)
			c.Password, c.SealBroken = "", true
		} else {
			c.Password = plain
		}
	}
	return &c, nil
}

func normalizeIntranetCredentialStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case IntranetCredValid:
		return IntranetCredValid
	case IntranetCredInvalid:
		return IntranetCredInvalid
	default:
		return IntranetCredUntested
	}
}

// UpsertIntranetCredential registers one credential. A duplicate
// (host, username, password) refreshes provenance/evidence but never resets a
// decided status; callers use MarkIntranetCredentialUsed for that.
func (d *DB) UpsertIntranetCredential(in IntranetCredentialInput) (*IntranetCredential, error) {
	host := strings.ToLower(strings.TrimSpace(in.Host))
	if host == "" {
		return nil, errors.New("需要 host")
	}
	username := strings.TrimSpace(in.Username)
	// Sealed here, and with a nonce derived from the plaintext: the ledger's
	// UNIQUE (host, username, password) constraint is what makes a re-register
	// refresh a row instead of duplicating it, so the stored form must stay
	// deterministic. Readers get the plaintext back transparently.
	password := d.sealCredential(in.Password)
	if username == "" || password == "" {
		return nil, errors.New("用户名和密码不能为空")
	}
	protocol := strings.ToLower(strings.TrimSpace(in.Protocol))
	if protocol == "" {
		protocol = "http"
	}
	source := strings.TrimSpace(in.Source)
	if source == "" {
		source = "weakpass"
	}
	var taskID, scanTaskID, findingID any
	if in.TaskID > 0 {
		taskID = in.TaskID
	}
	if in.ScanTaskID > 0 {
		scanTaskID = in.ScanTaskID
	}
	if in.FindingID > 0 {
		findingID = in.FindingID
	}
	url := strings.TrimSpace(in.URL)
	return d.scanIntranetCredential(d.QueryRow(`
INSERT INTO intranet_credentials(host, port, protocol, url, username, password, source,
    task_id, scan_task_id, finding_id, evidence)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (host, username, password) DO UPDATE SET
    port         = CASE WHEN EXCLUDED.port > 0 THEN EXCLUDED.port ELSE intranet_credentials.port END,
    protocol     = CASE WHEN EXCLUDED.protocol <> '' THEN EXCLUDED.protocol ELSE intranet_credentials.protocol END,
    url          = CASE WHEN EXCLUDED.url <> '' THEN EXCLUDED.url ELSE intranet_credentials.url END,
    evidence     = CASE WHEN EXCLUDED.evidence <> '' THEN EXCLUDED.evidence ELSE intranet_credentials.evidence END,
    task_id      = COALESCE(EXCLUDED.task_id, intranet_credentials.task_id),
    scan_task_id = COALESCE(EXCLUDED.scan_task_id, intranet_credentials.scan_task_id),
    finding_id   = COALESCE(EXCLUDED.finding_id, intranet_credentials.finding_id)
RETURNING `+intranetCredentialCols,
		host, in.Port, protocol, url, username, password, source,
		taskID, scanTaskID, findingID, strings.TrimSpace(in.Evidence)))
}

// ListIntranetCredentials returns credentials newest-first for the given filter.
func (d *DB) ListIntranetCredentials(f IntranetCredentialFilter) ([]*IntranetCredential, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	where := []string{}
	args := []any{}
	if v := strings.ToLower(strings.TrimSpace(f.Host)); v != "" {
		args = append(args, v)
		where = append(where, "host=$"+strconv.Itoa(len(args)))
	}
	if v := strings.ToLower(strings.TrimSpace(f.Status)); v != "" {
		args = append(args, v)
		where = append(where, "status=$"+strconv.Itoa(len(args)))
	}
	if f.TaskID > 0 {
		args = append(args, f.TaskID)
		where = append(where, "task_id=$"+strconv.Itoa(len(args)))
	}
	if f.ScanTaskID > 0 {
		args = append(args, f.ScanTaskID)
		where = append(where, "scan_task_id=$"+strconv.Itoa(len(args)))
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit)
	rows, err := d.Query(`SELECT `+intranetCredentialCols+` FROM intranet_credentials`+clause+
		` ORDER BY id DESC LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IntranetCredential{}
	for rows.Next() {
		c, err := d.scanIntranetCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) GetIntranetCredential(id int64) (*IntranetCredential, error) {
	c, err := d.scanIntranetCredential(d.QueryRow(`SELECT `+intranetCredentialCols+`
FROM intranet_credentials WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIntranetCredentialNotFound
	}
	return c, err
}

// MarkIntranetCredentialUsed records a reuse attempt outcome (valid/invalid)
// and stamps last_used_at.
func (d *DB) MarkIntranetCredentialUsed(id int64, status, evidence string) (*IntranetCredential, error) {
	status = normalizeIntranetCredentialStatus(status)
	c, err := d.scanIntranetCredential(d.QueryRow(`
UPDATE intranet_credentials SET
    status       = $2,
    evidence     = CASE WHEN $3='' THEN evidence ELSE $3 END,
    last_used_at = now()
WHERE id=$1
RETURNING `+intranetCredentialCols, id, status, strings.TrimSpace(evidence)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIntranetCredentialNotFound
	}
	return c, err
}

// ListArtifactsExpiringSoon 列出「即将到期且尚未告警」的落地物。
func (d *DB) ListArtifactsExpiringSoon(within time.Duration, limit int) ([]*IntranetArtifact, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.Query(`SELECT `+intranetArtifactCols+` FROM intranet_artifacts
WHERE status='active' AND expires_at IS NOT NULL AND expiry_notified_at IS NULL
  AND expires_at > now() AND expires_at <= now() + $1::interval
ORDER BY expires_at LIMIT $2`, within.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IntranetArtifact{}
	for rows.Next() {
		art, err := scanIntranetArtifact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, art)
	}
	return out, rows.Err()
}

// MarkArtifactExpiryNotified 标记已告警。
func (d *DB) MarkArtifactExpiryNotified(id int64) error {
	_, err := d.Exec(`UPDATE intranet_artifacts SET expiry_notified_at=now() WHERE id=$1`, id)
	return err
}
