package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// 凭据跨主机复用批次（F1）。一次复用 = 一个批次 + 每次尝试一行。
//
// 为什么要批次：复用是操作员主动发起的一次横向动作，事后要能整体复盘与整体撤销。
// 只记「成功的那几个」会让被拒绝、被跳过、发不出去的尝试全部消失，撤销时也说不清
// 这一批到底碰过哪些主机。

const (
	ReuseAttemptValid   = "valid"
	ReuseAttemptInvalid = "invalid"
	ReuseAttemptSkipped = "skipped"
	ReuseAttemptError   = "error"
)

// IntranetCredentialReuse is one reuse batch.
type IntranetCredentialReuse struct {
	ID           int64      `json:"id"`
	CredentialID int64      `json:"credential_id"`
	TaskID       int64      `json:"task_id"`
	Total        int        `json:"total"`
	ValidCount   int        `json:"valid_count"`
	InvalidCount int        `json:"invalid_count"`
	SkippedCount int        `json:"skipped_count"`
	ErrorCount   int        `json:"error_count"`
	Note         string     `json:"note"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// IntranetCredentialReuseAttempt is one target tried inside a batch.
type IntranetCredentialReuseAttempt struct {
	ID                  int64     `json:"id"`
	ReuseID             int64     `json:"reuse_id"`
	URL                 string    `json:"url"`
	Host                string    `json:"host"`
	Status              string    `json:"status"`
	Attempts            int       `json:"attempts"`
	ElapsedMS           int64     `json:"elapsed_ms"`
	Error               string    `json:"error,omitempty"`
	Evidence            string    `json:"evidence,omitempty"`
	CreatedCredentialID int64     `json:"created_credential_id,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

// IntranetCredentialReuseAttemptInput is one attempt to persist with its batch.
type IntranetCredentialReuseAttemptInput struct {
	URL                 string
	Host                string
	Status              string
	Attempts            int
	ElapsedMS           int64
	Error               string
	Evidence            string
	CreatedCredentialID int64
}

// IntranetCredentialReuseInput is the batch to persist.
type IntranetCredentialReuseInput struct {
	CredentialID int64
	TaskID       int64
	Note         string
	Attempts     []IntranetCredentialReuseAttemptInput
}

const intranetCredentialReuseCols = `id, credential_id, task_id, total, valid_count,
	invalid_count, skipped_count, error_count, note, revoked_at, created_at`

func normalizeReuseAttemptStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case ReuseAttemptValid:
		return ReuseAttemptValid
	case ReuseAttemptInvalid:
		return ReuseAttemptInvalid
	case ReuseAttemptSkipped:
		return ReuseAttemptSkipped
	default:
		return ReuseAttemptError
	}
}

// CreateIntranetCredentialReuse stores a batch and all of its attempts in one
// transaction: a batch whose attempts half-failed to write is worse than no
// batch at all, because the counts would no longer match what is on disk.
func (d *DB) CreateIntranetCredentialReuse(in IntranetCredentialReuseInput) (*IntranetCredentialReuse, error) {
	if in.CredentialID <= 0 {
		return nil, errors.New("需要 credential_id")
	}
	counts := map[string]int{}
	for _, a := range in.Attempts {
		counts[normalizeReuseAttemptStatus(a.Status)]++
	}
	tx, err := d.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var rec IntranetCredentialReuse
	if err := tx.QueryRow(`
INSERT INTO intranet_credential_reuses(credential_id, task_id, total, valid_count,
    invalid_count, skipped_count, error_count, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
RETURNING `+intranetCredentialReuseCols,
		in.CredentialID, in.TaskID, len(in.Attempts), counts[ReuseAttemptValid],
		counts[ReuseAttemptInvalid], counts[ReuseAttemptSkipped], counts[ReuseAttemptError],
		strings.TrimSpace(in.Note)).Scan(
		&rec.ID, &rec.CredentialID, &rec.TaskID, &rec.Total, &rec.ValidCount,
		&rec.InvalidCount, &rec.SkippedCount, &rec.ErrorCount, &rec.Note,
		&rec.RevokedAt, &rec.CreatedAt); err != nil {
		return nil, err
	}
	for _, a := range in.Attempts {
		var created any
		if a.CreatedCredentialID > 0 {
			created = a.CreatedCredentialID
		}
		if _, err := tx.Exec(`
INSERT INTO intranet_credential_reuse_attempts(reuse_id, url, host, status, attempts,
    elapsed_ms, error, evidence, created_credential_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			rec.ID, strings.TrimSpace(a.URL), strings.ToLower(strings.TrimSpace(a.Host)),
			normalizeReuseAttemptStatus(a.Status), a.Attempts, a.ElapsedMS,
			strings.TrimSpace(a.Error), a.Evidence, created); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ListIntranetCredentialReuses returns batches newest-first.
func (d *DB) ListIntranetCredentialReuses(credentialID int64, limit int) ([]*IntranetCredentialReuse, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := d.Query(`SELECT `+intranetCredentialReuseCols+` FROM intranet_credential_reuses
WHERE ($1 = 0 OR credential_id = $1) ORDER BY id DESC LIMIT $2`, credentialID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IntranetCredentialReuse{}
	for rows.Next() {
		var r IntranetCredentialReuse
		if err := rows.Scan(&r.ID, &r.CredentialID, &r.TaskID, &r.Total, &r.ValidCount,
			&r.InvalidCount, &r.SkippedCount, &r.ErrorCount, &r.Note, &r.RevokedAt,
			&r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// GetIntranetCredentialReuse returns one batch.
func (d *DB) GetIntranetCredentialReuse(id int64) (*IntranetCredentialReuse, error) {
	var r IntranetCredentialReuse
	if err := d.QueryRow(`SELECT `+intranetCredentialReuseCols+`
FROM intranet_credential_reuses WHERE id=$1`, id).Scan(
		&r.ID, &r.CredentialID, &r.TaskID, &r.Total, &r.ValidCount, &r.InvalidCount,
		&r.SkippedCount, &r.ErrorCount, &r.Note, &r.RevokedAt, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListIntranetCredentialReuseAttempts returns every attempt of a batch, including
// skipped and failed ones.
func (d *DB) ListIntranetCredentialReuseAttempts(reuseID int64) ([]*IntranetCredentialReuseAttempt, error) {
	rows, err := d.Query(`SELECT id, reuse_id, url, host, status, attempts, elapsed_ms,
    error, evidence, COALESCE(created_credential_id, 0), created_at
FROM intranet_credential_reuse_attempts WHERE reuse_id=$1 ORDER BY id`, reuseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IntranetCredentialReuseAttempt{}
	for rows.Next() {
		var a IntranetCredentialReuseAttempt
		if err := rows.Scan(&a.ID, &a.ReuseID, &a.URL, &a.Host, &a.Status, &a.Attempts,
			&a.ElapsedMS, &a.Error, &a.Evidence, &a.CreatedCredentialID, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// RevokeIntranetCredentialReuse undoes one batch: every credential this batch
// created is deleted and the batch is marked revoked. Attempts stay as audit
// records — the point of revoking is to remove what was added, not to erase the
// fact that it was tried. Credentials that already existed before the batch are
// never touched.
func (d *DB) RevokeIntranetCredentialReuse(id int64) (deleted int, err error) {
	tx, err := d.BeginTx(context.Background(), nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var revokedAt sql.NullTime
	if err := tx.QueryRow(`SELECT revoked_at FROM intranet_credential_reuses WHERE id=$1`, id).
		Scan(&revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrIntranetCredentialReuseNotFound
		}
		return 0, err
	}
	if revokedAt.Valid {
		// 幂等：重复撤销不报错，也不重复删。
		return 0, tx.Commit()
	}
	res, err := tx.Exec(`DELETE FROM intranet_credentials WHERE id IN (
    SELECT created_credential_id FROM intranet_credential_reuse_attempts
    WHERE reuse_id=$1 AND created_credential_id IS NOT NULL)`, id)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.Exec(`UPDATE intranet_credential_reuses SET revoked_at=now() WHERE id=$1`, id); err != nil {
		return 0, err
	}
	return int(n), tx.Commit()
}

// ErrIntranetCredentialReuseNotFound is returned for an unknown batch id.
var ErrIntranetCredentialReuseNotFound = errors.New("复用批次不存在")

// FindIntranetCredentialID looks up a ledger row by its natural key. The password
// is sealed deterministically before comparison, so callers can tell whether an
// upsert is about to insert a new credential or refresh an existing one.
func (d *DB) FindIntranetCredentialID(host, username, password string) (int64, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	username = strings.TrimSpace(username)
	if host == "" || username == "" || password == "" {
		return 0, false
	}
	var id int64
	err := d.QueryRow(`SELECT id FROM intranet_credentials
WHERE host=$1 AND username=$2 AND password=$3`, host, username, d.sealCredential(password)).Scan(&id)
	if err != nil {
		return 0, false
	}
	return id, true
}
