package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

var errManagedResourceIdentity = errors.New("受管资源缺少 kind 或 endpoint")

// Managed resource kinds. The ledger is intentionally generic so callbacks,
// webshells, tunnels and manually opened listeners share one lifecycle/audit.
const (
	ManagedKindCallback = "callback" // JNDI/OAST/回调端口
	ManagedKindWebshell = "webshell" // 已投放的 webshell
	ManagedKindTunnel   = "tunnel"   // 内网隧道
	ManagedKindListener = "listener" // 其它平台主动监听的端口
)

// Managed resource states.
const (
	ManagedActive   = "active"
	ManagedReleased = "released"
	ManagedExpired  = "expired"
)

// ManagedResource is one row of the managed-resource ledger.
type ManagedResource struct {
	ID         int64          `json:"id"`
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	Endpoint   string         `json:"endpoint"`
	Target     string         `json:"target"`
	Owner      string         `json:"owner"`
	TaskID     *int64         `json:"task_id,omitempty"`
	Status     string         `json:"status"`
	ExpiresAt  *time.Time     `json:"expires_at,omitempty"`
	ReleasedAt *time.Time     `json:"released_at,omitempty"`
	Metadata   map[string]any `json:"metadata"`
	Note       string         `json:"note"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// ManagedResourceInput registers or refreshes an active resource.
type ManagedResourceInput struct {
	Kind      string
	Name      string
	Endpoint  string
	Target    string
	Owner     string
	TaskID    *int64
	ExpiresAt *time.Time
	Metadata  map[string]any
	Note      string
}

const managedResourceCols = `id, kind, name, endpoint, target, owner, task_id, status,
	expires_at, released_at, metadata, note, created_at, updated_at`

func scanManagedResource(row interface{ Scan(...any) error }) (*ManagedResource, error) {
	var r ManagedResource
	var raw []byte
	if err := row.Scan(&r.ID, &r.Kind, &r.Name, &r.Endpoint, &r.Target, &r.Owner, &r.TaskID,
		&r.Status, &r.ExpiresAt, &r.ReleasedAt, &raw, &r.Note, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	r.Metadata = map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &r.Metadata)
	}
	return &r, nil
}

// RegisterManagedResource records a resource as active. Re-registering the same
// kind+endpoint refreshes the existing active row (owner, task, TTL, metadata)
// rather than creating duplicates.
func (d *DB) RegisterManagedResource(in ManagedResourceInput) (*ManagedResource, error) {
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	endpoint := strings.TrimSpace(in.Endpoint)
	if kind == "" || endpoint == "" {
		return nil, errManagedResourceIdentity
	}
	meta, _ := json.Marshal(in.Metadata)
	if in.Metadata == nil {
		meta = []byte("{}")
	}
	return scanManagedResource(d.QueryRow(`
INSERT INTO managed_resources(kind, name, endpoint, target, owner, task_id, expires_at, metadata, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (kind, endpoint) WHERE status = 'active' DO UPDATE SET
    name       = EXCLUDED.name,
    target     = EXCLUDED.target,
    owner      = EXCLUDED.owner,
    task_id    = EXCLUDED.task_id,
    expires_at = EXCLUDED.expires_at,
    metadata   = EXCLUDED.metadata,
    note       = EXCLUDED.note
RETURNING `+managedResourceCols,
		kind, strings.TrimSpace(in.Name), endpoint, strings.TrimSpace(in.Target),
		strings.TrimSpace(in.Owner), in.TaskID, in.ExpiresAt, string(meta), strings.TrimSpace(in.Note)))
}

// ListManagedResources returns resources newest-first with optional filters.
func (d *DB) ListManagedResources(kind, status string, limit, offset int) ([]*ManagedResource, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	where := []string{}
	args := []any{}
	if v := strings.ToLower(strings.TrimSpace(kind)); v != "" {
		args = append(args, v)
		where = append(where, "kind=$"+strconv.Itoa(len(args)))
	}
	if v := strings.ToLower(strings.TrimSpace(status)); v != "" {
		args = append(args, v)
		where = append(where, "status=$"+strconv.Itoa(len(args)))
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM managed_resources`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := d.Query(`SELECT `+managedResourceCols+` FROM managed_resources`+clause+
		` ORDER BY id DESC LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*ManagedResource{}
	for rows.Next() {
		r, err := scanManagedResource(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// GetManagedResource returns one resource.
func (d *DB) GetManagedResource(id int64) (*ManagedResource, error) {
	return scanManagedResource(d.QueryRow(`SELECT `+managedResourceCols+` FROM managed_resources WHERE id=$1`, id))
}

// ReleaseManagedResource marks an active resource released. found=false when no
// active row carries that id.
func (d *DB) ReleaseManagedResource(id int64, note string) (*ManagedResource, bool, error) {
	r, err := scanManagedResource(d.QueryRow(`
UPDATE managed_resources SET status='released', released_at=now(), note=CASE WHEN $2='' THEN note ELSE $2 END
WHERE id=$1 AND status='active'
RETURNING `+managedResourceCols, id, strings.TrimSpace(note)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return r, true, nil
}

// ReleaseManagedResourcesByTask releases every active resource owned by a task.
func (d *DB) ReleaseManagedResourcesByTask(taskID int64, note string) (int, error) {
	if taskID <= 0 {
		return 0, nil
	}
	res, err := d.Exec(`UPDATE managed_resources
SET status='released', released_at=now(), note=CASE WHEN $2='' THEN note ELSE $2 END
WHERE task_id=$1 AND status='active'`, taskID, strings.TrimSpace(note))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ReleaseManagedResourceByWebshell releases the ledger entry tied to a
// webshell id (stored in metadata), used when the webshell is deleted.
func (d *DB) ReleaseManagedResourceByWebshell(webshellID int64, note string) error {
	if webshellID <= 0 {
		return nil
	}
	_, err := d.Exec(`UPDATE managed_resources
SET status='released', released_at=now(), note=CASE WHEN $2='' THEN note ELSE $2 END
WHERE kind='webshell' AND status='active' AND metadata->>'webshell_id' = $1`,
		strconv.FormatInt(webshellID, 10), strings.TrimSpace(note))
	return err
}

// ReleaseManagedResourceByTunnel releases the ledger entry tied to an intranet
// tunnel id (stored in metadata), used on teardown.
func (d *DB) ReleaseManagedResourceByTunnel(tunnelID int64, note string) error {
	if tunnelID <= 0 {
		return nil
	}
	_, err := d.Exec(`UPDATE managed_resources
SET status='released', released_at=now(), note=CASE WHEN $2='' THEN note ELSE $2 END
WHERE kind='tunnel' AND status='active' AND metadata->>'tunnel_id' = $1`,
		strconv.FormatInt(tunnelID, 10), strings.TrimSpace(note))
	return err
}

// FindActiveManagedResourceByTunnel returns the active ledger row for a tunnel
// (nil when none), so teardown can release it through the resource manager.
func (d *DB) FindActiveManagedResourceByTunnel(tunnelID int64) (*ManagedResource, error) {
	if tunnelID <= 0 {
		return nil, nil
	}
	r, err := scanManagedResource(d.QueryRow(`SELECT `+managedResourceCols+`
FROM managed_resources WHERE kind='tunnel' AND status='active' AND metadata->>'tunnel_id' = $1
ORDER BY id DESC LIMIT 1`, strconv.FormatInt(tunnelID, 10)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return r, nil
}

// ExpireManagedResources marks overdue active resources expired and returns
// them so the caller can run any in-process cleanup (e.g. stop an idle service).
func (d *DB) ExpireManagedResources(now time.Time) ([]*ManagedResource, error) {
	rows, err := d.Query(`
UPDATE managed_resources SET status='expired', released_at=now(), note=CASE WHEN note='' THEN 'TTL 到期自动回收' ELSE note END
WHERE status='active' AND expires_at IS NOT NULL AND expires_at <= $1
RETURNING `+managedResourceCols, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ManagedResource{}
	for rows.Next() {
		r, err := scanManagedResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountActiveManagedResources counts active resources of a kind.
func (d *DB) CountActiveManagedResources(kind string) (int, error) {
	var n int
	err := d.QueryRow(`SELECT count(*) FROM managed_resources WHERE status='active' AND kind=$1`, kind).Scan(&n)
	return n, err
}
