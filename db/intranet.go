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
// 内网两阶段 MVP 存储层：逻辑会话、隧道、范围审批。
// 会话不驻留进程：每次 exec 复用已登记的 webshell，cwd 由平台维护。
// ---------------------------------------------------------------------------

const (
	IntranetSessionActive    = "active"
	IntranetSessionClosed    = "closed"
	IntranetTunnelPlanned    = "planned"
	IntranetTunnelDeployed   = "deployed"
	IntranetTunnelVerified   = "verified"
	IntranetTunnelFailed     = "failed"
	IntranetTunnelStopped    = "stopped"
	IntranetScopePending     = "pending"
	IntranetScopeApproved    = "approved"
	IntranetScopeRejected    = "rejected"
	IntranetTunnelKindSocks5 = "socks5"
	IntranetTunnelKindPort   = "port_forward"
	IntranetTunnelKindRemote = "reverse_forward"
)

type IntranetSession struct {
	ID           int64          `json:"id"`
	Name         string         `json:"name"`
	WebshellID   *int64         `json:"webshell_id,omitempty"`
	TaskID       *int64         `json:"task_id,omitempty"`
	Host         string         `json:"host"`
	Cwd          string         `json:"cwd"`
	Status       string         `json:"status"`
	LastSeen     *time.Time     `json:"last_seen,omitempty"`
	Metadata     map[string]any `json:"metadata"`
	Note         string         `json:"note"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	WebshellName string         `json:"webshell_name,omitempty"`
	WebshellURL  string         `json:"webshell_url,omitempty"`
	ShellType    string         `json:"shell_type,omitempty"`
}

type IntranetSessionInput struct {
	Name       string
	WebshellID int64
	TaskID     int64
	Host       string
	Cwd        string
	Note       string
	Metadata   map[string]any
}

type IntranetSessionEvent struct {
	ID        int64     `json:"id"`
	SessionID int64     `json:"session_id"`
	Kind      string    `json:"kind"`
	Command   string    `json:"command"`
	Output    string    `json:"output"`
	IsError   bool      `json:"is_error"`
	CreatedAt time.Time `json:"created_at"`
}

type IntranetTunnel struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	SessionID       *int64    `json:"session_id,omitempty"`
	TaskID          *int64    `json:"task_id,omitempty"`
	Kind            string    `json:"kind"`
	ListenHost      string    `json:"listen_host"`
	ListenPort      int       `json:"listen_port"`
	RemoteHost      string    `json:"remote_host"`
	RemotePort      int       `json:"remote_port"`
	Status          string    `json:"status"`
	DeployCommand   string    `json:"deploy_command"`
	VerifyCommand   string    `json:"verify_command"`
	TeardownCommand string    `json:"teardown_command"`
	PID             *int      `json:"pid,omitempty"`
	Evidence        string    `json:"evidence"`
	Note            string    `json:"note"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type IntranetTunnelInput struct {
	Name            string
	SessionID       int64
	TaskID          int64
	Kind            string
	ListenHost      string
	ListenPort      int
	RemoteHost      string
	RemotePort      int
	DeployCommand   string
	VerifyCommand   string
	TeardownCommand string
	Note            string
}

type IntranetScopeRequest struct {
	ID          int64      `json:"id"`
	TaskID      int64      `json:"task_id"`
	Host        string     `json:"host"`
	Port        int        `json:"port"`
	Reason      string     `json:"reason"`
	SessionID   *int64     `json:"session_id,omitempty"`
	Status      string     `json:"status"`
	DecidedNote string     `json:"decided_note"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type IntranetScopeRequestInput struct {
	TaskID    int64
	Host      string
	Port      int
	Reason    string
	SessionID int64
}

const intranetSessionCols = `s.id, s.name, s.webshell_id, s.task_id, s.host, s.cwd, s.status,
	s.last_seen, s.metadata, s.note, s.created_at, s.updated_at,
	COALESCE(w.name,''), COALESCE(w.url,''), COALESCE(w.shell_type,'')`

// intranetSessionReturningCols is the same projection minus the webshells join,
// for INSERT/UPDATE ... RETURNING where alias w is unavailable.
const intranetSessionReturningCols = `id, name, webshell_id, task_id, host, cwd, status,
	last_seen, metadata, note, created_at, updated_at, '', '', ''`

func scanIntranetSession(row interface{ Scan(...any) error }) (*IntranetSession, error) {
	var s IntranetSession
	var raw []byte
	if err := row.Scan(&s.ID, &s.Name, &s.WebshellID, &s.TaskID, &s.Host, &s.Cwd, &s.Status,
		&s.LastSeen, &raw, &s.Note, &s.CreatedAt, &s.UpdatedAt,
		&s.WebshellName, &s.WebshellURL, &s.ShellType); err != nil {
		return nil, err
	}
	s.Metadata = map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &s.Metadata)
	}
	return &s, nil
}

func (d *DB) CreateIntranetSession(in IntranetSessionInput) (*IntranetSession, error) {
	if in.WebshellID <= 0 {
		return nil, errors.New("需要 webshell_id")
	}
	cwd := strings.TrimSpace(in.Cwd)
	if cwd == "" {
		cwd = "/"
	}
	meta, _ := json.Marshal(in.Metadata)
	if in.Metadata == nil {
		meta = []byte("{}")
	}
	var taskID any
	if in.TaskID > 0 {
		taskID = in.TaskID
	}
	return scanIntranetSession(d.QueryRow(`
INSERT INTO intranet_sessions(name, webshell_id, task_id, host, cwd, note, metadata, last_seen)
VALUES ($1,$2,$3,$4,$5,$6,$7,now())
RETURNING `+intranetSessionReturningCols+``,
		strings.TrimSpace(in.Name), in.WebshellID, taskID, strings.TrimSpace(in.Host),
		cwd, strings.TrimSpace(in.Note), string(meta)))
}

// ListIntranetSessions returns sessions newest-first.
func (d *DB) ListIntranetSessions(status string, taskID int64, limit, offset int) ([]*IntranetSession, int, error) {
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
	if v := strings.ToLower(strings.TrimSpace(status)); v != "" {
		args = append(args, v)
		where = append(where, "s.status=$"+strconv.Itoa(len(args)))
	}
	if taskID > 0 {
		args = append(args, taskID)
		where = append(where, "s.task_id=$"+strconv.Itoa(len(args)))
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM intranet_sessions s`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := d.Query(`SELECT `+intranetSessionCols+`
FROM intranet_sessions s LEFT JOIN webshells w ON w.id=s.webshell_id`+clause+
		` ORDER BY s.id DESC LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*IntranetSession{}
	for rows.Next() {
		s, err := scanIntranetSession(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

func (d *DB) GetIntranetSession(id int64) (*IntranetSession, error) {
	return scanIntranetSession(d.QueryRow(`SELECT `+intranetSessionCols+`
FROM intranet_sessions s LEFT JOIN webshells w ON w.id=s.webshell_id WHERE s.id=$1`, id))
}

func (d *DB) UpdateIntranetSessionState(id int64, cwd, status, note string) (*IntranetSession, error) {
	return scanIntranetSession(d.QueryRow(`
UPDATE intranet_sessions SET
    cwd    = CASE WHEN $2='' THEN cwd ELSE $2 END,
    status = CASE WHEN $3='' THEN status ELSE $3 END,
    note   = CASE WHEN $4='' THEN note ELSE $4 END,
    last_seen = now()
WHERE id=$1
RETURNING `+intranetSessionReturningCols+``, id, strings.TrimSpace(cwd), strings.TrimSpace(status), strings.TrimSpace(note)))
}

func (d *DB) TouchIntranetSession(id int64) error {
	_, err := d.Exec(`UPDATE intranet_sessions SET last_seen=now() WHERE id=$1`, id)
	return err
}

func (d *DB) SetIntranetSessionTask(id, taskID int64) error {
	if taskID <= 0 {
		return nil
	}
	_, err := d.Exec(`UPDATE intranet_sessions SET task_id=$2 WHERE id=$1`, id, taskID)
	return err
}

func (d *DB) DeleteIntranetSession(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM intranet_sessions WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (d *DB) AddIntranetSessionEvent(sessionID int64, kind, command, output string, isErr bool) error {
	if sessionID <= 0 {
		return nil
	}
	_, err := d.Exec(`INSERT INTO intranet_session_events(session_id, kind, command, output, is_error)
VALUES ($1,$2,$3,$4,$5)`, sessionID, strings.TrimSpace(kind), command, output, isErr)
	return err
}

func (d *DB) ListIntranetSessionEvents(sessionID int64, limit int) ([]*IntranetSessionEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := d.Query(`SELECT id, session_id, kind, command, output, is_error, created_at
FROM intranet_session_events WHERE session_id=$1 ORDER BY id DESC LIMIT $2`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IntranetSessionEvent{}
	for rows.Next() {
		var e IntranetSessionEvent
		if err := rows.Scan(&e.ID, &e.SessionID, &e.Kind, &e.Command, &e.Output, &e.IsError, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

const intranetTunnelCols = `id, name, session_id, task_id, kind, listen_host, listen_port,
	remote_host, remote_port, status, deploy_command, verify_command, teardown_command,
	pid, evidence, note, created_at, updated_at`

func scanIntranetTunnel(row interface{ Scan(...any) error }) (*IntranetTunnel, error) {
	var t IntranetTunnel
	if err := row.Scan(&t.ID, &t.Name, &t.SessionID, &t.TaskID, &t.Kind, &t.ListenHost, &t.ListenPort,
		&t.RemoteHost, &t.RemotePort, &t.Status, &t.DeployCommand, &t.VerifyCommand, &t.TeardownCommand,
		&t.PID, &t.Evidence, &t.Note, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

func (d *DB) CreateIntranetTunnel(in IntranetTunnelInput) (*IntranetTunnel, error) {
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	switch kind {
	case IntranetTunnelKindSocks5, IntranetTunnelKindPort, IntranetTunnelKindRemote:
	default:
		return nil, errors.New("kind 必须是 socks5、port_forward 或 reverse_forward")
	}
	listenHost := strings.TrimSpace(in.ListenHost)
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}
	var sessionID, taskID any
	if in.SessionID > 0 {
		sessionID = in.SessionID
	}
	if in.TaskID > 0 {
		taskID = in.TaskID
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = kind
	}
	return scanIntranetTunnel(d.QueryRow(`
INSERT INTO intranet_tunnels(name, session_id, task_id, kind, listen_host, listen_port,
    remote_host, remote_port, deploy_command, verify_command, teardown_command, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
RETURNING `+intranetTunnelCols,
		name, sessionID, taskID, kind, listenHost, in.ListenPort,
		strings.TrimSpace(in.RemoteHost), in.RemotePort,
		strings.TrimSpace(in.DeployCommand), strings.TrimSpace(in.VerifyCommand),
		strings.TrimSpace(in.TeardownCommand), strings.TrimSpace(in.Note)))
}

func (d *DB) ListIntranetTunnels(status string, taskID, sessionID int64, limit, offset int) ([]*IntranetTunnel, int, error) {
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
	if v := strings.ToLower(strings.TrimSpace(status)); v != "" {
		args = append(args, v)
		where = append(where, "status=$"+strconv.Itoa(len(args)))
	}
	if taskID > 0 {
		args = append(args, taskID)
		where = append(where, "task_id=$"+strconv.Itoa(len(args)))
	}
	if sessionID > 0 {
		args = append(args, sessionID)
		where = append(where, "session_id=$"+strconv.Itoa(len(args)))
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM intranet_tunnels`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := d.Query(`SELECT `+intranetTunnelCols+` FROM intranet_tunnels`+clause+
		` ORDER BY id DESC LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*IntranetTunnel{}
	for rows.Next() {
		t, err := scanIntranetTunnel(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

func (d *DB) GetIntranetTunnel(id int64) (*IntranetTunnel, error) {
	return scanIntranetTunnel(d.QueryRow(`SELECT `+intranetTunnelCols+` FROM intranet_tunnels WHERE id=$1`, id))
}

func (d *DB) UpdateIntranetTunnelPlan(id int64, deploy, verify, teardown, evidence string) (*IntranetTunnel, error) {
	return scanIntranetTunnel(d.QueryRow(`
UPDATE intranet_tunnels SET
    deploy_command   = CASE WHEN $2='' THEN deploy_command ELSE $2 END,
    verify_command   = CASE WHEN $3='' THEN verify_command ELSE $3 END,
    teardown_command = CASE WHEN $4='' THEN teardown_command ELSE $4 END,
    evidence         = CASE WHEN $5='' THEN evidence ELSE $5 END
WHERE id=$1
RETURNING `+intranetTunnelCols, id, strings.TrimSpace(deploy), strings.TrimSpace(verify),
		strings.TrimSpace(teardown), evidence))
}

func (d *DB) SetIntranetTunnelStatus(id int64, status string, pid int, evidence, note string) (*IntranetTunnel, error) {
	var pidArg any
	if pid > 0 {
		pidArg = pid
	}
	return scanIntranetTunnel(d.QueryRow(`
UPDATE intranet_tunnels SET
    status   = $2,
    pid      = COALESCE($3, pid),
    evidence = CASE WHEN $4='' THEN evidence ELSE $4 END,
    note     = CASE WHEN $5='' THEN note ELSE $5 END
WHERE id=$1
RETURNING `+intranetTunnelCols, id, strings.TrimSpace(status), pidArg, evidence, strings.TrimSpace(note)))
}

func (d *DB) SetIntranetTunnelTask(id, taskID int64) error {
	if taskID <= 0 {
		return nil
	}
	_, err := d.Exec(`UPDATE intranet_tunnels SET task_id=$2 WHERE id=$1`, id, taskID)
	return err
}

func (d *DB) DeleteIntranetTunnel(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM intranet_tunnels WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

const intranetScopeCols = `id, task_id, host, port, reason, session_id, status, decided_note, decided_at, created_at`

func scanIntranetScope(row interface{ Scan(...any) error }) (*IntranetScopeRequest, error) {
	var r IntranetScopeRequest
	if err := row.Scan(&r.ID, &r.TaskID, &r.Host, &r.Port, &r.Reason, &r.SessionID, &r.Status,
		&r.DecidedNote, &r.DecidedAt, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// CreateIntranetScopeRequest inserts a pending request; a duplicate pending row
// for the same task+host+port is returned as-is (created=false).
func (d *DB) CreateIntranetScopeRequest(in IntranetScopeRequestInput) (*IntranetScopeRequest, bool, error) {
	if in.TaskID <= 0 {
		return nil, false, errors.New("需要 task_id")
	}
	host := strings.TrimSpace(in.Host)
	if host == "" {
		return nil, false, errors.New("host 不能为空")
	}
	var sessionID any
	if in.SessionID > 0 {
		sessionID = in.SessionID
	}
	row := d.QueryRow(`
INSERT INTO intranet_scope_requests(task_id, host, port, reason, session_id)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (task_id, host, port) WHERE status='pending' DO NOTHING
RETURNING `+intranetScopeCols, in.TaskID, host, in.Port, strings.TrimSpace(in.Reason), sessionID)
	r, err := scanIntranetScope(row)
	if err == nil {
		return r, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	existing, err := scanIntranetScope(d.QueryRow(`SELECT `+intranetScopeCols+`
FROM intranet_scope_requests WHERE task_id=$1 AND host=$2 AND port=$3 AND status='pending'`, in.TaskID, host, in.Port))
	if err != nil {
		return nil, false, err
	}
	return existing, false, nil
}

func (d *DB) ListIntranetScopeRequests(status string, taskID int64, limit, offset int) ([]*IntranetScopeRequest, int, error) {
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
	if v := strings.ToLower(strings.TrimSpace(status)); v != "" {
		args = append(args, v)
		where = append(where, "status=$"+strconv.Itoa(len(args)))
	}
	if taskID > 0 {
		args = append(args, taskID)
		where = append(where, "task_id=$"+strconv.Itoa(len(args)))
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM intranet_scope_requests`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := d.Query(`SELECT `+intranetScopeCols+` FROM intranet_scope_requests`+clause+
		` ORDER BY id DESC LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*IntranetScopeRequest{}
	for rows.Next() {
		r, err := scanIntranetScope(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (d *DB) GetIntranetScopeRequest(id int64) (*IntranetScopeRequest, error) {
	return scanIntranetScope(d.QueryRow(`SELECT `+intranetScopeCols+` FROM intranet_scope_requests WHERE id=$1`, id))
}

// DecideIntranetScopeRequest settles a pending request. found=false when it is
// already decided (or missing), so callers can surface a 409-style message.
func (d *DB) DecideIntranetScopeRequest(id int64, approved bool, note string) (*IntranetScopeRequest, bool, error) {
	status := IntranetScopeRejected
	if approved {
		status = IntranetScopeApproved
	}
	r, err := scanIntranetScope(d.QueryRow(`
UPDATE intranet_scope_requests SET status=$2, decided_note=$3, decided_at=now()
WHERE id=$1 AND status='pending'
RETURNING `+intranetScopeCols, id, status, strings.TrimSpace(note)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return r, true, nil
}
