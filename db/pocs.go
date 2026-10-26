package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/pocparse"
)

var (
	ErrPOCNotFound  = errors.New("poc template not found")
	ErrPOCDuplicate = errors.New("poc template already exists")
)

// POCTemplate is one nuclei YAML template stored in Jingwei's POC library.
// Content is only populated by GetPOCTemplate / POCTemplatesByIDs.
type POCTemplate struct {
	ID          int64     `json:"id"`
	TemplateID  string    `json:"template_id"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Protocol    string    `json:"protocol"`
	CVEID       string    `json:"cve_id"`
	CWEID       string    `json:"cwe_id"`
	CVSSScore   *float64  `json:"cvss_score"`
	Tags        []string  `json:"tags"`
	Author      string    `json:"author"`
	Description string    `json:"description"`
	References  []string  `json:"references"`
	Source      string    `json:"source"`
	SourceURL   string    `json:"source_url"`
	Digest      string    `json:"digest"`
	Enabled     bool      `json:"enabled"`
	SizeBytes   int64     `json:"size_bytes"`
	Content     string    `json:"content,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type POCFilter struct {
	Query    string
	Severity string
	Source   string
	Protocol string
	Enabled  *bool
	Page     int
	Size     int
}

type POCStats struct {
	Total      int            `json:"total"`
	Enabled    int            `json:"enabled"`
	BySeverity map[string]int `json:"by_severity"`
	Sources    []string       `json:"sources"`
}

const pocCols = `id, template_id, name, severity, protocol, cve_id, cwe_id, cvss_score,
       tags::text, author, description, refs::text, source, source_url, digest, enabled,
       created_at, updated_at, octet_length(content)`

func scanPOC(row interface{ Scan(...any) error }) (POCTemplate, error) {
	var p POCTemplate
	var tags, refs string
	var cvss sql.NullFloat64
	err := row.Scan(&p.ID, &p.TemplateID, &p.Name, &p.Severity, &p.Protocol, &p.CVEID, &p.CWEID,
		&cvss, &tags, &p.Author, &p.Description, &refs, &p.Source, &p.SourceURL, &p.Digest,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt, &p.SizeBytes)
	if err != nil {
		return p, err
	}
	if cvss.Valid {
		p.CVSSScore = &cvss.Float64
	}
	p.Tags = decodeStringList(tags)
	p.References = decodeStringList(refs)
	return p, nil
}

func decodeStringList(raw string) []string {
	out := []string{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func encodeStringList(items []string) string {
	if items == nil {
		items = []string{}
	}
	b, _ := json.Marshal(items)
	return string(b)
}

func (d *DB) ListPOCTemplates(f POCFilter) ([]POCTemplate, int, error) {
	var where []string
	var args []any
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		args = append(args, like)
		n := len(args)
		where = append(where, fmt.Sprintf(`(lower(name) LIKE $%d OR lower(template_id) LIKE $%d OR lower(cve_id) LIKE $%d OR lower(cwe_id) LIKE $%d OR lower(description) LIKE $%d)`, n, n, n, n, n))
	}
	if v := strings.TrimSpace(f.Severity); v != "" && v != "all" {
		add(`severity = $%d`, v)
	}
	if v := strings.TrimSpace(f.Source); v != "" && v != "all" {
		add(`source = $%d`, v)
	}
	if v := strings.TrimSpace(f.Protocol); v != "" && v != "all" {
		add(`protocol = $%d`, v)
	}
	if f.Enabled != nil {
		add(`enabled = $%d`, *f.Enabled)
	}
	if len(where) == 0 {
		where = []string{"true"}
	}
	clause := " WHERE " + strings.Join(where, " AND ")

	var total int
	if err := d.QueryRow(`SELECT count(*) FROM poc_templates`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	size := f.Size
	if size <= 0 {
		size = 50
	}
	if size > 200 {
		size = 200
	}
	page := f.Page
	if page < 0 {
		page = 0
	}
	args = append(args, size, page*size)
	rows, err := d.Query(`SELECT `+pocCols+` FROM poc_templates`+clause+
		fmt.Sprintf(` ORDER BY updated_at DESC, id DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []POCTemplate{}
	for rows.Next() {
		p, err := scanPOC(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, p)
	}
	return items, total, rows.Err()
}

func (d *DB) GetPOCTemplate(id int64) (*POCTemplate, error) {
	row := d.QueryRow(`SELECT `+pocCols+` FROM poc_templates WHERE id=$1`, id)
	p, err := scanPOC(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPOCNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := d.QueryRow(`SELECT content FROM poc_templates WHERE id=$1`, id).Scan(&p.Content); err != nil {
		return nil, err
	}
	return &p, nil
}

func (d *DB) CreatePOCTemplate(t *pocparse.Template, source, sourceURL string) (*POCTemplate, error) {
	row := d.QueryRow(`
INSERT INTO poc_templates(template_id,name,severity,protocol,cve_id,cwe_id,cvss_score,tags,author,
                          description,refs,source,source_url,content,digest)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11::jsonb,$12,$13,$14,$15)
ON CONFLICT (template_id) DO NOTHING
RETURNING `+pocCols,
		t.TemplateID, t.Name, t.Severity, t.Protocol, t.CVEID, t.CWEID, t.CVSSScore,
		encodeStringList(t.Tags), t.Author, t.Description, encodeStringList(t.References),
		source, sourceURL, t.Content, t.Digest)
	p, err := scanPOC(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPOCDuplicate
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdatePOCTemplate applies only the fields present in the request. enabled is
// explicit so toggling off is distinguishable from "leave unchanged".
func (d *DB) UpdatePOCTemplate(id int64, name, severity, description *string, enabled *bool) (*POCTemplate, error) {
	row := d.QueryRow(`
UPDATE poc_templates SET
    name        = COALESCE($2, name),
    severity    = COALESCE($3, severity),
    description = COALESCE($4, description),
    enabled     = COALESCE($5, enabled)
WHERE id=$1
RETURNING `+pocCols, id, name, severity, description, enabled)
	p, err := scanPOC(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPOCNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (d *DB) DeletePOCTemplate(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM poc_templates WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (d *DB) POCTemplatesByIDs(ids []int64) ([]POCTemplate, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := d.Query(`SELECT `+pocCols+` FROM poc_templates WHERE id = ANY($1) AND enabled`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []POCTemplate{}
	for rows.Next() {
		p, err := scanPOC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Bodies are fetched separately so list-shaped scans never pull megabytes.
	contentRows, err := d.Query(`SELECT id, content FROM poc_templates WHERE id = ANY($1) AND enabled`, ids)
	if err != nil {
		return nil, err
	}
	defer contentRows.Close()
	bodies := map[int64]string{}
	for contentRows.Next() {
		var id int64
		var content string
		if err := contentRows.Scan(&id, &content); err != nil {
			return nil, err
		}
		bodies[id] = content
	}
	for i := range out {
		out[i].Content = bodies[out[i].ID]
	}
	return out, contentRows.Err()
}

// POCTemplatesByTemplateIDs loads enabled templates by their nuclei template_id.
// The scan pipeline uses this to replay exactly the templates that matched
// instead of re-fingerprinting the target.
func (d *DB) POCTemplatesByTemplateIDs(templateIDs []string) ([]POCTemplate, error) {
	ids := make([]string, 0, len(templateIDs))
	seen := map[string]bool{}
	for _, id := range templateIDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := d.Query(`SELECT `+pocCols+` FROM poc_templates WHERE template_id = ANY($1) AND enabled ORDER BY id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []POCTemplate{}
	for rows.Next() {
		p, err := scanPOC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	contentRows, err := d.Query(`SELECT id, content FROM poc_templates WHERE template_id = ANY($1) AND enabled`, ids)
	if err != nil {
		return nil, err
	}
	defer contentRows.Close()
	bodies := map[int64]string{}
	for contentRows.Next() {
		var id int64
		var content string
		if err := contentRows.Scan(&id, &content); err != nil {
			return nil, err
		}
		bodies[id] = content
	}
	for i := range out {
		out[i].Content = bodies[out[i].ID]
	}
	return out, contentRows.Err()
}

func (d *DB) POCStats() (*POCStats, error) {
	stats := &POCStats{BySeverity: map[string]int{}, Sources: []string{}}
	if err := d.QueryRow(`SELECT count(*), count(*) FILTER (WHERE enabled) FROM poc_templates`).Scan(&stats.Total, &stats.Enabled); err != nil {
		return nil, err
	}
	rows, err := d.Query(`SELECT severity, count(*) FROM poc_templates GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		stats.BySeverity[sev] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	srcRows, err := d.Query(`SELECT DISTINCT source FROM poc_templates ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer srcRows.Close()
	for srcRows.Next() {
		var s string
		if err := srcRows.Scan(&s); err != nil {
			return nil, err
		}
		stats.Sources = append(stats.Sources, s)
	}
	return stats, srcRows.Err()
}
