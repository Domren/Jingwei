package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 客户授权清单（F4）：一组可验证的时间窗与目标范围，外加排除项。
// 这是「一等公民」的那份数据：guard 的拒绝原因要能指到具体条目，
// 而不是一句「不在任务范围里」。

type Authorization struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Targets    []string   `json:"targets"`
	Exclusions []string   `json:"exclusions"`
	StartsAt   *time.Time `json:"starts_at,omitempty"`
	EndsAt     *time.Time `json:"ends_at,omitempty"`
	Enabled    bool       `json:"enabled"`
	Note       string     `json:"note"`
	CreatedAt  time.Time  `json:"created_at"`
}

type AuthorizationInput struct {
	Name       string
	Targets    []string
	Exclusions []string
	StartsAt   *time.Time
	EndsAt     *time.Time
	Enabled    bool
	Note       string
}

const authorizationCols = `id, name, targets::text, exclusions::text, starts_at, ends_at, enabled, note, created_at`

func scanAuthorization(row interface{ Scan(...any) error }) (*Authorization, error) {
	var (
		a             Authorization
		targetsRaw    string
		exclusionsRaw string
	)
	if err := row.Scan(&a.ID, &a.Name, &targetsRaw, &exclusionsRaw, &a.StartsAt, &a.EndsAt,
		&a.Enabled, &a.Note, &a.CreatedAt); err != nil {
		return nil, err
	}
	// 解析失败必须报错，不能退化成空清单：授权清单为空意味着「不限制目标」，
	// 把读不出当成空值等于把「有授权才能打」变成「数据脏了就能打」。
	if err := json.Unmarshal([]byte(targetsRaw), &a.Targets); err != nil {
		return nil, fmt.Errorf("授权 %d 的 targets 不是合法的字符串数组: %w", a.ID, err)
	}
	if err := json.Unmarshal([]byte(exclusionsRaw), &a.Exclusions); err != nil {
		return nil, fmt.Errorf("授权 %d 的 exclusions 不是合法的字符串数组: %w", a.ID, err)
	}
	if a.Targets == nil {
		a.Targets = []string{}
	}
	if a.Exclusions == nil {
		a.Exclusions = []string{}
	}
	return &a, nil
}

func normalizeAuthzPatterns(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		p := strings.TrimSpace(strings.ToLower(raw))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func (d *DB) CreateAuthorization(in AuthorizationInput) (*Authorization, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, errors.New("授权名称不能为空")
	}
	targets := normalizeAuthzPatterns(in.Targets)
	exclusions := normalizeAuthzPatterns(in.Exclusions)
	if len(targets) == 0 {
		return nil, errors.New("授权至少需要一个目标范围（IP / CIDR / 域名后缀）")
	}
	if in.EndsAt != nil && in.StartsAt != nil && !in.EndsAt.After(*in.StartsAt) {
		return nil, errors.New("授权结束时间必须晚于开始时间")
	}
	// 数组列按本仓库的既有做法存 JSONB（jsonStringArray + ::text 读回）：
	// TEXT[] 在 pgx 的文本协议下读回来是 "{a,b}" 这种字面量，扫不进 []string。
	row := d.QueryRow(`INSERT INTO authorizations(name, targets, exclusions, starts_at, ends_at, enabled, note)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING `+authorizationCols,
		name, jsonStringArray(targets), jsonStringArray(exclusions), in.StartsAt, in.EndsAt, in.Enabled,
		strings.TrimSpace(in.Note))
	return scanAuthorization(row)
}

func (d *DB) ListAuthorizations(limit int) ([]*Authorization, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.Query(`SELECT `+authorizationCols+` FROM authorizations ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Authorization{}
	for rows.Next() {
		a, err := scanAuthorization(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) DeleteAuthorization(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM authorizations WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListActiveAuthorizations 返回当前生效的授权（启用且在时间窗内）。
func (d *DB) ListActiveAuthorizations() ([]*Authorization, error) {
	rows, err := d.Query(`SELECT ` + authorizationCols + ` FROM authorizations
WHERE enabled AND (starts_at IS NULL OR starts_at <= now())
  AND (ends_at IS NULL OR ends_at > now())
ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Authorization{}
	for rows.Next() {
		a, err := scanAuthorization(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
