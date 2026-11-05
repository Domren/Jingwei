package db

import (
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"
)

// 操作员导入的弱口令字典。内置精简字典在 scanner 里；这里只存导入档，
// 名字记进 cred_tasks.dict_profile，报告才能说清用的是哪本字典。

var credDictName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ErrCredDictNotFound 表示字典档不存在。
var ErrCredDictNotFound = errors.New("字典档不存在")

type CredDict struct {
	Name       string    `json:"name"`
	EntryCount int       `json:"entry_count"`
	CreatedAt  time.Time `json:"created_at"`
}

// SaveCredDict 新增或覆盖一个导入档。覆盖是显式的：同名再导入即替换内容与计数。
func (d *DB) SaveCredDict(name, content string, count int) (*CredDict, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !credDictName.MatchString(name) {
		return nil, errors.New("字典档名只能用 1-32 位字母、数字、- 和 _，并以字母或数字开头")
	}
	if name == "builtin" {
		return nil, errors.New("builtin 是内置档，不能被覆盖")
	}
	var out CredDict
	err := d.QueryRow(`
INSERT INTO cred_dicts(name, entries, entry_count) VALUES ($1, $2, $3)
ON CONFLICT (name) DO UPDATE SET entries=EXCLUDED.entries, entry_count=EXCLUDED.entry_count
RETURNING name, entry_count, created_at`, name, content, count).
		Scan(&out.Name, &out.EntryCount, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListCredDicts 列出导入档（不返回正文：列表页只要名字与规模）。
func (d *DB) ListCredDicts() ([]*CredDict, error) {
	rows, err := d.Query(`SELECT name, entry_count, created_at FROM cred_dicts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CredDict{}
	for rows.Next() {
		var c CredDict
		if err := rows.Scan(&c.Name, &c.EntryCount, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// GetCredDict 取导入档正文。
func (d *DB) GetCredDict(name string) (string, error) {
	var content string
	err := d.QueryRow(`SELECT entries FROM cred_dicts WHERE name=$1`,
		strings.ToLower(strings.TrimSpace(name))).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrCredDictNotFound
	}
	return content, err
}

// DeleteCredDict 删除导入档。已经建好的任务不受影响（运行中的任务用内存里的副本），
// 但之后不能再选它。
func (d *DB) DeleteCredDict(name string) (bool, error) {
	res, err := d.Exec(`DELETE FROM cred_dicts WHERE name=$1`, strings.ToLower(strings.TrimSpace(name)))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
