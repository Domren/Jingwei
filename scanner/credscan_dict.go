package scanner

import (
	"fmt"
	"strings"
)

// 内置精简字典。刻意小：弱口令检测的第一轮目标是「这个端口有没有低级错误」，
// 不是穷举。大字典属于操作员显式导入的档位（记在 cred_tasks.dict_profile 里），
// 两件事分开——默认把全网端口打一遍大字典，出了事没人说得清是谁的意图。
//
// 条目顺序就是尝试顺序：越常见越靠前。命中或锁定之后该端点的余下条目不再尝试，
// 所以顺序也决定了「最先试出来的是什么」。
type CredDictionary struct {
	Profile     string       `json:"profile"`
	Credentials []Credential `json:"-"`
}

var credBuiltin = CredDictionary{
	Profile: "builtin",
	Credentials: []Credential{
		{Username: "root", Password: "root"},
		{Username: "root", Password: "123456"},
		{Username: "root", Password: "toor"},
		{Username: "root", Password: "password"},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "123456"},
		{Username: "admin", Password: "password"},
		{Username: "admin", Password: "admin123"},
		{Username: "administrator", Password: "administrator"},
		{Username: "administrator", Password: "123456"},
		{Username: "test", Password: "test"},
		{Username: "test", Password: "123456"},
		{Username: "guest", Password: "guest"},
		{Username: "user", Password: "user"},
		{Username: "postgres", Password: "postgres"},
		{Username: "mysql", Password: "mysql"},
		{Username: "redis", Password: "redis"},
		{Username: "mongo", Password: "mongo"},
		{Username: "ftp", Password: "ftp"},
		{Username: "ubuntu", Password: "ubuntu"},
		{Username: "tomcat", Password: "tomcat"},
		{Username: "oracle", Password: "oracle"},
		{Username: "www", Password: "www"},
		{Username: "elastic", Password: "elastic"},
		{Username: "root", Password: ""},
	},
}

// CredDictionaryByName 取字典档。空名按内置档处理；未知档报错而不是悄悄回落到内置——
// 操作员以为在用导入的字典，实际跑的是内置的，报告里的结论就没有归因。
func CredDictionaryByName(profile string) (CredDictionary, error) {
	name := strings.ToLower(strings.TrimSpace(profile))
	if name == "" || name == credBuiltin.Profile {
		return credBuiltin, nil
	}
	return CredDictionary{}, &CredDictionaryError{Profile: name}
}

// CredDictionaryError 表示请求了不存在的字典档。
type CredDictionaryError struct{ Profile string }

func (e *CredDictionaryError) Error() string { return "字典档不存在：" + e.Profile }

// CredDictionaryNames 列出当前可用的字典档（给前端选择器）。
func CredDictionaryNames() []string { return []string{credBuiltin.Profile} }

// ParseCredDictionary 解析操作员导入的字典正文：一行一组，`用户:口令` 或只有 `口令`
// （少部分协议只认口令）。空行与 `#` 开头的注释跳过；同一组去重保序。
// 上限 5000 组：导入档是给「这个目标我怀疑有默认口令」用的，不是拿来做全量爆破的。
func ParseCredDictionary(content string) ([]Credential, error) {
	const maxEntries = 5000
	out := make([]Credential, 0, 64)
	seen := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		var c Credential
		if i := strings.Index(trimmed, ":"); i >= 0 {
			c = Credential{Username: strings.TrimSpace(trimmed[:i]), Password: trimmed[i+1:]}
		} else {
			c = Credential{Password: trimmed}
		}
		key := c.Username + "\x00" + c.Password
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
		if len(out) > maxEntries {
			return nil, fmt.Errorf("导入内容超过 5000 组上限")
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("字典内容为空（每行一组，用户:口令 或只有口令）")
	}
	return out, nil
}
