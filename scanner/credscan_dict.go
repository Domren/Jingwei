package scanner

import (
	"fmt"
	"sort"
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

// 内置字典的版本与分档（维护口径见 docs/弱口令字典维护口径.md）。
//
// 分两档不是为了少测，而是为了让「加一条」有地方放，并且让界面能说清这一版覆盖到哪：
//   - core：通用服务的出厂/默认口令，与具体厂商无关，几乎所有协议都该先试这几条；
//   - vendor：厂商与设备相关（MSSQL 的 sa、Jenkins/JBoss 控制台、svnserve、RouterOS、
//     SNMP 的 community 等），只对特定协议有意义，但对它们必须排在前面。
//
// 尝试顺序 = core 全量 → vendor 全量，与 1.6.0 的实际顺序一致：顺序也是「先试出什么」的
// 决定因素，调档不能悄悄改顺序。版本号随内容变动，格式 YYYY.MM（同一月内多次调整加 .1）。
const (
	CredBuiltinDictProfile = "builtin"
	CredBuiltinDictVersion = "2026.11"
	CredDictTierCore       = "core"
	CredDictTierVendor     = "vendor"
)

// credBuiltinCore 是通用档：空口令与 root/admin 这类几乎所有设备都有的组合。
var credBuiltinCore = []Credential{
	// 空口令本身是一组必须测的组合：Redis 未开认证、memcached /
	// Zookeeper 这类根本没有认证的服务，只有它才会命中。放在最前面，
	// 无认证目标第一条就能出结论，不必先把几十组口令打一遍。
	{},
	{Username: "root", Password: "root"},
	{Username: "root", Password: "123456"},
	{Username: "root", Password: "toor"},
	{Username: "root", Password: "password"},
	{Username: "root", Password: ""},
	{Username: "admin", Password: "admin"},
	{Username: "admin", Password: "123456"},
	{Username: "admin", Password: "password"},
	{Username: "admin", Password: "admin123"},
	{Username: "admin", Password: "passw0rd"},
	{Username: "admin", Password: ""},
	{Username: "administrator", Password: "administrator"},
	{Username: "administrator", Password: "123456"},
	{Username: "administrator", Password: "password"},
	{Username: "test", Password: "test"},
	{Username: "test", Password: "123456"},
	{Username: "guest", Password: "guest"},
	{Username: "guest", Password: ""},
	{Username: "user", Password: "user"},
	{Username: "postgres", Password: "postgres"},
	{Username: "mysql", Password: "mysql"},
	{Username: "redis", Password: "redis"},
	{Username: "mongo", Password: "mongo"},
	{Username: "ftp", Password: "ftp"},
	{Username: "ubuntu", Password: "ubuntu"},
	{Username: "tomcat", Password: "tomcat"},
	{Username: "www", Password: "www"},
	{Username: "elastic", Password: "elastic"},
}

// credBuiltinVendor 是厂商/设备档：只在对应协议上有意义，但对那些协议必须靠前。
// 加条目的门槛：能说出「哪个产品、哪个版本、出厂就是这样」，且能在 lab 里复现；
// 只写「网上见过」的条目进不来（那类东西的误报成本远高于命中收益）。
var credBuiltinVendor = []Credential{
	// MSSQL 的 sa、JBoss/Jenkins 控制台、svnserve、RouterOS 的出厂/示例口令。
	{Username: "sa", Password: "sa"},
	{Username: "sa", Password: ""},
	{Username: "sa", Password: "123456"},
	{Username: "jboss", Password: "jboss"},
	{Username: "jenkins", Password: "jenkins"},
	{Username: "svn", Password: "svn"},
	// SNMP 只把口令字段当 community 用：这几条是纯口令条目（无用户名）。
	{Password: "public"},
	{Password: "private"},
	{Password: "community"},
}

var credBuiltin = CredDictionary{
	Profile: CredBuiltinDictProfile,
	Credentials: append(append(make([]Credential, 0, len(credBuiltinCore)+len(credBuiltinVendor)),
		credBuiltinCore...), credBuiltinVendor...),
}

// CredDictionaryTier 是字典的一档，给目录接口与界面用。
type CredDictionaryTier struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
	Note  string `json:"note"`
}

// CredDictionaryInfo 是一份字典档的元信息。内置档的 Version 是内容版本，
// 导入档没有版本（内容由操作员自己维护），所以这里只描述内置档。
type CredDictionaryInfo struct {
	Profile string               `json:"profile"`
	Version string               `json:"version"`
	Total   int                  `json:"total"`
	Tiers   []CredDictionaryTier `json:"tiers"`
	// Order 写明尝试顺序，避免有人以为分档=分组并发。
	Order string `json:"order"`
}

// CredBuiltinDictionaryInfo 返回内置字典的版本与分档构成。
func CredBuiltinDictionaryInfo() CredDictionaryInfo {
	return CredDictionaryInfo{
		Profile: credBuiltin.Profile,
		Version: CredBuiltinDictVersion,
		Total:   len(credBuiltin.Credentials),
		Order:   "core 全量 → vendor 全量（严格按此顺序，命中/锁定即停）",
		Tiers: []CredDictionaryTier{
			{Key: CredDictTierCore, Label: "通用", Count: len(credBuiltinCore),
				Note: "空口令与 root/admin 这类通用出厂口令，任何协议都先试"},
			{Key: CredDictTierVendor, Label: "厂商/设备", Count: len(credBuiltinVendor),
				Note: "sa / jboss / jenkins / svn / snmp community 等只在对应协议上有意义"},
		},
	}
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

// credProtocolCommunityFirst 列出「凭据字段语义与用户/口令那一套不同」的协议，
// 以及该协议最该先试的条目。SNMP 的凭据就是 community（只有口令字段有意义），
// 内置字典里 40 多条 `root:root` 这类条目对它全是无效形状：每一条都会静默丢弃、
// 等满一个应答窗口（1.5s）才落 inconclusive。不重排的话，一个 SNMP 端点光把字典
// 空转到 `public` 就要一分多钟，而且预算耗尽时最先被牺牲的正是本该先试的那几条。
var credProtocolCommunityFirst = map[string][]string{
	"snmp": {"public", "private", "community"},
}

// OrderCredentialsForProtocol 按协议调整条目顺序：把该协议最该先试的条目提到前面，
// 其余条目保持原有相对顺序（稳定分区）。**只重排，不增删**——少一条就等于在报告里
// 声称测过一组其实没测的口令。
func OrderCredentialsForProtocol(protocol string, creds []Credential) []Credential {
	p := strings.ToLower(strings.TrimSpace(protocol))
	first, ok := credProtocolCommunityFirst[p]
	if !ok || len(creds) < 2 {
		return creds
	}
	rank := make(map[string]int, len(first))
	for i, pw := range first {
		rank[pw] = i + 1
	}
	// rank 为 0 的排在后面；同一 rank 内按原顺序（sort.SliceStable 保证稳定）。
	rankOf := func(c Credential) int {
		if c.Username != "" {
			return 0
		}
		return rank[c.Password]
	}
	out := make([]Credential, len(creds))
	copy(out, creds)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rankOf(out[i]), rankOf(out[j])
		if ri == 0 || rj == 0 {
			return ri != 0 // 有 rank 的在前
		}
		return ri < rj
	})
	return out
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
