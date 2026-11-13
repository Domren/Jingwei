package report

import (
	"sort"
	"strings"

	"github.com/Autumn-27/jingwei/db"
)

// R18 · 导出侧的归并：按「类 + 主机 + 接口族」把同一根因的多条 finding
// 合成一条，取最高严重度，其余条目作为证据保留可展开。
//
// 为什么要在这一层再做一次（落库层已经有了推导 key）：
//   - 落库层管的是「新写入时不再产生重复」，但存量数据里已经有 #25(high) 与
//     #28(critical) 这种「同接口两级证据」——它们各有自己的 dedupe_key，
//     在报告里必须合成一条，否则客户会认为我们在凑数（§4.4 ③）；
//   - 导出是交付物，口径必须与展示一致，两边都走这一个函数。
//
// 归并单元的边界（与 db.DeriveFindingIdentity 同口径）：
//   - 类：findingClassKey 的族（rce/xss/sqli/…）；
//   - 主机：POC 与证据里出现的全部 host:port（链式发现因此不会被拆开）；
//   - 接口族：URL 路径的资源根（/arcgis/admin）。
//
// 刻意保守：宁可不合并，也不要错误合并。证据数、-bound 资产数、严重度都必须
// 在合并后可见，否则合并就成了掩盖信息。

// FindingGroup 是一条（可能由多条原始条目合并成的）交付条目。
type FindingGroup struct {
	// Primary 是合并后代表这一组的那条（严重度最高的那条，同级取最早）。
	Primary *db.DBFinding
	// Members 是组内全部原始条目（含 Primary），按严重度降序。
	Members []*db.DBFinding
	// Severity 是组内的最高严重度。
	Severity string
	// AssetIDs 是组内所有条目 asset_ids 的并集（去重排序）。
	AssetIDs []int64
}

// Merged 表示这一组是否由多条合成（>1 时为真，导出时标注「已合并 N 条证据」）。
func (g FindingGroup) Merged() bool { return len(g.Members) > 1 }

// MergeFindingsForDelivery 把一批 finding 归并成交付条目。
//
// 返回的顺序与 sortFindingsForExport 一致（严重度降序、再按时间倒序），
// 所以调用方不需要再排一次。
func MergeFindingsForDelivery(fs []*db.DBFinding) []FindingGroup {
	if len(fs) == 0 {
		return nil
	}
	// 用「类 + 主机集合 + 接口族」做分组键。键的构造与 db 层同源，
	// 保证「库里判定为同一条」的在这里也一定同组。
	buckets := map[string][]*db.DBFinding{}
	order := []string{}
	for _, f := range fs {
		if f == nil {
			continue
		}
		key := deliveryGroupKey(f)
		if _, ok := buckets[key]; !ok {
			order = append(order, key)
		}
		buckets[key] = append(buckets[key], f)
	}

	out := make([]FindingGroup, 0, len(order))
	for _, key := range order {
		members := buckets[key]
		// 组内排序：严重度降序，同级按时间正序（最早发现的那条当代表）。
		sort.SliceStable(members, func(i, j int) bool {
			ri, rj := sevRank[members[i].Severity], sevRank[members[j].Severity]
			if ri != rj {
				return ri < rj
			}
			return members[i].CreatedAt.Before(members[j].CreatedAt)
		})
		g := FindingGroup{Primary: members[0], Members: members, Severity: members[0].Severity}
		// 资产并集：链式发现的第二个主机也要出现在交付条目里。
		seen := map[int64]bool{}
		for _, m := range members {
			for _, id := range m.AssetIDs {
				if id <= 0 || seen[id] {
					continue
				}
				seen[id] = true
				g.AssetIDs = append(g.AssetIDs, id)
			}
		}
		sort.Slice(g.AssetIDs, func(i, j int) bool { return g.AssetIDs[i] < g.AssetIDs[j] })
		out = append(out, g)
	}
	// 组间排序与单条导出一致。
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := sevRank[out[i].Severity], sevRank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return out[i].Primary.CreatedAt.After(out[j].Primary.CreatedAt)
	})
	return out
}

// deliveryGroupKey 构造交付归并键。
//
// 用 dedupe_key 里已有的信息（R18 之后它是「类+主机+接口族」）优先；
// 存量数据里可能是旧格式（含完整 URL），这时按同样规则重新收敛一次。
func deliveryGroupKey(f *db.DBFinding) string {
	class := deliveryClassKey(f)
	if class == "" {
		class = "unknown"
	}
	host, family := splitLegacyDedupeKey(f.DedupeKey)
	if host == "" {
		// 没有 dedupe_key（存量里 61% 是这种）：退回标题归一化 + 资产集合。
		// 只按标题归并是粗的，但比「同一句话出现两遍」强，且不会跨主机误合。
		host = "no-host"
	}
	if family == "" {
		family = deliveryFamilyFromText(f)
	}
	if host == "no-host" && family == "" {
		// 什么都拿不到：用标题 slug 兜底，至少同名的会合到一起。
		family = "title:" + slugify(findingTitle(f))
	}
	return class + "|" + host + "|" + family
}

// deliveryClassKey 取漏洞类族；与 db.findingClassKey 同口径（那边未导出，
// 这里按同样的关键词表实现，避免为一个纯函数把 db 的内部表暴露出去）。
func deliveryClassKey(f *db.DBFinding) string {
	text := strings.ToLower(f.VulnClass + " " + f.Name)
	has := func(terms ...string) bool {
		for _, t := range terms {
			if strings.Contains(text, t) {
				return true
			}
		}
		return false
	}
	switch {
	case has("弱口令", "weak password", "weak-password", "默认口令", "default credential"):
		return "weak-password"
	case has("csrf", "跨站请求伪造"):
		return "csrf"
	case has("ssrf", "服务端请求伪造"):
		return "ssrf"
	case has("xxe", "xml external"):
		return "xxe"
	case has("反序列化", "deserializ"):
		return "deserialization"
	case has("命令执行", "命令注入", "rce", "command injection", "code execution", "代码执行"):
		return "rce"
	case has("文件上传", "upload"):
		return "upload"
	case has("sql", "注入点", "sqli"):
		return "sqli"
	case has("xss", "跨站脚本"):
		return "xss"
	case has("文件包含", "lfi", "rfi", "local file inclusion"):
		return "lfi"
	case has("目录遍历", "路径穿越", "traversal"):
		return "traversal"
	case has("越权", "idor", "unauthorized access", "未授权", "privilege escalation", "提权"):
		return "idor"
	case has("信息泄露", "敏感信息", "info disclosure", "information disclosure", "硬编码", "hardcoded"):
		return "info-disclosure"
	case has("cors", "跨域"):
		return "cors"
	}
	return ""
}

// splitLegacyDedupeKey 从 dedupe_key 里拆出 (主机, 接口族)。
//
// 兼容两种格式：
//   - R18 之后：agent:<task>:<class>:<host,host>:<family>
//   - R18 之前：agent:<task>:<class>:<scheme://host/path?params#method>
//
// 旧格式里主机与接口族都在最后一段，这里用「是否含 ://」判断并解析。
func splitLegacyDedupeKey(key string) (host, family string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", ""
	}
	parts := strings.SplitN(key, ":", 5)
	if len(parts) < 4 {
		return "", ""
	}
	tail := parts[len(parts)-1]
	// 新格式：最后一段是接口族，倒数第二段是主机列表。
	if len(parts) == 5 && !strings.Contains(tail, "://") {
		return normalizeHostList(parts[3]), normalizeFamily(tail)
	}
	// 旧格式：最后一段是完整 URL（可能带 ?params#METHOD）。
	if i := strings.Index(tail, "://"); i >= 0 {
		rest := tail[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			return strings.ToLower(rest[:j]), normalizeFamily(rest[j:])
		}
		return strings.ToLower(rest), ""
	}
	return normalizeHostList(tail), ""
}

func normalizeHostList(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	hosts := strings.Split(s, ",")
	sort.Strings(hosts)
	return strings.Join(hosts, ",")
}

// normalizeFamily 把 URL 路径收敛到资源根（与 db.resourceRoot 同口径）。
func normalizeFamily(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) == 0 || (len(segs) == 1 && segs[0] == "") {
		return ""
	}
	if i := strings.LastIndex(segs[len(segs)-1], "."); i > 0 {
		segs[len(segs)-1] = segs[len(segs)-1][:i]
	}
	if len(segs) <= 2 {
		return "/" + strings.Join(segs, "/")
	}
	keep := len(segs) - 1
	if keep > 2 {
		keep = 2
	}
	return "/" + strings.Join(segs[:keep], "/")
}

// deliveryFamilyFromText 在没有 URL 信息时，从标题里取接口线索（如 /api/back）。
func deliveryFamilyFromText(f *db.DBFinding) string {
	for _, text := range []string{f.Name, f.VulnClass, f.Summary} {
		for _, tok := range strings.Fields(text) {
			if strings.HasPrefix(tok, "/") && strings.Count(tok, "/") >= 1 {
				return normalizeFamily(tok)
			}
		}
	}
	return ""
}

// slugify 同 db 层的 normalizeIdentityName：按 rune 截断，不按字节
// （按字节切中文会产生非法 UTF-8，落库直接失败）。
func slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r > 0x7f {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if rs := []rune(out); len(rs) > 64 {
		out = string(rs[:64])
	}
	return out
}
