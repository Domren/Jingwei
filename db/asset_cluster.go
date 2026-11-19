package db

// P3 · 站群资产聚类：按证书指纹 / 页面结构 hash / favicon / dedupe 族，
// 把指向同一套系统的多个域名归并成一族；原始条目始终保留可展开。
//
// 设计口径：
//   - 信号强度 cert > page > favicon > dedupe 族。强的先分，弱的只在强信号缺失时兜底；
//   - 与 finding 的 dedupe_key 兼容：族键取 dedupe_key 的最后一段（"类+主机+接口族"
//     里的接口族），所以「同一接口族、换主机」的镜像站会自然聚到一起；
//   - 镜像站不另算独立目标：一族只打 canonical（排序第一）那一条，其余标记为 mirror。
//
// 本文件全是纯函数，便于在无 DB/CI 环境写夹具。

import (
	"sort"
	"strings"
	"time"
)

// ClusterableAsset 是参与聚类的一条站点资产（只需聚类相关字段）。
type ClusterableAsset struct {
	ID              int64
	URL             string
	Domain          string
	CertFingerprint string // 证书 SHA-256 / 序列号等稳定指纹
	PageStructHash  string // 页面结构（去内容后的 DOM/Template hash）
	FaviconMMH3     string // favicon hash
	DedupeKey       string // 由 buildDedupeKey 产出的 finding 去重键（可选）
}

// AssetCluster 是一族同源站点。Members 是原始条目，永不丢弃。
type AssetCluster struct {
	Key     string             `json:"key"`
	Members []ClusterableAsset `json:"members"`
}

// ClusterKeyFor 计算一条资产的聚类键。空信号返回空串（不参与聚类）。
func ClusterKeyFor(a ClusterableAsset) string {
	if fp := normClusterSignal(a.CertFingerprint); fp != "" {
		return "cert:" + fp
	}
	if ph := normClusterSignal(a.PageStructHash); ph != "" {
		return "page:" + ph
	}
	if fav := normClusterSignal(a.FaviconMMH3); fav != "" {
		return "favicon:" + fav
	}
	if fam := DedupeFamily(a.DedupeKey); fam != "" {
		return "family:" + fam
	}
	return ""
}

func normClusterSignal(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// DedupeFamily 从 dedupe_key 里取接口族（最后一段）。
// dedupe_key 形如 "agent:12:SQLi:a.com:443,b.com:/api/admin"，host 段含冒号，
// 所以从左切会错，必须从右取最后一段。
func DedupeFamily(dedupeKey string) string {
	key := strings.TrimSpace(dedupeKey)
	if key == "" {
		return ""
	}
	if i := strings.LastIndex(key, ":"); i >= 0 && i < len(key)-1 {
		return key[i+1:]
	}
	return ""
}

// ClusterAssets 把资产按聚类键归并，返回按 key 排序的稳定结果。
// 没有聚类信号的资产各自成族（key = "id:<n>"），不会被强行合并。
func ClusterAssets(assets []ClusterableAsset) []AssetCluster {
	groups := map[string][]ClusterableAsset{}
	order := []string{}
	for _, a := range assets {
		key := ClusterKeyFor(a)
		if key == "" {
			key = "id:" + itoa64(a.ID)
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], a)
	}
	sort.Strings(order)
	out := make([]AssetCluster, 0, len(order))
	for _, key := range order {
		members := append([]ClusterableAsset{}, groups[key]...)
		sort.SliceStable(members, func(i, j int) bool {
			if members[i].ID != members[j].ID {
				return members[i].ID < members[j].ID
			}
			return members[i].URL < members[j].URL
		})
		out = append(out, AssetCluster{Key: key, Members: members})
	}
	return out
}

// ExpandClusterMembers 展开一族的原始条目（按聚类键）。找不到返回 nil。
func ExpandClusterMembers(clusters []AssetCluster, key string) []ClusterableAsset {
	for _, c := range clusters {
		if c.Key == key {
			return append([]ClusterableAsset{}, c.Members...)
		}
	}
	return nil
}

// Canonical 返回一族里作为唯一打点的那条（排序第一）。镜像站不再单独作为目标。
func (c AssetCluster) Canonical() (ClusterableAsset, bool) {
	if len(c.Members) == 0 {
		return ClusterableAsset{}, false
	}
	return c.Members[0], true
}

// IsMirror 报告某条资产是不是 canonical 之外的镜像（不应重复打）。
func (c AssetCluster) IsMirror(a ClusterableAsset) bool {
	canon, ok := c.Canonical()
	return ok && canon.ID != a.ID && canon.URL != a.URL
}

// IndependentTargets 返回一族里应当作为独立目标的数量（永远为 1 或 0）。
func (c AssetCluster) IndependentTargets() int {
	if _, ok := c.Canonical(); ok {
		return 1
	}
	return 0
}

// ---- 域名 / IP 变更时间线 ----

// DNSResolutionEvent 是一次域名解析观测。
type DNSResolutionEvent struct {
	Domain string
	IP     string
	At     time.Time
}

// DomainTimelineEntry 是某域名在某 IP 上的一段有效期。Until 为 nil 表示仍在生效
// 或被下一条观测截断；下一条同域名不同 IP 的观测会把上一条的 Until 设为该时刻。
type DomainTimelineEntry struct {
	Domain string     `json:"domain"`
	IP     string     `json:"ip"`
	Since  time.Time  `json:"since"`
	Until  *time.Time `json:"until,omitempty"`
}

// BuildDomainTimeline 把若干解析观测压成按域名/IP 分组的变更时间线。
// 同一域名连续解析到同一 IP 不会重复新增条目；解析到新 IP 会闭合上一段。
func BuildDomainTimeline(events []DNSResolutionEvent) []DomainTimelineEntry {
	if len(events) == 0 {
		return nil
	}
	sorted := append([]DNSResolutionEvent{}, events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Domain != sorted[j].Domain {
			return sorted[i].Domain < sorted[j].Domain
		}
		return sorted[i].At.Before(sorted[j].At)
	})
	out := []DomainTimelineEntry{}
	lastIdx := map[string]int{}
	for _, e := range sorted {
		domain := strings.ToLower(strings.TrimSpace(e.Domain))
		ip := strings.TrimSpace(e.IP)
		if domain == "" || ip == "" {
			continue
		}
		if idx, ok := lastIdx[domain]; ok {
			if out[idx].IP == ip {
				continue // 同一 IP 重复观测
			}
			t := e.At
			out[idx].Until = &t
		}
		lastIdx[domain] = len(out)
		out = append(out, DomainTimelineEntry{Domain: domain, IP: ip, Since: e.At})
	}
	return out
}
