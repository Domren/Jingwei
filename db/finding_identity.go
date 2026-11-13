package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// R18 · 服务端确定性推导：漏洞的资产绑定与去重键。
//
// 背景（2026-11-11 实测，任务 #4 的 165 条链接 / 28 条 findings）：
//   - `asset_ids` 空 2 条，且**空值集中在跨主机/跨端口的链式发现上**——最有交付
//     价值的那类（#31 跨端口凭据链）反而一条资产都没绑，报告里落进「未关联」桶；
//   - `dedupe_key` 空 17/28（61%），空值分布在三个 worker 上，同一个 report_finding
//     路径有时写有时不写；
//   - 同一根因换个端点就变成另一个 key（#21 与 #23 是 ArcGIS 管理接口整族免鉴权，
//     key 却是两个不同 URL），按 key 分组永远查不出重复；
//   - 同一接口的两级证据（#25 high 与 #28 critical）在报告里成了两条。
//
// 结论：这两个值**不该由模型自由裁量**。模型给的只是提示，真正的身份必须从
// 「这次漏洞的证据里确实出现过哪些 host:port」推导出来。本文件只做纯计算：
// 输入是已准备好的流量证据与模型给的资产列表，输出是推导值 + 是否与模型一致。
// 落库由调用方（RecordFindingTx / UpsertFinding）使用。

// DerivedIdentity 是一次漏洞记录的服务端推导结果。
type DerivedIdentity struct {
	// DedupeKey 是「类 + 主机 + 接口族」级别的稳定身份，永不为空（只要任务与
	// 类可判）。同根因换端点会落到同一个 key 上——这是它区别于旧
	// 「URL+参数集+方法」粒度的关键。
	DedupeKey string
	// AssetIDs 是由证据里出现的 host:port 反查出的资产 id（已排序去重）。
	// 链式证据里每一个主机都参与，不只最后一个请求。
	AssetIDs []int64
	// Hosts 是推导时用到的全部 host（含端口），用于审计与前端展示。
	Hosts []string
	// ModelKeyEmpty / ModelAssetsEmpty 记录模型是否漏给，便于事后统计
	// 「模型自由裁量」的比例是否真的降下来了。
	ModelKeyEmpty    bool
	ModelAssetsEmpty bool
}

// DeriveFindingIdentity 从证据推导去重键与资产绑定。
//
// hosts 是全量证据（按复现顺序），assetIDsByHost 是「host:port → 资产 id」的
// 反查表（由调用方一次性查好，避免本函数做 N 次查询）。modelAssetIDs 是模型
// 给的资产列表，只作为「补充」：它多给的会被保留，漏给的由推导补上。
func DeriveFindingIdentity(
	in RecordFindingInput,
	prepared []PreparedTrafficEvidence,
	assetIDsByHost map[string][]int64,
	modelAssetIDs []int64,
) DerivedIdentity {
	out := DerivedIdentity{
		ModelKeyEmpty:    false,
		ModelAssetsEmpty: len(modelAssetIDs) == 0,
	}

	// ① 收集证据里出现的所有 host:port，按出现顺序去重。
	//    链式证据的关键就在这一步：不能只看最后一个请求，也不能只看 proof 那条。
	hosts := collectEvidenceHosts(prepared)
	out.Hosts = hosts

	// ② 去重键：类 + 主机集合 + 接口族。
	//    「接口族」= 路径的稳定前缀（去掉最后一段与查询串），这样同根因换端点
	//    （/arcgis/admin/logs/query 与 /arcgis/admin/security/tokens）会归到
	//    /arcgis/admin 之下。
	//
	//    没有证据时必须用名字兜底：协议类漏洞（Redis/MySQL）没有 URL，若族一律
	//    落到 "root"，同一任务里所有协议洞都会被合成一条——那是过度合并，
	//    比漏合并更糟（会丢洞）。
	class := findingClassKey(in.VulnClass, in.Name)
	out.DedupeKey = buildDedupeKey(in.TaskID, class, hosts, prepared, in.Name)

	// ③ 资产绑定：模型给的 + 推导出的，取并集。
	//    推导优先（模型漏给的补上），模型多给的保留（可能是它另查的资产）。
	out.AssetIDs = mergeAssetIDs(modelAssetIDs, hostAssetIDs(hosts, assetIDsByHost))
	return out
}

// collectEvidenceHosts 返回证据里出现过的全部 host:port（小写、去重、保序）。
//
// 顺序有意义：报告与 POC 按复现顺序展示，身份计算也要稳定（同一组证据换顺序
// 不该换 key），所以最后会排序；这里保序只是为了「第一个主机」这类语义可用。
func collectEvidenceHosts(prepared []PreparedTrafficEvidence) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range prepared {
		h := evidenceHostKey(p.Snapshot.URL)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// evidenceHostKey 从 URL 取 host:port，端口缺省时按 scheme 补默认值。
// 补默认端口是为了让 `http://a/x` 与 `http://a:80/x` 归到同一个主机。
func evidenceHostKey(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http", "ws":
			port = "80"
		case "https", "wss":
			port = "443"
		}
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

// buildDedupeKey 组装「类 + 主机集合 + 接口族」级别的主键。
//
// 为什么用主机集合而不是单个 URL（旧实现的粒度）：
//   - 同一根因换个端点（ArcGIS 整族免鉴权）必须合成一条；
//   - 跨端口的链式发现（:1111 读配置 → :8887 用授权串）本身就是一个洞，
//     两个主机都在 key 里才不会被拆成两条。
//
// 为什么接口族取路径前缀：`/arcgis/admin/logs/query` 与
// `/arcgis/admin/security/tokens` 的共同前缀是 `/arcgis/admin`，同族。
// 前缀取到「第一段非通用词之后的路径」，避免所有接口都归到 `/`。
func buildDedupeKey(taskID int64, class string, hosts []string, prepared []PreparedTrafficEvidence, fallbackName string) string {
	if class == "" {
		class = "unknown"
	}
	// 排序保证「同一组证据、不同到达顺序」得到同一个 key。
	sortedHosts := append([]string{}, hosts...)
	sort.Strings(sortedHosts)
	hostPart := strings.Join(sortedHosts, ",")
	if hostPart == "" {
		hostPart = "no-host"
	}
	family := interfaceFamily(prepared)
	if family == "root" {
		// 没有 URL 证据（协议类漏洞）：用名字归一化后做族，避免同任务所有
		// 无证据的洞都被合并。名字也空时只能留在 root（此时确实无从区分）。
		if slug := normalizeIdentityName(fallbackName); slug != "" {
			family = "name:" + slug
		}
	}
	if taskID > 0 {
		return "agent:" + itoa64(taskID) + ":" + class + ":" + hostPart + ":" + family
	}
	return "agent:" + class + ":" + hostPart + ":" + family
}

// normalizeIdentityName 把自由文本名字压成稳定的 slug（小写、非字母数字折成 -）。
// 只用于「没有证据时」的族兜底，不用于证据充分的情况。
//
// 截断必须按 rune 而不是字节：按字节切会把中文切成半个字符，落库时报
// `invalid byte sequence for encoding "UTF8"` 并把整条漏洞写入回滚——
// 一个纯展示用的 slug 不该有能力搞丢一条真洞。
func normalizeIdentityName(s string) string {
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

// interfaceFamily 取证据里路径的「接口族」。
//
// 目标粒度：同一功能族的多个端点要归成一族（ArcGIS 的 /arcgis/admin/logs/query
// 与 /arcgis/admin/security/tokens 都是「ArcGIS 管理接口」），而不同功能（SQLi 的
// /vul/sqli 与 XSS 的 /vul/xss）必须分开。
//
// 两条规则叠加：
//  1. 多条证据时取公共路径前缀 —— 一条洞自己有多个请求时，族就是它们的交汇处；
//  2. 单条证据时收敛到「接口根」 —— 去掉最后一到两段动作词，留下资源根。
//
// 规则 2 是「同根因换端点」能合掉的关键：旧实现把整条 URL 当身份，换个端点
// 就换身份，于是永远查不出重复（§4.4 的 #21/#23）。
func interfaceFamily(prepared []PreparedTrafficEvidence) string {
	paths := make([]string, 0, len(prepared))
	for _, p := range prepared {
		u, err := url.Parse(strings.TrimSpace(p.Snapshot.URL))
		if err != nil {
			continue
		}
		if seg := normalizePath(u.Path); seg != "" {
			paths = append(paths, seg)
		}
	}
	if len(paths) == 0 {
		return "root"
	}
	if len(paths) == 1 {
		return resourceRoot(paths[0])
	}
	common := resourceRoot(paths[0])
	for _, p := range paths[1:] {
		common = commonPathPrefix(common, resourceRoot(p))
		if common == "" {
			// 跨接口的链式发现：族取两侧资源根的组合，保证同一条链稳定。
			return "chain:" + firstSegment(paths[0]) + "+" + firstSegment(paths[1])
		}
	}
	return common
}

// resourceRoot 把一条路径收敛到「接口根」：去掉末尾一到两段的动作/资源词。
//
//	/arcgis/admin/logs/query        → /arcgis/admin
//	/arcgis/admin/security/tokens   → /arcgis/admin
//	/api/back/user/list             → /api/back
//	/vul/sqli/sqli_str.php          → /vul/sqli
//
// 规则：至少保留两段（避免把 /api 当成全站族）；四段及以上时只保留前两段，
// 因为「产品根 + 模块」通常就是族的边界（/arcgis/admin、/api/back）。
func resourceRoot(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) <= 2 {
		return "/" + strings.Join(segs, "/")
	}
	keep := len(segs) - 1 // 至少去掉末段
	if keep > 2 {
		keep = 2 // 四段及以上统一收到前两段
	}
	return "/" + strings.Join(segs[:keep], "/")
}

// normalizePath 去掉尾部斜杠与文件扩展名，返回用于比较的路径。
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if i := strings.LastIndex(p, "/"); i > 0 {
		last := p[i+1:]
		if strings.Contains(last, ".") {
			p = p[:i]
		}
	}
	return strings.TrimRight(p, "/")
}

// commonPathPrefix 返回两个路径的公共段前缀（按 "/" 分段比较，不切字符，
// 否则 /api 与 /apix 会被误判为同族）。
func commonPathPrefix(a, b string) string {
	as := strings.Split(strings.Trim(a, "/"), "/")
	bs := strings.Split(strings.Trim(b, "/"), "/")
	i := 0
	for i < len(as) && i < len(bs) && as[i] == bs[i] {
		i++
	}
	if i == 0 {
		return ""
	}
	return "/" + strings.Join(as[:i], "/")
}

func firstSegment(p string) string {
	p = strings.Trim(p, "/")
	if i := strings.Index(p, "/"); i > 0 {
		return p[:i]
	}
	if p == "" {
		return "root"
	}
	return p
}

// hostAssetIDs 把 host 列表映射到资产 id（一个 host 可能对应多条资产：
// endpoint 与 service 各一条，都要绑）。
func hostAssetIDs(hosts []string, byHost map[string][]int64) []int64 {
	out := []int64{}
	for _, h := range hosts {
		out = append(out, byHost[h]...)
	}
	return out
}

// mergeAssetIDs 合并模型给的和推导出的，去重排序。
// 模型多给的不删——它可能绑了推导看不见的资产（例如同一主机的 IP 资产），
// 但模型**漏给**的必须补上，这正是 R18 的核心。
func mergeAssetIDs(model, derived []int64) []int64 {
	seen := map[int64]bool{}
	out := make([]int64, 0, len(model)+len(derived))
	for _, id := range append(append([]int64{}, model...), derived...) {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// HostAssetLookup 按 host:port 反查资产 id（R18）。
//
// 为什么要一次查完而不是每条洞查一次：链式证据里每个主机都要查，一条洞可能有
// 3–5 个主机；逐条查会把 report_finding 的事务拖长，而它持有任务级证据锁。
//
// 匹配口径（刻意宽）：同一个 host:port 下，IP 资产、service 资产、endpoint 资产
// 都算——报告里「这条洞挂在哪台机器上」这三种都该列出来。这正是旧实现漏掉的：
// 它只按 URL 精确匹配 endpoint，于是同主机的 IP 资产与 service 资产都不在结果里。
func HostAssetLookup(tx *sql.Tx, hosts []string) (map[string][]int64, error) {
	out := map[string][]int64{}
	if len(hosts) == 0 {
		return out, nil
	}
	// 用逐个占位符而不是数组参数：驱动是 pgx（database/sql 接口），数组绑定
	// 需要额外类型适配；host 数量是个位数，拼占位符更直白。
	pairs := make([]string, 0, len(hosts))
	args := make([]any, 0, len(hosts))
	for _, h := range hosts {
		host, _ := splitHostPort(h)
		if host == "" {
			continue
		}
		pairs = append(pairs, fmt.Sprintf("(ip = $%d OR domain = $%d)", len(args)+1, len(args)+1))
		args = append(args, host)
	}
	if len(pairs) == 0 {
		return out, nil
	}
	rows, err := tx.Query(`
SELECT id, COALESCE(ip, ''), COALESCE(domain, ''), COALESCE(port, 0)
FROM assets
WHERE `+strings.Join(pairs, " OR "), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var ip, domain string
		var port int
		if err := rows.Scan(&id, &ip, &domain, &port); err != nil {
			return nil, err
		}
		// 把这条资产归到它能匹配的每个 host:port 键上。
		for _, h := range hosts {
			host, wantPort := splitHostPort(h)
			if host == "" || (host != strings.ToLower(ip) && host != strings.ToLower(domain)) {
				continue
			}
			// 端口不同的资产不绑（除非该资产没有端口信息）。
			if port != 0 && wantPort != 0 && port != wantPort {
				continue
			}
			out[h] = append(out[h], id)
		}
	}
	return out, rows.Err()
}

// splitHostPort 把 "host:port" 拆开；无端口时 port=0。
func splitHostPort(h string) (string, int) {
	h = strings.TrimSpace(strings.ToLower(h))
	if h == "" {
		return "", 0
	}
	i := strings.LastIndex(h, ":")
	if i < 0 {
		return h, 0
	}
	host, portStr := h[:i], h[i+1:]
	port := 0
	for _, ch := range portStr {
		if ch < 0 || ch > 9 {
			return h, 0 // IPv6 字面量或异常形态，整体当 host
		}
		port = port*10 + int(ch-0)
	}
	return host, port
}

// deriveIdentityForTx 在事务内完成推导所需的查询，并返回推导结果。
//
// 设计取舍：推导失败（查询报错）时**不能让整条漏洞记录失败**——漏洞本身已经
// 验证过，丢一条真洞比丢一个归并属性糟得多。失败时退回「模型给什么用什么」
// 并在 DedupeKey 里留一个可识别的降级标记，便于事后统计降级比例。
func deriveIdentityForTx(tx *sql.Tx, in RecordFindingInput, prepared []PreparedTrafficEvidence) DerivedIdentity {
	hosts := collectEvidenceHosts(prepared)
	byHost, err := HostAssetLookup(tx, hosts)
	if err != nil {
		// 降级：仍然生成确定性 key（不含资产），资产沿用模型给的。
		classKey := findingClassKey(in.VulnClass, in.Name)
		return DerivedIdentity{
			DedupeKey:        buildDedupeKey(in.TaskID, classKey, hosts, prepared, in.Name),
			AssetIDs:         in.AssetIDs,
			Hosts:            hosts,
			ModelAssetsEmpty: len(in.AssetIDs) == 0,
		}
	}
	return DeriveFindingIdentity(in, prepared, byHost, in.AssetIDs)
}
