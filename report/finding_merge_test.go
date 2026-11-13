package report

import (
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// R18 导出侧归并层的夹具。
//
// 目标是钉住三件事，每件都能反向验证：
//  1. 同一根因换端点 → 合成一条，**取最高严重度**（§4.4 的 #25 high / #28 critical）；
//  2. 链式发现 → 两个主机的资产并集都在结果里（#31 跨端口凭据链）；
//  3. 不同接口族 / 不同主机 → 绝不合并（合并过度比不合并更糟：会丢洞）。

func finding(id int64, class, name, severity, dedupeKey string, assetIDs []int64, at time.Time) *db.DBFinding {
	return &db.DBFinding{
		ID: id, VulnClass: class, Name: name, Severity: severity,
		DedupeKey: dedupeKey, AssetIDs: assetIDs, CreatedAt: at,
	}
}

// 同根因、不同严重度（#25 high 与 #28 critical 的复现）→ 一条、取 critical。
func TestMergeFindingsTakesHighestSeverity(t *testing.T) {
	base := time.Date(2026, 11, 11, 19, 50, 0, 0, time.UTC)
	// 两条 dedupe_key 相同（R18 之后落库层会把它们推到同一个 key）。
	const key = "agent:4:info-disclosure:10.1.1.5:805:/base-api/proxy"
	fs := []*db.DBFinding{
		finding(25, "信息泄露", "MaxKey 代理规则写接口未纳入 Spring Security", "high", key, []int64{7}, base),
		finding(28, "信息泄露", "未认证可写入代理规则并回显数据源", "critical", key, []int64{7, 9}, base.Add(time.Hour)),
	}
	groups := MergeFindingsForDelivery(fs)
	if len(groups) != 1 {
		t.Fatalf("同根因两级证据必须合成一条，实得 %d 组", len(groups))
	}
	g := groups[0]
	if g.Severity != "critical" {
		t.Fatalf("合并后必须取最高严重度 critical，实得 %q", g.Severity)
	}
	if g.Primary.ID != 28 {
		t.Fatalf("代表条目应是最高严重度那条（id=28），实得 %d", g.Primary.ID)
	}
	if !g.Merged() || len(g.Members) != 2 {
		t.Fatalf("应标为已合并且保留 2 条证据，实得 merged=%v members=%d", g.Merged(), len(g.Members))
	}
	// 资产并集：[7] ∪ [7,9] = [7,9]，不能因为「取最高那条」就把 7 丢掉。
	if len(g.AssetIDs) != 2 || g.AssetIDs[0] != 7 || g.AssetIDs[1] != 9 {
		t.Fatalf("资产应为并集 [7 9]，实得 %v", g.AssetIDs)
	}
}

// 链式发现：两个主机的键不同，但 dedupe_key 里两个主机都在 → 同组。
func TestMergeFindingsKeepsChainHostsTogether(t *testing.T) {
	base := time.Date(2026, 11, 11, 21, 39, 0, 0, time.UTC)
	const key = "agent:4:info-disclosure:10.33.237.140:1111,10.33.237.140:8887:/static"
	fs := []*db.DBFinding{
		finding(31, "信息泄露", "跨端口凭据链：配置泄露→瓦片无凭据下载", "high", key, nil, base),
		finding(32, "信息泄露", "跨端口凭据链：配置泄露→瓦片无凭据下载", "high", key, []int64{197, 222}, base.Add(4*time.Minute)),
	}
	groups := MergeFindingsForDelivery(fs)
	if len(groups) != 1 {
		t.Fatalf("同一条链重复上报应合成一条，实得 %d 组", len(groups))
	}
	// #31 的 asset_ids 为空、#32 有两条 —— 合并后必须有两条（这是 R18 的核心症状）。
	if len(groups[0].AssetIDs) != 2 {
		t.Fatalf("合并后应继承非空那条的资产，实得 %v", groups[0].AssetIDs)
	}
}

// 不同接口族绝不合并。这是「合并不能过度」的边界。
func TestMergeFindingsKeepsDifferentFamiliesApart(t *testing.T) {
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	fs := []*db.DBFinding{
		finding(1, "SQL Injection", "字符型注入", "high",
			"agent:4:sqli:10.0.0.5:80:/vul/sqli", []int64{1}, base),
		finding(2, "Reflected XSS", "反射型 XSS", "medium",
			"agent:4:xss:10.0.0.5:80:/vul/xss", []int64{1}, base),
	}
	groups := MergeFindingsForDelivery(fs)
	if len(groups) != 2 {
		t.Fatalf("不同类/不同族必须分开，实得 %d 组", len(groups))
	}
}

// 不同主机绝不合并（同族、同类也不行）。
func TestMergeFindingsKeepsDifferentHostsApart(t *testing.T) {
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	fs := []*db.DBFinding{
		finding(1, "信息泄露", "目录列举", "low", "agent:4:info-disclosure:10.0.0.5:80:/files", nil, base),
		finding(2, "信息泄露", "目录列举", "low", "agent:4:info-disclosure:10.0.0.6:80:/files", nil, base),
	}
	if got := len(MergeFindingsForDelivery(fs)); got != 2 {
		t.Fatalf("不同主机必须分开（同一句标题也一样），实得 %d 组", got)
	}
}

// 存量数据（dedupe_key 为空，61% 是这种）也要能归并：
// 同一句话在同一个任务里出现两次，必须合成一条。
func TestMergeFindingsHandlesLegacyEmptyKey(t *testing.T) {
	base := time.Date(2026, 11, 11, 16, 0, 0, 0, time.UTC)
	fs := []*db.DBFinding{
		finding(19, "未授权访问", "RuoYi 后端 /api/back/* 整族免鉴权", "high", "", []int64{195}, base),
		finding(22, "未授权访问", "RuoYi 后端 /api/back/* 整族免鉴权", "high", "", []int64{226}, base.Add(56*time.Minute)),
	}
	groups := MergeFindingsForDelivery(fs)
	if len(groups) != 1 {
		t.Fatalf("存量空 key 的同名条目也应合成一条，实得 %d 组", len(groups))
	}
	// 两条绑了不同资产 → 合并后两条都在，不能只留代表那条。
	if len(groups[0].AssetIDs) != 2 {
		t.Fatalf("资产应为并集 [195 226]，实得 %v", groups[0].AssetIDs)
	}
}

// 旧格式 dedupe_key（含完整 URL）也要被收敛到同族：
// 这是 #21 / #23 的原始 shape——两个 key 不同，但同主机同族，必须合。
func TestMergeFindingsNormalizesLegacyURLKeys(t *testing.T) {
	base := time.Date(2026, 11, 11, 18, 21, 0, 0, time.UTC)
	k1 := "agent:4:info-disclosure:http://10.1.1.5:6080/arcgis/admin/logs/query?f&filter&filtertype&level&token#GET"
	k2 := "agent:4:info-disclosure:http://10.1.1.5:6080/arcgis/admin/security/tokens?f&token#GET"
	fs := []*db.DBFinding{
		finding(21, "信息泄露", "ArcGIS Server 管理接口整族免鉴权", "high", k1, []int64{5}, base),
		finding(23, "信息泄露", "ArcGIS Server 管理接口整族免鉴权", "high", k2, []int64{5}, base.Add(90*time.Minute)),
	}
	groups := MergeFindingsForDelivery(fs)
	if len(groups) != 1 {
		t.Fatalf("旧格式同族换端点必须合成一条（#21/#23），实得 %d 组", len(groups))
	}
}

// 组间顺序：严重度降序。导出时客户先看最严重的。
func TestMergeFindingsSortsBySeverity(t *testing.T) {
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	fs := []*db.DBFinding{
		finding(1, "信息泄露", "低危 A", "low", "agent:4:info-disclosure:h1:/a", nil, base),
		finding(2, "信息泄露", "严重 B", "critical", "agent:4:info-disclosure:h2:/b", nil, base),
		finding(3, "信息泄露", "中危 C", "medium", "agent:4:info-disclosure:h3:/c", nil, base),
	}
	groups := MergeFindingsForDelivery(fs)
	if len(groups) != 3 {
		t.Fatalf("应 3 组，实得 %d", len(groups))
	}
	want := []string{"critical", "medium", "low"}
	for i, s := range want {
		if groups[i].Severity != s {
			t.Fatalf("第 %d 组应为 %s，实得 %s（顺序 %v）", i, s, groups[i].Severity, []string{groups[0].Severity, groups[1].Severity, groups[2].Severity})
		}
	}
}

func TestMergeFindingsEmptyInput(t *testing.T) {
	if got := MergeFindingsForDelivery(nil); got != nil {
		t.Fatalf("空输入应返回 nil，实得 %v", got)
	}
}
