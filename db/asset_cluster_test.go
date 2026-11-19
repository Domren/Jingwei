package db

import (
	"testing"
	"time"
)

// P3 验收：10 域名指向 2 套系统 → 归并 2 族且原始条目可展开；
// 与 dedupe_key 口径兼容；镜像站不当独立目标重复打；域名/IP 变更有timeline。

func tenDomainsTwoSystems() []ClusterableAsset {
	out := make([]ClusterableAsset, 0, 10)
	for i := 1; i <= 5; i++ {
		out = append(out, ClusterableAsset{
			ID: int64(i), URL: "https://site" + itoa64(int64(i)) + "-a.example.com",
			Domain:          "site" + itoa64(int64(i)) + "-a.example.com",
			CertFingerprint: "CERT-SYSTEM-A", FaviconMMH3: "fav-a",
			DedupeKey: "agent:12:SQLi:site" + itoa64(int64(i)) + "-a.example.com:/api/admin",
		})
	}
	for i := 6; i <= 10; i++ {
		out = append(out, ClusterableAsset{
			ID: int64(i), URL: "https://site" + itoa64(int64(i)) + "-b.example.org",
			Domain:         "site" + itoa64(int64(i)) + "-b.example.org",
			PageStructHash: "PAGE-SYSTEM-B", FaviconMMH3: "fav-b",
			DedupeKey: "agent:13:SQLi:site" + itoa64(int64(i)) + "-b.example.org:/web/home",
		})
	}
	return out
}

func TestClusterAssetsMergeTenDomainsIntoTwoFamilies(t *testing.T) {
	clusters := ClusterAssets(tenDomainsTwoSystems())
	if len(clusters) != 2 {
		t.Fatalf("10 域名应归并 2 族，得到 %d 族: %+v", len(clusters), clusters)
	}
	byKey := map[string]AssetCluster{}
	for _, c := range clusters {
		byKey[c.Key] = c
		if len(c.Members) != 5 {
			t.Fatalf("族 %s 应有 5 原始条目，得到 %d", c.Key, len(c.Members))
		}
	}
	if _, ok := byKey["cert:cert-system-a"]; !ok {
		t.Fatalf("缺 A 系统证书族: %+v", byKey)
	}
	if _, ok := byKey["page:page-system-b"]; !ok {
		t.Fatalf("缺 B 系统页面结构族: %+v", byKey)
	}
	// 原始条目可展开。
	if got := ExpandClusterMembers(clusters, "cert:cert-system-a"); len(got) != 5 {
		t.Fatalf("展开 A 族得到 %d 条", len(got))
	}
	if got := ExpandClusterMembers(clusters, "page:page-system-b"); len(got) != 5 {
		t.Fatalf("展开 B 族得到 %d 条", len(got))
	}
}

func TestClusterMirrorsNotIndependentTargets(t *testing.T) {
	clusters := ClusterAssets(tenDomainsTwoSystems())
	for _, c := range clusters {
		if c.IndependentTargets() != 1 {
			t.Fatalf("族 %s 独立目标数=%d，镜像站不该重复打", c.Key, c.IndependentTargets())
		}
		canon, ok := c.Canonical()
		if !ok {
			t.Fatalf("族 %s 无 canonical", c.Key)
		}
		for _, m := range c.Members {
			if m.ID == canon.ID {
				continue
			}
			if !c.IsMirror(m) {
				t.Fatalf("族 %s 的 %s 未标为镜像", c.Key, m.URL)
			}
		}
	}
}

func TestDedupeFamilyCompatibility(t *testing.T) {
	// dedupe_key 里 host 段含冒号（host:port），族必须取最后一段而不是从左切。
	key := "agent:12:SQLi:a.example.com:443,b.example.com:80:/api/admin"
	if got := DedupeFamily(key); got != "/api/admin" {
		t.Fatalf("DedupeFamily = %q", got)
	}
	a := ClusterableAsset{ID: 1, Domain: "a.example.com", DedupeKey: key}
	b := ClusterableAsset{ID: 2, Domain: "b.example.org",
		// buildDedupeKey 会把 /api/admin/logs/query 等收敛到 /api/admin 族
		DedupeKey: "agent:13:SQLi:c.example.org:/api/admin"}
	if ClusterKeyFor(a) != "family:/api/admin" || ClusterKeyFor(b) != "family:/api/admin" {
		t.Fatalf("dedupe 族聚类不一致: %q / %q", ClusterKeyFor(a), ClusterKeyFor(b))
	}
	clusters := ClusterAssets([]ClusterableAsset{a, b})
	if len(clusters) != 1 || len(clusters[0].Members) != 2 {
		t.Fatalf("同族换主机应归并: %+v", clusters)
	}
}

func TestClusterKeyPriority(t *testing.T) {
	a := ClusterableAsset{ID: 1, CertFingerprint: "CERT1", PageStructHash: "PAGE1", FaviconMMH3: "F1", DedupeKey: "agent:1:X:h:/api"}
	if got := ClusterKeyFor(a); got != "cert:cert1" {
		t.Fatalf("证书优先级最高: %q", got)
	}
	a.CertFingerprint = ""
	if got := ClusterKeyFor(a); got != "page:page1" {
		t.Fatalf("页面结构次之: %q", got)
	}
	a.PageStructHash = ""
	if got := ClusterKeyFor(a); got != "favicon:f1" {
		t.Fatalf("favicon 再次: %q", got)
	}
}

func TestBuildDomainTimeline(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(48 * time.Hour)
	timeline := BuildDomainTimeline([]DNSResolutionEvent{
		{Domain: "b.example", IP: "3.3.3.3", At: t0},
		{Domain: "a.example", IP: "1.1.1.1", At: t0},
		{Domain: "a.example", IP: "1.1.1.1", At: t0.Add(time.Hour)}, // 重复观测不新增
		{Domain: "a.example", IP: "2.2.2.2", At: t1},
	})
	if len(timeline) != 3 {
		t.Fatalf("timeline 条目数=%d: %+v", len(timeline), timeline)
	}
	if timeline[0].Domain != "a.example" || timeline[0].IP != "1.1.1.1" {
		t.Fatalf("第一段: %+v", timeline[0])
	}
	if timeline[0].Until == nil || !timeline[0].Until.Equal(t1) {
		t.Fatalf("IP 变更应闭合上一段: %+v", timeline[0])
	}
	if timeline[1].IP != "2.2.2.2" || timeline[1].Until != nil {
		t.Fatalf("第二段: %+v", timeline[1])
	}
	if timeline[2].Domain != "b.example" {
		t.Fatalf("第三段: %+v", timeline[2])
	}
}
