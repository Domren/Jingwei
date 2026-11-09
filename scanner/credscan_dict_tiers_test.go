package scanner

import (
	"regexp"
	"strings"
	"testing"
)

// 内置字典现在是分档维护的（core / vendor）。这三条锁住「分档」这一层不能悄悄改变行为：
// 顺序、条数、去重，任何一条变了都会影响「先试出什么」以及报告里的尝试次数。

func TestCredBuiltinDictTiersShape(t *testing.T) {
	info := CredBuiltinDictionaryInfo()
	if info.Profile != "builtin" {
		t.Fatalf("profile = %q", info.Profile)
	}
	if !regexp.MustCompile(`^\d{4}\.\d{2}(\.\d+)?$`).MatchString(info.Version) {
		t.Fatalf("版本号 %q 不是 YYYY.MM 形状；版本是内容版本，界面要靠它说清覆盖到哪", info.Version)
	}
	if len(info.Tiers) != 2 {
		t.Fatalf("tiers = %+v，want core + vendor 两档", info.Tiers)
	}
	sum := 0
	for _, tier := range info.Tiers {
		if tier.Count <= 0 || strings.TrimSpace(tier.Note) == "" {
			t.Fatalf("档 %+v 缺少条数或说明", tier)
		}
		sum += tier.Count
	}
	if sum != info.Total || info.Total != len(credBuiltin.Credentials) {
		t.Fatalf("分档合计 %d / 元信息总数 %d / 实际条目 %d 三者不一致", sum, info.Total, len(credBuiltin.Credentials))
	}
}

// 尝试顺序 = core 全量 → vendor 全量。顺序变了就是行为变了，必须在这里拦住。
func TestCredBuiltinDictTierOrder(t *testing.T) {
	all := credBuiltin.Credentials
	if len(all) != len(credBuiltinCore)+len(credBuiltinVendor) {
		t.Fatalf("合并后条数 %d != core %d + vendor %d", len(all), len(credBuiltinCore), len(credBuiltinVendor))
	}
	for i := range credBuiltinCore {
		if credKey(all[i]) != credKey(credBuiltinCore[i]) {
			t.Fatalf("第 %d 条应是 core 的第 %d 条：%+v vs %+v", i, i, all[i], credBuiltinCore[i])
		}
	}
	for i := range credBuiltinVendor {
		pos := len(credBuiltinCore) + i
		if credKey(all[pos]) != credKey(credBuiltinVendor[i]) {
			t.Fatalf("第 %d 条应是 vendor 的第 %d 条：%+v vs %+v", pos, i, all[pos], credBuiltinVendor[i])
		}
	}
}

// 同一组口令出现两次就是白打一次（预算与尝试次数都会被它吃掉）。
func TestCredBuiltinDictNoDuplicate(t *testing.T) {
	seen := map[string]int{}
	for i, c := range credBuiltin.Credentials {
		key := c.Username + "\x00" + c.Password
		if prev, dup := seen[key]; dup {
			t.Fatalf("第 %d 条与第 %d 条重复：user=%q pw=%q", i+1, prev+1, c.Username, c.Password)
		}
		seen[key] = i
	}
}

// SNMP 的 community 是「纯口令」形态：vendor 档里的 public/private/community 必须无用户名，
// 否则适配器会把用户名当成 community 的一部分发出去，永远命中不了。
func TestCredBuiltinDictSNMPCommunityShape(t *testing.T) {
	for _, want := range []string{"public", "private", "community"} {
		found := false
		for _, c := range credBuiltinVendor {
			if c.Password == want && c.Username == "" {
				found = true
			}
		}
		if !found {
			t.Fatalf("vendor 档缺少纯口令条目 %q", want)
		}
	}
}
