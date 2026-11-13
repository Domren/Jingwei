package server

import (
	"strings"
	"testing"

	pgdb "github.com/Autumn-27/jingwei/db"
)

// R19 序 5：ip_port 严格粒度的授权对判定（纯函数，不连库）。
// 反向验证锚点：10.0.0.5:35888 正是 11-11 实机越权端口的那类泄漏——把
// targetPairViolation 的端口匹配删掉，本用例立即失败。

func TestBuildTargetPairSetNormalizes(t *testing.T) {
	set := buildTargetPairSet([]pgdb.TaskTargetPair{
		{Host: "1.2.3.4.", Port: 8080},
		{Host: "Example.com", Port: 443},
		{Host: "", Port: 80},
		{Host: "bad", Port: 0},
	})
	if len(set) != 2 {
		t.Fatalf("want 2 hosts, got %d (%+v)", len(set), set)
	}
	if len(set["1.2.3.4"]) != 1 || set["1.2.3.4"][0] != 8080 {
		t.Fatalf("ip pair lost: %+v", set["1.2.3.4"])
	}
	if len(set["example.com"]) != 1 || set["example.com"][0] != 443 {
		t.Fatalf("domain pair lost: %+v", set["example.com"])
	}
}

func TestTargetPairViolationIPPortStrict(t *testing.T) {
	set := buildTargetPairSet([]pgdb.TaskTargetPair{
		{Host: "1.2.3.4", Port: 8080},
		{Host: "10.0.0.5", Port: 80},
		{Host: "10.0.0.5", Port: 443},
	})
	// 登记对内：合规
	if v := targetPairViolation("1.2.3.4:8080", set); v != "" {
		t.Fatalf("listed pair must pass, got %q", v)
	}
	if v := targetPairViolation("10.0.0.5:443", set); v != "" {
		t.Fatalf("listed pair must pass, got %q", v)
	}
	// 未登记端口 → 违规（R19 原始泄漏形态）
	if v := targetPairViolation("10.0.0.5:35888", set); v == "" {
		t.Fatal("unlisted port must violate")
	}
	// 未登记主机 → 违规
	if v := targetPairViolation("6.6.6.6:80", set); v == "" {
		t.Fatal("unlisted host must violate")
	}
	// 裸主机（无端口探测，如 ICMP/裸主机名）在清单里 → 合规；不在 → 违规
	if v := targetPairViolation("1.2.3.4", set); v != "" {
		t.Fatalf("bare host of a listed pair passes port-free probes, got %q", v)
	}
	if v := targetPairViolation("7.7.7.7", set); v == "" {
		t.Fatal("bare host not in list must violate")
	}
	// 大小写/尾点归一
	if v := targetPairViolation("1.2.3.4.:8080", set); v != "" {
		t.Fatalf("normalization failed, got %q", v)
	}
}

// 拒绝原因必须点名登记对——操作员要能直接看到「授权的到底是什么」。
func TestTargetPairSummaryReadable(t *testing.T) {
	set := buildTargetPairSet([]pgdb.TaskTargetPair{
		{Host: "1.2.3.4", Port: 8080},
		{Host: "1.2.3.4", Port: 443},
	})
	s := targetPairSummary(set)
	for _, want := range []string{"1.2.3.4:443", "1.2.3.4:8080"} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary must list %s, got %q", want, s)
		}
	}
}
