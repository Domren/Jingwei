package scanner

import (
	"strings"
	"testing"
)

// E3 B 段：JDK 版本 → JNDI 路线决策。阈值是 JDK 公开默认值，不是「已验证可用」；
// 这里钉死解析与边界，避免以后改阈值时悄悄放宽/收紧。

func TestParseJavaVersion(t *testing.T) {
	cases := []struct {
		raw    string
		major  int
		update int
	}{
		{"1.8.0_392", 8, 392},
		{"1.8.0_191-b12", 8, 191},
		{"1.7.0_80", 7, 80},
		{"8u191", 8, 191},
		{"11.0.21", 11, 0},
		{"17.0.9+9", 17, 0},
		{"17", 17, 0},
		{"21.0.2", 21, 0},
		{`"1.8.0_202"`, 8, 202},
	}
	for _, c := range cases {
		rt := ParseJavaVersion(c.raw)
		if rt.Major != c.major || rt.Update != c.update {
			t.Fatalf("%q → %+v, want major=%d update=%d", c.raw, rt, c.major, c.update)
		}
	}
	if rt := ParseJavaVersion(""); rt.Known() {
		t.Fatalf("empty should be unknown: %+v", rt)
	}
	if rt := ParseJavaVersion("garbage"); rt.Known() {
		t.Fatalf("garbage should be unknown: %+v", rt)
	}
	if got := ParseJavaVersion("1.8.0_392").String(); got != "8(update 392)" {
		t.Fatalf("string = %s", got)
	}
}

func TestPlanJavaChainThresholds(t *testing.T) {
	// 8u191 之前：远程类加载默认开启。
	plan := PlanJavaChain(ParseJavaVersion("1.8.0_181"))
	if plan.Route != JNDIRouteRemoteClass || !plan.AllowRemoteClass || plan.PreferLocalChain {
		t.Fatalf("8u181 plan = %+v", plan)
	}
	if !strings.Contains(plan.Reason, "8u191 之前") {
		t.Fatalf("reason = %s", plan.Reason)
	}

	// 8u191 起：两个开关默认关闭，只走本地链。
	plan = PlanJavaChain(ParseJavaVersion("1.8.0_191"))
	if plan.Route != JNDIRouteLocalGadget || plan.AllowRemoteClass || !plan.PreferLocalChain {
		t.Fatalf("8u191 plan = %+v", plan)
	}
	for _, raw := range []string{"1.8.0_392", "11.0.21", "1.7.0_201", "1.6.0_211"} {
		if p := PlanJavaChain(ParseJavaVersion(raw)); p.AllowRemoteClass {
			t.Fatalf("%s should not allow remote class loading: %+v", raw, p)
		}
	}

	// 只知道 JDK 8 不知道 update：按保守口径走本地链，并要求补版本。
	plan = PlanJavaChain(ParseJavaVersion("1.8.0"))
	if plan.AllowRemoteClass || !strings.Contains(strings.Join(plan.Warnings, "|"), "update") {
		t.Fatalf("1.8.0 plan = %+v", plan)
	}

	// JDK 16+：强封装，只考虑本机 gadget，并提示 --add-opens。
	for _, raw := range []string{"16", "17.0.9", "21.0.2"} {
		p := PlanJavaChain(ParseJavaVersion(raw))
		if p.Route != JNDIRouteLocalOnly || p.AllowRemoteClass {
			t.Fatalf("%s plan = %+v", raw, p)
		}
		if !strings.Contains(strings.Join(p.Warnings, "|"), "--add-opens") {
			t.Fatalf("%s warnings = %v", raw, p.Warnings)
		}
	}

	// 版本未知：不做远程类加载可用的结论。
	p := PlanJavaChain(ParseJavaVersion(""))
	if p.Route != JNDIRouteUnknown || p.AllowRemoteClass {
		t.Fatalf("unknown plan = %+v", p)
	}
	if !strings.Contains(p.Reason, "不") {
		t.Fatalf("reason = %s", p.Reason)
	}
}

func TestOrderJavaChainsPresets(t *testing.T) {
	presets := []JavaChainsPreset{
		{ID: "a", Intent: "outbound-jndi"},
		{ID: "b", Intent: "command-exec"},
		{ID: "c", Intent: "gadget"},
	}
	// 远程类加载可用时保持调用方顺序。
	keep := OrderJavaChainsPresets(PlanJavaChain(ParseJavaVersion("1.8.0_181")), presets)
	if keep[0].ID != "a" || keep[1].ID != "b" || keep[2].ID != "c" {
		t.Fatalf("remote plan should keep order: %v", presetIDs(keep))
	}
	// 本地链优先时 outbound-jndi 排到最后。
	got := OrderJavaChainsPresets(PlanJavaChain(ParseJavaVersion("17.0.9")), presets)
	if got[0].ID != "b" || got[len(got)-1].ID != "a" {
		t.Fatalf("local plan order = %v", presetIDs(got))
	}
	// 不丢预设：排到最后仍是 fallback。
	if len(got) != 3 {
		t.Fatalf("presets dropped: %v", presetIDs(got))
	}
}

func presetIDs(p []JavaChainsPreset) []string {
	out := make([]string, len(p))
	for i := range p {
		out[i] = p[i].ID
	}
	return out
}
