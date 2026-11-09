package scanner

import (
	"strings"
	"testing"
)

// 内存马自动选型：探测结果 → 类型。E3 要交付的是「不再需要人工选档位」，
// 同时保留人工显式指定；错配必须点名目标环境，不许盲选。

func TestParseMemshellProbe(t *testing.T) {
	p := ParseMemshellProbe(map[string]string{
		"container":    " Tomcat ",
		"servlet_api":  "Javax",
		"java_version": "1.8.0_392",
		"types":        "agent, filter ,servlet",
	})
	if p.Container != "tomcat" || p.ServletAPI != "javax" || p.JavaVersion != "1.8.0_392" {
		t.Fatalf("probe = %+v", p)
	}
	if len(p.Available) != 3 || !p.Has("filter") || !p.Has("agent") || p.Has("valve") {
		t.Fatalf("available = %v", p.Available)
	}
	if got := p.Describe(); !strings.Contains(got, "container=tomcat") || !strings.Contains(got, "java=1.8.0_392") {
		t.Fatalf("describe = %s", got)
	}
	// 字段缺失时不猜。
	empty := ParseMemshellProbe(map[string]string{})
	if empty.Container != "" || len(empty.Available) != 0 {
		t.Fatalf("empty probe = %+v", empty)
	}
	if !strings.Contains(empty.Describe(), "unknown") {
		t.Fatalf("empty describe = %s", empty.Describe())
	}
}

func TestSelectMemshellTypeAutoPreference(t *testing.T) {
	// Tomcat 有全部映射型时按 filter→servlet→listener→valve 取第一个。
	full := MemshellProbe{Container: "tomcat", ServletAPI: "javax", JavaVersion: "17.0.9",
		Available: []string{"agent", "valve", "listener", "servlet", "filter"}}
	sel, err := SelectMemshellType(full, "")
	if err != nil {
		t.Fatal(err)
	}
	if !sel.Auto || sel.Type != MemshellTypeFilter {
		t.Fatalf("sel = %+v", sel)
	}
	if !strings.Contains(sel.Reason, "自动选型") || !strings.Contains(sel.Reason, "java=17.0.9") {
		t.Fatalf("reason = %s", sel.Reason)
	}

	// 缺 filter 时落到 servlet，而不是直接跳 agent。
	noFilter := MemshellProbe{Container: "tomcat", Available: []string{"agent", "servlet", "valve"}}
	if sel, err := SelectMemshellType(noFilter, ""); err != nil || sel.Type != MemshellTypeServlet {
		t.Fatalf("no-filter sel = %+v err=%v", sel, err)
	}

	// 只有 agent 可用时回退 agent。
	onlyAgent := MemshellProbe{Container: "tomcat", Available: []string{"agent"}}
	sel, err = SelectMemshellType(onlyAgent, "")
	if err != nil || sel.Type != MemshellTypeAgent || !sel.Auto {
		t.Fatalf("only-agent sel = %+v err=%v", sel, err)
	}
	if !strings.Contains(sel.Reason, "回退 agent") {
		t.Fatalf("reason = %s", sel.Reason)
	}
}

func TestSelectMemshellTypeNonTomcat(t *testing.T) {
	// 非 Tomcat 容器不能映射，只能 agent。
	other := MemshellProbe{Container: "jetty", Available: []string{"agent"}}
	sel, err := SelectMemshellType(other, "")
	if err != nil || sel.Type != MemshellTypeAgent {
		t.Fatalf("sel = %+v err=%v", sel, err)
	}
	if !strings.Contains(sel.Reason, "不支持容器映射") {
		t.Fatalf("reason = %s", sel.Reason)
	}

	// 非 Tomcat 又没有 agent 可用 —— 明确失败，不盲选。
	if _, err := SelectMemshellType(MemshellProbe{Container: "jetty", Available: []string{"filter"}}, ""); err == nil {
		t.Fatal("expected failure when nothing is installable")
	}

	// 探测没报任何类型：拒绝盲选，并把探测结果带出来。
	_, err = SelectMemshellType(MemshellProbe{Container: "tomcat"}, "")
	if err == nil || !strings.Contains(err.Error(), "未报告任何可用") {
		t.Fatalf("err = %v", err)
	}
}

func TestSelectMemshellTypeExplicit(t *testing.T) {
	p := MemshellProbe{Container: "tomcat", ServletAPI: "jakarta", JavaVersion: "11.0.21",
		Available: []string{"agent", "filter", "servlet"}}

	// 显式指定仍优先生效，且标 auto=false（保留人工覆盖）。
	sel, err := SelectMemshellType(p, "Servlet")
	if err != nil {
		t.Fatal(err)
	}
	if sel.Auto || sel.Type != MemshellTypeServlet {
		t.Fatalf("sel = %+v", sel)
	}

	// 显式选了目标不支持的型 —— 点名可用集合。
	_, err = SelectMemshellType(p, "valve")
	if err == nil || !strings.Contains(err.Error(), "不支持 valve") || !strings.Contains(err.Error(), "agent,filter,servlet") {
		t.Fatalf("err = %v", err)
	}

	// 非 Tomcat 却显式选映射型 —— 明确拒绝并带出探测环境。
	_, err = SelectMemshellType(MemshellProbe{Container: "other", Available: []string{"agent"}}, "filter")
	if err == nil || !strings.Contains(err.Error(), "不是 Tomcat") || !strings.Contains(err.Error(), "container=other") {
		t.Fatalf("err = %v", err)
	}

	// 非法型名。
	if _, err := SelectMemshellType(p, "memshell"); err == nil {
		t.Fatal("expected invalid type error")
	}
}
