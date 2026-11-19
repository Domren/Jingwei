package server

// P11：无 sidecar 的最小探测结论落在结构化 summary 字段，区分「依赖存在/链未验证」
// 与「目标无该链」，全程不访问 sidecar、不生成 payload。纯函数测试，不依赖 DB。

import (
	"testing"

	"github.com/Domren/jingwei/db"
	"github.com/Domren/jingwei/scanner"
)

func TestJavaChainsProbeSummary_DependencyPresent(t *testing.T) {
	candidates := []javaChainCandidate{{
		tpl:    db.POCTemplate{TemplateID: "fastjson-rce", Content: "{\"@type\":\"com.alibaba.fastjson.JSON\"}"},
		family: "fastjson",
	}}
	summary := javaChainsProbeSummary(candidates)

	if summary["java_chains_no_sidecar"] != true {
		t.Fatal("应明确标记没装 sidecar")
	}
	if summary["java_chains_probe_status"] != string(scanner.JavaChainChainUnverified) {
		t.Fatalf("无 sidecar 时链应未验证，得到 %v", summary["java_chains_probe_status"])
	}
	probes, ok := summary["java_chains_probe"].([]map[string]any)
	if !ok || len(probes) != 1 {
		t.Fatalf("应产出结构化探测结果：%#v", summary["java_chains_probe"])
	}
	if probes[0]["status"] != string(scanner.JavaChainDependencyPresent) {
		t.Fatalf("有依赖特征串应判依赖存在，得到 %v", probes[0]["status"])
	}
	if note, _ := probes[0]["note"].(string); note == "" || containsText(note, "待复核") {
		t.Fatalf("结论不应笼统待复核：%q", note)
	}
	counts, _ := summary["java_chains_probe_counts"].(map[string]int)
	if counts[string(scanner.JavaChainDependencyPresent)] != 1 {
		t.Fatalf("依赖存在计数应为 1：%#v", counts)
	}
}

func TestJavaChainsProbeSummary_NoDependencyStillUnverified(t *testing.T) {
	candidates := []javaChainCandidate{{
		tpl:    db.POCTemplate{TemplateID: "fastjson-rce", Content: "plain body, no library marker"},
		family: "fastjson",
	}}
	summary := javaChainsProbeSummary(candidates)
	probes, _ := summary["java_chains_probe"].([]map[string]any)
	if len(probes) != 1 || probes[0]["status"] != string(scanner.JavaChainChainUnverified) {
		t.Fatalf("无依赖特征串应判链未验证：%#v", probes)
	}
	// 不能把「链未验证」误写成「目标无该链」。
	if summary["java_chains_probe_status"] == string(scanner.JavaChainNoChain) {
		t.Fatal("识别到链但无特征串时不应判目标无该链")
	}
}

func TestJavaChainsProbeSummary_NoSidecarVsNoChain(t *testing.T) {
	// 没装 sidecar：有候选，结论是链未验证 + 依赖存在性标注。
	withCandidates := javaChainsProbeSummary([]javaChainCandidate{{
		tpl: db.POCTemplate{TemplateID: "shiro-rce", Content: "org.apache.shiro"}, family: "shiro",
	}})
	if withCandidates["java_chains_probe_status"] != string(scanner.JavaChainChainUnverified) {
		t.Fatalf("没装 sidecar 应有链未验证结论：%v", withCandidates["java_chains_probe_status"])
	}

	// 目标无该链：family 为空的候选在探测器里直接判 no_java_chain。
	noChain := scanner.ProbeJavaChainDependency("", "not java")
	if noChain.Status != scanner.JavaChainNoChain {
		t.Fatalf("目标无该链应判 no_java_chain：%s", noChain.Status)
	}

	// 两者必须不同，且都不是笼统「待复核」。
	if withCandidates["java_chains_probe_status"] == string(noChain.Status) {
		t.Fatal("没装 sidecar 与目标无该链必须区分")
	}
	for k, v := range withCandidates {
		if s, ok := v.(string); ok && s == "待复核" {
			t.Fatalf("%s 不应是笼统待复核", k)
		}
	}
}

func containsText(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
