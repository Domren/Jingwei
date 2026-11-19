package scanner

// P11：无 sidecar 时用内置最小探测判断依赖存在性，不生成 payload，不复用笼统「待复核」。

import "testing"

func TestProbeJavaChainDependency_PresentAndUnverified(t *testing.T) {
	// 有依赖：fastjson 家族 + 证据里出现 com.alibaba.fastjson 特征串。
	got := ProbeJavaChainDependency("fastjson", "POST / HTTP/1.1\n\n{\"@type\":\"com.alibaba.fastjson.JSON\"}")
	if got.Status != JavaChainDependencyPresent {
		t.Fatalf("应判依赖存在，得到 %s", got.Status)
	}
	if got.Signal == "" {
		t.Fatal("命中依赖存在时应记录特征串")
	}
	if !containsText(got.Note, "依赖存在") || !containsText(got.Note, "链未验证") {
		t.Fatalf("结论应同时说明依赖存在与链未验证：%q", got.Note)
	}

	// 无依赖：同样识别到 fastjson 链，但证据里没有任何依赖特征串 → 链未验证。
	got = ProbeJavaChainDependency("fastjson", "generic request body without library markers")
	if got.Status != JavaChainChainUnverified {
		t.Fatalf("应判链未验证，得到 %s", got.Status)
	}
	if containsText(got.Note, "待复核") {
		t.Fatalf("不应使用笼统的待复核：%q", got.Note)
	}
	if !containsText(got.Note, "链未验证") {
		t.Fatalf("应明确链未验证：%q", got.Note)
	}
}

func TestProbeJavaChainDependency_NoChain(t *testing.T) {
	// family 为空来自 JavaDeserializationKeyword：目标无该链，与「没装 sidecar」不同。
	got := ProbeJavaChainDependency("", "some non-java POC content")
	if got.Status != JavaChainNoChain {
		t.Fatalf("应判目标无该链，得到 %s", got.Status)
	}
	if !containsText(got.Note, "目标无该链") {
		t.Fatalf("应明确目标无该链：%q", got.Note)
	}
}

func TestProbeJavaChainDependency_NoPayloadGenerated(t *testing.T) {
	// 最小探测只做特征串存在性判断，不得在证据里生成/拼装 payload 标记。
	evidence := "benign evidence"
	got := ProbeJavaChainDependency("java deserialization", evidence)
	if got.Signal != "" {
		t.Fatalf("未命中依赖时不应有特征串，得到 %q", got.Signal)
	}
	if containsText(got.Note, "payload") && !containsText(got.Note, "不生成") {
		t.Fatalf("探测结论不应暗示生成了 payload：%q", got.Note)
	}
}

func TestJavaDeserializationKeywordReused(t *testing.T) {
	// 家族识别复用既有函数：探测流程不另起一套判断。
	fam := JavaDeserializationKeyword("fastjson-rce", "", []string{"fastjson"}, "body")
	if fam != "fastjson" {
		t.Fatalf("JavaDeserializationKeyword 应识别 fastjson，得到 %q", fam)
	}
	probe := ProbeJavaChainDependency(fam, "com.alibaba.fastjson")
	if probe.Family != "fastjson" || probe.Status != JavaChainDependencyPresent {
		t.Fatalf("复用家族识别后的探测应判依赖存在：%+v", probe)
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
