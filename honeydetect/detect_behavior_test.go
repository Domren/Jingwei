package honeydetect

import (
	"strings"
	"testing"
	"time"
)

// P5 验收：静态漏检的蜜罐样本由行为判据命中；强制复核不影响正常样本判定。

func TestDetectBehaviorCatchesTooPerfectStaticMiss(t *testing.T) {
	// 这段页面没有任何静态签名——普通 Detect 判 clean。
	in := Input{Protocol: "http", Headers: "Server: nginx/1.24.0", Body: "<html><body>Welcome</body></html>"}
	static := Detect(in)
	if static.Verdict != "clean" {
		t.Fatalf("夹具前提：静态应漏检，实际 %s", static.Verdict)
	}

	samples := []TimingSample{
		{Payload: "/api/a", Success: true, Elapsed: 18 * time.Millisecond},
		{Payload: "/api/b", Success: true, Elapsed: 22 * time.Millisecond},
		{Payload: "/api/c", Success: true, Elapsed: 19 * time.Millisecond},
		{Payload: "/api/d", Success: true, Elapsed: 21 * time.Millisecond},
	}
	behavior := DetectBehavior(in, samples...)
	if !behavior.ForceRecheck || behavior.Verdict != "likely_honeypot" {
		t.Fatalf("过度完美应命中并强制复核: %+v", behavior)
	}
	found := false
	for _, sig := range behavior.Signals {
		if sig.Rule == "behavior-too-perfect" {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺 behavior-too-perfect 信号: %+v", behavior.Signals)
	}
	merged := MergeScores(static, behavior)
	if merged.Verdict != "likely_honeypot" || !NeedsRecheck(merged) {
		t.Fatalf("合并后应强制复核: %+v", merged)
	}
}

func TestDetectBehaviorCatchesConstantFast(t *testing.T) {
	in := Input{Body: "<html>Welcome</html>"}
	// 有一次带噪声，避免 too-perfect 也命中，单独验证时间反常判据。
	samples := []TimingSample{
		{Payload: "a", Success: true, Elapsed: 210 * time.Microsecond},
		{Payload: "b", Success: false, Elapsed: 220 * time.Microsecond, Noise: `404 not found`},
		{Payload: "c", Success: true, Elapsed: 205 * time.Microsecond},
	}
	behavior := DetectBehavior(in, samples...)
	if !behavior.ForceRecheck {
		t.Fatalf("时间反常应强制复核: %+v", behavior)
	}
	for _, sig := range behavior.Signals {
		if sig.Rule == "behavior-too-perfect" {
			t.Fatal("有噪声不应命中过度完美")
		}
	}
	foundFast := false
	for _, sig := range behavior.Signals {
		if sig.Rule == "behavior-constant-fast" {
			foundFast = true
		}
	}
	if !foundFast {
		t.Fatalf("缺 behavior-constant-fast 信号: %+v", behavior.Signals)
	}
}

func TestDetectBehaviorNormalServiceStaysClean(t *testing.T) {
	in := Input{Body: "<html>Welcome</html>"}
	samples := []TimingSample{
		{Payload: "a", Success: true, Elapsed: 12 * time.Millisecond},
		{Payload: "b", Success: false, Elapsed: 43 * time.Millisecond, Noise: `500 error`},
		{Payload: "c", Success: true, Elapsed: 31 * time.Millisecond},
	}
	behavior := DetectBehavior(in, samples...)
	if behavior.Verdict != "clean" || behavior.ForceRecheck || len(behavior.Signals) != 0 {
		t.Fatalf("正常服务不应触发行为判据: %+v", behavior)
	}
	merged := MergeScores(Detect(in), behavior)
	if merged.ForceRecheck || merged.Verdict != "clean" {
		t.Fatalf("正常样本合并后不得强制复核: %+v", merged)
	}
}

func TestDetectBehaviorInsufficientSamples(t *testing.T) {
	// 少于 3 个样本不下行为结论，避免把偶发快响应当成蜜罐。
	behavior := DetectBehavior(Input{}, TimingSample{Success: true, Elapsed: 100 * time.Microsecond})
	if behavior.Verdict != "clean" || behavior.ForceRecheck {
		t.Fatalf("样本不足: %+v", behavior)
	}
}

func TestParseTimingSamples(t *testing.T) {
	output := strings.Join([]string{
		"payload=/api/a success=1 elapsed_ms=0.35",
		`payload=/api/b success=true elapsed_ms=0.31 noise="permission denied"`,
		"payload=/api/c success=0 elapsed_ms=42.5",
		"unrelated log line",
	}, "\n")
	got := ParseTimingSamples(output)
	if len(got) != 3 {
		t.Fatalf("解析样本数=%d: %+v", len(got), got)
	}
	if !got[0].Success || got[0].Elapsed != 350*time.Microsecond || got[0].Noise != "" {
		t.Fatalf("样本0: %+v", got[0])
	}
	if got[1].Noise != "permission denied" {
		t.Fatalf("样本1 noise: %+v", got[1])
	}
	if got[2].Success || got[2].Elapsed != 42500*time.Microsecond {
		t.Fatalf("样本2: %+v", got[2])
	}
}
