package report

import (
	"strings"
	"testing"
)

// P14：档案外的真实痕迹必须显式出现在报告里，不能静默略过；
// 「没采集」和「采集了但没差异」也必须是两句不同的话。
func TestTraceMatrixMarkdownListsProfileDiff(t *testing.T) {
	out := TraceMatrixMarkdown(TraceMatrixInput{
		Rows: []TraceMatrixRow{{Kind: "cron", Name: "cron 计划任务", Verdict: TraceVerdictCleared}},
		Observed:    []string{"cron: */5 * * * * echo hi"},
		ProfileDiff: []string{"cron: 档案里没写过的 /etc/cron.d/unknown-job"},
	})
	for _, want := range []string{
		"档案外痕迹（动态采集发现，静态档案未覆盖）",
		"/etc/cron.d/unknown-job",
		"必须人工确认",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("报告缺少档案外痕迹 %q：\n%s", want, out)
		}
	}
}

func TestTraceMatrixMarkdownDistinguishesNoScanFromNoDiff(t *testing.T) {
	noScan := TraceMatrixMarkdown(TraceMatrixInput{})
	if !strings.Contains(noScan, "本轮未执行动态痕迹采集") {
		t.Fatalf("没采集时必须明说：\n%s", noScan)
	}
	scanned := TraceMatrixMarkdown(TraceMatrixInput{Observed: []string{"cron: x"}})
	if !strings.Contains(scanned, "动态采集未发现静态档案之外的痕迹") ||
		strings.Contains(scanned, "本轮未执行动态痕迹采集") {
		t.Fatalf("采集过但无差异时不能说成没采集：\n%s", scanned)
	}
}
