package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

// C5：两轮扫描的增量。重点是「消失」的原因：目标不可达不能算已修复。
func TestComputeScanDiff(t *testing.T) {
	base := []db.ScanTaskResult{
		{TemplateID: "t-sqli", Host: "10.0.0.1", MatchedAt: "http://10.0.0.1/a?id=1", Name: "SQLi", Severity: "high"},
		{TemplateID: "t-xss", Host: "10.0.0.1", MatchedAt: "http://10.0.0.1/b", Name: "XSS", Severity: "medium"},
		{TemplateID: "t-lfi", Host: "10.0.0.2", MatchedAt: "http://10.0.0.2/c", Name: "LFI", Severity: "high"},
		{TemplateID: "t-ssrf", Host: "10.0.0.3", MatchedAt: "http://10.0.0.3/d", Name: "SSRF", Severity: "low"},
	}
	current := []db.ScanTaskResult{
		{TemplateID: "t-sqli", Host: "10.0.0.1", MatchedAt: "http://10.0.0.1/a?id=1", Name: "SQLi", Severity: "critical"}, // 等级变化
		{TemplateID: "t-rce", Host: "10.0.0.1", MatchedAt: "http://10.0.0.1/e", Name: "RCE", Severity: "critical"},        // 新增
		{TemplateID: "t-lfi", Host: "10.0.0.2", MatchedAt: "http://10.0.0.2/c", Name: "LFI", Severity: "high"},            // 仍在
	}
	reachable := map[string]bool{"10.0.0.1": true, "10.0.0.2": true} // 10.0.0.3 本轮没出现
	diff := computeScanDiff(current, base, reachable)

	if len(diff.New) != 1 || diff.New[0].TemplateID != "t-rce" {
		t.Fatalf("new = %+v", diff.New)
	}
	if len(diff.SeverityChanged) != 1 || diff.SeverityChanged[0].OldSeverity != "high" ||
		diff.SeverityChanged[0].NewSeverity != "critical" {
		t.Fatalf("sev = %+v", diff.SeverityChanged)
	}
	// t-xss 的 host 本轮可达 → 已修复；t-ssrf 的 host 没出现 → 不可达。
	if len(diff.Gone) != 2 {
		t.Fatalf("gone = %+v", diff.Gone)
	}
	reasons := map[string]string{}
	for _, g := range diff.Gone {
		reasons[g.TemplateID] = g.Reason
	}
	if !strings.Contains(reasons["t-xss"], "已修复") {
		t.Fatalf("t-xss reason = %q", reasons["t-xss"])
	}
	if !strings.Contains(reasons["t-ssrf"], "不可达") {
		t.Fatalf("t-ssrf reason = %q", reasons["t-ssrf"])
	}
}

// 本轮完全没有结果时不能把「消失」解释成已修复。
func TestComputeScanDiffEmptyCurrent(t *testing.T) {
	base := []db.ScanTaskResult{{TemplateID: "t", Host: "10.0.0.9", MatchedAt: "http://x/", Name: "x", Severity: "high"}}
	diff := computeScanDiff(nil, base, nil)
	if len(diff.Gone) != 1 || !strings.Contains(diff.Gone[0].Reason, "无法区分") {
		t.Fatalf("gone = %+v", diff.Gone)
	}
}
