package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// H1：客户交付版——只含已确认项、中英双语标签、按资产分组、CVSS 与报文附录。
func TestClientMarkdown(t *testing.T) {
	cvss := 8.8
	fs := []*db.DBFinding{
		{ID: 1, Name: "SQL 注入", VulnClass: "sqli", Severity: "high", Status: "confirmed",
			Summary: "id 参数可注入", AssetIDs: []int64{10}, CVSS: &cvss,
			HTTPRequest:  "GET /a?id=1 HTTP/1.1\r\nHost: app.corp\r\n\r\n",
			HTTPResponse: "HTTP/1.1 200 OK\r\n\r\nok"},
		{ID: 2, Name: "待确认项", VulnClass: "xss", Severity: "medium", Status: "pending", AssetIDs: []int64{10}},
		{ID: 3, Name: "误报", VulnClass: "xss", Severity: "low", Status: "false_positive", AssetIDs: []int64{20}},
	}
	md := ClientMarkdown(ClientReportInput{
		Findings: fs, Assets: map[int64]string{10: "app.corp", 20: "other.corp"},
		GeneratedAt: time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC),
		ScopeNote:   "授权编号 A-2026-11，有效期至 2026-12-31",
	})
	for _, want := range []string{
		"安全测试报告 / Security Assessment Report",
		"风险概览 / Risk Overview",
		"受影响资产 / Affected asset: app.corp",
		"CVSS v3.1**: 8.8",
		"修复建议 / Remediation",
		"参数化查询",
		"附录：原始报文 / Appendix: Raw Packets",
		"GET /a?id=1 HTTP/1.1",
		"授权编号 A-2026-11",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("客户报告缺 %q", want)
		}
	}
	if strings.Contains(md, "待确认项") || strings.Contains(md, "误报") {
		t.Fatalf("客户报告混入未确认项:\n%s", md)
	}
}
