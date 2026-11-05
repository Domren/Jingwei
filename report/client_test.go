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

// 端口探测类发现没有请求字节，也常常落进修复建议映射的默认分支——这两条在客户
// 报告里都很难看：一个空的 ```http 块像是导出坏了，一句「按标准方案处理」没有信息量。
func TestClientMarkdownPassiveFinding(t *testing.T) {
	fs := []*db.DBFinding{
		{ID: 4, Name: "Redis 服务对外暴露", VulnClass: "exposed-service-redis", Severity: "high",
			Status: "confirmed", Summary: "6379 可从扫描网段直连", AssetIDs: []int64{30},
			HTTPRequest: "", HTTPResponse: "-ERR unknown command 'PING'"},
	}
	md := ClientMarkdown(ClientReportInput{
		Findings: fs, Assets: map[int64]string{30: "10.99.0.10"},
		GeneratedAt: time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC),
	})
	for _, want := range []string{
		"无请求字节：被动读取", // 空请求块要写成一句话，而不是留空
		"绑定到内网或回环地址", // 暴露/未授权访问类要给出具体处置，不能落到兜底文案
		"-ERR unknown command",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("客户报告缺 %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "```http\n\n```") {
		t.Fatalf("报告里出现空的报文代码块:\n%s", md)
	}
}
