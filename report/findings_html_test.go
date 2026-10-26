package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestFindingsHTMLPaginatesByTaskAndEmbedsRealPackets(t *testing.T) {
	taskID := int64(7)
	at := time.Date(2026, 10, 24, 10, 0, 0, 0, time.Local)
	req := "POST /vul/sqli/sqli_str.php?id=1 HTTP/1.1\r\nHost: 127.0.0.1:18080\r\n\r\nsearch=1"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>ok</h1>"
	fs := []*db.DBFinding{
		{
			ID: 1, TaskID: &taskID, TaskDescription: "皮卡丘靶场回归",
			Name: "SQL 注入", VulnClass: "sqli", Severity: db.SeverityHigh, Status: db.FindingPending,
			Summary: "参数 id 存在注入", Evidence: "布尔条件差异明显",
			HTTPRequest: req, HTTPResponse: resp,
			CreatedAt: at, Worker: "scan:nuclei", AssetIDs: []int64{11, 12},
		},
		{
			ID: 2, TaskID: &taskID, TaskDescription: "皮卡丘靶场回归",
			Name: "未采集报文的发现", VulnClass: "exposure", Severity: db.SeverityLow, Status: db.FindingPending,
			Summary: "目录可列", CreatedAt: at.Add(time.Minute),
		},
	}

	out := string(FindingsHTML(fs, FindingsHTMLOptions{GeneratedAt: at, ScopeLabel: "筛选结果（2 条）"}))
	for _, want := range []string{
		`<section class="cover">`,
		"page-break-after:always",
		`<section class="toc">`,
		"目录",
		`class="chapter"`,
		`class="finding"`,
		"JW-20261024-100000",
		"共 2 条漏洞发现",
		"POST /vul/sqli/sqli_str.php?id=1 HTTP/1.1",
		"Host: 127.0.0.1:18080",
		"HTTP/1.1 200 OK",
		"未采集到原始报文或协议数据",
		"测试方法与数据说明",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("html report missing %q", want)
		}
	}
}

func TestFindingsHTMLEscapesStoredContent(t *testing.T) {
	fs := []*db.DBFinding{{
		ID: 9, Name: `<script>alert(1)</script>`, VulnClass: "xss", Severity: "high",
		Summary: `<img src=x onerror=alert(1)>`, CreatedAt: time.Now(),
	}}
	out := string(FindingsHTML(fs, FindingsHTMLOptions{}))
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("finding name must be HTML-escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("expected escaped finding name")
	}
}

func TestVerificationStepsCiteCapturedRequestAndResponse(t *testing.T) {
	in := FindingReportInput{
		HTTPRequest:  "GET /admin/?id=1 HTTP/1.1\r\nHost: target.example\r\n\r\n",
		HTTPResponse: "HTTP/1.1 302 Found\r\nContent-Type: text/html\r\n\r\nmoved",
		Extracted:    []string{"admin"},
	}
	steps, rows := verificationSteps(in)
	joined := strings.Join(steps, "\n")
	for _, want := range []string{
		"发送原始请求：`GET /admin/?id=1 HTTP/1.1`",
		"Host: `target.example`",
		"读取响应：`HTTP/1.1 302 Found`",
		"Content-Type: `text/html`",
		"核对验证特征：admin",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("steps missing %q:\n%s", want, joined)
		}
	}
	labels := map[string]string{}
	for _, row := range rows {
		labels[row.Label] = row.Value
	}
	if labels["状态行"] != "HTTP/1.1 302 Found" {
		t.Fatalf("status row = %q", labels["状态行"])
	}
	if labels["请求目标"] != "/admin/?id=1" {
		t.Fatalf("target row = %q", labels["请求目标"])
	}
}

func TestVerificationStepsWithoutPacketsFallBackToEvidence(t *testing.T) {
	steps, _ := verificationSteps(FindingReportInput{
		MatchedAt: "http://host.example:8080/app",
		Evidence:  "匹配地址: http://host.example:8080/app\n命中特征: <title>admin</title>",
	})
	joined := strings.Join(steps, "\n")
	if !strings.Contains(joined, "未采集到原始报文或协议数据") {
		t.Fatalf("expected explicit no-packet fallback:\n%s", joined)
	}
	if strings.Contains(joined, "发送原始请求") {
		t.Fatalf("must not invent a replay step without packets:\n%s", joined)
	}
	rawSteps, _ := verificationSteps(FindingReportInput{
		Type:      "tcp",
		MatchedAt: "redis://host.example:6379",
		Evidence:  "匹配地址: redis://host.example:6379",
	})
	if strings.Contains(strings.Join(rawSteps, "\n"), "原始 HTTP 报文") {
		t.Fatalf("raw protocol fallback must not mention HTTP packets:\n%s", strings.Join(rawSteps, "\n"))
	}
}
