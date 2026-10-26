package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestBuildFindingReportEmbedsRawHTTPAndParamSources(t *testing.T) {
	request := strings.Join([]string{
		"POST /vul/sqli/sqli_str.php?id=1&name=test HTTP/1.1",
		"Host: 127.0.0.1:18080",
		"Content-Type: application/x-www-form-urlencoded",
		"Cookie: PHPSESSID=abc123",
		"Authorization: Bearer demo-token",
		"",
		"search=hello&submit=submit",
	}, "\r\n")
	response := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>ok</h1>"

	out := BuildFindingReport(FindingReportInput{
		FindingID:    42,
		Name:         "SQL 注入",
		VulnClass:    "sqli",
		Severity:     db.SeverityHigh,
		Status:       db.FindingPending,
		Summary:      "参数 id 存在 SQL 注入",
		Evidence:     "布尔条件差异明显",
		Source:       "自动化漏扫任务 #7（nuclei 模板 sqli）",
		TemplateID:   "sqli",
		MatchedAt:    "http://127.0.0.1:18080/vul/sqli/sqli_str.php",
		HTTPRequest:  request,
		HTTPResponse: response,
		GeneratedAt:  time.Date(2026, 10, 23, 12, 0, 0, 0, time.Local),
	})

	for _, want := range []string{
		db.AutoReportMarker,
		autoReportTemplateMarker,
		"## 概述",
		"## 影响与危害",
		"## 受影响范围",
		"## 复现与验证步骤",
		"发送原始请求：`POST /vul/sqli/sqli_str.php?id=1&name=test HTTP/1.1`",
		"读取响应：`HTTP/1.1 200 OK`",
		"## 验证数据",
		"| 响应摘要 |",
		"## 证据",
		"## PoC",
		"### HTTP 请求报文",
		"### HTTP 响应报文",
		"POST /vul/sqli/sqli_str.php?id=1&name=test HTTP/1.1",
		"search=hello&submit=submit",
		"HTTP/1.1 200 OK",
		"## 参数与数据来源",
		"| `id` | URL 查询参数 |",
		"| `search` | 表单正文 |",
		"| `PHPSESSID` | Cookie |",
		"| `authorization` | 请求头 |",
		"## 根因分析",
		"## 修复建议",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "curl") {
		t.Fatalf("report must not fall back to curl commands:\n%s", out)
	}
}

// PoC 章节只放原始报文（请求行/头/空行/正文 + 状态行/头/空行/正文），
// 扫描器附带的 curl 复现命令不再进入报告。
func TestBuildFindingReportPoCHoldsRawPacketsNotCurl(t *testing.T) {
	request := strings.Join([]string{
		"POST /nacos/v1/auth/users HTTP/1.1",
		"Host: target.example",
		"serverIdentity: security",
		"Content-Type: application/x-www-form-urlencoded",
		"Content-Length: 27",
		"",
		"password=test&username=test",
	}, "\r\n")
	response := strings.Join([]string{
		"HTTP/1.1 200",
		"Server: nginx/1.29.0",
		"Content-Type: application/json",
		"Content-Length: 52",
		"",
		`{"code":200,"message":null,"data":"create user ok!"}`,
	}, "\r\n")

	out := BuildFindingReport(FindingReportInput{
		FindingID:    88,
		Name:         "Nacos 默认凭据后台创建用户",
		VulnClass:    "default-password",
		Severity:     db.SeverityCritical,
		Evidence:     "模板: Nacos (nacos-default-admin)\n复现命令:\ncurl -X 'POST' -d 'username=test' 'http://target.example/nacos/v1/auth/users'\n\n原始 HTTP 请求/响应报文已保存，见漏洞详情的「证据 / PoC」与详细报告。",
		Curl:         "curl -X 'POST' -d 'username=test' 'http://target.example/nacos/v1/auth/users'",
		HTTPRequest:  request,
		HTTPResponse: response,
	})

	poc := out[strings.Index(out, "## PoC"):strings.Index(out, "## 参数与数据来源")]
	for _, want := range []string{
		"POST /nacos/v1/auth/users HTTP/1.1",
		"serverIdentity: security",
		"Content-Length: 27",
		"password=test&username=test",
		"HTTP/1.1 200",
		"Server: nginx/1.29.0",
		`{"code":200,"message":null,"data":"create user ok!"}`,
	} {
		if !strings.Contains(poc, want) {
			t.Fatalf("PoC missing %q:\n%s", want, poc)
		}
	}
	if strings.Contains(out, "curl") || strings.Contains(out, "复现命令") {
		t.Fatalf("report must not contain curl/复现命令:\n%s", out)
	}
	if !strings.Contains(out, "| `password` | 表单正文 | `test` |") || !strings.Contains(out, "| `username` | 表单正文 | `test` |") {
		t.Fatalf("form parameter table missing:\n%s", out)
	}
}

// 旧版本模板生成的自动报告在读取时按新模板重建，人工/LLM 报告保持原样。
func TestCompleteFindingReportRebuildsOlderAutoTemplate(t *testing.T) {
	f := &db.DBFinding{
		ID:                    8,
		Name:                  "命令执行",
		VulnClass:             "rce",
		Severity:              db.SeverityCritical,
		EvidenceVersion:       3,
		ReportEvidenceVersion: 3,
		Report:                db.AutoReportMarker + "\n# 旧模板报告\n\n### 复现命令\n\n```bash\ncurl 'http://lab/cmd'\n```",
	}
	if got := CompleteFindingReport(f); !strings.Contains(got, autoReportTemplateMarker) || strings.Contains(got, "旧模板报告") {
		t.Fatalf("stale template report should be rebuilt:\n%s", got)
	}

	f.Report = "# 人工报告\n\n已复现。"
	f.ReportEvidenceVersion = f.EvidenceVersion
	if got := CompleteFindingReport(f); !strings.Contains(got, "# 人工报告") || strings.Contains(got, autoReportTemplateMarker) {
		t.Fatalf("human report must be left alone:\n%s", got)
	}
}

// 命令注入/SQL 载荷常带 `;`，url.ParseQuery 会拒绝整段查询，参数表因此变空。
func TestBuildFindingReportParsesPayloadSeparators(t *testing.T) {
	request := strings.Join([]string{
		"POST /vul/rce/rce_ping.php?ip=127.0.0.1;id HTTP/1.1",
		"Host: pikachu-lab",
		"Content-Type: application/x-www-form-urlencoded",
		"",
		"ipaddress=127.0.0.1%3Bid&submit=ping",
	}, "\r\n")

	out := BuildFindingReport(FindingReportInput{
		FindingID:    7,
		Name:         "命令注入",
		VulnClass:    "rce",
		Severity:     db.SeverityCritical,
		HTTPRequest:  request,
		HTTPResponse: "HTTP/1.1 200 OK\r\n\r\nuid=0",
	})
	for _, want := range []string{"| `ip` | URL 查询参数 | `127.0.0.1;id` |", "| `ipaddress` | 表单正文 | `127.0.0.1;id` |", "| `submit` | 表单正文 | `ping` |"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}

func TestCompleteFindingReportFallsBackAndAppendsHTTP(t *testing.T) {
	f := &db.DBFinding{
		ID:           7,
		Name:         "命令执行",
		VulnClass:    "rce",
		Severity:     db.SeverityCritical,
		Status:       db.FindingConfirmed,
		Summary:      "命令回显已确认",
		Evidence:     "uid=33(www-data)",
		HTTPRequest:  "GET /cmd?ip=127.0.0.1;id HTTP/1.1\r\nHost: lab\r\n\r\n",
		HTTPResponse: "HTTP/1.1 200 OK\r\n\r\nuid=33(www-data)",
		CreatedAt:    time.Now(),
	}
	fallback := CompleteFindingReport(f)
	if !strings.Contains(fallback, "### HTTP 请求报文") || !strings.Contains(fallback, "uid=33(www-data)") {
		t.Fatalf("fallback report missing raw HTTP:\n%s", fallback)
	}

	f.Report = "# 人工报告\n\n已复现。"
	completed := CompleteFindingReport(f)
	if !strings.Contains(completed, "# 人工报告") {
		t.Fatal("existing report should be preserved")
	}
	if !strings.Contains(completed, "## 附：原始 HTTP 报文（系统补充）") {
		t.Fatalf("raw HTTP appendix missing:\n%s", completed)
	}

	f.Report = completed
	if again := CompleteFindingReport(f); strings.Count(again, "## 附：原始 HTTP 报文") != 1 {
		t.Fatalf("appendix should not duplicate:\n%s", again)
	}
}

func TestBuildFindingReportWithoutHTTPStillRenders(t *testing.T) {
	out := BuildFindingReport(FindingReportInput{
		FindingID: 9,
		Name:      "弱口令",
		VulnClass: "weak-password",
		Severity:  db.SeverityMedium,
		Summary:   "管理员账号使用弱口令",
		Evidence:  "登录成功: admin/admin",
		Source:    "Agent 上报（worker）",
	})
	if !strings.Contains(out, "未采集到原始 HTTP 请求/响应报文") {
		t.Fatalf("non-HTTP fallback missing:\n%s", out)
	}
	if !strings.Contains(out, "## 参数与数据来源") {
		t.Fatalf("parameter section missing:\n%s", out)
	}
}

// curl 命令不得出现在导出叙述中；原始 HTTP 报文代码块即使正文含 curl 也必须原样保留。
func TestStripCurlArtifactsKeepsRawPackets(t *testing.T) {
	in := strings.Join([]string{
		"## 复现步骤",
		"1. 登录后执行：",
		"```",
		"   curl -b cookies.txt 'http://target.example/a'",
		"   ```",
		"2. 读取响应。",
		"```http",
		"POST /abc HTTP/1.1",
		"Host: target.example",
		"",
		"payload=curl -X POST",
		"```",
		"直接执行：",
		"curl -b cookies.txt 'http://target.example/b' \\",
		"  --data 'x=1'",
	}, "\n")
	out := stripCurlArtifacts(in, curlOmittedNote)
	if strings.Contains(out, "curl -b") {
		t.Fatalf("curl commands must be stripped:\n%s", out)
	}
	for _, want := range []string{"POST /abc HTTP/1.1", "payload=curl -X POST", curlOmittedNote, "2. 读取响应。"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(stripCurlArtifacts("plain text without commands", "note"), "note") {
		t.Fatal("placeholder must not appear when nothing was removed")
	}
}
