package report

// P10 验收：WAF 改写回显落 inferred 且不进报告；normal finding 仍进报告；默认 observed 兼容。
// 纯函数测试，不依赖 Postgres / sidecar。

import (
	"strings"
	"testing"
	"time"

	"github.com/Domren/jingwei/db"
)

const wafEchoMarker = "WAF_REWRITE_MARKER_9f3a"

// wafEchoFixture 模拟一条回显被 WAF 改写的 finding：证据、响应正文与提取结果里
// 都出现了篡改后的标记串。只有 observed 的证据才允许把它写进报告正文。
func wafEchoFixture() FindingReportInput {
	return FindingReportInput{
		FindingID:    42,
		Name:         "SQL 注入",
		VulnClass:    "sqli",
		Severity:     "high",
		Status:       db.FindingPending,
		Summary:      "参数 id 存在注入",
		Evidence:     "回显包含 " + wafEchoMarker,
		HTTPRequest:  "GET /vuln?id=1 HTTP/1.1\r\nHost: t.example\r\n\r\n",
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<div>User ID: " + wafEchoMarker + "</div>",
		Extracted:    []string{wafEchoMarker},
		GeneratedAt:  time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC),
	}
}

func TestBuildFindingReport_InferredEchoExcluded(t *testing.T) {
	in := wafEchoFixture()
	in.Confidence = db.FindingConfidenceInferred
	got := BuildFindingReport(in)

	if strings.Contains(got, wafEchoMarker) {
		t.Fatalf("inferred 的 WAF 改写回显不应出现在报告正文：\n%s", got)
	}
	if !strings.Contains(got, "inferred") {
		t.Fatalf("附录应标注置信度 inferred：\n%s", got)
	}
	if !strings.Contains(got, "不进入正式报告正文") {
		t.Fatalf("应说明非 observed 证据已从正文移除：\n%s", got)
	}
	// 验证步骤也不得引用该回显。
	steps, rows := verificationSteps(in)
	for _, s := range steps {
		if strings.Contains(s, wafEchoMarker) {
			t.Fatalf("inferred 的验证步骤不应引用回显：%q", s)
		}
	}
	if len(rows) != 0 {
		t.Fatalf("inferred 不应产生取自回显的验证数据行，得到 %d 行", len(rows))
	}
}

func TestBuildFindingReport_NormalFindingIncluded(t *testing.T) {
	in := wafEchoFixture()
	in.Confidence = db.FindingConfidenceObserved
	got := BuildFindingReport(in)
	if !strings.Contains(got, wafEchoMarker) {
		t.Fatalf("observed 的回显证据应进报告正文：\n%s", got)
	}
	steps, rows := verificationSteps(in)
	if len(steps) == 0 || len(rows) == 0 {
		t.Fatal("observed 的 finding 应产生验证步骤与验证数据")
	}
}

func TestBuildFindingReport_DefaultObservedCompatibility(t *testing.T) {
	// 老 finding 没有 confidence 字段（空字符串）时默认 observed，既有报告语义不变。
	for _, tc := range []struct {
		name string
		conf string
	}{
		{"空值", ""},
		{"未知值", "legacy_unknown"},
		{"显式 observed", "observed"},
	} {
		in := wafEchoFixture()
		in.Confidence = tc.conf
		got := BuildFindingReport(in)
		if !strings.Contains(got, wafEchoMarker) {
			t.Fatalf("%s 置信度应回退到 observed，回显应保留在报告中", tc.name)
		}
		if !strings.Contains(got, "observed") {
			t.Fatalf("%s 置信度应在报告中标注为 observed", tc.name)
		}
	}
}

func TestBuildFindingReport_FailedEchoExcluded(t *testing.T) {
	in := wafEchoFixture()
	in.Confidence = db.FindingConfidenceFailed
	got := BuildFindingReport(in)
	if strings.Contains(got, wafEchoMarker) {
		t.Fatal("failed 的证据不应进报告正文")
	}
	if !strings.Contains(got, "failed") {
		t.Fatal("附录应标注 failed")
	}
}

func TestBuildFindingReportFromDB_PassesConfidence(t *testing.T) {
	f := &db.DBFinding{
		ID: 7, Name: "RCE", VulnClass: "rce", Severity: "high",
		Evidence: "回显 " + wafEchoMarker,
		HTTPRequest: wafEchoFixture().HTTPRequest,
		HTTPResponse: wafEchoFixture().HTTPResponse,
		Confidence: db.FindingConfidenceInferred,
	}
	got := BuildFindingReportFromDB(f)
	if !strings.Contains(got, "inferred") {
		t.Fatalf("FromDB 应把 confidence 传给报告：\n%s", got)
	}
}
