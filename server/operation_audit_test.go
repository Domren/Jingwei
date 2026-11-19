package server

import (
	"strings"
	"testing"
	"time"

	"github.com/Domren/jingwei/db"
	"github.com/Domren/jingwei/guard"
)

// P1 验收：导出含授权书引用与操作者；测了什么（任务流水）、谁批的（授权清单）、
// 谁在操作（operator）三者齐全；代理口令等凭据脱敏。

func TestBuildOperationAuditReportIncludesOperatorAuthAndTasks(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC)
	rep := BuildOperationAuditReport(OperationAuditInput{
		Operator:                 "Jingwei",
		AuthorizationRef:         "授权书 JW-2026-0011",
		OperationProxyChain:      "socks5://alice:s3cr3t@10.0.0.1:1080",
		OperatorSessionIsolation: true,
		Authorizations: []*db.Authorization{
			{ID: 7, Name: "客户A授权", Targets: []string{"example.com"}, Enabled: true, StartsAt: &start, EndsAt: &end},
		},
		Tasks: []OperationAuditTask{
			{
				ID: "42", Description: "测了 /api/admin 越权",
				Entries: []guard.AuditEntry{
					{TS: 100, Tool: "Bash", Action: "allow", Reason: "", Command: "curl -H 'Authorization: Bearer abc123' https://example.com/api/admin"},
					{TS: 101, Tool: "Bash", Action: "block", Reason: "超出范围", Command: "curl http://evil.example"},
				},
				Attributions: map[string]int{"ok": 3, "blocked": 1},
			},
		},
		GeneratedAt: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC),
	})

	if rep.Operator != "Jingwei" {
		t.Fatalf("operator: %q", rep.Operator)
	}
	if rep.AuthorizationRef != "授权书 JW-2026-0011" {
		t.Fatalf("auth ref: %q", rep.AuthorizationRef)
	}
	if len(rep.Authorizations) != 1 || rep.Authorizations[0].Name != "客户A授权" || !rep.Authorizations[0].Enabled {
		t.Fatalf("auth view: %+v", rep.Authorizations)
	}
	if rep.EntryCount != 2 || len(rep.Tasks) != 1 || rep.Tasks[0].Description != "测了 /api/admin 越权" {
		t.Fatalf("tasks: %+v", rep.Tasks)
	}
	if rep.Tasks[0].Attributions["blocked"] != 1 {
		t.Fatalf("attribution lost: %+v", rep.Tasks[0].Attributions)
	}
	// 凭据脱敏：代理链、Authorization 头都不能以明文出现在报告里。
	if strings.Contains(rep.OperationProxyChain, "s3cr3t") || !strings.Contains(rep.OperationProxyChain, "***") {
		t.Fatalf("proxy chain not redacted: %q", rep.OperationProxyChain)
	}
	for _, e := range rep.Tasks[0].Entries {
		if strings.Contains(e.Command, "abc123") {
			t.Fatalf("command credential leaked: %q", e.Command)
		}
	}
	md := OperationAuditMarkdown(rep)
	for _, want := range []string{"操作者：**Jingwei**", "授权书 JW-2026-0011", "客户A授权", "测了 /api/admin 越权", "审计条目合计：2"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown 缺少 %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "s3cr3t") || strings.Contains(md, "abc123") {
		t.Fatalf("markdown 泄漏凭据:\n%s", md)
	}
}

func TestRedactSecretsInText(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"socks5://alice:s3cr3t@10.0.0.1:1080", "socks5://***:***@10.0.0.1:1080"},
		{"http://user:pass@proxy.local:8080", "http://***:***@proxy.local:8080"},
		{"api_key=sk-live-abcdef", "api_key=***"},
		{"token: 'bearer-xyz'", "token=***"},
		{"curl https://example.com/api", "curl https://example.com/api"},
	}
	for _, c := range cases {
		if got := RedactSecretsInText(c.in); got != c.want {
			t.Errorf("RedactSecretsInText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedactProxyURLKeepsHost(t *testing.T) {
	got := RedactProxyURL("http://admin:hunter2@proxy.corp:3128")
	if strings.Contains(got, "hunter2") || !strings.Contains(got, "proxy.corp:3128") {
		t.Fatalf("RedactProxyURL = %q", got)
	}
	if RedactProxyURL("") != "" {
		t.Fatal("空代理链应保持空")
	}
}

func TestOperationAuditMarkdownEmptySources(t *testing.T) {
	rep := BuildOperationAuditReport(OperationAuditInput{Operator: "Jingwei"})
	md := OperationAuditMarkdown(rep)
	if !strings.Contains(md, "无授权清单条目") || !strings.Contains(md, "无任务记录") {
		t.Fatalf("空来源应明确标注:\n%s", md)
	}
}
