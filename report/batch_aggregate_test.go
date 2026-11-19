package report

import (
	"strings"
	"testing"

	"github.com/Domren/jingwei/db"
)

// P7 验收：10 目标模板一次派生（在 server 包测）；跨任务合并去重且不误合；
// 汇总报告可导出。

func taskPtr(id int64) *int64 { return &id }

func TestAggregateFindingsAcrossTasksMergesSameRootCause(t *testing.T) {
	fs := []*db.DBFinding{
		{ID: 1, TaskID: taskPtr(11), VulnClass: "SQLi", Name: "SQL 注入", Severity: "high",
			DedupeKey: "agent:11:SQLi:a.example.com:443:/api/admin"},
		{ID: 2, TaskID: taskPtr(12), VulnClass: "SQLi", Name: "SQL 注入", Severity: "high",
			DedupeKey: "agent:12:SQLi:a.example.com:443:/api/admin"},
	}
	groups := AggregateFindingsAcrossTasks(fs)
	if len(groups) != 1 || groups[0].Count != 2 {
		t.Fatalf("同根因跨任务应合并成 1 族 2 条: %+v", groups)
	}
	if len(groups[0].TaskIDs) != 2 || groups[0].TaskIDs[0] != 11 || groups[0].TaskIDs[1] != 12 {
		t.Fatalf("任务来源丢失: %+v", groups[0].TaskIDs)
	}
}

func TestAggregateFindingsNoFalseMerge(t *testing.T) {
	fs := []*db.DBFinding{
		{ID: 1, TaskID: taskPtr(1), VulnClass: "SQLi", Name: "SQLi",
			DedupeKey: "agent:1:SQLi:a.example.com:443:/api/admin"},
		{ID: 2, TaskID: taskPtr(1), VulnClass: "XSS", Name: "XSS",
			DedupeKey: "agent:1:XSS:a.example.com:443:/api/admin"},
		{ID: 3, TaskID: taskPtr(2), VulnClass: "SQLi", Name: "SQLi",
			DedupeKey: "agent:2:SQLi:b.example.com:443:/api/admin"},
	}
	groups := AggregateFindingsAcrossTasks(fs)
	if len(groups) != 3 {
		t.Fatalf("不同类/不同主机不应误合，得到 %d 族: %+v", len(groups), groups)
	}
	for _, g := range groups {
		if g.Count != 1 {
			t.Fatalf("不该合并却合并了: %+v", g)
		}
	}
}

func TestCrossTaskDedupeKeyKeepsShape(t *testing.T) {
	if got := CrossTaskDedupeKey("agent:12:SQLi:a.example.com:443:/api/admin"); got != "agent:0:SQLi:a.example.com:443:/api/admin" {
		t.Fatalf("CrossTaskDedupeKey = %q", got)
	}
	if got := CrossTaskDedupeKey("legacy-key"); got != "legacy-key" {
		t.Fatalf("存量 key 应原样: %q", got)
	}
}

func TestBatchAggregateMarkdownExportable(t *testing.T) {
	fs := []*db.DBFinding{
		{ID: 1, TaskID: taskPtr(1), VulnClass: "SQLi", Name: "SQL 注入", Severity: "high",
			DedupeKey: "agent:1:SQLi:a.example.com:443:/api/admin"},
		{ID: 2, TaskID: taskPtr(2), VulnClass: "SQLi", Name: "SQL 注入", Severity: "high",
			DedupeKey: "agent:2:SQLi:a.example.com:443:/api/admin"},
	}
	md := BatchAggregateMarkdown("站群批次 A", AggregateFindingsAcrossTasks(fs))
	for _, want := range []string{"站群批次 A", "归并后发现族数：**1**", "原始发现条数：**2**", "sqli", "SQL 注入"} {
		if !strings.Contains(md, want) {
			t.Fatalf("汇总报告缺 %q:\n%s", want, md)
		}
	}
}
