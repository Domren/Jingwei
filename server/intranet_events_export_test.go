package server

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/Domren/jingwei/db"
)

// TestRenderIntranetEventsCSVHasWhoWhenWhereWhat 审计导出必须含四要素：
// 操作者(who)、时间(when)、主机(where)、命令(what)。CSV 用 BOM + 单行一条。
func TestRenderIntranetEventsCSVHasWhoWhenWhereWhat(t *testing.T) {
	when := time.Date(2026, 11, 19, 10, 30, 0, 0, time.UTC)
	events := []*db.IntranetSessionEvent{{
		ID: 7, SessionID: 42, Kind: "exec", Operator: "Jingwei",
		Host: "10.0.0.9", SessionName: "web-01", Command: "whoami",
		CreatedAt: when, IsError: false,
	}}
	raw := renderIntranetEventsCSV(events)
	if !bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		t.Fatal("CSV 缺少 UTF-8 BOM，Excel 打开中文表头会乱码")
	}
	text := strings.TrimPrefix(string(raw), "\xef\xbb\xbf")
	rows, err := csv.NewReader(strings.NewReader(text)).ReadAll()
	if err != nil {
		t.Fatalf("CSV 解析失败: %v\n%s", err, text)
	}
	if len(rows) != 2 {
		t.Fatalf("期望表头+1条事件，实际 %d 行", len(rows))
	}
	header := rows[0]
	for _, col := range []string{"时间", "操作者", "主机", "会话", "命令"} {
		if !containsCol(header, col) {
			t.Fatalf("CSV 表头缺少列 %q: %v", col, header)
		}
	}
	row := rows[1]
	if row[0] != when.Format(time.RFC3339) {
		t.Fatalf("时间列=%q", row[0])
	}
	if row[1] != "Jingwei" || row[2] != "10.0.0.9" || row[6] != "whoami" {
		t.Fatalf("四要素不全: who=%q where=%q what=%q", row[1], row[2], row[6])
	}
}

func containsCol(cols []string, want string) bool {
	for _, c := range cols {
		if c == want {
			return true
		}
	}
	return false
}

// TestRenderIntranetEventsJSONHasFourElements JSON 导出同样带齐四要素字段。
func TestRenderIntranetEventsJSONHasFourElements(t *testing.T) {
	when := time.Date(2026, 11, 19, 10, 30, 0, 0, time.UTC)
	events := []*db.IntranetSessionEvent{{
		ID: 1, SessionID: 2, Operator: "Jingwei", Host: "10.0.0.9",
		Command: "whoami", CreatedAt: when,
	}}
	raw := string(renderIntranetEventsJSON(events))
	for _, field := range []string{`"operator"`, `"created_at"`, `"host"`, `"command"`} {
		if !strings.Contains(raw, field) {
			t.Fatalf("JSON 导出缺少字段 %s: %s", field, raw)
		}
	}
}
