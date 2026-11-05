package server

import (
	"context"
	"strings"
	"testing"
)

// B12：模型能主动发起检测并读到结论。工具与页面走同一条任务链，所以这里验的是
// 「工具 → 任务 → 引擎 → 事实」的接线，认证正确性本身在 scanner 的真机验证里。
func TestCredscanToolsStartAndStatus(t *testing.T) {
	s, _ := newCredTestServer(t)
	ctx := context.Background()

	start := workflowTool(t, s.credscanTools(), "credscan_start")
	out := workflowCall(t, ctx, start, map[string]any{
		"targets":      []string{"127.0.0.1:1"},
		"protocols":    []string{"credtest-srv"},
		"name":         "工具流水线",
		"wait_seconds": 10,
	}, false)
	if !strings.Contains(out, "已完成") || !strings.Contains(out, "root/root") {
		t.Fatalf("start 结果应当带着命中与终态: %s", out)
	}
	if !strings.Contains(out, "没有自动登录或复用") {
		t.Fatalf("结果必须说明没有自动复用: %s", out)
	}

	status := workflowTool(t, s.credscanTools(), "credscan_status")
	// 用任务名找回 ID（工具返回值里已带任务号，但这里不依赖文本格式）。
	var id int64
	if err := s.m.pg.QueryRow(`SELECT id FROM cred_tasks WHERE name='工具流水线' ORDER BY id DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	out2 := workflowCall(t, ctx, status, map[string]any{"task_id": id}, false)
	if !strings.Contains(out2, "各态计数") || !strings.Contains(out2, "hit=1") {
		t.Fatalf("status 应当返回计数: %s", out2)
	}

	// 三档不支持的协议必须当场拒绝，不建任务。
	raw := workflowCall(t, ctx, start, map[string]any{
		"targets": []string{"10.0.0.1"}, "protocols": []string{"rdp"},
	}, true)
	if !strings.Contains(raw, "该协议暂不支持") {
		t.Fatalf("不支持协议的错误说明不足: %s", raw)
	}

	// 工具产出的命中同样不带任何自动动作：凭据仍是 untested。
	var st string
	if err := s.m.pg.QueryRow(`SELECT status FROM intranet_credentials
		WHERE host='127.0.0.1' AND port=1 AND username='root' ORDER BY id DESC LIMIT 1`).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "untested" {
		t.Fatalf("LLM 发起也不许自动复用凭据: status=%q", st)
	}
	t.Cleanup(func() {
		_, _ = s.m.pg.Exec(`DELETE FROM intranet_credentials WHERE source='credscan' AND port=1`)
		_, _ = s.m.pg.Exec(`DELETE FROM findings WHERE dedupe_key LIKE 'credscan:%'`)
		_, _ = s.m.pg.Exec(`DELETE FROM assets WHERE type='service' AND port=1 AND service_name='credtest-srv'`)
	})
}
