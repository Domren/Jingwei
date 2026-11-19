package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P6 验收：与 1.5.0 目录枚举/JS-URL 结果去重；同目标手动与自动两路产出一致。

func TestBuildAPIReconAutoPlanDedupesExisting(t *testing.T) {
	js := []string{
		"/api/web/user/list", "https://target.example/api/web/role_permissions?page=1",
		"/api/web/user/list", // 自身重复
	}
	existing := []string{"https://target.example/api/web/user/list?page=2", "/assets/app.js"}
	plan := BuildAPIReconAutoPlan("https://target.example", js, existing)
	if len(plan.EndpointsAuto) != 1 || plan.EndpointsAuto[0] != "/api/web/role_permissions" {
		t.Fatalf("去重结果: %+v", plan.EndpointsAuto)
	}
	if plan.DedupedAgainst != 2 || plan.SkillName != "api-recon" {
		t.Fatalf("plan: %+v", plan)
	}
	if len(plan.Steps) < 2 {
		t.Fatalf("执行计划为空: %+v", plan.Steps)
	}
	// 确定性：同输入两次构造逐字节一致（手动与自动产出一致的前提）。
	b1, _ := json.Marshal(plan)
	b2, _ := json.Marshal(BuildAPIReconAutoPlan("https://target.example", js, existing))
	if string(b1) != string(b2) {
		t.Fatalf("产出不确定: %s vs %s", b1, b2)
	}
}

func TestAutoAPIReconToolUsesSkillLoader(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "api-recon")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"),
		[]byte("---\nname: api-recon\ndescription: test\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Server{skillDir: dir}
	if !s.apiReconSkillAvailable() {
		t.Fatal("skill 加载器应能看到 api-recon")
	}

	var tool = s.toolAutoAPIRecon()
	input, _ := json.Marshal(map[string]any{
		"target":       "https://target.example",
		"js_endpoints": []string{"/api/web/user/list"},
		"existing":     []string{"/api/web/user/list?page=1"},
	})
	res, err := tool.Call(context.Background(), input, nil)
	if err != nil || res.IsError {
		t.Fatalf("tool call: err=%v res=%s", err, res.Flatten())
	}
	out := res.Flatten()
	for _, want := range []string{"api-recon", "skill_available", "endpoints_auto"} {
		if !strings.Contains(out, want) {
			t.Fatalf("产出缺 %q: %s", want, out)
		}
	}
	// 已存在的端点被去掉，所以 auto 列表为空但仍是合法产出。
	if !strings.Contains(out, `"endpoints_auto":[]`) {
		t.Fatalf("去重结果应为空: %s", out)
	}
}

func TestAutoAPIReconToolFailsWhenSkillMissing(t *testing.T) {
	s := &Server{skillDir: t.TempDir()}
	if s.apiReconSkillAvailable() {
		t.Fatal("空 skillDir 不应看到 api-recon")
	}
	input, _ := json.Marshal(map[string]any{"target": "https://x.example"})
	res, err := s.toolAutoAPIRecon().Call(context.Background(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "不可见") {
		t.Fatalf("skill 缺失应报错: %s", res.Flatten())
	}
}
