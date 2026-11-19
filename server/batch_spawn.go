package server

// P7 · 批量任务工作流：同配置一键派生 N 任务。
// 纯函数负责把「模板 + 目标列表」展开成确定性计划；host 工具复用已有的
// spawn_task（含 seed 绑定与 launchTask），不重复实现建任务流程。

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// BatchSpawnItem 是一个派生任务的输入。
type BatchSpawnItem struct {
	Index       int    `json:"index"`
	Target      string `json:"target"`
	Description string `json:"description"`
	Goal        string `json:"goal"`
}

// BuildBatchSpawnPlan 把模板展开成 N 个任务。目标去重、保序、非空；
// 产出确定性（同输入同结果），便于夹具核对派生数量。
func BuildBatchSpawnPlan(description, goal string, targets []string) []BatchSpawnItem {
	seen := map[string]bool{}
	clean := make([]string, 0, len(targets))
	for _, raw := range targets {
		t := strings.TrimSpace(raw)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		clean = append(clean, t)
	}
	// 排序保证模板列表换序也得到同一批任务（避免父任务关联漂移）。
	sort.Strings(clean)
	out := make([]BatchSpawnItem, 0, len(clean))
	for i, t := range clean {
		out = append(out, BatchSpawnItem{
			Index:       i + 1,
			Target:      t,
			Description: fmt.Sprintf("%s · %s", strings.TrimSpace(description), t),
			Goal:        fmt.Sprintf("%s\n目标：%s", strings.TrimSpace(goal), t),
		})
	}
	return out
}

// toolBatchSpawn 一键从模板派生 N 个任务（复用 spawn_task 的 seed 绑定流程）。
func (s *Server) toolBatchSpawn() actool.CoreTool {
	return wrTool("batch_spawn",
		"同一份配置（描述/目标/预算/授权粒度）一键派生 N 个子任务，每个目标一个任务；返回各任务 id 供跨任务汇总。复用 spawn_task 的 seed 绑定流程。",
		objSchema(map[string]any{
			"description":       strParam("任务模板描述(简短标题)"),
			"goal":              strParam("任务模板目标"),
			"targets":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "目标列表（一次派生 N 个任务）"},
			"parent_ref":        strParam("可选：父任务 id（父子关联）"),
			"seed_first_intent": map[string]any{"type": "boolean", "description": "可选：简单任务直接下发种子意图，默认 false"},
		}, "description", "goal", "targets"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Description     string   `json:"description"`
				Goal            string   `json:"goal"`
				Targets         []string `json:"targets"`
				ParentRef       string   `json:"parent_ref"`
				SeedFirstIntent bool     `json:"seed_first_intent"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Goal) == "" {
				return actool.Errorf("goal 为必填"), nil
			}
			plan := BuildBatchSpawnPlan(a.Description, a.Goal, a.Targets)
			if len(plan) == 0 {
				return actool.Errorf("targets 至少需要一个非空目标"), nil
			}
			spawner := s.toolSpawnTask()
			created := make([]map[string]any, 0, len(plan))
			for _, item := range plan {
				payload, _ := json.Marshal(map[string]any{
					"description":       item.Description,
					"goal":              item.Goal,
					"parent_ref":        a.ParentRef,
					"seed_first_intent": a.SeedFirstIntent,
				})
				res, err := spawner.Call(ctx, payload, nil)
				if err != nil || res.IsError {
					return actool.Errorf(fmt.Sprintf("目标 %s 派生失败: %s", item.Target, res.Flatten())), nil
				}
				created = append(created, map[string]any{
					"index": item.Index, "target": item.Target, "result": res.Flatten(),
				})
			}
			return jsonResult(map[string]any{
				"requested": len(plan), "created": created,
			})
		})
}
