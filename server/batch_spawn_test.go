package server

import (
	"sort"
	"strconv"
	"testing"
)

// P7 验收：10 目标模板一次派生 10 个任务；去重后目标数正确；产出确定性。

func TestBuildBatchSpawnPlanDerivesTenTasks(t *testing.T) {
	targets := make([]string, 0, 10)
	for i := 1; i <= 10; i++ {
		targets = append(targets, "https://host"+strconv.Itoa(i)+".example.com")
	}
	plan := BuildBatchSpawnPlan("测站群", "枚举并验证", targets)
	if len(plan) != 10 {
		t.Fatalf("10 目标应派生 10 任务，得到 %d", len(plan))
	}
	wantSorted := append([]string{}, targets...)
	sort.Strings(wantSorted)
	for i, item := range plan {
		if item.Index != i+1 || item.Target != wantSorted[i] {
			t.Fatalf("第 %d 项: %+v", i, item)
		}
		if item.Description == "" || item.Goal == "" {
			t.Fatalf("模板未应用到第 %d 项: %+v", i, item)
		}
	}
	// 换序 / 重复目标不改变结果。
	shuffled := append([]string{}, targets[5:]...)
	shuffled = append(shuffled, targets[:5]...)
	shuffled = append(shuffled, targets[0]) // 重复
	plan2 := BuildBatchSpawnPlan("测站群", "枚举并验证", shuffled)
	if len(plan2) != 10 {
		t.Fatalf("重复目标应去重: %d", len(plan2))
	}
	for i := range plan {
		if plan[i].Target != plan2[i].Target {
			t.Fatalf("派生顺序不确定: %s vs %s", plan[i].Target, plan2[i].Target)
		}
	}
}

func TestBuildBatchSpawnPlanIgnoresEmptyTargets(t *testing.T) {
	plan := BuildBatchSpawnPlan("d", "g", []string{"", "  ", "https://a.example"})
	if len(plan) != 1 || plan[0].Target != "https://a.example" {
		t.Fatalf("空目标应忽略: %+v", plan)
	}
}
