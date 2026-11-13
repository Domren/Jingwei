package db

import "testing"

// R19 序 4：任务级预算闸门字段的落库/回读。CreateTaskWithOptions 写入 max_rounds /
// max_input_tokens，taskCols/scanTask 读回；stop_reason 由 settleTask 在终态后写入，
// 这里直接测 SetTaskStopReason 的回读。IsTerminal 的 budget 终态也在本文件钉住
// （status CHECK 已在 schema.sql 重建，这里钉应用层单一真源）。
func TestCreateTaskWithBudgetFieldsRoundTrip(t *testing.T) {
	d := testDB(t)
	pt, err := d.CreateTaskWithOptions("R19 预算字段回读", "验证 max_rounds/max_input_tokens/stop_reason 落库", TaskCreateOptions{
		MaxRounds: 40, MaxInputTokens: 1500000,
	})
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := d.ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	var back *Task
	for _, tt := range tasks {
		if tt.ID == pt.ID {
			back = tt
			break
		}
	}
	if back == nil {
		t.Fatalf("task %d not listed", pt.ID)
	}
	if back.MaxRounds != 40 || back.MaxInputTokens != 1500000 {
		t.Fatalf("budget fields lost on read-back: max_rounds=%d max_input_tokens=%d", back.MaxRounds, back.MaxInputTokens)
	}
	if back.StopReason != "" {
		t.Fatalf("fresh task should have empty stop_reason, got %q", back.StopReason)
	}

	const reason = "达到规划轮数上限（max_rounds=40）"
	if err := d.SetTaskStopReason(pt.ID, reason); err != nil {
		t.Fatal(err)
	}
	tasks, err = d.ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tasks {
		if tt.ID == pt.ID {
			if tt.StopReason != reason {
				t.Fatalf("stop_reason not persisted, got %q", tt.StopReason)
			}
			break
		}
	}

	// budget 是终态（单一真源）；运行态不是。
	if !IsTerminal("budget") {
		t.Fatal("budget must be a terminal status")
	}
	if IsTerminal("running") || IsTerminal("created") {
		t.Fatal("running/created must not be terminal")
	}
}
