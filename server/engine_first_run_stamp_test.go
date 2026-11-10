package server

import (
	"strconv"
	"testing"
)

// 2026-11-10 实机回归：一个没设超时的 LLM 任务跑了 15 分钟、200 多条活动，库里
// `tasks.status` 仍是 created、`first_run_at` 是空的——`stampFirstRun` 在
// TimeoutSeconds<=0 时直接 return。而 status 的 running 只在 API 派生，所以库里
// 完全没有「什么时候真正开始跑」的痕迹，按库统计/导出都只能拿 created_at 起算。
func TestStampFirstRunPersistsWithoutTimeout(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	task, err := m.CreateTask("盖章测试", "无超时的任务也要能回答何时开跑", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	s := newAdmissionTestServer(m, nil)
	s.engine.stampFirstRun(task)
	s.engine.stampFirstRun(task) // 重复唤醒只盖一次

	id, _ := strconv.ParseInt(task.ID, 10, 64)
	stored, err := m.pg.GetTask(id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.FirstRunAt == nil {
		t.Fatalf("timeout=0 的任务没有落下 first_run_at：库里无法判断它是否已经开始运行")
	}
	if stored.DeadlineAt != nil {
		t.Errorf("没设超时却算出了 deadline_at=%v", *stored.DeadlineAt)
	}
}

// 设了超时的路径不变：盖章同时算出截止时间，供超时收尾使用。
func TestStampFirstRunStillComputesDeadline(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	task, err := m.CreateTask("盖章测试-带超时", "带超时", nil, 120, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	s := newAdmissionTestServer(m, nil)
	s.engine.stampFirstRun(task)

	id, _ := strconv.ParseInt(task.ID, 10, 64)
	stored, err := m.pg.GetTask(id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.FirstRunAt == nil || stored.DeadlineAt == nil {
		t.Fatalf("带超时的任务应同时有 first_run_at 与 deadline_at，实际 first_run=%v deadline=%v", stored.FirstRunAt, stored.DeadlineAt)
	}
}
