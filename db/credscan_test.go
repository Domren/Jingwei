package db

import (
	"errors"
	"fmt"
	"testing"
)

const credScanTestSchema = "jingwei_credscan_test"

func credTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := OpenTestSchema(testDSN(t), credScanTestSchema)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestCredTaskLifecycle(t *testing.T) {
	d := credTestDB(t)

	task, err := d.CreateCredTask(CredTaskInput{
		Name:      "边界段弱口令",
		Targets:   []string{"10.0.0.10", " 10.0.0.10 ", "", "10.0.0.11:2222"},
		Protocols: []string{"SSH", "redis", " "},
		Options:   map[string]any{"concurrency": 8, "rate_limit": 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != CredTaskQueued || task.Stage != "queued" {
		t.Fatalf("新任务应当在排队: %+v", task)
	}
	// 重复目标去重但保序：同一目标写两遍不该在报告里变成两个端点。
	if len(task.Targets) != 2 || task.Targets[0] != "10.0.0.10" || task.Targets[1] != "10.0.0.11:2222" {
		t.Fatalf("targets = %+v", task.Targets)
	}
	if len(task.Protocols) != 2 || task.Protocols[0] != "ssh" || task.Protocols[1] != "redis" {
		t.Fatalf("protocols = %+v", task.Protocols)
	}

	got, err := d.GetCredTask(task.ID)
	if err != nil || got.Options["rate_limit"] == nil {
		t.Fatalf("get = %+v, %v", got, err)
	}

	ok, err := d.StartCredTask(task.ID)
	if err != nil || !ok {
		t.Fatalf("start = %v, %v", ok, err)
	}
	if ok, _ = d.StartCredTask(task.ID); ok {
		t.Fatal("排队态只能被抢一次")
	}
	if err := d.SetCredTaskStage(task.ID, "testing", map[string]any{"endpoints": 3, "attempts": 12}); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendCredTaskLog(task.ID, "线 A: 先测 10.0.0.10:6379"); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendCredTaskLog(task.ID, "线 B: 先测 10.0.0.11:2222"); err != nil {
		t.Fatal(err)
	}

	if err := d.FinishCredTask(task.ID, CredTaskDone, map[string]any{"hit": 1}, ""); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetCredTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != CredTaskDone || got.Stage != "done" || got.FinishedAt == nil {
		t.Fatalf("收尾状态 = %+v", got)
	}
	if got.Progress["endpoints"] == nil {
		t.Fatalf("progress 丢了: %+v", got.Progress)
	}
	if got.Log != "线 A: 先测 10.0.0.10:6379\n线 B: 先测 10.0.0.11:2222" {
		t.Fatalf("log = %q", got.Log)
	}

	// 收尾只认三种终态，手误写别的不能把任务永久留在 running 里。
	if err := d.FinishCredTask(task.ID, "done-ish", nil, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ = d.GetCredTask(task.ID); got.Status != CredTaskFailed {
		t.Fatalf("非法终态应按 failed 处理: %q", got.Status)
	}

	if _, err := d.GetCredTask(99999999); !errors.Is(err, ErrCredTaskNotFound) {
		t.Fatalf("不存在的任务要给出可判定的错误: %v", err)
	}
}

func TestCredResultsBatchFilterAndCounts(t *testing.T) {
	d := credTestDB(t)
	task, err := d.CreateCredTask(CredTaskInput{Name: "结果批次", Targets: []string{"10.1.0.1"}})
	if err != nil {
		t.Fatal(err)
	}

	// 超过单批上限（200）才能真正走到分块那条路。
	rows := make([]CredResult, 0, 450)
	for i := 0; i < 450; i++ {
		outcome := "deny"
		if i%150 == 0 {
			outcome = "hit"
		}
		host := "10.1.0.1"
		if i%3 == 0 {
			host = "10.1.0.2"
		}
		rows = append(rows, CredResult{
			Host: host, Port: 6379, Protocol: "redis", ProtocolSource: "explicit",
			ProtocolConfirmed: true, Params: map[string]string{"database": "0"},
			Username: fmt.Sprintf("u%d", i), Password: "p", Outcome: outcome,
			Banner: "+OK", Evidence: "REQ/RESP", Attempts: 1, ElapsedMS: 5,
		})
	}
	if err := d.InsertCredResults(task.ID, rows); err != nil {
		t.Fatal(err)
	}
	if err := d.InsertCredResults(task.ID, nil); err != nil {
		t.Fatalf("空批次不该报错: %v", err)
	}

	list, total, err := d.ListCredResults(task.ID, CredResultFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 450 || len(list) != 200 {
		t.Fatalf("total=%d len=%d", total, len(list))
	}
	// 默认按 id 升序，报告里「先测的先出现」。
	if list[0].Username != "u0" || list[0].Params["database"] != "0" || !list[0].ProtocolConfirmed {
		t.Fatalf("首行 = %+v", list[0])
	}

	hits, hitTotal, err := d.ListCredResults(task.ID, CredResultFilter{Outcome: "hit"})
	if err != nil {
		t.Fatal(err)
	}
	if hitTotal != 3 || len(hits) != 3 || hits[0].Outcome != "hit" {
		t.Fatalf("hit total=%d len=%d", hitTotal, len(hits))
	}

	_, hostTotal, err := d.ListCredResults(task.ID, CredResultFilter{Host: "10.1.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	if hostTotal != 150 {
		t.Fatalf("按主机筛选 = %d", hostTotal)
	}

	page, pageTotal, err := d.ListCredResults(task.ID, CredResultFilter{Offset: 440, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if pageTotal != 450 || len(page) != 10 || page[0].Username != "u440" {
		t.Fatalf("分页 total=%d len=%d first=%q", pageTotal, len(page), page[0].Username)
	}

	counts, err := d.CredTaskOutcomeCounts(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if counts["hit"] != 3 || counts["deny"] != 447 {
		t.Fatalf("counts = %+v", counts)
	}
}

func TestCredTaskCancelDeleteAndRecover(t *testing.T) {
	d := credTestDB(t)

	running, err := d.CreateCredTask(CredTaskInput{Name: "运行中", Targets: []string{"10.2.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.StartCredTask(running.ID); err != nil {
		t.Fatal(err)
	}
	queued, err := d.CreateCredTask(CredTaskInput{Name: "排队中", Targets: []string{"10.2.0.2"}})
	if err != nil {
		t.Fatal(err)
	}
	finished, err := d.CreateCredTask(CredTaskInput{Name: "已结束", Targets: []string{"10.2.0.3"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = d.FinishCredTask(finished.ID, CredTaskDone, nil, "")
	if err := d.InsertCredResults(finished.ID, []CredResult{{
		Host: "10.2.0.3", Port: 22, Protocol: "ssh", Outcome: "hit", Username: "root", Password: "toor",
	}}); err != nil {
		t.Fatal(err)
	}

	// 运行中与排队中的任务都能取消，已结束的改不动。
	if ok, err := d.CancelCredTask(queued.ID); err != nil || !ok {
		t.Fatalf("取消排队任务 = %v, %v", ok, err)
	}
	if ok, err := d.CancelCredTask(finished.ID); err != nil || ok {
		t.Fatalf("已结束的任务不该被改状态 = %v, %v", ok, err)
	}

	// 重启恢复：运行中的任务标失败，别的状态不动。
	n, err := d.RecoverInterruptedCredTasks()
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("至少该恢复自己这条运行中任务: n=%d", n)
	}
	if got, _ := d.GetCredTask(running.ID); got.Status != CredTaskFailed || got.Error == "" {
		t.Fatalf("恢复后 = %+v", got)
	}
	if got, _ := d.GetCredTask(queued.ID); got.Status != CredTaskCanceled {
		t.Fatalf("取消态被恢复逻辑改了: %+v", got)
	}

	// 删除：运行中的删不掉；结束的删掉后结果级联消失。
	active, err := d.CreateCredTask(CredTaskInput{Name: "又被抢到", Targets: []string{"10.2.0.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := d.StartCredTask(active.ID); !ok {
		t.Fatal("新任务应当能抢到")
	}
	deleted, err := d.DeleteCredTasks([]int64{active.ID, finished.ID})
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("运行中的任务不该被删: deleted=%d", deleted)
	}
	if _, err := d.GetCredTask(finished.ID); !errors.Is(err, ErrCredTaskNotFound) {
		t.Fatalf("已结束任务应当删掉: %v", err)
	}
	if _, total, err := d.ListCredResults(finished.ID, CredResultFilter{}); err != nil || total != 0 {
		t.Fatalf("结果应当级联删除: total=%d err=%v", total, err)
	}
}
