package db

import (
	"testing"
)

const subdomainTestSchema = "jingwei_subdomain_test"

func subdomainTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := OpenTestSchema(testDSN(t), subdomainTestSchema)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// 任务生命周期与结果台账。单独走一遍库，是因为这类「只有落库才会暴露」的错
// （JSONB 列读不回、占位符漏参、级联没配）在纯函数测试里永远抓不到。
func TestSubdomainTaskLifecycle(t *testing.T) {
	d := subdomainTestDB(t)
	const prefix = "subdomain-lifecycle-"
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM subdomain_tasks WHERE name LIKE $1`, prefix+"%")
	})

	task, err := d.CreateSubdomainTask(SubdomainTaskInput{
		Name:    prefix + "根域枚举",
		Targets: []string{" example.com ", "EXAMPLE.COM", "https://shop.corp.example.org/x", "", "lab.internal"},
		Options: map[string]any{"words": "builtin", "public_sources": []string{}, "probe_ports": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 存储层只按字面去重、保序：台账要记的是操作员输入了什么，大小写变体是两行输入。
	// 「同一个根不查两遍」由引擎负责（它按规范化后的根去重），两层各管各的事。
	if len(task.Targets) != 4 || task.Targets[0] != "example.com" || task.Targets[3] != "lab.internal" {
		t.Fatalf("目标去重保序不对：%v", task.Targets)
	}
	if task.Status != SubdomainTaskQueued {
		t.Fatalf("新建任务应排队，得到 %s", task.Status)
	}
	if got, ok := task.Options["probe_ports"].(bool); !ok || !got {
		t.Fatalf("options 没原样读回：%+v", task.Options)
	}

	claimed, err := d.ClaimNextSubdomainTask()
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.ID != task.ID || claimed.Status != SubdomainTaskRunning {
		t.Fatalf("抢占失败：%+v", claimed)
	}
	// 队里没有第二条时，抢占要返回 (nil, nil)：调度循环靠它与「数据库出错」区分。
	again, err := d.ClaimNextSubdomainTask()
	if err != nil {
		t.Fatal(err)
	}
	if again != nil && again.ID != 0 {
		t.Fatalf("没有排队任务时不该抢到什么：%+v", again)
	}

	if err := d.SetSubdomainTaskStage(task.ID, "resolving", map[string]any{"queried": 120}); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendSubdomainTaskLog(task.ID, "泛解析：example.com 存在 *. 记录"); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendSubdomainTaskLog(task.ID, "预算：已问 200 次"); err != nil {
		t.Fatal(err)
	}

	asset := int64(4242)
	results := []SubdomainResult{
		{
			Name: "www.example.com", Root: "example.com", Source: "input",
			Records: []SubdomainRecord{{Type: "A", Values: []string{"93.184.216.34"}}},
			IPs:     []string{"93.184.216.34"}, AssetID: &asset,
		},
		{
			Name: "api.example.com", Root: "example.com", Source: "dict",
			Records: []SubdomainRecord{{Type: "A", Values: []string{"1.2.3.4"}}, {Type: "CNAME", Values: []string{"cdn.example.net"}}},
			IPs: []string{"1.2.3.4"}, AssetID: &asset,
		},
		{
			Name: "junk.example.com", Root: "example.com", Source: "dict",
			Records: []SubdomainRecord{{Type: "A", Values: []string{"5.6.7.8"}}},
			IPs:     []string{"5.6.7.8"}, Wildcard: true,
		},
	}
	if err := d.InsertSubdomainResults(task.ID, results); err != nil {
		t.Fatal(err)
	}
	// 重跑同名结果要覆盖而不是叠第二条，否则台账条数与引擎结论就对不上了。
	if err := d.InsertSubdomainResults(task.ID, []SubdomainResult{{
		Name: "api.example.com", Root: "example.com", Source: "public",
		Records: []SubdomainRecord{{Type: "AAAA", Values: []string{"2001:db8::1"}}},
		IPs:     []string{"2001:db8::1"},
	}}); err != nil {
		t.Fatal(err)
	}

	list, err := d.ListSubdomainResults(task.ID, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("期望 3 条结果，得到 %d：%+v", len(list), list)
	}
	// wildcard 排在前面的反例：泛解析命中要排在正常发现之后，别在页面上抢走注意力。
	if list[0].Wildcard {
		t.Fatalf("泛解析命中不该排在最前：%+v", list[0])
	}
	for _, r := range list {
		if r.Name == "api.example.com" {
			if r.Source != "public" {
				t.Fatalf("重跑同名结果应按最新来源覆盖，得到 %q", r.Source)
			}
			if len(r.Records) != 1 || r.Records[0].Type != "AAAA" || len(r.Records[0].Values) != 1 {
				t.Fatalf("JSONB 记录列没读回原样：%+v", r.Records)
			}
			// 第二次写没带 asset_id，COALESCE 要保住已有的关联，不能覆盖成空。
			if r.AssetID == nil {
				t.Fatal("覆盖写入把资产关联抹掉了")
			}
		}
	}
	if n, err := d.SubdomainResultCount(task.ID); err != nil || n != 3 {
		t.Fatalf("结果计数不对：%d (%v)", n, err)
	}

	// 筛选：按根、按来源。
	onlyRoot, err := d.ListSubdomainResults(task.ID, "example.com", "", 0)
	if err != nil || len(onlyRoot) != 3 {
		t.Fatalf("按根筛选不对：%d (%v)", len(onlyRoot), err)
	}
	onlyPublic, err := d.ListSubdomainResults(task.ID, "", "public", 0)
	if err != nil || len(onlyPublic) != 1 {
		t.Fatalf("按来源筛选不对：%+v (%v)", onlyPublic, err)
	}

	if err := d.FinishSubdomainTask(task.ID, "nonsense", map[string]any{"found": 3}, ""); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetSubdomainTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 认不出的终态一律按失败收尾：留在 running 上的任务永远不会有人再去碰它。
	if got.Status != SubdomainTaskFailed {
		t.Fatalf("非法终态应按失败处理，得到 %s", got.Status)
	}
	if err := d.FinishSubdomainTask(task.ID, SubdomainTaskDone, map[string]any{"found": 3}, ""); err != nil {
		t.Fatal(err)
	}

	if n, err := d.DeleteSubdomainTasks([]int64{task.ID}); err != nil || n != 1 {
		t.Fatalf("删除已结束任务失败：%d (%v)", n, err)
	}
	// 外键级联：任务删掉后结果不能变成孤儿行。
	if left, err := d.SubdomainResultCount(task.ID); err != nil || left != 0 {
		t.Fatalf("结果没随任务删除：%d (%v)", left, err)
	}
	if _, err := d.GetSubdomainTask(task.ID); err != ErrSubdomainTaskNotFound {
		t.Fatalf("取已删除任务应返回不存在错误，得到 %v", err)
	}
}

// 运行中的任务不许删、可以取消；重启遗留的 running 要标成失败而不是永远挂着。
func TestSubdomainTaskCancelAndRecover(t *testing.T) {
	d := subdomainTestDB(t)
	const prefix = "subdomain-cancel-"
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM subdomain_tasks WHERE name LIKE $1`, prefix+"%")
	})

	task, err := d.CreateSubdomainTask(SubdomainTaskInput{Name: prefix + "在跑的任务", Targets: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := d.DeleteSubdomainTasks([]int64{task.ID}); err != nil || n != 0 {
		t.Fatalf("排队中的任务不该被删掉：%d (%v)", n, err)
	}
	if _, err := d.ClaimNextSubdomainTask(); err != nil {
		t.Fatal(err)
	}
	if n, err := d.RecoverInterruptedSubdomainTasks(); err != nil || n == 0 {
		t.Fatalf("重启恢复应把 running 标失败：%d (%v)", n, err)
	}
	got, err := d.GetSubdomainTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != SubdomainTaskFailed || got.Error != "服务重启，任务中断" {
		t.Fatalf("恢复文案不对：%s / %s", got.Status, got.Error)
	}

	if ok, err := d.CancelSubdomainTask(task.ID); err != nil || ok {
		t.Fatalf("已结束的任务不该被取消：%v (%v)", ok, err)
	}
	// 把行摆回运行中（Finish 不接受 running 这种终态，只能直接写库）：取消只认 queued/running。
	if _, err := d.Exec(`UPDATE subdomain_tasks SET status='running', stage='resolving', error='' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.CancelSubdomainTask(task.ID); err != nil || !ok {
		t.Fatalf("取消失败：%v (%v)", ok, err)
	}
	if ok, err := d.CancelSubdomainTask(task.ID); err != nil || ok {
		t.Fatalf("重复取消应无效果：%v (%v)", ok, err)
	}
}
