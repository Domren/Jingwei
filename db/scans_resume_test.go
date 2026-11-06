package db

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// D5 断点续扫的存储层：检查点必须「写一次算一次、重放不覆盖、对不上就拒」。
// 分片进度是续扫唯一的依据，所以这里的每一条不变量都对应一个会被谎报的场景。
func TestScanShardCheckpoint(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateScanTask(ScanTaskInput{
		Name: "d5-checkpoint", Targets: []string{"http://10.0.0.1/"}, Mode: "auto", Ports: "80",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM scan_tasks WHERE id=$1`, task.ID) })

	layout := []ScanShardSpec{
		{Ordinal: 0, Chunk: 0, Target: "http://10.0.0.1/", Templates: 400},
		{Ordinal: 1, Chunk: 0, Target: "http://10.0.0.2/", Templates: 400},
		{Ordinal: 2, Chunk: 1, Target: "http://10.0.0.1/", Templates: 120},
	}
	plan := `{"phase":"poc","targets":["http://10.0.0.1/","http://10.0.0.2/"],"template_ids":[1,2],"template_keys":["a","b"],"digests":["1","2"]}`

	shards, err := d.SaveScanPlan(task.ID, plan, layout)
	if err != nil {
		t.Fatal(err)
	}
	if len(shards) != 3 || shards[0].Status != "pending" || shards[2].Target != "http://10.0.0.1/" {
		t.Fatalf("shards = %+v", shards)
	}
	if err := d.StartScanShard(task.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.FinishScanShard(task.ID, 0, "done", 7, ""); err != nil {
		t.Fatal(err)
	}

	// 重放同一个计划：已完成进度不能被覆盖。
	again, err := d.SaveScanPlan(task.ID, plan, layout)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Status != "done" || again[0].Results != 7 {
		t.Fatalf("重复写计划覆盖了已完成进度：%+v", again[0])
	}

	// 布局对不上必须报错，而且不能就地压缩或改写历史。
	shifted := []ScanShardSpec{
		{Ordinal: 0, Chunk: 0, Target: "http://10.0.0.1/", Templates: 400},
		{Ordinal: 1, Chunk: 0, Target: "http://10.0.0.2/", Templates: 380},
		{Ordinal: 2, Chunk: 1, Target: "http://10.0.0.1/", Templates: 120},
	}
	if _, err := d.SaveScanPlan(task.ID, plan, shifted); !errors.Is(err, ErrScanLayoutChanged) {
		t.Fatalf("模板数变了应该报布局不一致，得到：%v", err)
	}
	compact := []ScanShardSpec{{Ordinal: 0, Chunk: 0, Target: "http://10.0.0.1/,http://10.0.0.2/", Templates: 520}}
	if _, err := d.SaveScanPlan(task.ID, plan, compact); !errors.Is(err, ErrScanLayoutChanged) {
		t.Fatalf("片数变了应该报布局不一致，得到：%v", err)
	}
	kept, err := d.ListScanShards(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 3 || kept[1].Templates != 400 || kept[0].Status != "done" {
		t.Fatalf("被拒绝的写入动了库里的布局：%+v", kept)
	}
	if _, err := d.SaveScanPlan(task.ID, plan, layout); err != nil {
		t.Fatalf("原布局应该仍然可写：%v", err)
	}
	if _, err := d.SaveScanPlan(task.ID, plan, nil); err == nil || !strings.Contains(err.Error(), "空") {
		t.Fatalf("空布局应该被拒，得到：%v", err)
	}
}

// 续扫准入条件：只有停在 poc 阶段、且留有分片行的失败/已取消任务能重新排队。
func TestScanResumeAdmission(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateScanTask(ScanTaskInput{
		Name: "d5-resume-admission", Targets: []string{"http://10.0.0.1/"}, Mode: "auto", Ports: "80",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM scan_tasks WHERE id=$1`, task.ID) })

	fail := func(status string) {
		t.Helper()
		if _, err := d.Exec(`UPDATE scan_tasks SET status='running', stage='scan' WHERE id=$1`, task.ID); err != nil {
			t.Fatal(err)
		}
		if err := d.FinishScanTask(task.ID, status, status, "中断", map[string]any{}); err != nil {
			t.Fatal(err)
		}
	}

	// 没有任何检查点：不可续扫，也不能谎报「可以续」。
	fail("failed")
	if ok, err := d.RequestScanResume(task.ID); err != nil || ok {
		t.Fatalf("无检查点任务不该可续扫：ok=%v err=%v", ok, err)
	}
	if got, _ := d.GetScanTask(task.ID); got.CanResume {
		t.Fatal("无检查点任务的 can_resume 不该为真")
	}

	// poc 阶段计划 + 分片行：可续扫，排队时带上续扫标记并清掉旧错误。
	layout := []ScanShardSpec{{Ordinal: 0, Chunk: 0, Target: "http://10.0.0.1/", Templates: 400}}
	if _, err := d.SaveScanPlan(task.ID, `{"phase":"poc","targets":["http://10.0.0.1/"],"template_ids":[1],"template_keys":["a"],"digests":["d"]}`, layout); err != nil {
		t.Fatal(err)
	}
	fail("canceled")
	if got, _ := d.GetScanTask(task.ID); !got.CanResume {
		t.Fatal("停在 poc 阶段且有分片行的已取消任务，界面应该给出「续扫」")
	}
	ok, err := d.RequestScanResume(task.ID)
	if err != nil || !ok {
		t.Fatalf("已取消且留有 poc 检查点的任务应可续扫：ok=%v err=%v", ok, err)
	}
	got, err := d.GetScanTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "queued" || !got.ResumeRequested || got.Error != "" {
		t.Fatalf("续扫入队状态不对：status=%s resume=%v error=%q", got.Status, got.ResumeRequested, got.Error)
	}

	// 阶段推进到 postprocess 后不再可续：重放那段会把同一批漏洞再深挖一遍。
	if _, err := d.Exec(`UPDATE scan_tasks SET status='running' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.SetScanPlanPhase(task.ID, "postprocess"); err != nil {
		t.Fatal(err)
	}
	fail("failed")
	if ok, _ := d.RequestScanResume(task.ID); ok {
		t.Fatal("postprocess 阶段的任务不该可续扫")
	}

	// done 阶段写回时顺带清续扫标记（只有确认成功才算完）。
	if err := d.SetScanPlanPhase(task.ID, "poc"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE scan_tasks SET status='running', resume_requested=true WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.SetScanPlanPhase(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.GetScanTask(task.ID); got.ResumeRequested {
		t.Fatal("任务收尾后续扫标记没被清掉")
	}
}

// 汇总数字按库内实际行数重算：分片重跑时唯一键吃掉重复行，累加本轮返回值会少算；
// 同表里的目录枚举行与深挖回填行也不能被算成 POC 覆盖。
func TestScanPOCResultCounts(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateScanTask(ScanTaskInput{
		Name: "d5-counts", Targets: []string{"http://10.0.0.1/"}, Mode: "auto", Ports: "80",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM scan_tasks WHERE id=$1`, task.ID) })

	nucleiRaw := func(id string) map[string]any {
		return map[string]any{"template-id": id, "matched-at": "http://10.0.0.1/x", "info": map[string]any{"severity": "high", "tags": "sqli"}}
	}
	// 两条 POC 命中 + 目录枚举行 + 一条「只有深挖回填形状」的行（没有 nuclei 事件）。
	if _, err := d.AddScanTaskResult(task.ID, 0, ScanTaskResult{TemplateID: "a", Name: "A", Severity: "high", MatchedAt: "http://10.0.0.1/x", Raw: nucleiRaw("a")}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddScanTaskResult(task.ID, 0, ScanTaskResult{TemplateID: "b", Name: "B", Severity: "critical", MatchedAt: "http://10.0.0.1/y", Raw: nucleiRaw("b")}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddScanTaskResult(task.ID, 0, ScanTaskResult{TemplateID: "dir-enum:robots", MatchedAt: "http://10.0.0.1/robots.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddScanTaskResult(task.ID, 0, ScanTaskResult{
		TemplateID: "c", Severity: "high", MatchedAt: "http://10.0.0.1/z", Raw: map[string]any{"source": "deep"},
	}); err != nil {
		t.Fatal(err)
	}
	keys := []string{"a", "b", "c"}
	results, findings, err := d.ScanPOCResultCounts(task.ID, keys)
	if err != nil {
		t.Fatal(err)
	}
	if results != 2 {
		t.Fatalf("目录枚举/深挖行不该算进 POC 结果：%d", results)
	}
	if findings != 0 {
		t.Fatalf("这两条没有挂发现，findings=%d", findings)
	}

	// 同一条命中再写一次（分片重跑）不会增加行数——续扫后的汇总才不会翻倍。
	id, err := d.AddScanTaskResult(task.ID, 0, ScanTaskResult{TemplateID: "a", Name: "A", Severity: "high", MatchedAt: "http://10.0.0.1/x", Raw: nucleiRaw("a")})
	if err != nil || id != 0 {
		t.Fatalf("重复命中应被唯一键吃掉：id=%d err=%v", id, err)
	}
	if results, _, _ := mustInts(d.ScanPOCResultCounts(task.ID, keys)); results != 2 {
		t.Fatalf("重跑后行数应仍是 2，得到 %d", results)
	}

	// 命中恢复只取带 nuclei 事件的行，并带回发现编号与 tags。
	hits, err := d.ListScanTaskPOCHits(task.ID, keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %+v", hits)
	}
	for _, h := range hits {
		if h.Raw == nil || h.Raw["template-id"] == nil {
			t.Fatalf("恢复的命中缺少 nuclei 事件原文：%+v", h)
		}
	}
	var info struct {
		Tags string `json:"tags"`
	}
	raw, _ := json.Marshal(hits[0].Raw["info"])
	if err := json.Unmarshal(raw, &info); err != nil || !strings.Contains(info.Tags, "sqli") {
		t.Fatalf("tags 没能原样恢复（深挖分流靠它）：%s", raw)
	}
}

func mustInts(results, findings int, err error) (int, int, error) { return results, findings, err }

// 重跑（QueueScanTask）必须把上一轮的检查点清干净，否则新一轮会继承「已扫完」的进度；
// 而且要先锁住确认可重跑再删产出。
func TestScanQueueResetsCheckpoint(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateScanTask(ScanTaskInput{
		Name: "d5-queue-reset", Targets: []string{"http://10.0.0.1/"}, Mode: "auto", Ports: "80",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM scan_tasks WHERE id=$1`, task.ID) })

	layout := []ScanShardSpec{{Ordinal: 0, Chunk: 0, Target: "http://10.0.0.1/", Templates: 10}}
	if _, err := d.SaveScanPlan(task.ID, `{"phase":"poc","targets":["http://10.0.0.1/"],"template_ids":[1],"template_keys":["a"],"digests":["d"]}`, layout); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddScanTaskResult(task.ID, 0, ScanTaskResult{
		TemplateID: "a", MatchedAt: "http://10.0.0.1/x",
		Raw: map[string]any{"template-id": "a", "info": map[string]any{"severity": "high"}},
	}); err != nil {
		t.Fatal(err)
	}

	// 正在跑的任务不能被打断式重排：先锁住确认可重跑，再删产出。
	if _, err := d.Exec(`UPDATE scan_tasks SET status='running', stage='scan' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	ok, err := d.QueueScanTask(task.ID)
	if err != nil || ok {
		t.Fatalf("running 任务不该被重排：ok=%v err=%v", ok, err)
	}
	if rows, _, _ := mustInts(d.ScanPOCResultCounts(task.ID, []string{"a"})); rows != 1 {
		t.Fatalf("被拒绝的重排不该删掉产出：rows=%d", rows)
	}

	if _, err := d.Exec(`UPDATE scan_tasks SET status='done', stage='done' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.QueueScanTask(task.ID); err != nil || !ok {
		t.Fatalf("已完成任务应可重排：ok=%v err=%v", ok, err)
	}
	got, err := d.GetScanTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Plan != "" || got.ResumeRequested || got.CanResume {
		t.Fatalf("重排后仍带着上一轮检查点：plan=%q resume=%v can=%v", got.Plan, got.ResumeRequested, got.CanResume)
	}
	var shardCount int
	if err := d.QueryRow(`SELECT count(*) FROM scan_task_shards WHERE scan_task_id=$1`, task.ID).Scan(&shardCount); err != nil {
		t.Fatal(err)
	}
	if shardCount != 0 {
		t.Fatalf("重排后分片行没清干净：%d", shardCount)
	}
	if rows, _, _ := mustInts(d.ScanPOCResultCounts(task.ID, []string{"a"})); rows != 0 {
		t.Fatalf("重排后结果行应清空，得到 %d", rows)
	}
}

// 服务重启后的恢复文案不能对没有检查点的任务承诺「可续扫」。
func TestScanRecoveryMessages(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	inputs := map[string]string{
		"d5-recover-poc":  `{"phase":"poc"}`,
		"d5-recover-post": `{"phase":"postprocess"}`,
		"d5-recover-none": `{}`,
	}
	ids := map[string]int64{}
	for name, plan := range inputs {
		task, err := d.CreateScanTask(ScanTaskInput{Name: name, Targets: []string{"http://10.0.0.1/"}, Mode: "auto", Ports: "80"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM scan_tasks WHERE id=$1`, task.ID) })
		if _, err := d.Exec(`UPDATE scan_tasks SET status='running', plan=$2::jsonb WHERE id=$1`, task.ID, plan); err != nil {
			t.Fatal(err)
		}
		ids[name] = task.ID
	}
	// poc 那条还要有分片行才算真有检查点。
	if _, err := d.Exec(`INSERT INTO scan_task_shards(scan_task_id, ordinal, chunk, target, templates) VALUES ($1,0,0,'http://10.0.0.1/',10)`,
		ids["d5-recover-poc"]); err != nil {
		t.Fatal(err)
	}
	n, err := d.RecoverInterruptedScanTasks()
	if err != nil {
		t.Fatal(err)
	}
	if n < 3 {
		t.Fatalf("应恢复 3 条中断任务，实际 %d", n)
	}
	for name, want := range map[string]string{
		"d5-recover-poc":  "可用「续扫」",
		"d5-recover-post": "不支持续跑",
		"d5-recover-none": "未建立 POC 分片检查点",
	} {
		got, err := d.GetScanTask(ids[name])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got.Error, want) {
			t.Fatalf("%s 的恢复文案不对：error=%q，应含 %q", name, got.Error, want)
		}
	}
}

// 排队原因只能写在还在排队的任务上：正在跑的任务的 progress 由执行器整体覆盖，
// 从旁边往里塞一个键会被下一次进度刷新无声吃掉，看起来像「写了但没生效」。
func TestQueueNoteOnlyOnQueued(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	queued, err := d.CreateScanTask(ScanTaskInput{Name: "f6-note-queued", Targets: []string{"http://10.0.0.1/"}, Mode: "auto", Ports: "80", Proxy: "socks5://10.0.0.9:1080"})
	if err != nil {
		t.Fatal(err)
	}
	running, err := d.CreateScanTask(ScanTaskInput{Name: "f6-note-running", Targets: []string{"http://10.0.0.1/"}, Mode: "auto", Ports: "80", Proxy: "socks5://10.0.0.9:1080"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM scan_tasks WHERE id IN ($1,$2)`, queued.ID, running.ID)
	})
	if _, err := d.Exec(`UPDATE scan_tasks SET status='running', stage='scan' WHERE id=$1`, running.ID); err != nil {
		t.Fatal(err)
	}

	note := "隧道/代理 10.0.0.9:1080 上已有 1 个任务在跑（预算 1），排队等待"
	for _, id := range []int64{queued.ID, running.ID} {
		if err := d.SetScanTaskQueueNote(id, note); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := d.GetScanTask(queued.ID); got.Progress["queue_note"] != note {
		t.Fatalf("排队任务没记下原因：%v", got.Progress)
	}
	if got, _ := d.GetScanTask(running.ID); got.Progress["queue_note"] != nil {
		t.Fatalf("运行中的任务被写进了排队原因：%v", got.Progress)
	}

	// 同一句话重复写不产生新写入（认领循环每 30 秒跑一次，不能每次都摸一遍行）。
	if err := d.SetScanTaskQueueNote(queued.ID, note); err != nil {
		t.Fatal(err)
	}
	if err := d.SetScanTaskQueueNote(queued.ID, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.GetScanTask(queued.ID); got.Progress["queue_note"] != nil {
		t.Fatalf("清空排队原因没生效：%v", got.Progress)
	}

	// 候选列表按 FIFO，并原样带上代理串（端点归一化在 server 侧只做一次）。
	candidates, err := d.QueuedScanProxies(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) == 0 || candidates[0].ID != queued.ID || candidates[0].Proxy != "socks5://10.0.0.9:1080" {
		t.Fatalf("排队候选不对：%+v", candidates)
	}
}
