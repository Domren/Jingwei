package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/pocparse"
	"github.com/Autumn-27/jingwei/scanner"
)

// D5 的分片布局必须只由计划决定：同一个计划算两遍要得到逐格一致的结果，否则续扫时
// 「第 3 片已经跑过」这类判断根本没有意义。
func TestScanShardLayoutDeterministic(t *testing.T) {
	p := scanPlan{
		Phase: scanPhasePOC, TemplateChunk: 2, UnitBudget: 4,
		Targets:      []string{"http://10.0.0.1/", "http://10.0.0.2/", "http://10.0.0.3/"},
		TemplateIDs:  []int64{1, 2, 3, 4, 5},
		TemplateKeys: []string{"t1", "t2", "t3", "t4", "t5"},
		Digests:      []string{"d1", "d2", "d3", "d4", "d5"},
	}
	templates := make([]scanner.NucleiTemplate, 0, len(p.TemplateKeys))
	for _, k := range p.TemplateKeys {
		templates = append(templates, scanner.NucleiTemplate{ID: k, Content: "http:\n  - raw:\n      - |\n        GET / HTTP/1.1\n"})
	}
	runs := scanShardRuns(p, templates)
	if !reflect.DeepEqual(runs, scanShardRuns(p, templates)) {
		t.Fatal("同一个计划两次算出的布局不一致，续扫的进度判断无从成立")
	}
	// chunk=2 → 3 段模板（2/2/1）。每段按单元预算 4 分目标：前两段每片 2 个目标 → 2 片，
	// 最后一段只有 1 条模板 → 3 个目标都装得下 → 1 片。
	if len(runs) != 5 {
		t.Fatalf("runs = %d, want 5：%+v", len(runs), specsOf(runs))
	}
	seen := map[string]int{}
	units := 0
	for i, sr := range runs {
		if sr.ordinal != i {
			t.Fatalf("分片编号必须连续：第 %d 个片编号是 %d", i, sr.ordinal)
		}
		// 片内模板要和计划里的顺序严丝合缝：布局校验按顺序切片重建，错位等于扫错东西。
		wantFirst := p.TemplateKeys[sr.chunk*p.TemplateChunk]
		if sr.templates[0].ID != wantFirst {
			t.Fatalf("第 %d 片应 %s 开头，实际 %s 开头", i, wantFirst, sr.templates[0].ID)
		}
		if len(sr.templates)*len(sr.targets) > p.UnitBudget {
			t.Fatalf("分片 %d 超出单元预算：%d × %d", i, len(sr.templates), len(sr.targets))
		}
		units += len(sr.templates) * len(sr.targets)
		for _, tpl := range sr.templates {
			for _, target := range sr.targets {
				key := tpl.ID + "|" + target
				seen[key]++
			}
		}
	}
	// 覆盖矩阵：每条模板 × 每个目标恰好一次。少一次是漏扫，多一次是重跑没被布局识别出来。
	want := len(p.TemplateKeys) * len(p.Targets)
	if len(seen) != want {
		t.Fatalf("覆盖 %d 组，应为 %d 组", len(seen), want)
	}
	for key, n := range seen {
		if n != 1 {
			t.Fatalf("%s 被安排了 %d 次", key, n)
		}
	}
	if units != want {
		t.Fatalf("总单元数 %d 与覆盖矩阵 %d 不符", units, want)
	}
	// 段在前、目标在后：模板段是按危险等级排的，先让高危段覆盖所有目标。
	if runs[0].chunk != 0 || runs[1].chunk != 0 || runs[2].chunk != 1 {
		t.Fatalf("分片顺序不对：%+v", specsOf(runs))
	}
}

func specsOf(runs []scanShardRun) []db.ScanShardSpec {
	out := make([]db.ScanShardSpec, 0, len(runs))
	for _, sr := range runs {
		out = append(out, sr.spec())
	}
	return out
}

// 计划里钉的不只是「哪些模板」，还有内容摘要与分片参数：续扫要能发现 POC 库在中断期间
// 被人改过。解析时的每一道拒绝都对应一种会被谎报的情况。
func TestScanPlanPinAndParse(t *testing.T) {
	templates := []scanner.NucleiTemplate{
		{ID: "a", Content: "http:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n"},
		{ID: "b", Content: "http:\n  - raw:\n      - |\n        GET /b HTTP/1.1\n"},
	}
	p := newScanPlan([]string{"http://10.0.0.1/"}, templates, []int64{7, 8}, nil, nil)
	if p.Phase != scanPhasePOC || len(p.Digests) != 2 || p.Digests[0] == p.Digests[1] {
		t.Fatalf("计划没有钉住模板摘要：%+v", p)
	}
	if !strings.Contains(p.JSON(), `"digests"`) || !strings.Contains(p.JSON(), `"template_chunk"`) {
		t.Fatalf("计划 JSON 少了必要字段：%s", p.JSON())
	}
	got, err := parseScanPlan(p.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Digests, p.Digests) || !reflect.DeepEqual(got.TemplateIDs, []int64{7, 8}) {
		t.Fatalf("计划读回不一致：%+v", got)
	}

	for _, c := range []struct {
		name, plan, want string
	}{
		{"空计划", "", "没有续扫计划"},
		{"损坏计划", "{", "无法解析"},
		{"不在 poc 阶段", `{"phase":"postprocess","targets":["a"],"template_ids":[1],"template_keys":["a"],"digests":["d"]}`, "只有 POC 分片阶段可以续跑"},
		{"摘要缺失", `{"phase":"poc","targets":["a"],"template_ids":[1],"template_keys":["a"],"digests":[]}`, "计划不完整"},
		{"没有目标", `{"phase":"poc","targets":[],"template_ids":[1],"template_keys":["a"],"digests":["d"]}`, "计划不完整"},
	} {
		if _, err := parseScanPlan(c.plan); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: 应报「%s」，实际 err=%v", c.name, c.want, err)
		}
	}
}

// POC 被改动、停用或删除时必须拒绝续扫：把旧的分片进度拼到新的模板集合上，
// 报出来的「已覆盖」就是假的。
func TestScanPinnedTemplatesRejectsChangedPOC(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM poc_templates WHERE source=$1`, "d5-pin") })

	content := "id: d5-pin-a\nhttp:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n        Host: {{Hostname}}\n"
	mk := func(shortID, name string) int64 {
		p, err := pg.CreatePOCTemplate(&pocparse.Template{
			TemplateID: shortID, Name: name, Severity: "high", Protocol: "http", Content: content,
		}, "d5-pin", "")
		if err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	idA, idB := mk("d5-pin-a", "钉住 A"), mk("d5-pin-b", "钉住 B")

	templates := []scanner.NucleiTemplate{{ID: "d5-pin-a", Content: content}, {ID: "d5-pin-b", Content: content}}
	plan := newScanPlan([]string{"http://10.0.0.1/"}, templates, []int64{idA, idB}, nil, nil)
	r := &scanRun{s: s, pg: pg, task: &db.ScanTask{ID: 1, Name: "d5"}, ctx: context.Background(), progress: map[string]any{}}

	got, err := r.pinnedTemplates(plan)
	if err != nil {
		t.Fatalf("未改动的模板应能重建：%v", err)
	}
	if len(got) != 2 || got[0].ID != "d5-pin-a" || got[1].ID != "d5-pin-b" {
		t.Fatalf("模板顺序必须与计划一致（布局按顺序切片）：%+v", got)
	}

	if _, err := pg.Exec(`UPDATE poc_templates SET content=$2 WHERE id=$1`, idA, content+"# 有人改过\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.pinnedTemplates(plan); err == nil || !strings.Contains(err.Error(), "内容已改动") {
		t.Fatalf("模板内容被改后应拒绝续扫，得到：%v", err)
	}
	if _, err := pg.Exec(`UPDATE poc_templates SET content=$2 WHERE id=$1`, idA, content); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE poc_templates SET enabled=false WHERE id=$1`, idB); err != nil {
		t.Fatal(err)
	}
	if _, err := r.pinnedTemplates(plan); err == nil || !strings.Contains(err.Error(), "停用") {
		t.Fatalf("模板被停用应拒绝续扫，得到：%v", err)
	}
	if _, err := pg.Exec(`UPDATE poc_templates SET enabled=true WHERE id=$1`, idB); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`DELETE FROM poc_templates WHERE id=$1`, idA); err != nil {
		t.Fatal(err)
	}
	if _, err := r.pinnedTemplates(plan); err == nil || !strings.Contains(err.Error(), "删除") {
		t.Fatalf("模板被删除应拒绝续扫，得到：%v", err)
	}
}

// 续扫准入：只有停在 poc 阶段、留有分片行、且当前仍被平台允许的任务能排队。
// 状态与原因都要分得开，否则用户只能对着一个笼统的 400 猜。
func TestScanResumeAPI(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM scan_tasks WHERE name LIKE 'd5-resume-%'`) })

	task, err := pg.CreateScanTask(db.ScanTaskInput{
		Name: "d5-resume-api", Targets: []string{"http://10.0.0.1/"}, Mode: "auto", Ports: "80",
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(id int64) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.SetPathValue("id", jsonInt(id))
		rec := httptest.NewRecorder()
		s.resumeScanTask(rec, req)
		return rec
	}
	setStatus := func(status string) {
		t.Helper()
		if _, err := pg.Exec(`UPDATE scan_tasks SET status=$2, stage=$2 WHERE id=$1`, task.ID, status); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name string, rec *httptest.ResponseRecorder, code int, want string) {
		t.Helper()
		if rec.Code != code || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("%s: 应 %d 且含 %q，实际 %d %s", name, code, want, rec.Code, rec.Body.String())
		}
	}

	check("不存在的任务", do(99999999), http.StatusNotFound, "不存在")
	setStatus("running")
	check("进行中", do(task.ID), http.StatusConflict, "正在进行中")
	setStatus("queued")
	check("排队中", do(task.ID), http.StatusConflict, "正在进行中")
	setStatus("done")
	check("已完成", do(task.ID), http.StatusConflict, "已完成")

	// 失败但没有检查点：中断在 POC 分片之前，续扫无从判断哪些片是空的。
	setStatus("failed")
	check("无检查点", do(task.ID), http.StatusConflict, "不可续扫")

	layout := []db.ScanShardSpec{{Ordinal: 0, Chunk: 0, Target: "http://10.0.0.1/", Templates: 4}}
	plan := scanPlan{Phase: scanPhasePOC, TemplateChunk: 4, UnitBudget: 4000,
		Targets: []string{"http://10.0.0.1/"}, TemplateIDs: []int64{1}, TemplateKeys: []string{"a"}, Digests: []string{"d"}}
	if _, err := pg.SaveScanPlan(task.ID, plan.JSON(), layout); err != nil {
		t.Fatal(err)
	}
	// 授权清单管得住续扫：中断期间被移出的目标，不该因为「上次能扫」而继续打。
	restore := settingGuardMode(t, pg, "strict")
	defer restore()
	auth, err := pg.CreateAuthorization(db.AuthorizationInput{
		Name: "统一测试-d5续扫", Targets: []string{"203.0.113.0/24"}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM authorizations WHERE id=$1`, auth.ID) })
	check("范围外目标", do(task.ID), http.StatusBadRequest, "未发起续扫")
	if got, _ := pg.GetScanTask(task.ID); got.Status != "failed" {
		t.Fatalf("被拒绝的续扫不该改任务状态：%s", got.Status)
	}
	// 把目标纳回授权范围就该放行：判定用的是现场清单，不是建任务时那一份。
	if _, err := pg.Exec(`UPDATE authorizations SET targets='["203.0.113.0/24","10.0.0.1"]'::jsonb WHERE id=$1`, auth.ID); err != nil {
		t.Fatal(err)
	}

	rec := do(task.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("可续扫任务应 200：%d %s", rec.Code, rec.Body.String())
	}
	got, err := pg.GetScanTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "queued" || !got.ResumeRequested || got.Error != "" {
		t.Fatalf("续扫入队状态不对：status=%s resume=%v error=%q", got.Status, got.ResumeRequested, got.Error)
	}
	var stored scanPlan
	if err := json.Unmarshal([]byte(got.Plan), &stored); err != nil || !reflect.DeepEqual(stored.Digests, plan.Digests) {
		t.Fatalf("排队时计划被改动：%q err=%v", got.Plan, err)
	}

	// 收尾阶段的任务不再可续（深挖/基线不能被重放）。
	if _, err := pg.Exec(`UPDATE scan_tasks SET status='running' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetScanPlanPhase(task.ID, scanPhasePostprocess); err != nil {
		t.Fatal(err)
	}
	setStatus("failed")
	check("postprocess 阶段", do(task.ID), http.StatusConflict, "不可续扫")
}

// 收尾用的命中要从库里恢复，而不是只拿本轮内存里的结果：续扫时前面几片是上次跑的，
// 只数本轮就等于把首轮扫出来的高危漏洞漏掉。tags 必须跟着回来——sqlmap/dalfox 分流靠它。
func TestScanRestorePOCHitsFromDB(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM scan_tasks WHERE name='d5-restore'`) })
	task, err := pg.CreateScanTask(db.ScanTaskInput{
		Name: "d5-restore", Targets: []string{"http://10.0.0.1/"}, Mode: "auto", Ports: "80",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := func(id string) map[string]any {
		return map[string]any{
			"template-id": id, "host": "10.0.0.1", "matched-at": "http://10.0.0.1/" + id,
			"type": "http", "curl-command": "curl 'http://10.0.0.1/" + id + "'",
			"info": map[string]any{"name": "命中 " + id, "severity": "critical", "tags": []any{"sqli", "cgi"}},
		}
	}
	nucleiID, _, err := pg.UpsertFinding(0, 0, "hit-a", "命中 a", "critical", "s", "e", fmt.Sprintf("scan:%d", task.ID), nil, "d5-hit-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.AddScanTaskResult(task.ID, nucleiID, db.ScanTaskResult{
		TemplateID: "hit-a", Name: "命中 a", Severity: "critical", Host: "10.0.0.1",
		MatchedAt: "http://10.0.0.1/hit-a", Type: "http", Curl: "curl 'http://10.0.0.1/hit-a'", Raw: event("hit-a"),
	}); err != nil {
		t.Fatal(err)
	}
	// 同表的其它写入方不该被当成 POC 命中。
	if _, err := pg.AddScanTaskResult(task.ID, 0, db.ScanTaskResult{
		TemplateID: "dir-enum:robots", MatchedAt: "http://10.0.0.1/robots.txt",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.AddScanTaskResult(task.ID, 0, db.ScanTaskResult{
		TemplateID: "hit-b", MatchedAt: "http://10.0.0.1/hit-b", Raw: map[string]any{"source": "deep"},
	}); err != nil {
		t.Fatal(err)
	}

	r := &scanRun{s: s, pg: pg, task: task, ctx: context.Background(), progress: map[string]any{}}
	plan := scanPlan{TemplateKeys: []string{"hit-a", "hit-b", "dir-enum:robots"}}
	hits, findingIDs, err := r.restorePOCHits(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].TemplateID != "hit-a" {
		t.Fatalf("只应恢复 nuclei 事件形状的 POC 命中：%+v", hits)
	}
	if hits[0].Severity != "critical" || strings.Join(hits[0].Tags, ",") != "sqli,cgi" {
		t.Fatalf("恢复的命中少了等级或 tags（深挖分流要靠它们）：%+v", hits[0])
	}
	if hits[0].Curl == "" || hits[0].MatchedAt != "http://10.0.0.1/hit-a" {
		t.Fatalf("恢复的命中少了 curl/匹配地址：%+v", hits[0])
	}
	if got := findingIDs[scanResultKey(hits[0])]; got != nucleiID {
		t.Fatalf("发现编号没有跟着恢复：got=%d want=%d", got, nucleiID)
	}
	if _, err := pg.Exec(`DELETE FROM findings WHERE id=$1`, nucleiID); err != nil {
		t.Fatalf("清理测试发现失败：%v", err)
	}
}

// 每一片执行前重新问策略，用的目标是这一片自己的：一次续扫可能横跨十几个主机，
// 只按「任务最初的输入」放行会让被移出授权的主机继续挨打。
func TestScanShardGuardUsesFreshPolicy(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM authorizations`)
		_, _ = pg.Exec(`DELETE FROM asset_intercept_rules WHERE comment LIKE 'd5-%'`)
	})
	r := &scanRun{s: s, pg: pg, task: &db.ScanTask{ID: 1, Name: "d5"}, ctx: context.Background(), progress: map[string]any{}}

	restore := settingGuardMode(t, pg, "strict")
	defer restore()
	if _, err := pg.CreateAuthorization(db.AuthorizationInput{
		Name: "统一测试-d5分片", Targets: []string{"203.0.113.0/24"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if deny, _ := r.shardGuard([]string{"http://10.0.0.1/"}); deny == "" {
		t.Fatal("范围外分片目标应被拒")
	}
	if deny, warn := r.shardGuard([]string{"http://203.0.113.20/"}); deny != "" || warn != "" {
		t.Fatalf("授权内的分片目标不该被拦：%q / %q", deny, warn)
	}
	// 清单改完立刻生效：片与片之间可能隔着几十分钟，进程级 30 秒缓存不能成为放行理由。
	if _, err := pg.Exec(`UPDATE authorizations SET targets='["10.0.0.0/8"]' WHERE name=$1`, "统一测试-d5分片"); err != nil {
		t.Fatal(err)
	}
	if deny, warn := r.shardGuard([]string{"http://10.0.0.1/"}); deny != "" || warn != "" {
		t.Fatalf("授权范围调整后应立即放行，得到 %q / %q", deny, warn)
	}

	// 资产禁令同样要在每一片前重问：它比授权清单更容易在扫描期间被临时加上。
	if _, err := pg.CreateAssetInterceptRule("fuzzy_domain", "blocked.example.com", "d5-禁令", true); err != nil {
		t.Fatal(err)
	}
	if deny, _ := r.shardGuard([]string{"http://blocked.example.com/"}); deny == "" || !strings.Contains(deny, "拦截") {
		t.Fatalf("命中资产禁令的分片应被拒，得到：%q", deny)
	}
	// 读不到策略数据时按拒绝处理（与 guard 其它地方一致），不能静默放行。
	if deny, _ := r.shardGuard([]string{":::不是目标:::"}); deny == "" {
		t.Fatal("目标解析失败必须给出拒绝理由，不能当成放行")
	}
}
