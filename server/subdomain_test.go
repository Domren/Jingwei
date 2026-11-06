package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// 子域名枚举的服务层用例。引擎本身在 scanner/subdomain_test.go 里已经钉过，
// 这里钉的是「服务层会不会把结论说歪」：范围闸在什么位置生效、结果落到哪、
// 探测被拒时名字还在不在。

const subdomainTestPrefix = "统一测试-subdomain-"

func newSubdomainTestServer(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	pg := m.pg
	if _, err := pg.Exec(`DELETE FROM subdomain_tasks`); err != nil {
		t.Fatalf("clean subdomain tasks: %v", err)
	}
	s := newAdmissionTestServer(m, nil)
	// 调度循环故意不启动：用例直接驱动 execute()，真引擎在钩子里就被换掉了。
	// 起了循环反而会看到「假引擎没被调用、真 DNS 被调用」这种误导性失败。
	s.subMgr = newSubdomainManager(s)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM assets WHERE domain LIKE $1 OR url LIKE $2`,
			"%subdomain-test.internal", "http://198.51.100.%")
		_, _ = pg.Exec(`DELETE FROM authorizations`)
	})
	return s, pg
}

// stubSubdomainEngine 换掉引擎入口：用例不该依赖真实 DNS 与真实端口。
func stubSubdomainEngine(t *testing.T, enumerate func(context.Context, []string, scanner.SubdomainOptions) (scanner.SubdomainOutcome, error),
	discover func(context.Context, []scanner.Target, scanner.DiscoverOptions) (*scanner.DiscoverResult, error)) {
	t.Helper()
	oldEnum, oldDisc := subdomainEnumerate, subdomainDiscover
	subdomainEnumerate = enumerate
	if discover != nil {
		subdomainDiscover = discover
	}
	t.Cleanup(func() {
		subdomainEnumerate = oldEnum
		subdomainDiscover = oldDisc
	})
}

func TestSubdomainRunPersistsResultsAssetsAndProbes(t *testing.T) {
	s, pg := newSubdomainTestServer(t)
	const root = "subdomain-test.internal"
	outcome := scanner.SubdomainOutcome{
		Roots: []string{root}, Queried: 12, Candidates: 12,
		Found: []scanner.SubdomainFinding{
			{
				Name: "www." + root, Root: root, Source: scanner.SubdomainSourceInput,
				Records: []scanner.SubdomainRecord{
					{Type: scanner.SubdomainRecordA, Values: []string{"198.51.100.7"}},
					{Type: scanner.SubdomainRecordCNAME, Values: []string{"cdn.subdomain-test.internal"}},
				},
				IPs: []string{"198.51.100.7"},
			},
			{
				Name: "api." + root, Root: root, Source: scanner.SubdomainSourceDict,
				Records: []scanner.SubdomainRecord{{Type: scanner.SubdomainRecordAAAA, Values: []string{"2001:db8::7"}}},
				IPs:     []string{"2001:db8::7"},
			},
		},
	}
	var probed []string
	stubSubdomainEngine(t,
		func(context.Context, []string, scanner.SubdomainOptions) (scanner.SubdomainOutcome, error) {
			return outcome, nil
		},
		func(_ context.Context, targets []scanner.Target, _ scanner.DiscoverOptions) (*scanner.DiscoverResult, error) {
			for _, t := range targets {
				probed = append(probed, t.Host)
			}
			return &scanner.DiscoverResult{
				Ports:    []scanner.PortFinding{{IP: "198.51.100.7", Port: 80, Service: "http"}},
				Services: []scanner.WebService{{IP: "198.51.100.7", Host: "www." + root, URL: "http://198.51.100.7", StatusCode: 200}},
			}, nil
		})

	task, err := pg.CreateSubdomainTask(db.SubdomainTaskInput{
		Name: subdomainTestPrefix + "整链路", Targets: []string{root},
		Options: map[string]any{"probe_ports": true, "ports": "top100"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &subdomainRun{s: s, pg: pg, task: task, ctx: context.Background()}
	status, errMsg, summary := r.execute()
	if status != db.SubdomainTaskDone {
		t.Fatalf("应正常收尾：status=%s err=%s", status, errMsg)
	}
	if summary["found"] != 2 || summary["asset_rows"] != 3 {
		t.Fatalf("汇总不对：%+v", summary)
	}
	if !containsString(probed, "198.51.100.7") || !containsString(probed, "2001:db8::7") {
		t.Fatalf("解析出的 IP 没送去端口探测：%v", probed)
	}
	if summary["open_ports"] != 1 || summary["services"] != 1 {
		t.Fatalf("探测结果没进汇总：%+v", summary)
	}

	results, err := pg.ListSubdomainResults(task.ID, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("结果台账应有 2 条：%+v", results)
	}
	for _, res := range results {
		if res.Name == "www."+root {
			if len(res.Records) != 2 {
				t.Fatalf("A 与 CNAME 要各成一条记录：%+v", res.Records)
			}
			// 资产关联是「不需要手工搬运」的证据：没有它，用户还得自己去资产页找。
			if res.AssetID == nil {
				t.Fatal("结果没有关联到子域名资产")
			}
		}
	}

	// 资产侧：每个记录类型一行（与 (domain, record_type) 唯一键一致），IP 行带上探测到的端口。
	var subRows int
	if err := pg.QueryRow(`SELECT count(*) FROM assets WHERE type='subdomain' AND domain LIKE $1`,
		"%."+root).Scan(&subRows); err != nil {
		t.Fatal(err)
	}
	if subRows != 3 {
		t.Fatalf("应有 3 行子域名资产（www 的 A 与 CNAME、api 的 AAAA），得到 %d", subRows)
	}
	var portsJSON string
	if err := pg.QueryRow(`SELECT open_ports::text FROM assets WHERE type='ip' AND ip='198.51.100.7'`).Scan(&portsJSON); err != nil {
		t.Fatalf("探测到的端口没写进 IP 资产：%v", err)
	}
	if !strings.Contains(portsJSON, "80") {
		t.Fatalf("IP 资产的端口不对：%s", portsJSON)
	}
	var svcCount int
	if err := pg.QueryRow(`SELECT count(*) FROM assets WHERE type='service' AND url LIKE $1`,
		"http://198.51.100.7%").Scan(&svcCount); err != nil || svcCount != 1 {
		t.Fatalf("Web 服务资产应写进行（得到 %d，err=%v）——拓扑图上的 HTTP 节点就来自这里", svcCount, err)
	}

	// 报告要能直接贴进交付物：表头、来源中文、结论一句都在。
	md := subdomainMarkdown(&db.SubdomainTask{
		ID: task.ID, Name: subdomainTestPrefix + "整链路", Targets: []string{root}, Status: db.SubdomainTaskDone,
		Summary: map[string]any{"found": 2, "unresolved": 3, "probe_skipped": ""},
	}, results)
	for _, want := range []string{"子域名枚举（任务 #", "来源", "字典命中", "直接给出", "未判定 3 次（不等于不存在）"} {
		if !strings.Contains(md, want) {
			t.Fatalf("报告少了 %q：\n%s", want, md)
		}
	}
}

// 根域名不在授权清单里：整单拒绝，一次查询都不发。
func TestSubdomainRefusesDeniedRootBeforeAnyQuery(t *testing.T) {
	s, pg := newSubdomainTestServer(t)
	restore := settingGuardMode(t, pg, "strict")
	defer restore()
	if _, err := pg.CreateAuthorization(db.AuthorizationInput{
		Name: subdomainTestPrefix + "只授权别处", Targets: []string{"203.0.113.0/24"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	stubSubdomainEngine(t,
		func(context.Context, []string, scanner.SubdomainOptions) (scanner.SubdomainOutcome, error) {
			called = true
			return scanner.SubdomainOutcome{}, nil
		}, nil)

	task, err := pg.CreateSubdomainTask(db.SubdomainTaskInput{
		Name: subdomainTestPrefix + "范围外", Targets: []string{"subdomain-test.internal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &subdomainRun{s: s, pg: pg, task: task, ctx: context.Background()}
	status, errMsg, _ := r.execute()
	if status != db.SubdomainTaskFailed || !strings.Contains(errMsg, "未发起任何查询") {
		t.Fatalf("范围外根域名应被拒且说明没发包：status=%s msg=%s", status, errMsg)
	}
	if called {
		t.Fatal("被拒的任务还是调用了枚举引擎")
	}
	if n, err := pg.SubdomainResultCount(task.ID); err != nil || n != 0 {
		t.Fatalf("被拒的任务留下了 %d 条结果（err=%v）", n, err)
	}
}

// 域名在授权里、解析出的 IP 不在：只跳过探测，名字必须留下，原因必须写出来。
// 这一步最容易做错成「探测失败就整单失败」或「跳过当没发生」，两种都会让报告少说话。
func TestSubdomainSkipsProbeWhenIPsOutOfScope(t *testing.T) {
	s, pg := newSubdomainTestServer(t)
	restore := settingGuardMode(t, pg, "strict")
	defer restore()
	const root = "subdomain-test.internal"
	if _, err := pg.CreateAuthorization(db.AuthorizationInput{
		Name: subdomainTestPrefix + "只授权域名", Targets: []string{root}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	discovered := false
	stubSubdomainEngine(t,
		func(context.Context, []string, scanner.SubdomainOptions) (scanner.SubdomainOutcome, error) {
			return scanner.SubdomainOutcome{
				Roots: []string{root}, Found: []scanner.SubdomainFinding{{
					Name: "www." + root, Root: root, Source: scanner.SubdomainSourceInput,
					Records: []scanner.SubdomainRecord{{Type: scanner.SubdomainRecordA, Values: []string{"198.51.100.9"}}},
					IPs:     []string{"198.51.100.9"},
				}},
			}, nil
		},
		func(context.Context, []scanner.Target, scanner.DiscoverOptions) (*scanner.DiscoverResult, error) {
			discovered = true
			return &scanner.DiscoverResult{}, nil
		})

	task, err := pg.CreateSubdomainTask(db.SubdomainTaskInput{
		Name: subdomainTestPrefix + "IP 越界", Targets: []string{root}, Options: map[string]any{"probe_ports": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &subdomainRun{s: s, pg: pg, task: task, ctx: context.Background()}
	status, errMsg, summary := r.execute()
	if status != db.SubdomainTaskDone {
		t.Fatalf("探测被拒不该让整单失败：%s %s", status, errMsg)
	}
	if discovered {
		t.Fatal("IP 不在授权范围内还去探测了")
	}
	skipped, _ := summary["probe_skipped"].(string)
	if strings.TrimSpace(skipped) == "" {
		t.Fatalf("摘要必须写明为什么没探测：%+v", summary)
	}
	if summary["found"] != 1 {
		t.Fatalf("名字要留下：%+v", summary)
	}
	log, err := pg.GetSubdomainTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.Log, "端口探测被平台拒绝") {
		t.Fatalf("任务日志要写明跳过探测的原因：%q", log.Log)
	}
}

// 关掉探测开关时不该问范围，也不该出现「探测失败」的字样。
func TestSubdomainProbeDisabledByOption(t *testing.T) {
	s, pg := newSubdomainTestServer(t)
	stubSubdomainEngine(t,
		func(context.Context, []string, scanner.SubdomainOptions) (scanner.SubdomainOutcome, error) {
			return scanner.SubdomainOutcome{Found: []scanner.SubdomainFinding{{
				Name: "www.subdomain-test.internal", Root: "subdomain-test.internal",
				Source: scanner.SubdomainSourceInput, IPs: []string{"198.51.100.10"},
				Records: []scanner.SubdomainRecord{{Type: scanner.SubdomainRecordA, Values: []string{"198.51.100.10"}}},
			}}}, nil
		},
		func(context.Context, []scanner.Target, scanner.DiscoverOptions) (*scanner.DiscoverResult, error) {
			t.Fatal("关了探测还调用引擎")
			return nil, nil
		})
	task, err := pg.CreateSubdomainTask(db.SubdomainTaskInput{
		Name: subdomainTestPrefix + "关探测", Targets: []string{"subdomain-test.internal"},
		Options: map[string]any{"probe_ports": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &subdomainRun{s: s, pg: pg, task: task, ctx: context.Background()}
	status, _, summary := r.execute()
	if status != db.SubdomainTaskDone {
		t.Fatalf("status=%s", status)
	}
	if summary["probed_ips"] != 0 || !strings.Contains(summary["probe_skipped"].(string), "没开") {
		t.Fatalf("摘要要说明是设置里没开：%+v", summary)
	}
}

// 建任务的接口：IP-only 目标直接拒，且不留下任务行。
func TestSubdomainCreateRejectsIPOnlyTargets(t *testing.T) {
	s, pg := newSubdomainTestServer(t)
	rec := credPost(t, s.createSubdomainTask, map[string]any{
		"name": subdomainTestPrefix + "只有 IP", "targets": []string{"10.0.0.1", "192.168.0.0/24"},
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "根域名") {
		t.Fatalf("应 400 并说明要域名，得到 %d %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM subdomain_tasks WHERE name=$1`, subdomainTestPrefix+"只有 IP").Scan(&n); err != nil || n != 0 {
		t.Fatalf("被拒的请求留下了 %d 条任务（err=%v）", n, err)
	}
}

// 取消与批量删除的接口行为。
func TestSubdomainCancelAndBatchDelete(t *testing.T) {
	s, pg := newSubdomainTestServer(t)
	task, err := pg.CreateSubdomainTask(db.SubdomainTaskInput{
		Name: subdomainTestPrefix + "待取消", Targets: []string{"subdomain-test.internal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/subdomain/tasks/1/cancel", nil)
	req.SetPathValue("id", i64s(task.ID))
	rec := httptest.NewRecorder()
	s.cancelSubdomainTask(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("取消失败：%d %s", rec.Code, rec.Body.String())
	}
	got, err := pg.GetSubdomainTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != db.SubdomainTaskCanceled {
		t.Fatalf("状态应为已取消，得到 %s", got.Status)
	}
	// 已结束的任务再取消是 409，不是静默成功。
	rec = httptest.NewRecorder()
	s.cancelSubdomainTask(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("重复取消应 409，得到 %d", rec.Code)
	}

	rec = credPost(t, s.batchDeleteSubdomainTasks, map[string]any{"ids": []int64{task.ID}})
	if rec.Code != http.StatusOK {
		t.Fatalf("批量删除失败：%d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Deleted != 1 {
		t.Fatalf("删除条数不对：%s", rec.Body.String())
	}

	rec = credPost(t, s.batchDeleteSubdomainTasks, map[string]any{"ids": []int64{}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("空编号应 400，得到 %d", rec.Code)
	}
}

// 详情接口要带上结果条数：界面列表只显示任务行时，用户看不出这一轮跑出了多少东西。
func TestSubdomainGetTaskIncludesResultCount(t *testing.T) {
	s, pg := newSubdomainTestServer(t)
	task, err := pg.CreateSubdomainTask(db.SubdomainTaskInput{
		Name: subdomainTestPrefix + "详情", Targets: []string{"subdomain-test.internal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.InsertSubdomainResults(task.ID, []db.SubdomainResult{
		{Name: "a.subdomain-test.internal", Root: "subdomain-test.internal", Source: "dict"},
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/subdomain/tasks/1", nil)
	req.SetPathValue("id", i64s(task.ID))
	rec := httptest.NewRecorder()
	s.getSubdomainTask(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		ResultCount int `json:"result_count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.ResultCount != 1 {
		t.Fatalf("结果条数不对：%s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/subdomain/tasks/99999999", nil)
	req.SetPathValue("id", "99999999")
	rec = httptest.NewRecorder()
	s.getSubdomainTask(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("不存在应 404，得到 %d", rec.Code)
	}
}

func TestSubdomainSettingsFromOptions(t *testing.T) {
	set := subdomainSettingsFrom(map[string]any{
		"words":           "admin\napi , mail",
		"concurrency":     float64(999),
		"timeout_seconds": float64(0),
		"max_queries":     float64(-1),
		"ports":           "web",
		"public_sources":  []any{"CRTSH", " unknown "},
		"probe_ports":     false,
		"keep_wildcard":   true,
	})
	if strings.Join(set.Words, ",") != "admin,api,mail" {
		t.Fatalf("自定义字典解析不对：%v", set.Words)
	}
	if set.Concurrency != 16 || set.TimeoutSecs != subdomainDefaultTimeout || set.MaxQueries != 20000 {
		t.Fatalf("越界参数要收回默认值：%+v", set)
	}
	if set.ProbePorts {
		t.Fatal("probe_ports=false 应当生效")
	}
	if !set.KeepWildcard {
		t.Fatal("keep_wildcard 应当生效")
	}
	if strings.Join(set.Sources, ",") != "crtsh,unknown" {
		t.Fatalf("公开接口来源应原样保留（未知来源由引擎记为跳过而不是静默丢弃）：%v", set.Sources)
	}
	// 缺省即「探测端口 + 不用第三方」——默认值就是最保守的那一档。
	def := subdomainSettingsFrom(map[string]any{})
	if !def.ProbePorts || len(def.Sources) != 0 || def.Ports != subdomainDefaultPorts {
		t.Fatalf("默认口径不对：%+v", def)
	}
}

func TestSubdomainProgressWriterIsRateLimited(t *testing.T) {
	s, pg := newSubdomainTestServer(t)
	task, err := pg.CreateSubdomainTask(db.SubdomainTaskInput{Name: subdomainTestPrefix + "进度", Targets: []string{"x.internal"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = pg.Exec(`DELETE FROM subdomain_tasks WHERE id=$1`, task.ID) }()

	write := subdomainProgressWriter(s.m.pg, task.ID, 100)
	for i := 1; i <= 50; i++ {
		write(i, 0)
	}
	var progress map[string]any
	var raw string
	if err := pg.QueryRow(`SELECT progress::text FROM subdomain_tasks WHERE id=$1`, task.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(raw), &progress)
	// 限频生效时只写过一次：queried 应是第一次调用那个值，而不是 50。
	if got, _ := progress["queried"].(float64); got != 1 {
		t.Fatalf("进度每刷一次库就写一遍，会淹掉任务表：%+v", progress)
	}
}

// 台账写不进去时不能报完成：报告说「这一轮查到 2 条」而台账一行都查不到，
// 比直接失败更难发现。这里用外键违反造一次真实写入失败（任务行已不在）。
func TestSubdomainLedgerWriteFailureFailsTask(t *testing.T) {
	s, pg := newSubdomainTestServer(t)
	const root = "subdomain-test.internal"
	stubSubdomainEngine(t,
		func(context.Context, []string, scanner.SubdomainOptions) (scanner.SubdomainOutcome, error) {
			return scanner.SubdomainOutcome{Roots: []string{root}, Found: []scanner.SubdomainFinding{{
				Name: "www." + root, Root: root, Source: scanner.SubdomainSourceInput,
				Records: []scanner.SubdomainRecord{{Type: scanner.SubdomainRecordA, Values: []string{"198.51.100.11"}}},
				IPs:     []string{"198.51.100.11"},
			}}}, nil
		}, nil)
	task, err := pg.CreateSubdomainTask(db.SubdomainTaskInput{
		Name: subdomainTestPrefix + "台账写不进", Targets: []string{root},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 把任务行删掉：结果表的外键就会拒绝写入，这是最省事的一次真失败。
	if _, err := pg.Exec(`DELETE FROM subdomain_tasks WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	r := &subdomainRun{s: s, pg: pg, task: task, ctx: context.Background()}
	status, errMsg, summary := r.execute()
	if status != db.SubdomainTaskFailed || !strings.Contains(errMsg, "结果写入失败") {
		t.Fatalf("台账写入失败必须让任务失败：status=%s msg=%s", status, errMsg)
	}
	if summary["found"] == 1 {
		t.Fatalf("失败的任务不该在摘要里声称查到 1 条：%+v", summary)
	}
}
