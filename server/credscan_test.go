package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/scanner"
)

// credFakeServerAdapter 用「口令 root 即命中」的假协议把「任务框架 → 引擎 → 落库 →
// API」整条链接起来。真协议的认证正确性在 scanner 的真机验证里，这里只验编排。
type credFakeServerAdapter struct{}

func (credFakeServerAdapter) Protocol() string { return "credtest-srv" }

func (credFakeServerAdapter) Identify(context.Context, scanner.CredEndpoint) (bool, string, error) {
	return true, "CREDTEST banner", nil
}

func (credFakeServerAdapter) Try(_ context.Context, ep scanner.CredEndpoint, cred scanner.Credential) (scanner.CredAttempt, error) {
	res := scanner.CredAttempt{Host: ep.Host, Port: ep.Port, Protocol: ep.Protocol, Cred: cred,
		RawReq: []byte("AUTH " + cred.Password + "\r\n"), Attempts: 1}
	if cred.Username == "root" && cred.Password == "root" {
		res.Outcome, res.Banner, res.RawResp = scanner.CredHit, "+OK", []byte("+OK\r\n")
	} else {
		res.Outcome, res.Banner, res.RawResp = scanner.CredDeny, "-ERR", []byte("-ERR\r\n")
	}
	return res, nil
}

func init() { scanner.RegisterCredAdapter(credFakeServerAdapter{}) }

func newCredTestServer(t *testing.T) (*Server, context.CancelFunc) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	if _, err := m.pg.Exec(`DELETE FROM cred_tasks`); err != nil {
		t.Fatalf("clean cred tasks: %v", err)
	}
	s := newAdmissionTestServer(m, nil)
	ctx, cancel := context.WithCancel(context.Background())
	s.credMgr = newCredManager(s)
	s.credMgr.start(ctx)
	t.Cleanup(cancel)
	return s, cancel
}

func credPost(t *testing.T, h http.HandlerFunc, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestCredTaskAPIRejectsUnsupportedAndBadInput(t *testing.T) {
	s, _ := newCredTestServer(t)

	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"不支持的三档协议", map[string]any{
			"targets": []string{"10.0.0.1"}, "protocols": []string{"rdp"}}, "该协议暂不支持"},
		{"二档协议带降级原因", map[string]any{
			"targets": []string{"10.0.0.1"}, "protocols": []string{"mssql"}}, "TDS"},
		{"没有适配器的协议", map[string]any{
			"targets": []string{"10.0.0.1"}, "protocols": []string{"snmp"}}, "该协议暂不支持"},
		{"空目标", map[string]any{
			"targets": []string{" "}, "protocols": []string{"ssh"}}, "至少需要一个目标"},
		{"非法目标", map[string]any{
			"targets": []string{"http://"}, "protocols": []string{"ssh"}}, "无效"},
		{"空协议", map[string]any{
			"targets": []string{"10.0.0.1"}}, "至少勾选一个协议"},
		{"未知字典档", map[string]any{
			"targets": []string{"10.0.0.1"}, "protocols": []string{"ssh"}, "dict_profile": "big"}, "字典档不存在"},
	}
	for _, c := range cases {
		rec := credPost(t, s.createCredTask, c.body)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), c.want) {
			t.Fatalf("%s: code=%d body=%s", c.name, rec.Code, rec.Body.String())
		}
	}

	// 校验失败不该留下任何任务行。
	var n int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM cred_tasks`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("被拒的请求留下了 %d 条任务", n)
	}
}

func TestCredTaskRunsToCompletionAndPersistsRows(t *testing.T) {
	s, _ := newCredTestServer(t)

	rec := credPost(t, s.createCredTask, map[string]any{
		"name":      "假协议流水线",
		"targets":   []string{"127.0.0.1:1"},
		"protocols": []string{"credtest-srv"},
		"options":   map[string]any{"concurrency": 2, "rate_limit": 0, "budget_seconds": 60},
	})
	if rec.Code != 200 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == 0 {
		t.Fatalf("create response: %s", rec.Body.String())
	}

	// 执行是异步的：轮询详情直到终态。命中之后该端点不再尝试别的凭据，
	// 所以内置字典（首条 root/root）应当恰好产出一行命中。
	var task map[string]any
	deadline := time.Now().Add(15 * time.Second)
	for {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetPathValue("id", jsonInt(created.ID))
		rec = httptest.NewRecorder()
		s.getCredTask(rec, req)
		if rec.Code != 200 {
			t.Fatalf("detail: %d %s", rec.Code, rec.Body.String())
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &task); err != nil {
			t.Fatal(err)
		}
		status, _ := task["task"].(map[string]any)["status"].(string)
		if status == "done" || status == "failed" || status == "canceled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("任务没有在期限内结束: %s", rec.Body.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	tk := task["task"].(map[string]any)
	if tk["status"] != "done" {
		t.Fatalf("status = %v error = %v", tk["status"], tk["error"])
	}
	if logText, _ := tk["log"].(string); !strings.Contains(logText, "收尾：命中 1") {
		t.Fatalf("任务日志没有收尾摘要: %q", logText)
	}
	counts, _ := task["counts"].(map[string]any)
	if counts["hit"] != float64(1) {
		t.Fatalf("counts = %+v", counts)
	}

	// 结果行：证据与凭据都要在，报告才有可复现的内容。
	req := httptest.NewRequest(http.MethodGet, "/?outcome=hit", nil)
	req.SetPathValue("id", jsonInt(created.ID))
	rec = httptest.NewRecorder()
	s.listCredTaskResults(rec, req)
	if rec.Code != 200 {
		t.Fatalf("results: %d %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Results []struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Outcome  string `json:"outcome"`
			Evidence string `json:"evidence"`
			Protocol string `json:"protocol"`
		} `json:"results"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Results) != 1 {
		t.Fatalf("results = %+v", page)
	}
	r := page.Results[0]
	if r.Outcome != "hit" || r.Username != "root" || r.Password != "root" || r.Protocol != "credtest-srv" {
		t.Fatalf("row = %+v", r)
	}
	if !strings.Contains(r.Evidence, "凭据: root / root") || !strings.Contains(r.Evidence, "AUTH root") {
		t.Fatalf("evidence = %q", r.Evidence)
	}

	// B9：命中要落成三条事实——资产服务行、发现、凭据台账——并且凭据状态是
	// untested（没有任何动作被自动触发，用不用由人决定）。
	var vulnclass, worker string
	if err := s.m.pg.QueryRow(`SELECT vulnclass, worker FROM findings
		WHERE dedupe_key LIKE 'credscan:%' ORDER BY id DESC LIMIT 1`).Scan(&vulnclass, &worker); err != nil {
		t.Fatalf("命中没有写成发现: %v", err)
	}
	if vulnclass != "weak-credential" || worker != "credscan:"+jsonInt(created.ID) {
		t.Fatalf("finding = %q / %q", vulnclass, worker)
	}
	var credSource, credStatus string
	if err := s.m.pg.QueryRow(`SELECT source, status FROM intranet_credentials
		WHERE host='127.0.0.1' AND port=1 AND username='root' ORDER BY id DESC LIMIT 1`).Scan(&credSource, &credStatus); err != nil {
		t.Fatalf("命中没有登记凭据台账: %v", err)
	}
	if credSource != "credscan" || credStatus != "untested" {
		t.Fatalf("credential = %q / %q（不允许自动标记或自动复用）", credSource, credStatus)
	}
	var services int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM assets
		WHERE type='service' AND port=1 AND service_name='credtest-srv'`).Scan(&services); err != nil {
		t.Fatal(err)
	}
	if services == 0 {
		t.Fatal("命中没有写成资产服务行")
	}
	t.Cleanup(func() {
		_, _ = s.m.pg.Exec(`DELETE FROM intranet_credentials WHERE source='credscan' AND port=1`)
		_, _ = s.m.pg.Exec(`DELETE FROM findings WHERE dedupe_key LIKE 'credscan:%'`)
		_, _ = s.m.pg.Exec(`DELETE FROM assets WHERE type='service' AND port=1 AND service_name='credtest-srv'`)
	})

	// 删除：先取消/结束的状态才允许删，结果行随任务级联消失。
	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	req.SetPathValue("id", jsonInt(created.ID))
	rec = httptest.NewRecorder()
	s.deleteCredTask(rec, req)
	if rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	var left int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM cred_results WHERE task_id=$1`, created.ID).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("结果行没有级联删除: %d", left)
	}
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// B10：导入的字典能被选用、被记进任务、删掉后不能再选；同名覆盖是显式的。
func TestCredDictImportAndUse(t *testing.T) {
	s, _ := newCredTestServer(t)
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM cred_dicts WHERE name IN ('acme','builtin')`) })

	rec := credPost(t, s.saveCredDict, map[string]any{
		"name": "acme", "content": "# 目标客户的默认口令\nroot:root\nadmin:Acme-2026\n\n",
	})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"entry_count":2`) {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	// 内置档不可覆盖。
	rec = credPost(t, s.saveCredDict, map[string]any{"name": "builtin", "content": "root:root"})
	if rec.Code != 400 {
		t.Fatalf("builtin 不该能被覆盖: %d %s", rec.Code, rec.Body.String())
	}

	// 协议目录里能看到导入档。
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	s.credProtocols(rec, req)
	if !strings.Contains(rec.Body.String(), `"acme"`) {
		t.Fatalf("protocols 未列出导入档: %s", rec.Body.String())
	}

	rec = credPost(t, s.createCredTask, map[string]any{
		"name": "用导入字典", "targets": []string{"127.0.0.1:1"},
		"protocols": []string{"credtest-srv"}, "dict_profile": "acme",
		"options": map[string]any{"budget_seconds": 60},
	})
	if rec.Code != 200 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ ID int64 }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	deadline := time.Now().Add(15 * time.Second)
	for {
		req = httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetPathValue("id", jsonInt(created.ID))
		rec = httptest.NewRecorder()
		s.getCredTask(rec, req)
		var detail struct {
			Task struct {
				Status string `json:"status"`
				Log    string `json:"log"`
			} `json:"task"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &detail)
		if detail.Task.Status == "done" || detail.Task.Status == "failed" {
			if !strings.Contains(detail.Task.Log, "字典 acme") {
				t.Fatalf("任务日志没有记下用的字典: %q", detail.Task.Log)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("任务没有结束: %s", rec.Body.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 删除后不能再选。
	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	req.SetPathValue("name", "acme")
	rec = httptest.NewRecorder()
	s.deleteCredDict(rec, req)
	if rec.Code != 200 {
		t.Fatalf("delete dict: %d %s", rec.Code, rec.Body.String())
	}
	rec = credPost(t, s.createCredTask, map[string]any{
		"targets": []string{"127.0.0.1:1"}, "protocols": []string{"credtest-srv"}, "dict_profile": "acme",
	})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "字典档不存在") {
		t.Fatalf("删掉后应当不能再选: %d %s", rec.Code, rec.Body.String())
	}
}
