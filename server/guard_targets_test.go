package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// 确定性任务（界面直接建的漏扫与弱口令检测）必须问目标策略。
//
// 这道闸此前只挂在 agent 工具与内网执行上：从界面点「新建」，客户授权清单管不住它，
// 弱口令检测还会对着不在授权范围内的主机一路发认证包（能把账号打进锁定，且不可撤回）。
// 三档语义都得钉：strict 拒绝、warn 放行但要留痕、off 完全不问。
func TestGuardCheckTargetsForDeterministicTasks(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	defer func() { _, _ = pg.Exec(`DELETE FROM authorizations`) }()
	restore := settingGuardMode(t, pg, "strict")
	defer restore()

	pol := newGuardTargetPolicy(pg)
	if deny, warn := guardCheckTargets(nil, nil, []string{"10.0.0.1"}); deny != "" || warn != "" {
		t.Fatalf("没有策略源时应放行，得到 deny=%q warn=%q", deny, warn)
	}
	if deny, warn := guardCheckTargets(pol, nil, nil); deny != "" || warn != "" {
		t.Fatalf("没有目标时不该有任何裁决，得到 deny=%q warn=%q", deny, warn)
	}

	// 平台里还没有任何有效授权：保持历史行为（不强制），否则整个功能一上线就全停。
	if deny, warn := guardCheckTargets(pol, nil, []string{"10.0.0.1"}); deny != "" || warn != "" {
		t.Fatalf("无有效授权时不该拦，得到 deny=%q warn=%q", deny, warn)
	}

	if _, err := pg.CreateAuthorization(db.AuthorizationInput{
		Name: "统一测试-guard", Targets: []string{"203.0.113.0/24"}, Exclusions: []string{"203.0.113.9"},
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	fresh := newGuardTargetPolicy(pg) // 绕开 30 秒授权缓存

	if deny, warn := guardCheckTargets(fresh, nil, []string{"10.0.0.1"}); deny == "" ||
		!strings.Contains(deny, "不在任何有效的客户授权清单内") {
		t.Fatalf("范围外目标在 strict 下应被拒并点名授权，得到 deny=%q warn=%q", deny, warn)
	}
	if deny, warn := guardCheckTargets(fresh, nil, []string{"203.0.113.10"}); deny != "" || warn != "" {
		t.Fatalf("授权内目标不该被拦：%q / %q", deny, warn)
	}
	// 命中排除项等于没授权：宁可拒了让人去改清单。
	if deny, _ := guardCheckTargets(fresh, nil, []string{"203.0.113.9"}); deny == "" {
		t.Fatal("排除项内的目标应被拒")
	}

	// warn：放行，但必须把话交回调用方写进日志——静默放行是「失败关闭」最坏的样子。
	restore()
	modeOff := settingGuardMode(t, pg, "warn")
	defer modeOff()
	if deny, warn := guardCheckTargets(newGuardTargetPolicy(pg), nil, []string{"10.0.0.1"}); deny != "" || warn == "" {
		t.Fatalf("warn 模式应只告警，得到 deny=%q warn=%q", deny, warn)
	}
	restore()
	if err := pg.SetSetting(settingGuardEnforcement, "off"); err != nil {
		t.Fatal(err)
	}
	if deny, warn := guardCheckTargets(newGuardTargetPolicy(pg), nil, []string{"10.0.0.1"}); deny != "" || warn != "" {
		t.Fatalf("off 模式应完全不问，得到 deny=%q warn=%q", deny, warn)
	}
}

// 建任务时就拒：不建任务行、不发一个包，原因要点名是哪条授权不管用。
func TestCredscanCreateRejectsTargetOutsideAuthorization(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	defer func() { _, _ = pg.Exec(`DELETE FROM authorizations`) }()
	restore := settingGuardMode(t, pg, "strict")
	defer restore()
	if _, err := pg.CreateAuthorization(db.AuthorizationInput{
		Name: "统一测试-cred", Targets: []string{"203.0.113.0/24"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	rec := credPost(t, s.createCredTask, map[string]any{
		"targets": []string{"10.0.0.1:22"}, "protocols": []string{"ssh"}, "dict_profile": "builtin",
	})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "未发起任何连接") {
		t.Fatalf("范围外目标应 400：%d %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM cred_tasks`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("被拒的请求留了 %d 条任务（err=%v）", n, err)
	}

	// 授权只管范围外的：清单内的目标照常建任务（跑不跑得动是另一件事，这里不进网络）。
	rec = credPost(t, s.createCredTask, map[string]any{
		"targets": []string{"203.0.113.10:22"}, "protocols": []string{"ssh"},
		"dict_profile": "builtin", "queue_only": true,
	})
	if rec.Code != 200 {
		t.Fatalf("授权内目标被误拒：%d %s", rec.Code, rec.Body.String())
	}
}

// 同一道闸也要挡在漏扫前面：一次 POC 全量扫描对未授权主机是几千次请求，
// 而弱口令那侧单独测过——两处 wiring 不一样（一个 400、一个执行器直接失败），各测一次。
func TestScanCreateRejectsTargetOutsideAuthorization(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	defer func() { _, _ = pg.Exec(`DELETE FROM authorizations`) }()
	restore := settingGuardMode(t, pg, "strict")
	defer restore()
	if _, err := pg.CreateAuthorization(db.AuthorizationInput{
		Name: "统一测试-scan", Targets: []string{"203.0.113.0/24"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"name": "范围外扫描", "targets": []string{"10.0.0.1"}, "mode": "auto", "ports": "80",
	})
	rec := httptest.NewRecorder()
	s.createScanTask(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "未创建任务") {
		t.Fatalf("范围外目标应 400 且不建任务：%d %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM scan_tasks WHERE name='范围外扫描'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("被拒的扫描请求留下了 %d 条任务（err=%v）", n, err)
	}
}

// 授权可能在任务入队之后才加、才改、才到期，所以执行器自己还要再问一次。
// 这里直接跑执行器：拒绝必须发生在任何连接之前，结果行一条都不该有。
//
// 目标用 TEST-NET 地址，不用 10.0.0.1：这道断言一旦失效，用例就会真的朝那台主机发
// 认证包——10.0.0.1 在很多环境里是活的网关，而认证包能把别人的账号打进锁定且收不回。
// 失败的用例不该顺手变成一次越界攻击。
func TestCredRunRefusesDeniedTargetBeforeAnyPacket(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	defer func() { _, _ = pg.Exec(`DELETE FROM authorizations`) }()

	task, err := pg.CreateCredTask(db.CredTaskInput{
		Name: "先建后加授权", Targets: []string{"192.0.2.20:22"}, Protocols: []string{"ssh"},
		DictProfile: "builtin",
	})
	if err != nil {
		t.Fatal(err)
	}
	restore := settingGuardMode(t, pg, "strict")
	defer restore()
	// 引信：先让进程级策略查一次授权清单，把「平台上还没有任何授权」这份结果缓存住
	// （它缓存 30 秒）。执行期检查一旦退回那个共享策略，下面补的授权就看不见，
	// 越界目标会被放行——先建后加授权这条路看着通过了，其实只是缓存恰好是冷的。
	if deny, _ := guardCheckTargets(s.m.guardPolicy, nil, []string{"203.0.113.10"}); deny != "" {
		t.Fatalf("预热用的授权内目标不该被拒：%s", deny)
	}
	if _, err := pg.CreateAuthorization(db.AuthorizationInput{
		Name: "统一测试-执行期", Targets: []string{"203.0.113.0/24"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	r := &credRun{s: s, pg: pg, task: task, ctx: context.Background()}
	status, msg, _ := r.execute()
	if status != db.CredTaskFailed || !strings.Contains(msg, "未发起任何连接") {
		t.Fatalf("执行器应拒绝该目标：status=%s msg=%s", status, msg)
	}
	var rows int
	if err := pg.QueryRow(`SELECT count(*) FROM cred_results WHERE task_id=$1`, task.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("被拒绝的任务留下了 %d 行结果，说明已经发过包", rows)
	}
}

// CIDR 目标要摊成具体地址再比：授权规则里的 10.0.0.0/8 只有拿地址去问才判得出包含关系。
func TestGuardProbeTargetsExpandsCIDR(t *testing.T) {
	targets, err := scanner.ParseTargets([]string{"10.99.0.0/30", "http://shop.example.com:8080/"})
	if err != nil {
		t.Fatal(err)
	}
	urls, hosts, err := guardProbeTargets(targets)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(hosts, ",")
	for _, want := range []string{"10.99.0.0", "10.99.0.1", "10.99.0.2", "shop.example.com"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("hosts=%q 少了 %s", joined, want)
		}
	}
	if len(urls) == 0 || !strings.Contains(urls[0], "shop.example.com") {
		t.Fatalf("URL 目标应作为 url 交出去，得到 %v", urls)
	}
}

// 进程级策略缓存授权清单 30 秒。补授权的人下一步就是重跑任务，删授权的人下一步就是
// 确认「这台机器现在应该被拦住」——两边都不该等缓存过期。这里两头都钉：
// 建完授权，原本因为没有授权而放行的目标必须立刻被拒；删掉授权，必须立刻回到放行。
func TestGuardAuthorizationWriteInvalidatesCache(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	defer func() { _, _ = pg.Exec(`DELETE FROM authorizations`) }()
	restore := settingGuardMode(t, pg, "strict")
	defer restore()

	// 引信：先把「平台上还没有任何授权」这份结果缓存住。
	if deny, _ := guardCheckTargets(s.m.guardPolicy, nil, []string{"192.0.2.10"}); deny != "" {
		t.Fatalf("没有任何授权时按老语义放行，得到 %q", deny)
	}

	rec := credPost(t, s.createAuthorization, map[string]any{
		"name": "统一测试-写入即生效", "targets": []string{"203.0.113.0/24"}, "enabled": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("建授权失败：%d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if deny, _ := guardCheckTargets(s.m.guardPolicy, nil, []string{"192.0.2.10"}); deny == "" {
		t.Fatal("新登记的授权没被执行：范围外目标仍被放行（缓存里那份空清单没作废）")
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/authorizations/1", nil)
	req.SetPathValue("id", strconv.FormatInt(created.ID, 10))
	del := httptest.NewRecorder()
	s.deleteAuthorization(del, req)
	if del.Code != http.StatusOK {
		t.Fatalf("删授权失败：%d %s", del.Code, del.Body.String())
	}
	if deny, _ := guardCheckTargets(s.m.guardPolicy, nil, []string{"192.0.2.10"}); deny != "" {
		t.Fatalf("授权已删除，仍按旧清单拦人：%s", deny)
	}
}

// settingGuardMode 临时改目标防护档位，返回还原函数。
func settingGuardMode(t *testing.T, pg *db.DB, mode string) func() {
	t.Helper()
	prev, _, err := pg.GetSetting(settingGuardEnforcement)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.SetSetting(settingGuardEnforcement, mode); err != nil {
		t.Fatal(err)
	}
	return func() {
		if prev == "" {
			_, _ = pg.Exec(`DELETE FROM settings WHERE key=$1`, settingGuardEnforcement)
			return
		}
		_ = pg.SetSetting(settingGuardEnforcement, prev)
	}
}
