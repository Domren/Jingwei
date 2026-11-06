package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// G3 的验收是「一条可执行的补救流程」，所以这里的断言重点是两件事：平台该做的那一半真的
// 做完并落库了；不该假装的那一半**没有**被写成完成。后者比前者重要——把「台账已换新密钥」
// 说成「目标已修复」，下一次基于它得出的结论全是假的。

const (
	sealTestKeyKnown = "seal-test-jwt-key-32-bytes!!!!"
	sealTestKeyOther = "seal-OTHER-jwt-key-32-bytes!!!!"
)

func newSealTestServer(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	s, _ := newCredTestServer(t)
	key := []byte(sealTestKeyKnown)
	// UseSealKey 装上密封内核；测试里直接调它，等价于启动时从 platform_secret 读到的根密钥。
	s.m.pg.UseSealKey(key)
	s.jwtKey = key
	t.Cleanup(func() { s.m.pg.UseSealKey(nil) })
	return s, s.m.pg
}

// foreignSeal 造一个「格式正确、但当前根密钥解不开」的密封值——轮换后的真实状态。
func foreignSeal(t *testing.T, purpose db.SealPurpose, plain string) string {
	t.Helper()
	v, err := db.Seal([]byte(sealTestKeyOther), purpose, plain)
	if err != nil {
		t.Fatalf("foreign seal: %v", err)
	}
	if _, err := db.OpenSealed([]byte(sealTestKeyKnown), purpose, v); err == nil {
		t.Fatal("测试前提不成立：旧密钥的值被新密钥解开了")
	}
	return v
}

func TestSealRemediationReissuesBrokenWebshell(t *testing.T) {
	s, pg := newSealTestServer(t)
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM webshells WHERE name LIKE 'g3-%'`) })

	shell, err := pg.CreateWebshell(db.WebshellInput{
		Name: "g3-php", URL: "http://127.0.0.1:1/x.php", ShellType: "php", Protocol: scanner.ShellProtocolV2,
	})
	if err != nil {
		t.Fatal(err)
	}
	stale := foreignSeal(t, db.SealPurposeShell, "0123456789abcdef0123456789abcdef")
	if err := pg.UpdateWebshellSecret(shell.ID, stale, shell.Carrier, shell.PayloadSHA256, 1); err != nil {
		t.Fatal(err)
	}

	audit := pg.AuditSealedSecrets()
	if got := audit.UnreadableIDs(db.SealCategoryWebshell); len(got) != 1 || got[0] != shell.ID {
		t.Fatalf("自检没找出这条失效的壳：%+v", got)
	}
	if cat := audit.Categories[0]; !cat.Automatable || cat.Total < 1 || !strings.Contains(cat.Rows[0].Label, "g3-php") {
		t.Fatalf("分类元数据不对：%+v", cat)
	}

	// 演练：一个字都不改。
	dry := s.runSealRemediation(true)
	if dry.Reissued != 0 || len(dry.Items) == 0 {
		t.Fatalf("演练不该做完任何一条：%+v", dry)
	}
	if cur, _ := pg.GetWebshell(shell.ID); cur.Secret != stale {
		t.Fatal("dry_run 改了库里的密钥")
	}
	if !strings.Contains(dry.Note, "dry_run") {
		t.Fatalf("演练结论没说明这是演练：%q", dry.Note)
	}

	run := s.runSealRemediation(false)
	if run.Reissued != 1 || run.Remaining != 0 {
		t.Fatalf("补救应当做完这一条：%+v", run.Items)
	}
	item := run.Items[0]
	if !item.Done || item.Error != "" {
		t.Fatalf("这一条本该由平台做完：%+v", item)
	}
	updated, err := pg.GetWebshell(shell.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Secret == stale {
		t.Fatal("密钥没有被换掉")
	}
	if updated.KeyVersion != 2 {
		t.Fatalf("key_version 应当递增到 2，得到 %d", updated.KeyVersion)
	}
	if updated.Status != "needs_reland" || !strings.Contains(updated.Note, "等待重新投放") {
		t.Fatalf("台账没有诚实标注等待投放：%+v", updated)
	}
	if item.Payload == "" || item.PayloadFilename == "" || item.PayloadSHA256 == "" {
		t.Fatalf("没有把新载荷交出去：%+v", item)
	}
	if !strings.Contains(item.Next, "覆盖") || !strings.Contains(item.Next, "检测") {
		t.Fatalf("剩余的人工步骤没写清楚：%q", item.Next)
	}
	// 新密钥必须真的能用：解封后重建载荷。注意**不能**比对源码——载荷是多态构建的，
	// 同一个密钥两次构建出来的字节本来就不同；这里要钉的是「解得开、口径一致」。
	reopened, err := s.shellPayloadFor(updated)
	if err != nil {
		t.Fatalf("新密钥读不出来：%v", err)
	}
	if len(reopened.Key) != 32 || reopened.Carrier != updated.Carrier ||
		reopened.KeyVersion != 2 || reopened.Protocol != scanner.ShellProtocolV2 {
		t.Fatalf("重建出来的载荷口径不对：%+v / 台账 %+v", reopened, updated)
	}
	if updated.Carrier == "" || updated.PayloadSHA256 != item.PayloadSHA256 {
		t.Fatalf("台账里的载体与指纹没有跟着换新：%+v", updated)
	}
	if after := pg.AuditSealedSecrets(); after.UnreadableTotal != 0 {
		t.Fatalf("补救后自检仍报失效：%+v", after.Categories)
	}
}

func TestSealRemediationDoesNotFakeTheHumanSteps(t *testing.T) {
	s, pg := newSealTestServer(t)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM java_memshells WHERE name LIKE 'g3-%'`)
		_, _ = pg.Exec(`DELETE FROM webshells WHERE name LIKE 'g3-%'`)
		_, _ = pg.Exec(`DELETE FROM intranet_credentials WHERE host LIKE 'g3-%'`)
	})

	parent, err := pg.CreateWebshell(db.WebshellInput{
		Name: "g3-jsp-parent", URL: "http://127.0.0.1:1/p.jsp", ShellType: "jsp", Protocol: scanner.ShellProtocolV2,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 父壳是健康的：密钥正常密封，载荷能重建。
	parentPayload, parentSealed, err := s.newV2ShellMaterial("jsp", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.UpdateWebshellSecret(parent.ID, parentSealed, parentPayload.Carrier, parentPayload.SHA256, 1); err != nil {
		t.Fatal(err)
	}
	if parent, err = pg.GetWebshell(parent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.renderShellPayloadFor(parent); err != nil {
		t.Fatalf("父壳本该健康：%v", err)
	}
	parentID := parent.ID
	mem, err := pg.CreateJavaMemshell(db.JavaMemshellInput{
		WebshellID: &parentID, Type: "filter", Name: "g3-mem", Path: "/g3mem",
		Secret: foreignSeal(t, db.SealPurposeShell, "0123456789abcdef0123456789abcdef"), Status: "alive",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: "g3-10.99.0.9", Username: "root", Password: "placeholder", Protocol: "ssh",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE intranet_credentials SET password=$1 WHERE host=$2`,
		foreignSeal(t, db.SealPurposeCredential, "placeholder"), "g3-10.99.0.9"); err != nil {
		t.Fatal(err)
	}

	run := s.runSealRemediation(false)
	byCategory := map[string]SealRemediationItem{}
	for _, it := range run.Items {
		byCategory[it.Category] = it
	}
	if run.Reissued != 0 {
		t.Fatalf("这几类都不该被算成平台已做完：%+v", run.Items)
	}
	memItem, ok := byCategory[db.SealCategoryMemshell]
	if !ok {
		t.Fatalf("内存马没被列出来：%+v", run.Items)
	}
	if memItem.Done {
		t.Fatal("内存马被假装成已补救：只换库内密钥而没重注入，台账就在说一件目标上不存在的事")
	}
	if !strings.Contains(memItem.Next, "父壳 #"+strconv.FormatInt(int64(parentID), 10)) || !strings.Contains(memItem.Next, "重新注入") {
		t.Fatalf("没有指出经哪条父壳重注入：%q", memItem.Next)
	}
	if !strings.Contains(memItem.Next, "残留") {
		t.Fatalf("没有说明旧注入物无法撤销、会作为残留：%q", memItem.Next)
	}
	credItem, ok := byCategory[db.SealCategoryCredential]
	if !ok {
		t.Fatal("失效凭据没被列出来")
	}
	if credItem.Done || !strings.Contains(credItem.Next, "重新登记") {
		t.Fatalf("凭据应当只列出人工步骤：%+v", credItem)
	}
	// 备注要落库：轮换之后每条记录自己就该说明「为什么现在用不了」。
	if cur, _ := pg.GetJavaMemshell(mem.ID); cur == nil || !strings.Contains(cur.Note, "需重新注入") {
		t.Fatalf("内存马备注没有落库：%+v", cur)
	}
	if cur, err := pg.ListIntranetCredentials(db.IntranetCredentialFilter{Host: "g3-10.99.0.9"}); err == nil && len(cur) == 1 {
		if _, derr := db.OpenSealed([]byte(sealTestKeyKnown), db.SealPurposeCredential, cur[0].Password); derr == nil {
			t.Fatal("测试前提变了：旧凭据现在能解开了")
		}
	}
}

func TestSealAuditAndRemediationHandlers(t *testing.T) {
	s, pg := newSealTestServer(t)
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM webshells WHERE name LIKE 'g3-%'`) })

	rec := httptest.NewRecorder()
	s.sealAuditHandler(rec, httptest.NewRequest(http.MethodGet, "/api/system/seal-audit", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("自检接口：%d %s", rec.Code, rec.Body.String())
	}
	var auditResp struct {
		Audit   db.SealAudit `json:"audit"`
		Summary string       `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auditResp); err != nil {
		t.Fatal(err)
	}
	if !auditResp.Audit.SealEnabled || len(auditResp.Audit.Categories) != 4 {
		t.Fatalf("自检响应不完整：%+v", auditResp.Audit)
	}
	if !strings.Contains(auditResp.Summary, "没有") {
		t.Fatalf("空库的自检结论应当说清没有失效项：%q", auditResp.Summary)
	}

	shell, err := pg.CreateWebshell(db.WebshellInput{
		Name: "g3-api", URL: "http://127.0.0.1:1/a.php", ShellType: "php", Protocol: scanner.ShellProtocolV2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.UpdateWebshellSecret(shell.ID,
		foreignSeal(t, db.SealPurposeShell, "0123456789abcdef0123456789abcdef"), shell.Carrier, shell.PayloadSHA256, 1); err != nil {
		t.Fatal(err)
	}

	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		s.sealRemediationHandler(r, httptest.NewRequest(http.MethodPost, "/api/system/seal-remediation",
			strings.NewReader(body)))
		return r
	}
	eventsBeforeDry := countRotationEvents(pg, t)
	res := post(`{"dry_run":true}`)
	if res.Code != http.StatusOK {
		t.Fatalf("演练接口：%d %s", res.Code, res.Body.String())
	}
	var dry SealRemediation
	if err := json.Unmarshal(res.Body.Bytes(), &dry); err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || dry.Reissued != 0 || len(dry.Items) != 1 {
		t.Fatalf("演练结果不对：%+v", dry)
	}
	// 载荷源码含新密钥，演练里不该出现。
	if dry.Items[0].Payload != "" {
		t.Fatal("演练不该交出新载荷源码")
	}
	if afterDry := countRotationEvents(pg, t); afterDry != eventsBeforeDry {
		t.Fatalf("dry_run 不该留下运维事件：%d → %d", eventsBeforeDry, afterDry)
	}

	eventsBefore := countRotationEvents(pg, t)
	res = post(`{}`)
	if res.Code != http.StatusOK {
		t.Fatalf("执行接口：%d %s", res.Code, res.Body.String())
	}
	var done SealRemediation
	if err := json.Unmarshal(res.Body.Bytes(), &done); err != nil {
		t.Fatal(err)
	}
	if done.DryRun || done.Reissued != 1 || done.Items[0].Payload == "" {
		t.Fatalf("执行结果不对：%+v", done)
	}
	// 载荷源码只在响应里出现，绝不进日志与事件；用例之间共用 schema，所以看增量。
	if got := countRotationEvents(pg, t); got != eventsBefore+1 {
		t.Fatalf("补救应当留下一条运维事件：%d → %d", eventsBefore, got)
	}
	var snapshot string
	if err := pg.QueryRow(`SELECT snapshot::text FROM notification_events WHERE kind='secret_rotation' ORDER BY id DESC LIMIT 1`).
		Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(snapshot, "BEGIN") || strings.Contains(snapshot, done.Items[0].Payload) {
		t.Fatal("运维事件里漏出了载荷源码")
	}
}

// countRotationEvents 数一下轮换补救留下的运维事件。
func countRotationEvents(pg *db.DB, t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := pg.QueryRow(`SELECT count(*) FROM notification_events WHERE kind='secret_rotation'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
