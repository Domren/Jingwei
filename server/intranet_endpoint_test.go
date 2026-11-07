package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

// F5 的服务层用例：识别结果怎么进发现台账、什么情况下**不**进。
//
// 后半句比前半句重要：读不到进程列表、补丁列表不完整、只有未登记的可疑名字，
// 这三种情况如果也写出一条发现，报告里就多了三条没有证据的结论。

func f5TestSession(t *testing.T, pg *db.DB) *db.IntranetSession {
	t.Helper()
	ws, err := pg.CreateWebshell(db.WebshellInput{
		Name: "统一测试-f5", URL: "http://127.0.0.1:9/f5-fixture.php", ShellType: "php",
		Password: "test", Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := pg.CreateIntranetSession(db.IntranetSessionInput{
		Name: "统一测试-f5", WebshellID: ws.ID, Host: "10.250.88.77", Cwd: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM intranet_script_runs WHERE session_id=$1`, sess.ID)
		_, _ = pg.Exec(`DELETE FROM findings WHERE dedupe_key LIKE $1`, fmt.Sprintf("endpoint:%d:%%", sess.ID))
		_, _ = pg.Exec(`DELETE FROM findings WHERE dedupe_key LIKE $1`, fmt.Sprintf("patch:%d:%%", sess.ID))
		_, _ = pg.Exec(`DELETE FROM intranet_sessions WHERE id=$1`, sess.ID)
		_, _ = pg.Exec(`DELETE FROM webshells WHERE id=$1`, ws.ID)
	})
	return sess
}

func findingCountByKey(t *testing.T, pg *db.DB, key string) int {
	t.Helper()
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM findings WHERE dedupe_key=$1`, key).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func findingRow(t *testing.T, pg *db.DB, key string) (name, severity, class, summary string) {
	t.Helper()
	if err := pg.QueryRow(`SELECT name, severity, vulnclass, summary FROM findings WHERE dedupe_key=$1`, key).
		Scan(&name, &severity, &class, &summary); err != nil {
		t.Fatalf("查 %s 失败：%v", key, err)
	}
	return
}

func TestRecordEndpointFindingsWritesAndDedupes(t *testing.T) {
	s, pg := newAdmissionFixtureServer(t)
	sess := f5TestSession(t, pg)
	out := strings.Join([]string{
		`"Image Name","PID"`,
		`"MsMpEng.exe","4120"`,
		`"CSFalconService.exe","5000"`,
	}, "\n")
	parsed := parseEndpointScript("windows", out)
	note := s.recordEndpointFindings(pg, sess, 0, intranetScriptWinEndpoint, parsed)
	if !strings.Contains(note, "已写入发现台账") {
		t.Fatalf("说明要讲清写了什么：%q", note)
	}
	key := fmt.Sprintf("endpoint:%d:Microsoft Defender 防病毒", sess.ID)
	if n := findingCountByKey(t, pg, key); n != 1 {
		t.Fatalf("应有 1 条发现：%d", n)
	}
	name, severity, class, summary := findingRow(t, pg, key)
	if class != findingClassEndpointSecurity || severity != "low" {
		t.Fatalf("类别/严重度不对：%s / %s", class, severity)
	}
	if !strings.Contains(name, "Microsoft Defender") {
		t.Fatalf("标题要点名产品：%s", name)
	}
	// 这条发现的价值在于「环境事实 + 不承诺绕过」，两句都得在正文里。
	if !strings.Contains(summary, "任何规避建议") || !strings.Contains(summary, "环境事实") {
		t.Fatalf("结论不能留规避空间：%s", summary)
	}

	// 重跑一次：dedupe key 让它更新而不是再堆一条。
	if note2 := s.recordEndpointFindings(pg, sess, 0, intranetScriptWinEndpoint, parsed); note2 == "" {
		t.Fatal("重跑也该给一句说明")
	}
	if n := findingCountByKey(t, pg, key); n != 1 {
		t.Fatalf("重跑堆出了 %d 条同键发现", n)
	}
	if n := findingCountByKey(t, pg, fmt.Sprintf("endpoint:%d:CrowdStrike Falcon", sess.ID)); n != 1 {
		t.Fatalf("第二个产品没落库：%d", n)
	}
}

// 读不到列表时不写发现，并且要给一句「不做判断」。
func TestRecordEndpointFindingsMakesNoClaimsWhenUnreadable(t *testing.T) {
	s, pg := newAdmissionFixtureServer(t)
	sess := f5TestSession(t, pg)
	parsed := parseEndpointScript("windows", "ERROR: Access is denied.")
	note := s.recordEndpointFindings(pg, sess, 0, intranetScriptWinEndpoint, parsed)
	if !strings.Contains(note, "不做判断") || !strings.Contains(note, "不等于没有防护") {
		t.Fatalf("空输入必须说明不做判断：%q", note)
	}
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM findings WHERE dedupe_key LIKE $1 OR dedupe_key LIKE $2`,
		fmt.Sprintf("endpoint:%d:%%", sess.ID), fmt.Sprintf("patch:%d:%%", sess.ID)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("读不到列表却写了 %d 条发现", n)
	}
}

// 只有未登记的可疑名字：不猜产品，也不写发现，但要在说明里留痕。
func TestRecordEndpointFindingsKeepsUnregisteredOutOfLedger(t *testing.T) {
	s, pg := newAdmissionFixtureServer(t)
	sess := f5TestSession(t, pg)
	parsed := parseEndpointScript("windows", `"SangforEdrAgent.exe","7"`)
	note := s.recordEndpointFindings(pg, sess, 0, intranetScriptWinEndpoint, parsed)
	if !strings.Contains(note, "未登记") || !strings.Contains(note, "人工确认") {
		t.Fatalf("待确认项要说明：%q", note)
	}
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM findings WHERE dedupe_key LIKE $1`,
		fmt.Sprintf("endpoint:%d:%%", sess.ID)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("未登记的产品名不该变成发现：%d", n)
	}
}

func TestRecordEndpointFindingsPatchesArePending(t *testing.T) {
	s, pg := newAdmissionFixtureServer(t)
	sess := f5TestSession(t, pg)
	out := strings.Join([]string{
		"OS Name:                   Microsoft Windows Server 2016 Standard",
		"OS Version:                10.0.14393 N/A Build 14393",
		"Hotfix(s):                 1 Hotfix(s) Installed.",
		"[01]: KB4012212",
	}, "\n")
	parsed := parsePatchScript(out)
	note := s.recordEndpointFindings(pg, sess, 0, "win-systeminfo", parsed)
	if !strings.Contains(note, "待确认") {
		t.Fatalf("补丁结论必须带待确认：%q", note)
	}
	// MS17-010 命中了基线 → 不该有发现；BlueKeep 未命中 → 一条待确认。
	if n := findingCountByKey(t, pg, fmt.Sprintf("patch:%d:MS17-010", sess.ID)); n != 0 {
		t.Fatalf("命中的通告不该写发现：%d", n)
	}
	key := fmt.Sprintf("patch:%d:CVE-2019-0708", sess.ID)
	if n := findingCountByKey(t, pg, key); n != 1 {
		t.Fatalf("未命中的通告应有 1 条：%d", n)
	}
	name, severity, class, summary := findingRow(t, pg, key)
	if class != findingClassMissingPatch || severity != "medium" {
		t.Fatalf("类别/严重度不对：%s / %s", class, severity)
	}
	if !strings.Contains(name, "待确认") || !strings.Contains(summary, "不等于") {
		t.Fatalf("标题与正文都要写明未验证：%s / %s", name, summary)
	}
}

// 补丁列表不完整时一条都不写。
func TestRecordEndpointFindingsSkipsIncompletePatchInput(t *testing.T) {
	s, pg := newAdmissionFixtureServer(t)
	sess := f5TestSession(t, pg)
	parsed := parsePatchScript("ERROR: The system cannot find the file specified.")
	note := s.recordEndpointFindings(pg, sess, 0, intranetScriptWinHotfixes, parsed)
	if !strings.Contains(note, "不做缺失判断") {
		t.Fatalf("不完整输入要说明：%q", note)
	}
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM findings WHERE dedupe_key LIKE $1`,
		fmt.Sprintf("patch:%d:%%", sess.ID)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("不完整输入写出了 %d 条缺失补丁发现", n)
	}
}

func TestSessionEndpointNoteReadsBackStoredRuns(t *testing.T) {
	_, pg := newAdmissionFixtureServer(t)
	sess := f5TestSession(t, pg)
	if note := sessionEndpointNote(pg, sess.ID); note != "" {
		t.Fatalf("还没有运行记录时不该编出内容：%q", note)
	}
	code := 0
	if _, err := pg.CreateIntranetScriptRun(db.IntranetScriptRunInput{
		SessionID: sess.ID, ScriptID: intranetScriptWinEndpoint, Name: "终端防护进程与服务",
		OS: "windows", Command: "tasklist", ExitCode: &code, Status: "done",
		Output: `"MsMpEng.exe","4120"`, Parsed: parseEndpointScript("windows", `"MsMpEng.exe","4120"`),
	}); err != nil {
		t.Fatal(err)
	}
	note := sessionEndpointNote(pg, sess.ID)
	if !strings.Contains(note, "Microsoft Defender 防病毒") || !strings.Contains(note, "不提供规避建议") {
		t.Fatalf("回看不该有的内容：%q", note)
	}

	// 失败的那次运行不能被当成「查过了、没有防护」。
	sess2 := f5TestSession(t, pg)
	failed := 1
	if _, err := pg.CreateIntranetScriptRun(db.IntranetScriptRunInput{
		SessionID: sess2.ID, ScriptID: intranetScriptWinEndpoint, Name: "终端防护进程与服务",
		OS: "windows", Command: "tasklist", ExitCode: &failed, Status: "failed",
		Output: "ERROR: Access is denied.", Parsed: parseEndpointScript("windows", "ERROR: Access is denied."),
	}); err != nil {
		t.Fatal(err)
	}
	if note := sessionEndpointNote(pg, sess2.ID); note != "" {
		t.Fatalf("失败的运行记录不该被回看：%q", note)
	}
}

// newAdmissionFixtureServer 只要一个带库的 Server：F5 的这几条不依赖真实会话通道。
func newAdmissionFixtureServer(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	pg := prescanTestDB(t)
	return &Server{m: &Manager{pg: pg}}, pg
}
