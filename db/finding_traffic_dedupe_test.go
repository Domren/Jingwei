package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestAgentFindingClassKeyFoldsWording(t *testing.T) {
	cases := []struct{ class, name, want string }{
		{"Command Injection / RCE", "Pikachu RCE 命令注入", "rce"},
		{"命令执行", "shell 注入", "rce"},
		{"CWE-98 / 本地文件包含（Local File Inclusion）", "LFI 路径穿越", "lfi"},
		{"目录遍历", "目录遍历读取 /etc/passwd", "traversal"},
		{"Reflected XSS", "反射型XSS（Reflected XSS）", "xss"},
		{"SQL Injection", "字符型注入", "sqli"},
		{"IDOR", "越权读取订单", "idor"},
		{"", "pkxss 后台弱口令", "weak-password"},
		{"", "弱口令登录", "weak-password"},
		{"CSRF", "修改个人信息 CSRF", "csrf"},
		{"Cross-Site Request Forgery", "跨站请求伪造", "csrf"},
		{"", "未分类问题", ""},
	}
	for _, tc := range cases {
		if got := findingClassKey(tc.class, tc.name); got != tc.want {
			t.Fatalf("findingClassKey(%q,%q)=%q want %q", tc.class, tc.name, got, tc.want)
		}
	}
}

func TestAgentFindingIdentityUsesVerifiedSinkNotPayload(t *testing.T) {
	first := PreparedTrafficEvidence{Ref: TrafficRef{Role: "proof"}, Snapshot: TrafficEvidenceSnapshot{
		URL: "http://192.0.2.4/vul/sqli/sqli_str.php?name=kobe%27+or+1%3D1&submit=x", Method: "GET",
	}}
	second := PreparedTrafficEvidence{Ref: TrafficRef{Role: "proof"}, Snapshot: TrafficEvidenceSnapshot{
		URL: "http://192.0.2.4/vul/sqli/sqli_str.php?name=kobe%27+union+select+1&submit=x", Method: "GET",
	}}
	in := RecordFindingInput{TaskID: 9, VulnClass: "SQL Injection", Name: "字符型注入"}
	a := agentFindingIdentity(in, []PreparedTrafficEvidence{first})
	b := agentFindingIdentity(in, []PreparedTrafficEvidence{second})
	if a == "" || a != b {
		t.Fatalf("same sink with different payloads must share identity:\n%s\n%s", a, b)
	}
	other := PreparedTrafficEvidence{Ref: TrafficRef{Role: "proof"}, Snapshot: TrafficEvidenceSnapshot{
		URL: "http://192.0.2.4/vul/xss/xss_reflected_get.php?message=x&submit=x", Method: "GET",
	}}
	if agentFindingIdentity(in, []PreparedTrafficEvidence{other}) == a {
		t.Fatal("different sink must not share identity")
	}
	if got := agentFindingIdentity(RecordFindingInput{TaskID: 0, VulnClass: "SQL Injection"}, []PreparedTrafficEvidence{first}); got != "" {
		t.Fatalf("taskless finding must not dedupe: %q", got)
	}
}

func TestRecordFindingTxMergesRepeatedAgentReport(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("agent finding dedupe", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	defer func() { purgeTaskNow(t, d, task.ID, ids...) }()

	record := func(class, name, summary, evidence, snapshotURL, reqHead string) *RecordedFinding {
		t.Helper()
		snapshot := TrafficEvidenceSnapshot{
			SourceTrafficID: name, CapturedAt: time.Now().Unix(), URL: snapshotURL, Method: "GET",
			Status: 200, ContentType: "text/html", ReqHead: reqHead, RespHead: "HTTP/1.1 200 OK",
			ReqHash: strings.Repeat("a", 8), RespHash: strings.Repeat("b", 8), ReqLen: 10, RespLen: 20,
		}
		snapshot.ID = TrafficSnapshotID(snapshot)
		var out *RecordedFinding
		err := d.WithEvidenceTx(context.Background(), func(tx *sql.Tx) error {
			var e error
			out, e = RecordFindingTx(context.Background(), tx, RecordFindingInput{
				TaskID: task.ID, ExplorationID: task.ExplorationID,
				VulnClass: class, Name: name, Severity: "high", Summary: summary, Evidence: evidence, Worker: "work#1",
			}, []PreparedTrafficEvidence{{Ref: TrafficRef{TrafficID: name, Role: "proof"}, Snapshot: snapshot}})
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, out.FindingID)
		return out
	}

	const sink = "http://192.0.2.4/vul/rce/rce_ping.php?ip=127.0.0.1"
	first := record("Command Injection / RCE", "RCE 命令注入", "短摘要", "短证据", sink, "GET /rce HTTP/1.1\r\nHost: t\r\n\r\n")
	second := record("命令执行", "RCE 命令注入（三路复现）", "更完整的摘要，包含复现条件与回显。", "更完整的证据：uid=1000(www-data)", sink, "GET /rce HTTP/1.1\r\nHost: t\r\nX-Second: 1\r\n\r\n")
	if second.FindingID != first.FindingID {
		t.Fatalf("repeated report created a new finding: %d vs %d", second.FindingID, first.FindingID)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("server-side duplicate row count=%d want 1", count)
	}
	var severity, summary, evidence string
	if err := d.QueryRow(`SELECT severity, summary, evidence FROM findings WHERE id=$1`, first.FindingID).
		Scan(&severity, &summary, &evidence); err != nil {
		t.Fatal(err)
	}
	if severity != "high" || !strings.Contains(summary, "更完整") || !strings.Contains(evidence, "uid=1000") {
		t.Fatalf("merge did not keep richest text: severity=%q summary=%q evidence=%q", severity, summary, evidence)
	}
	var bindings int
	if err := d.QueryRow(`SELECT count(*) FROM finding_traffic_bindings WHERE finding_id=$1`, first.FindingID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if bindings != 2 {
		t.Fatalf("merged finding bindings=%d want 2", bindings)
	}
	other := record("Command Injection / RCE", "另一个接口命令注入", "另一个入口", "other evidence", "http://192.0.2.4/vul/rce/rce_exec.php", "GET /exec HTTP/1.1\r\nHost: t\r\n\r\n")
	if other.FindingID == first.FindingID {
		t.Fatal("a different endpoint must remain a separate finding")
	}
}
