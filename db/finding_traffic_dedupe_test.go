package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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

// R18：身份粒度从「单个 URL + 参数集 + 方法」改成「类 + 主机集合 + 接口族」。
//
// 旧实现（agentFindingIdentity）在 §4.4 实测里暴露了两个问题：
//   - 同一根因换个端点就是另一个 key（#21 与 #23 是 ArcGIS 管理接口整族免鉴权，
//     却是两个不同 URL 的 key），按 key 分组永远查不出重复；
//   - 跨端口的链式发现里，第二个主机不在 key 里（#31 跨端口凭据链）。
//
// 新语义下：同主机同接口族 → 同身份；同主机不同接口族 → 不同身份；跨主机 → 不同身份。
func TestDerivedIdentityGroupsByClassHostAndFamily(t *testing.T) {
	ev := func(rawURL string) PreparedTrafficEvidence {
		return PreparedTrafficEvidence{Ref: TrafficRef{Role: "proof"},
			Snapshot: TrafficEvidenceSnapshot{URL: rawURL, Method: "GET"}}
	}
	derive := func(in RecordFindingInput, evs ...PreparedTrafficEvidence) DerivedIdentity {
		return DeriveFindingIdentity(in, evs, map[string][]int64{}, nil)
	}

	in := RecordFindingInput{TaskID: 9, VulnClass: "SQL Injection", Name: "字符型注入"}
	a := derive(in, ev("http://192.0.2.4/vul/sqli/sqli_str.php?name=kobe&submit=x"))
	b := derive(in, ev("http://192.0.2.4/vul/sqli/sqli_str.php?name=union+select&submit=x"))
	if a.DedupeKey == "" {
		t.Fatal("身份不该为空（任务与类都给全了）")
	}
	if a.DedupeKey != b.DedupeKey {
		t.Fatalf("同主机同接口族、仅 payload 不同，必须同身份：\n%s\n%s", a.DedupeKey, b.DedupeKey)
	}

	// 同主机、不同接口族 → 不同身份（这是正确的：真的是两个不同接口的洞）。
	other := derive(in, ev("http://192.0.2.4/vul/xss/xss_reflected_get.php?message=x"))
	if other.DedupeKey == a.DedupeKey {
		t.Fatal("不同接口族不该共享身份")
	}

	// 同一根因换端点：同族前缀 → 同一个身份（旧实现这里会分成两条）。
	fam1 := derive(RecordFindingInput{TaskID: 9, VulnClass: "信息泄露", Name: "ArcGIS 管理接口整族免鉴权"},
		ev("http://192.0.2.5:6080/arcgis/admin/logs/query?f=json&level=WARNING"))
	fam2 := derive(RecordFindingInput{TaskID: 9, VulnClass: "信息泄露", Name: "ArcGIS 管理接口整族免鉴权"},
		ev("http://192.0.2.5:6080/arcgis/admin/security/tokens?f=json"))
	if fam1.DedupeKey != fam2.DedupeKey {
		t.Fatalf("同族接口（/arcgis/admin 下）换端点必须合成一条，实得：\n%s\n%s", fam1.DedupeKey, fam2.DedupeKey)
	}

	// 无任务时不生成身份（平台对话里的漏洞不走任务去重）。
	if got := derive(RecordFindingInput{VulnClass: "SQL Injection"}, ev("http://192.0.2.4/x")).DedupeKey; got == "" {
		t.Fatal("无任务时仍应给出一个非空身份（用于展示），只是不参与任务内去重")
	}
}

// 链式证据：两个主机都要进身份，且两个主机的资产都要绑上。
//
// 这是 #31 的直接复现：`:1111` 读配置 → `:8887` 用授权串，旧实现只取最后一个
// 请求的 host，于是「最有交付价值的那条」落进「未关联」桶。
func TestDerivedIdentityIncludesEveryHostInChain(t *testing.T) {
	prepared := []PreparedTrafficEvidence{
		{Ref: TrafficRef{Role: "proof"}, Snapshot: TrafficEvidenceSnapshot{
			URL: "http://10.33.237.140:1111/static/Data/Config.xml", Method: "GET"}},
		{Ref: TrafficRef{Role: "proof"}, Snapshot: TrafficEvidenceSnapshot{
			URL: "http://10.33.237.140:8887/pbs/tile/1/2/3.png", Method: "GET"}},
	}
	in := RecordFindingInput{TaskID: 4, VulnClass: "未授权访问", Name: "跨端口凭据链：配置泄露→瓦片无凭据下载"}
	byHost := map[string][]int64{
		"10.33.237.140:1111": {195, 453},
		"10.33.237.140:8887": {226, 495},
	}
	got := DeriveFindingIdentity(in, prepared, byHost, nil)

	if len(got.Hosts) != 2 {
		t.Fatalf("链式证据的 2 个主机都要收集到，实得 %v", got.Hosts)
	}
	want := []int64{195, 226, 453, 495}
	if len(got.AssetIDs) != len(want) {
		t.Fatalf("两个主机的资产都要绑：期望 %v，实得 %v", want, got.AssetIDs)
	}
	for i := range want {
		if got.AssetIDs[i] != want[i] {
			t.Fatalf("资产应去重排序为 %v，实得 %v", want, got.AssetIDs)
		}
	}
	if !got.ModelAssetsEmpty {
		t.Error("模型没给资产时应记下 ModelAssetsEmpty，便于统计模型漏给的比例")
	}
}

// 模型多给的资产要保留，漏给的要补上。
func TestDerivedIdentityKeepsModelAssetsAndFillsGaps(t *testing.T) {
	prepared := []PreparedTrafficEvidence{
		{Ref: TrafficRef{Role: "proof"}, Snapshot: TrafficEvidenceSnapshot{
			URL: "http://10.0.0.5:8080/api/user", Method: "GET"}},
	}
	in := RecordFindingInput{TaskID: 1, VulnClass: "越权", Name: "IDOR"}
	byHost := map[string][]int64{"10.0.0.5:8080": {11, 12}}
	// 模型给了 11（已覆盖）与 99（推导看不见，比如手工绑的 IP 资产）。
	got := DeriveFindingIdentity(in, prepared, byHost, []int64{11, 99})

	want := []int64{11, 12, 99}
	if len(got.AssetIDs) != len(want) {
		t.Fatalf("期望 %v，实得 %v", want, got.AssetIDs)
	}
	for i := range want {
		if got.AssetIDs[i] != want[i] {
			t.Fatalf("期望 %v，实得 %v", want, got.AssetIDs)
		}
	}
	if got.ModelAssetsEmpty {
		t.Error("模型给了资产时不该标空")
	}
}

// 端口缺省要按 scheme 归一，否则 http://a/x 与 http://a:80/x 会被当成两台主机。
func TestDerivedHostKeyNormalizesDefaultPort(t *testing.T) {
	cases := map[string]string{
		"http://a.example/x":       "a.example:80",
		"http://a.example:80/x":    "a.example:80",
		"https://a.example/x":      "a.example:443",
		"https://a.example:8443/x": "a.example:8443",
		"http://10.0.0.5:8080/x":   "10.0.0.5:8080",
	}
	for raw, want := range cases {
		if got := evidenceHostKey(raw); got != want {
			t.Errorf("evidenceHostKey(%q)=%q，期望 %q", raw, got, want)
		}
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
	// R18 改写了这一段的期望：旧断言是「不同端点必须分开」。
	//
	// 但 §4.4 的实测证明那条期望是错的：#21 与 #23 是同一个根因（ArcGIS 管理
	// 接口整族免鉴权）换了两个端点，被拆成两条，报告里看着像在凑数。R18 的
	// 判据明确要求「按 类+主机+接口族 合并、取最高严重度」。
	//
	// 所以现在：同族不同端点 → 合并（下一条断言）；不同接口族 → 仍然分开。
	other := record("Command Injection / RCE", "另一个接口命令注入", "另一个入口", "other evidence",
		"http://192.0.2.4/vul/rce/rce_exec.php", "GET /exec HTTP/1.1\r\nHost: t\r\n\r\n")
	if other.FindingID != first.FindingID {
		t.Fatalf("同族不同端点必须合成一条（R18 判据）；实得 %d vs %d", other.FindingID, first.FindingID)
	}

	// 不同接口族的洞必须仍是两条：这是「合并」不能过度的那条边界。
	// /vul/xss 与 /vul/rce 属于不同族。
	xss := record("Reflected XSS", "反射型 XSS", "另一个族的洞", "xss evidence",
		"http://192.0.2.4/vul/xss/xss_reflected_get.php?message=x", "GET /xss HTTP/1.1\r\nHost: t\r\n\r\n")
	if xss.FindingID == first.FindingID {
		t.Fatal("不同接口族的洞不该被合并——合并只能发生在同族内")
	}
}

// 回归：slug 截断必须按 rune。按字节切中文会产生非法 UTF-8，落库时报
// `invalid byte sequence for encoding "UTF8"` 并把整条漏洞写入回滚——
// 一个纯展示用的 slug 有能力搞丢一条真洞，这是实测撞到的。
func TestNormalizeIdentityNameTruncatesByRune(t *testing.T) {
	// 60 个中文字符 = 180 字节，远超 64；按字节切会切在字符中间。
	long := strings.Repeat("超长漏洞名称", 10)
	got := normalizeIdentityName(long)
	if !utf8.ValidString(got) {
		t.Fatalf("slug 必须是合法 UTF-8（按 rune 截断），实得 %q", got)
	}
	if n := len([]rune(got)); n > 64 {
		t.Fatalf("slug 长度应 ≤64 rune，实得 %d", n)
	}
	// 纯 ASCII 的行为不变。
	if got := normalizeIdentityName("Redis CONFIG REWRITE"); got != "redis-config-rewrite" {
		t.Fatalf("ASCII slug 变了：%q", got)
	}
}
