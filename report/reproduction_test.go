package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// reproFinding 造一条带结构化复现 + 已绑定报文的发现：第 1 步上传、第 2 步访问 shell。
func reproFinding() *db.DBFinding {
	taskID := int64(9)
	uploadReq := "POST /upload.php HTTP/1.1\r\nHost: lab.example\r\nContent-Length: 42\r\n\r\nContent-Disposition: filename=\"shell.php\""
	uploadResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>upload success</p>"
	execReq := "GET /uploads/shell.php?cmd=id HTTP/1.1\r\nHost: lab.example\r\n\r\n"
	execResp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nuid=33(www-data) gid=33(www-data) groups=33(www-data)"

	f := &db.DBFinding{
		ID: 501, TaskID: &taskID, TaskDescription: "本地靶场演示",
		Name: "文件上传导致远程代码执行", VulnClass: "upload", Severity: db.SeverityCritical,
		Status: db.FindingPending, CreatedAt: time.Date(2026, 10, 27, 10, 0, 0, 0, time.Local),
		HTTPRequest: uploadReq, HTTPResponse: uploadResp,
		Reproduction: &db.Reproduction{
			EntryPoint:    "POST /upload.php（multipart，avatar 字段）",
			Prerequisites: []string{"无需认证", "上传目录 PHP 可解析"},
			Provenance:    "头像上传接口 → 上传目录未做可执行限制",
			Steps: []db.ReproStep{
				{Request: uploadReq, Response: uploadResp, Expected: "上传成功并返回路径", Proves: "任意文件可写入", SnapshotID: "snap-1"},
				{Request: execReq, Response: execResp, Expected: "命令回显 uid", Proves: "上传文件被解析执行", SnapshotID: "snap-2"},
			},
		},
		TrafficBindings: []db.FindingTrafficBinding{
			{ID: 11, Position: 0, Role: "proof", SnapshotID: "snap-1", Snapshot: db.TrafficEvidenceSnapshot{ID: "snap-1", Method: "POST", URL: "http://lab.example/upload.php", Status: 200}},
			{ID: 12, Position: 1, Role: "proof", SnapshotID: "snap-2", Snapshot: db.TrafficEvidenceSnapshot{ID: "snap-2", Method: "GET", URL: "http://lab.example/uploads/shell.php?cmd=id", Status: 200}},
		},
		EvidencePackets: []db.FindingEvidencePacket{
			{BindingID: 11, Role: "proof", Snapshot: db.TrafficEvidenceSnapshot{ID: "snap-1", Method: "POST", URL: "http://lab.example/upload.php", Status: 200}, HTTPRequest: uploadReq, HTTPResponse: uploadResp, Primary: true},
			{BindingID: 12, Role: "proof", Snapshot: db.TrafficEvidenceSnapshot{ID: "snap-2", Method: "GET", URL: "http://lab.example/uploads/shell.php?cmd=id", Status: 200}, HTTPRequest: execReq, HTTPResponse: execResp},
		},
	}
	return f
}

func TestFindingsHTMLRendersStructuredReproduction(t *testing.T) {
	out := string(FindingsHTML([]*db.DBFinding{reproFinding()}, FindingsHTMLOptions{
		GeneratedAt: time.Date(2026, 10, 27, 11, 0, 0, 0, time.Local),
		ScopeLabel:  "筛选结果（1 条）",
	}))

	for _, want := range []string{
		"复现过程",
		"入口点",
		"POST /upload.php（multipart，avatar 字段）",
		"前置条件",
		"上传目录 PHP 可解析",
		"攻击链来源",
		"步骤 1",
		"步骤 2",
		"预期：上传成功并返回路径",
		"证明：上传文件被解析执行",
		"对应流量证据 #11",
		"对应流量证据 #12",
		"uid=33(www-data)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML report missing %q", want)
		}
	}
	// 结构化复现接管后，旧的「验证步骤」标题与重复的主报文段落都不该再出现。
	if strings.Contains(out, "<h4>验证步骤</h4>") {
		t.Fatal("legacy 验证步骤 should be replaced by 复现过程")
	}
}

func TestFindingsHTMLFallsBackWhenNoReproduction(t *testing.T) {
	f := reproFinding()
	f.Reproduction = nil
	f.TrafficBindings = nil
	f.EvidencePackets = nil
	out := string(FindingsHTML([]*db.DBFinding{f}, FindingsHTMLOptions{
		GeneratedAt: time.Date(2026, 10, 27, 11, 0, 0, 0, time.Local),
		ScopeLabel:  "筛选结果（1 条）",
	}))
	if !strings.Contains(out, "<h4>验证步骤</h4>") {
		t.Fatal("without reproduction the report must keep the legacy verification steps")
	}
	if strings.Contains(out, "复现过程") {
		t.Fatal("no reproduction recorded, so nothing should claim 复现过程")
	}
}

func TestFindingsDOCXRendersStructuredReproduction(t *testing.T) {
	raw, err := FindingsDOCX([]*db.DBFinding{reproFinding()}, FindingsDOCXOptions{
		GeneratedAt: time.Date(2026, 10, 27, 11, 0, 0, 0, time.Local),
		ScopeLabel:  "筛选结果（1 条）",
	})
	if err != nil {
		t.Fatalf("render docx: %v", err)
	}
	xml := string(readDOCXParts(t, raw)["word/document.xml"])
	for _, want := range []string{
		"复现过程",
		"入口点",
		"前置条件：无需认证",
		"步骤 1",
		"步骤 2",
		"uid=33(www-data)",
		"对应流量证据 #12",
	} {
		if !strings.Contains(xml, want) {
			t.Fatalf("DOCX missing %q", want)
		}
	}
}

func TestBuildReproViewPrefersCapturedBytes(t *testing.T) {
	f := reproFinding()
	// agent 抄下来的文本与抓包字节不一致时，报告必须用抓到的真实报文。
	f.Reproduction.Steps[0].Request = "POST /upload.php (转录版本)"
	v := buildReproView(f)
	if v == nil || len(v.Steps) != 2 {
		t.Fatalf("unexpected view: %+v", v)
	}
	if !v.anyFromPacket() {
		t.Fatal("expected steps to render from captured packets")
	}
	if !strings.Contains(v.Steps[0].Request, "POST /upload.php HTTP/1.1") {
		t.Fatalf("should use captured request bytes, got %q", v.Steps[0].Request)
	}
	if v.Steps[1].BindingID != 12 {
		t.Fatalf("step 2 should link binding 12, got %d", v.Steps[1].BindingID)
	}
}
