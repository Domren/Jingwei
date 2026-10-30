package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

func TestFindingsDOCXPaginatesAndEmbedsRealPackets(t *testing.T) {
	taskID := int64(7)
	at := time.Date(2026, 10, 24, 10, 0, 0, 0, time.Local)
	req := "POST /vul/sqli/sqli_str.php?id=1 HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nContent-Length: 8\r\n\r\nsearch=1"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>ok</h1>\x00\x01binary"
	fs := []*db.DBFinding{
		{
			ID: 1, TaskID: &taskID, TaskDescription: "皮卡丘靶场回归",
			Name: "SQL 注入", VulnClass: "sqli", Severity: db.SeverityHigh, Status: db.FindingPending,
			Summary: "参数 id 存在注入", Evidence: "布尔条件差异明显",
			HTTPRequest: req, HTTPResponse: resp,
			CreatedAt: at, Worker: "scan:nuclei", AssetIDs: []int64{11, 12},
		},
		{
			ID: 2, TaskID: &taskID, TaskDescription: "皮卡丘靶场回归",
			Name:      `<script>alert(1)</script>`,
			VulnClass: "exposure", Severity: db.SeverityLow, Status: db.FindingPending,
			Summary: "目录可列", CreatedAt: at.Add(time.Minute),
		},
	}

	data, err := FindingsDOCX(fs, FindingsDOCXOptions{GeneratedAt: at, ScopeLabel: "筛选结果（2 条）"})
	if err != nil {
		t.Fatal(err)
	}
	files := readDOCXParts(t, data)
	for _, name := range []string{
		"[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/styles.xml",
		"word/settings.xml", "word/footer1.xml", "word/_rels/document.xml.rels",
	} {
		if len(files[name]) == 0 {
			t.Fatalf("missing docx part %s", name)
		}
	}
	for name, part := range files {
		if strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".rels") {
			var v any
			if err := xml.Unmarshal(part, &v); err != nil {
				t.Fatalf("%s is not well-formed XML: %v", name, err)
			}
		}
	}

	doc := string(files["word/document.xml"])
	for _, want := range []string{
		"JW-20261024-100000",
		"共 2 条漏洞发现",
		"报告摘要",
		"1. 皮卡丘靶场回归",
		"1.1 SQL 注入",
		"1.2 &lt;script&gt;alert(1)&lt;/script&gt;",
		"POST /vul/sqli/sqli_str.php?id=1 HTTP/1.1",
		"Host: 127.0.0.1:18080",
		"HTTP/1.1 200 OK",
		"未采集到原始报文或协议数据",
		"发送原始请求",
		"验证数据",
		"<w:trPr><w:tblHeader/></w:trPr>",
		`w:br w:type="page"`,
		"w:pageBreakBefore",
		`TOC \o "1-2"`,
		"测试方法与数据说明",
		`<w:footerReference w:type="default" r:id="rId3"/>`,
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("document.xml missing %q", want)
		}
	}
	if strings.ContainsAny(doc, "\x00\x01") {
		t.Fatal("control bytes leaked into document.xml")
	}
	if strings.Contains(doc, "<script>alert(1)</script>") {
		t.Fatal("finding name must be XML-escaped")
	}
	if !strings.Contains(string(files["word/footer1.xml"]), "NUMPAGES") ||
		!strings.Contains(string(files["word/footer1.xml"]), "PAGE") {
		t.Fatal("footer page fields missing")
	}
	if !strings.Contains(string(files["word/settings.xml"]), `w:updateFields w:val="true"`) {
		t.Fatal("TOC fields must refresh on open")
	}
}

func TestFindingsDOCXGroupsScanTaskFindings(t *testing.T) {
	scanID := int64(22)
	at := time.Date(2026, 10, 24, 16, 26, 0, 0, time.Local)
	fs := []*db.DBFinding{{
		ID: 1, ScanTaskID: &scanID, ScanTaskName: "DVWA N3 无LLM Top1000",
		Name: "DVWA Authenticated SQL Injection", VulnClass: "sqli", Severity: db.SeverityHigh,
		Status: db.FindingPending, Summary: "id 参数存在 SQL 注入",
		HTTPRequest:  "GET /vulnerabilities/sqli/?id=1%27 HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\n",
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nSQL syntax",
		CreatedAt:    at, Worker: "scan:nuclei",
	}}
	data, err := FindingsDOCX(fs, FindingsDOCXOptions{GeneratedAt: at, ScopeLabel: "DVWA N3 无LLM Top1000（1 条）"})
	if err != nil {
		t.Fatal(err)
	}
	doc := string(readDOCXParts(t, data)["word/document.xml"])
	for _, want := range []string{
		"DVWA N3 无LLM Top1000",
		"1. DVWA N3 无LLM Top1000",
		"漏扫任务：DVWA N3 无LLM Top1000",
		"GET /vulnerabilities/sqli/?id=1%27 HTTP/1.1",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("scan-task document.xml missing %q", want)
		}
	}
	if strings.Contains(doc, "1. 未关联任务") {
		t.Fatal("scan findings must not be grouped as an unassigned task")
	}
}

func readDOCXParts(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("not a zip/docx: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = raw
	}
	return out
}

func TestFindingsDOCXRendersProtocolBannerPacket(t *testing.T) {
	at := time.Date(2026, 10, 25, 9, 0, 0, 0, time.Local)
	scanID := int64(46)
	packet := "# 协议: MYSQL (TCP)\n" +
		"# 端点: 192.0.2.4:3306\n" +
		"# 采集方式: TCP 三次握手后被动读取服务端首发数据，扫描器未发送任何应用层请求字节\n" +
		"# 响应字节: 78\n" +
		"# 复现命令:\n" +
		"#   nc -w 2 192.0.2.4 3306 | xxd | head -8\n" +
		"\n# ---- 原始响应数据（hexdump，与抓包字节一致）----\n" +
		"00000000  68 00 00 00 0a 2d 2d 20  2d 2d 20 2d 2d 20 2d 20  |h....-- -- -- - |\n"
	fs := []*db.DBFinding{{
		ID: 9, ScanTaskID: &scanID, ScanTaskName: "Pikachu N4 无LLM",
		Name: "MySQL 数据库服务对外暴露", VulnClass: "exposed-service-mysql", Severity: db.SeverityMedium,
		Status: db.FindingPending, Summary: "3306 端口对外开放",
		Evidence:  "服务暴露: mysql 3306/tcp\n类型: mysql\n主机: 192.0.2.4:3306\n探测方式: TCP 端口探测 + 服务 Banner 指纹识别\n风险说明: 弱口令或未授权访问会导致业务数据泄露\n",
		CreatedAt: at, Worker: "scan:46",
		HTTPResponse: packet,
	}}
	doc := string(readDOCXParts(t, mustDOCX(t, fs, at))["word/document.xml"])
	for _, want := range []string{
		"原始协议报文",
		"原始响应数据",
		"nc -w 2 192.0.2.4 3306 | xxd | head -8",
		"00000000  68 00 00 00 0a 2d 2d 20",
		"MYSQL",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("document.xml missing %q", want)
		}
	}
	for _, absent := range []string{
		"未采集到原始报文或协议数据",
		"未采集到原始协议请求/响应数据",
	} {
		if strings.Contains(doc, absent) {
			t.Fatalf("document.xml must not contain %q for a banner finding", absent)
		}
	}
	if strings.Contains(doc, "读取原始响应：`#") {
		t.Fatal("response excerpt must be captured bytes, not a packet header comment")
	}
}

func mustDOCX(t *testing.T, fs []*db.DBFinding, at time.Time) []byte {
	t.Helper()
	data, err := FindingsDOCX(fs, FindingsDOCXOptions{GeneratedAt: at, ScopeLabel: "筛选结果"})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestFindingsDOCXShowsAllBoundPackets(t *testing.T) {
	at := time.Date(2026, 10, 24, 17, 5, 0, 0, time.Local)
	fs := []*db.DBFinding{{
		ID: 3, Name: "盲注验证", VulnClass: "SQL Injection (Blind)", Severity: db.SeverityHigh, Status: db.FindingPending,
		Summary: "布尔盲注", CreatedAt: at,
		HTTPRequest:  "GET /sqli_blind?id=1 HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\n",
		HTTPResponse: "HTTP/1.1 200 OK\r\n\r\nUser ID exists in the database.",
		EvidencePackets: []db.FindingEvidencePacket{
			{
				BindingID: 41, Role: "proof", Primary: true,
				Snapshot:     db.TrafficEvidenceSnapshot{Method: "GET", URL: "http://192.0.2.4/sqli_blind?id=1", Status: 200},
				HTTPRequest:  "GET /sqli_blind?id=1 HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\n",
				HTTPResponse: "HTTP/1.1 200 OK\r\n\r\nUser ID exists in the database.",
			},
			{
				BindingID: 42, Role: "verification",
				Snapshot:     db.TrafficEvidenceSnapshot{Method: "GET", URL: "http://192.0.2.4/sqli_blind?id=1%27+AND+%271%27%3D%272", Status: 404},
				HTTPRequest:  "GET /sqli_blind?id=1%27+AND+%271%27%3D%272 HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\n",
				HTTPResponse: "HTTP/1.1 404 Not Found\r\n\r\nUser ID is MISSING from the database.",
			},
		},
	}}
	data, err := FindingsDOCX(fs, FindingsDOCXOptions{GeneratedAt: at, ScopeLabel: "筛选结果（1 条）"})
	if err != nil {
		t.Fatal(err)
	}
	doc := string(readDOCXParts(t, data)["word/document.xml"])
	for _, want := range []string{
		"全部验证报文（按复现顺序）",
		"证据 #42 · 补充验证",
		"User ID is MISSING from the database.",
		"GET /sqli_blind?id=1%27+AND+%271%27%3D%272 HTTP/1.1",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("document.xml missing %q", want)
		}
	}
}

func TestFindingsDOCXDisclosesMergedAndCappedPackets(t *testing.T) {
	at := time.Date(2026, 10, 25, 10, 0, 0, 0, time.Local)
	fs := []*db.DBFinding{{
		ID: 7, Name: "存储型XSS", VulnClass: "XSS", Severity: db.SeverityHigh, Status: db.FindingPending,
		Summary: "评论存储型 XSS", CreatedAt: at,
		HTTPRequest:  "POST /vul/xss/xss_stored.php HTTP/1.1\r\nHost: lab\r\n\r\ncontent=%3Cscript%3E1%3C%2Fscript%3E",
		HTTPResponse: "HTTP/1.1 200 OK\r\n\r\n<script>1</script>",
		EvidencePackets: []db.FindingEvidencePacket{
			{BindingID: 51, Role: "proof", Primary: true, Repeated: 6,
				Snapshot:     db.TrafficEvidenceSnapshot{Method: "POST", URL: "http://lab/vul/xss/xss_stored.php", Status: 200},
				HTTPRequest:  "POST /vul/xss/xss_stored.php HTTP/1.1\r\nHost: lab\r\n\r\ncontent=%3Cscript%3E1%3C%2Fscript%3E",
				HTTPResponse: "HTTP/1.1 200 OK\r\n\r\n<script>1</script>"},
			{BindingID: 52, Role: "supporting", Repeated: 3,
				Snapshot:     db.TrafficEvidenceSnapshot{Method: "GET", URL: "http://lab/vul/xss/xss_stored.php", Status: 200},
				HTTPRequest:  "GET /vul/xss/xss_stored.php HTTP/1.1\r\nHost: lab\r\n\r\n",
				HTTPResponse: "HTTP/1.1 200 OK\r\n\r\n<script>1</script>"},
		},
		EvidencePacketOmitted: 4,
		TrafficBindings:       []db.FindingTrafficBinding{{ID: 51}, {ID: 52}},
	}}
	doc := string(readDOCXParts(t, mustDOCX(t, fs, at))["word/document.xml"])
	for _, want := range []string{
		"后续复测中该步骤又被采集 3 次",
		"另有 4 组报文属于超出展示上限的复现步骤",
		"该发现共绑定 2 组流量证据，其中 2 组按复现顺序在上方展示",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("document.xml missing %q", want)
		}
	}
	if strings.Contains(doc, "证据 #51 ·") {
		t.Fatal("the primary packet is rendered once, above the sequence")
	}
}

func TestFindingsDOCXEmbedsScreenshots(t *testing.T) {
	at := time.Date(2026, 10, 27, 10, 0, 0, 0, time.Local)
	// 1x1 红色 PNG
	pngB64 := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
	fs := []*db.DBFinding{
		{
			ID: 1, Name: "反射型 XSS", VulnClass: "xss", Severity: db.SeverityMedium,
			Status: db.FindingConfirmed, Summary: "存在反射型 XSS",
			Screenshots: []db.FindingScreenshot{{ID: 9, FindingID: 1, Caption: "重放截图", Data: pngB64}},
			CreatedAt:   at,
		},
	}
	data, err := FindingsDOCX(fs, FindingsDOCXOptions{GeneratedAt: at, ScopeLabel: "筛选"})
	if err != nil {
		t.Fatal(err)
	}
	files := readDOCXParts(t, data)

	// 1) media 文件存在且内容正确
	media, ok := files["word/media/image1.png"]
	if !ok {
		t.Fatalf("expected word/media/image1.png, got parts: %v", keysOf(files))
	}
	if len(media) == 0 {
		t.Fatal("media file empty")
	}
	if media[0] != 0x89 || media[1] != 'P' || media[2] != 'N' || media[3] != 'G' {
		t.Fatalf("media file is not a PNG, first bytes: % x", media[:8])
	}

	// 2) document.xml 引用了图片关系 rId4
	doc := string(files["word/document.xml"])
	if !strings.Contains(doc, `r:embed="rId4"`) {
		t.Fatalf("document.xml missing r:embed=rId4:\n%s", doc[strings.Index(doc, "<w:drawing>"):][:300])
	}

	// 3) 关系文件含 image 关系
	rels := string(files["word/_rels/document.xml.rels"])
	if !strings.Contains(rels, `Target="media/image1.png"`) {
		t.Fatalf("rels missing media/image1.png:\n%s", rels)
	}

	// 4) content types 声明了 png
	ct := string(files["[Content_Types].xml"])
	if !strings.Contains(ct, `Extension="png"`) {
		t.Fatalf("content types missing png default:\n%s", ct)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
