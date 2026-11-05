package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

func credReportFixture() CredReportInput {
	started := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	done := started.Add(42 * time.Second)
	return CredReportInput{
		TaskID: 7, Name: "边界段弱口令", Targets: []string{"10.0.0.10"},
		Protocols: []string{"ssh", "redis", "rdp"}, DictProfile: "builtin",
		Status: "done", CreatedAt: started, StartedAt: &started, FinishedAt: &done,
		GeneratedAt: done,
		Rows: []*db.CredResult{
			{Host: "10.0.0.10", Port: 22, Protocol: "ssh", Username: "root", Password: "toor",
				Outcome: "hit", Banner: "SSH-2.0-OpenSSH_9.6", Evidence: "REQ-AUTH\nRESP-OK\n凭据: root / toor"},
			{Host: "10.0.0.10", Port: 22, Protocol: "ssh", Username: "admin", Password: "x",
				Outcome: "deny", Banner: "Permission denied", Evidence: "REQ-DENY\nRESP-DENY"},
			{Host: "10.0.0.10", Port: 6379, Protocol: "redis", Username: "",
				Outcome: "inconclusive", Reason: "端口上没有确认出该协议的握手特征"},
			{Host: "10.0.0.10", Port: 3389, Protocol: "rdp",
				Outcome: "unsupported", Reason: "该协议的握手形态本平台不实现，未发起连接"},
		},
	}
}

func TestCredscanMarkdownInternalHasEverything(t *testing.T) {
	in := credReportFixture()
	in.Internal = true
	md := CredscanMarkdown(in)
	for _, want := range []string{
		"内部版", "## 二、可用凭据", "root", "toor", "## 四、附录",
		"REQ-DENY", "RESP-DENY", "不可判定", "暂不支持",
		"没有完成任何一次有效认证判定",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("内部版缺 %q:\n%s", want, md)
		}
	}
}

func TestCredscanMarkdownExternalMasksAndListsGaps(t *testing.T) {
	in := credReportFixture()
	in.Internal = false
	md := CredscanMarkdown(in)
	if strings.Contains(md, "toor") {
		t.Fatalf("对外版不能出现口令明文:\n%s", md)
	}
	if strings.Contains(md, "REQ-DENY") {
		t.Fatalf("对外版不应收录拒绝行的报文:\n%s", md)
	}
	// 「未测 / 不支持」必须显式写出，不能留空。
	for _, want := range []string{"对外版", "t***r", "暂不支持", "未测", "没有完成任何一次有效认证判定"} {
		if !strings.Contains(md, want) {
			t.Fatalf("对外版缺 %q:\n%s", want, md)
		}
	}
}
