package scanner

import (
	"context"
	"strings"
	"testing"
)

// B4 降级口径：二档八项必须逐项出现在目录里、标为不支持、带原因与展示端口。
// 少一项，界面上就静默少一个「不能勾」的协议；原因缺了，操作员就不知道为什么不能勾。
func TestCredCatalogSecondTierDowngrade(t *testing.T) {
	secondTier := map[string]int{
		"mssql": 1433, "smb": 445, "winrm": 5985, "oracle": 1521,
		"routeros": 8728, "cobaltstrike": 50050, "jenkins": 8080, "svn": 3690,
	}
	catalog := map[string]CredProtocolInfo{}
	for _, p := range CredProtocolCatalog() {
		if _, dup := catalog[p.Name]; dup {
			t.Fatalf("目录里出现重复协议 %q", p.Name)
		}
		catalog[p.Name] = p
	}
	for name, port := range secondTier {
		info, ok := catalog[name]
		if !ok {
			t.Fatalf("二档协议 %q 没有进目录", name)
		}
		if info.Supported {
			t.Fatalf("%q 本版不做适配器，必须标为不支持", name)
		}
		if info.DefaultPort != port {
			t.Fatalf("%q 展示端口 = %d，want %d", name, info.DefaultPort, port)
		}
		if strings.TrimSpace(info.Note) == "" {
			t.Fatalf("%q 缺少降级原因", name)
		}
		if CredProtocolSupported(name) {
			t.Fatalf("%q 应当报不支持", name)
		}
		if CredUnsupportedReason(name) != info.Note {
			t.Fatalf("%q 目录原因与 CredUnsupportedReason 不一致", name)
		}
	}
	for name, info := range catalog {
		if info.Supported && info.Note != "" {
			t.Fatalf("支持的协议 %q 不该带降级原因", name)
		}
	}
}

// 引擎遇到降级协议时，登记的原因要原样进结果行——报告与前端靠这句话解释「为什么没测」。
func TestCredRunUnsupportedCarriesRegisteredReason(t *testing.T) {
	plan := []CredEndpoint{{Host: "10.0.0.42", Port: 1433, Protocol: "mssql", ProtocolConfirmed: true}}
	c := &credCollector{}
	if err := CredRun(context.Background(), plan, []Credential{{Username: "sa", Password: "x"}},
		CredOptions{}, c.emit); err != nil {
		t.Fatal(err)
	}
	rows := c.all()
	if len(rows) != 1 || rows[0].Outcome != CredUnsupported {
		t.Fatalf("results = %+v", rows)
	}
	if !strings.Contains(rows[0].Reason, CredUnsupportedReason("mssql")) ||
		!strings.Contains(rows[0].Reason, "未发起连接") {
		t.Fatalf("原因要带登记的降级理由与未连接声明: %q", rows[0].Reason)
	}
}