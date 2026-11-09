package scanner

import (
	"context"
	"strings"
	"testing"
)

// 12 个原降级协议在本版都实现了适配器：目录里必须逐项标为支持、端口正确、
// 且不再带「暂不支持」原因。少一项，界面上就静默少一个可勾的协议。
func TestCredCatalogDowngradedProtocolsNowSupported(t *testing.T) {
	former := map[string]int{
		"mssql": 1433, "smb": 445, "winrm": 5985, "oracle": 1521,
		"routeros": 8728, "cobaltstrike": 50050, "jenkins": 8080, "svn": 3690,
		"snmp": 161, "rdp": 3389, "weblogic-console": 7001, "jboss-console": 8080,
	}
	catalog := map[string]CredProtocolInfo{}
	for _, p := range CredProtocolCatalog() {
		if _, dup := catalog[p.Name]; dup {
			t.Fatalf("目录里出现重复协议 %q", p.Name)
		}
		catalog[p.Name] = p
	}
	for name, port := range former {
		info, ok := catalog[name]
		if !ok {
			t.Fatalf("协议 %q 没有进目录", name)
		}
		if !info.Supported {
			t.Fatalf("%q 已实现适配器，目录必须标为支持（note=%q）", name, info.Note)
		}
		if info.DefaultPort != port {
			t.Fatalf("%q 展示端口 = %d，want %d", name, info.DefaultPort, port)
		}
		if strings.TrimSpace(info.Note) != "" {
			t.Fatalf("%q 已支持却仍带降级原因: %q", name, info.Note)
		}
		if !CredProtocolSupported(name) {
			t.Fatalf("%q 应当报支持", name)
		}
		if CredUnsupportedReason(name) != "" {
			t.Fatalf("%q 不该再有降级原因", name)
		}
	}
	for name, info := range catalog {
		if info.Supported && info.Note != "" {
			t.Fatalf("支持的协议 %q 不该带降级原因", name)
		}
	}
}

// 没有适配器的协议：落 unsupported + 明确原因，且一个包都不发。
func TestCredRunUnimplementedCarriesReason(t *testing.T) {
	plan := []CredEndpoint{{Host: "10.0.0.42", Port: 1433, Protocol: "legacy-proto-xyz", ProtocolConfirmed: true}}
	c := &credCollector{}
	if err := CredRun(context.Background(), plan, []Credential{{Username: "sa", Password: "x"}},
		CredOptions{}, c.emit); err != nil {
		t.Fatal(err)
	}
	rows := c.all()
	if len(rows) != 1 || rows[0].Outcome != CredUnsupported {
		t.Fatalf("results = %+v", rows)
	}
	if !strings.Contains(rows[0].Reason, "尚未实现") || !strings.Contains(rows[0].Reason, "未发起连接") {
		t.Fatalf("原因要说明未实现且未连接: %q", rows[0].Reason)
	}
}
