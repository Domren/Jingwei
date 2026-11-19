package guard

import (
	"strings"
	"testing"
)

// P8：被动线索出网在 egress guard 注册审计，只记固定 API 的 host 与字段名。

func TestAuditPassiveRecordsTargetAndFields(t *testing.T) {
	g := NewEgressGuard()
	g.AuditPassive("ct_log", "crt.sh", []string{"domain"}, true, "")
	g.AuditPassive("dns_history", "api.example", []string{"domain"}, false, "被动线索默认关闭")
	entries := g.PassiveAudit()
	if len(entries) != 2 {
		t.Fatalf("审计条数=%d", len(entries))
	}
	if entries[0].Kind != "ct_log" || entries[0].Target != "crt.sh" || !entries[0].Allowed {
		t.Fatalf("第一条: %+v", entries[0])
	}
	if len(entries[0].Fields) != 1 || entries[0].Fields[0] != "domain" {
		t.Fatalf("字段: %+v", entries[0].Fields)
	}
	if entries[1].Allowed || !strings.Contains(entries[1].Reason, "默认关闭") {
		t.Fatalf("第二条: %+v", entries[1])
	}
}
