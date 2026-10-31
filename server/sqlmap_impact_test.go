package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/scanner"
)

func TestSQLMapImpactLines(t *testing.T) {
	if got := sqlmapImpactLines(nil); got != "" {
		t.Fatalf("nil escalation rendered %q", got)
	}
	esc := &scanner.SQLMapEscalation{
		Banner: "5.7.26", CurrentUser: "root@localhost", CurrentDB: "dvwa",
		Hostname: "db01", DBAText: "True", IsDBA: true, TimedOut: true,
	}
	text := sqlmapImpactLines(esc)
	for _, want := range []string{"影响评估", "5.7.26", "root@localhost", "dvwa", "db01", "DBA 权限: True", "超出时限"} {
		if !strings.Contains(text, want) {
			t.Errorf("impact lines missing %q:\n%s", want, text)
		}
	}
	// The header must say the run stayed metadata-only: this text lands in the
	// finding evidence a reviewer reads.
	if !strings.Contains(text, "未读取业务数据") {
		t.Errorf("impact lines do not state the metadata-only scope:\n%s", text)
	}
}

func TestSQLMapImpactCritical(t *testing.T) {
	if sqlmapImpactCritical(nil) {
		t.Error("nil escalation marked critical")
	}
	if sqlmapImpactCritical(&scanner.SQLMapEscalation{DBAText: "False"}) {
		t.Error("non-DBA escalation marked critical")
	}
	if !sqlmapImpactCritical(&scanner.SQLMapEscalation{DBAText: "True", IsDBA: true}) {
		t.Error("DBA escalation not marked critical")
	}
}

func TestParamDefaultTrue(t *testing.T) {
	if !paramDefaultTrue(nil, "escalate") {
		t.Error("nil params should default to true")
	}
	if !paramDefaultTrue(map[string]any{}, "escalate") {
		t.Error("missing key should default to true")
	}
	if paramDefaultTrue(map[string]any{"escalate": false}, "escalate") {
		t.Error("explicit false ignored")
	}
	if paramDefaultTrue(map[string]any{"escalate": "false"}, "escalate") {
		t.Error("string false ignored")
	}
	if !paramDefaultTrue(map[string]any{"escalate": true}, "escalate") {
		t.Error("explicit true ignored")
	}
}
