package db

import (
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/pocparse"
)

// TestListEnabledPOCContentsSeverityFirst pins the full-scan template pick: the
// cap must drop the lowest-severity templates, never the newest ones (the old
// ORDER BY id cut exactly the templates a lab backfill adds), and the total
// must be reported so truncation is visible to the caller.
func TestListEnabledPOCContentsSeverityFirst(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM poc_templates WHERE template_id LIKE 't-fullcap-%'`) })

	seed := func(n int, severity string) {
		t.Helper()
		for i := 0; i < n; i++ {
			p, err := d.CreatePOCTemplate(&pocparse.Template{
				TemplateID: fmt.Sprintf("t-fullcap-%s-%d", severity, i),
				Name:       "fullcap " + severity, Severity: severity, Protocol: "http",
				Content:    "id: " + severity,
			}, "test", "")
			if err != nil {
				t.Fatal(err)
			}
			if !p.Enabled {
				t.Fatalf("seed %s not enabled", p.TemplateID)
			}
		}
	}
	seed(2, "critical")
	seed(3, "info")

	all, total, err := d.ListEnabledPOCContents(10000)
	if err != nil {
		t.Fatal(err)
	}
	if total != len(all) {
		t.Fatalf("total=%d but returned %d rows — total must count every enabled template", total, len(all))
	}
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	pos := map[string]int{}
	for i, p := range all {
		if i > 0 {
			if rank[all[i-1].Severity] < rank[p.Severity] {
				t.Fatalf("row %d (%s) outranks row %d (%s) — severity must be non-increasing", i, p.Severity, i-1, all[i-1].Severity)
			}
		}
		if len(p.TemplateID) > 9 && p.TemplateID[:9] == "t-fullcap" {
			pos[p.TemplateID] = i
		}
	}
	if len(pos) != 5 {
		t.Fatalf("expected 5 seeded templates in the full list, got %d", len(pos))
	}
	// The critical seeds were inserted AFTER the info ones (higher ids), yet must
	// sort ahead of them: that ordering is what keeps a freshly backfilled
	// authenticated POC inside the capped full scan.
	for c, i := range pos {
		if len(c) > 18 && c[:18] == "t-fullcap-critical" {
			for in, j := range pos {
				if len(in) > 13 && in[:13] == "t-fullcap-info" && i > j {
					t.Fatalf("critical seed %s at %d sorts after info seed %s at %d", c, i, in, j)
				}
			}
		}
	}

	// A capped call must return exactly the head of the same ordering.
	one, total1, err := d.ListEnabledPOCContents(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].TemplateID != all[0].TemplateID {
		t.Fatalf("capped pick = %v, want the top of the full ordering %q", one, all[0].TemplateID)
	}
	if total1 != total {
		t.Fatalf("capped total=%d, want %d — truncation must be reportable", total1, total)
	}
}
