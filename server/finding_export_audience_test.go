package server

import (
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

// H2：对外版只含已确认项。抽查一批混合状态的发现，未确认与被撤销的必须被排除且计数可查。
func TestFindingExportExternalKeepsConfirmedOnly(t *testing.T) {
	fs := []*db.DBFinding{
		{ID: 1, Status: "confirmed"},
		{ID: 2, Status: "fixed"},
		{ID: 3, Status: "resolved"},
		{ID: 4, Status: "risk_accepted"},
		{ID: 5, Status: "pending"},
		{ID: 6, Status: "in_progress"},
		{ID: 7, Status: "false_positive"},
		{ID: 8, Status: "ignored"},
		{ID: 9, Status: "duplicate"},
	}
	kept, excluded := findingExportExternal(fs)
	if excluded != 5 {
		t.Fatalf("excluded = %d want 5", excluded)
	}
	if len(kept) != 4 {
		t.Fatalf("kept = %d want 4", len(kept))
	}
	for _, f := range kept {
		switch f.Status {
		case "confirmed", "fixed", "resolved", "risk_accepted":
		default:
			t.Fatalf("对外版混入了 %q", f.Status)
		}
	}
}
