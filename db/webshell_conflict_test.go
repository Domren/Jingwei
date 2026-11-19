package db

import "testing"

// TestWebshellDeployConflictRecord 验证 P18 的拦截记录能落库/列出/标记处置，
// 依赖真实 PG，无库时按惯例跳过。
func TestWebshellDeployConflictRecord(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	id, err := d.AddWebshellDeployConflict(nil,
		"http://t/shell.php", "http://t/upload.php", "JW_FILE_EXISTS", "落地已有文件")
	if err != nil {
		t.Fatalf("add conflict: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM webshell_deploy_conflicts WHERE id=$1`, id) })

	list, err := d.ListWebshellDeployConflicts(true, 10)
	if err != nil || len(list) == 0 {
		t.Fatalf("list unresolved: n=%d err=%v", len(list), err)
	}
	found := false
	for _, c := range list {
		if c.ID == id {
			found = true
			if c.Marker != "JW_FILE_EXISTS" || c.Status != "manual" || c.Resolved {
				t.Fatalf("record shape: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("new conflict not in unresolved list")
	}
	if err := d.ResolveWebshellDeployConflict(id); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	list, err = d.ListWebshellDeployConflicts(true, 10)
	if err != nil {
		t.Fatalf("list after resolve: %v", err)
	}
	for _, c := range list {
		if c.ID == id {
			t.Fatal("resolved conflict should not appear in unresolved list")
		}
	}
}
