package db

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestFindingReproductionRoundTrip 验证 reproduction 列能原样存取，并且
// ReResolveFindingReproduction 能在后补流量后把步骤重新连到快照上。
func TestFindingReproductionRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	var findingID int64
	if err := d.QueryRow(`INSERT INTO findings(vulnclass,name,severity,summary,evidence,worker,asset_ids,reproduction)
		VALUES('upload','文件上传导致RCE','critical','上传可执行','证据','test','[]',
		$1::jsonb) RETURNING id`,
		`{"entry_point":"POST /upload.php","prerequisites":["无需认证"],"provenance":"上传接口","steps":[{"request":"POST /upload.php HTTP/1.1","expected":"上传成功","proves":"可写文件"}]}`,
	).Scan(&findingID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, findingID)
	})

	f, err := d.GetFinding(findingID)
	if err != nil || f == nil {
		t.Fatalf("get finding: %v", err)
	}
	if f.Reproduction == nil {
		t.Fatal("reproduction not parsed back")
	}
	if f.Reproduction.EntryPoint != "POST /upload.php" || len(f.Reproduction.Steps) != 1 {
		t.Fatalf("unexpected reproduction: %+v", f.Reproduction)
	}
	if f.Reproduction.Prerequisites[0] != "无需认证" {
		t.Fatalf("prerequisites lost: %+v", f.Reproduction.Prerequisites)
	}

	// 后补一条真实流量快照并绑定，然后重新解析：步骤应被连到这条快照上。
	// ID 带时间戳，避免上次中断运行留下的行让本用例撞主键。
	snapID := fmt.Sprintf("repro-test-snapshot-%d", time.Now().UnixNano())
	if _, err := d.Exec(`INSERT INTO traffic_evidence_snapshots(id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len)
		VALUES($1,$1,0,'http://lab.example/upload.php','POST',200,'','POST /upload.php HTTP/1.1','','h1','h2',0,0)`, snapID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM traffic_evidence_snapshots WHERE id=$1`, snapID) })
	if _, err := d.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position) VALUES($1,$2,'proof','复现第 1 步',0)`, findingID, snapID); err != nil {
		t.Fatal(err)
	}

	if err := d.ReResolveFindingReproduction(ctx, findingID); err != nil {
		t.Fatalf("re-resolve: %v", err)
	}
	f2, err := d.GetFinding(findingID)
	if err != nil || f2 == nil || f2.Reproduction == nil {
		t.Fatalf("reload: %v", err)
	}
	if f2.Reproduction.Steps[0].SnapshotID != snapID {
		t.Fatalf("step not linked to snapshot, got %q", f2.Reproduction.Steps[0].SnapshotID)
	}
	if f2.Reproduction.Steps[0].Match != "request" {
		t.Fatalf("expected request match, got %q", f2.Reproduction.Steps[0].Match)
	}
}
