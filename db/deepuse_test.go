package db

import (
	"fmt"
	"testing"
	"time"
)

func deepTestSetup(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	return d
}

func TestDeepTaskLifecycle(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateDeepTask(DeepTaskInput{
		Name:   "验证测试",
		Kind:   DeepTaskVerify,
		Target: "http://127.0.0.1:1/",
		Params: map[string]any{"template_ids": []any{int64(1)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM deep_tasks WHERE id = $1`, task.ID)

	if task.Status != "queued" {
		t.Errorf("expected queued, got %q", task.Status)
	}
	if task.Params["template_ids"] == nil {
		t.Error("params not persisted")
	}

	claimed, err := d.ClaimNextDeepTask()
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.ID != task.ID {
		t.Fatalf("expected to claim task %d, got %v", task.ID, claimed)
	}

	if err := d.UpdateDeepTaskProgress(task.ID, "verify", map[string]any{"checked": 2}, "line one"); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetDeepTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "running" || got.Stage != "verify" {
		t.Errorf("unexpected state: status=%q stage=%q", got.Status, got.Stage)
	}
	if got.Log == "" {
		t.Error("log line not persisted")
	}

	if err := d.FinishDeepTask(task.ID, "done", "done", "", map[string]any{"results": 3}); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetDeepTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "done" || got.Summary["results"] == nil {
		t.Errorf("finish not persisted: status=%q summary=%v", got.Status, got.Summary)
	}
	if got.FinishedAt == nil {
		t.Error("finished_at not set")
	}

	// A finished task is not claimable again.
	claimed, err = d.ClaimNextDeepTask()
	if err != nil {
		t.Fatal(err)
	}
	if claimed != nil {
		t.Errorf("finished task was reclaimed: %+v", claimed)
	}

	tasks, total, err := d.ListDeepTasks(DeepTaskVerify, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total < 1 {
		t.Errorf("expected at least one task, got %d", total)
	}
	found := false
	for _, tk := range tasks {
		if tk.ID == task.ID {
			found = true
		}
	}
	if !found {
		t.Error("created task missing from filtered list")
	}
}

func TestDeepTaskCancelAndRecover(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateDeepTask(DeepTaskInput{Kind: DeepTaskExploit, Target: "http://127.0.0.1:2/"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM deep_tasks WHERE id = $1`, task.ID)

	ok, err := d.CancelDeepTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected cancel to succeed")
	}
	got, err := d.GetDeepTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "canceled" {
		t.Errorf("expected canceled, got %q", got.Status)
	}

	// A canceled task must not be claimable.
	claimed, err := d.ClaimNextDeepTask()
	if err != nil {
		t.Fatal(err)
	}
	if claimed != nil {
		t.Errorf("canceled task was claimed: %+v", claimed)
	}

	// Interrupt recovery flips running tasks to failed.
	d.Exec(`UPDATE deep_tasks SET status='running' WHERE id = $1`, task.ID)
	n, err := d.RecoverInterruptedDeepTasks()
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Error("expected at least one recovered task")
	}
	got, err = d.GetDeepTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "failed" {
		t.Errorf("expected failed after recovery, got %q", got.Status)
	}
}

func TestExploitRecordAndWAFResultStorage(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateDeepTask(DeepTaskInput{Kind: DeepTaskExploit, Target: "http://127.0.0.1:3/"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM deep_tasks WHERE id = $1`, task.ID)

	status := 200
	if _, err := d.AddExploitRecord(ExploitRecord{
		TaskID:     task.ID,
		Mode:       "verify",
		TemplateID: "test-template",
		Name:       "测试漏洞",
		Severity:   "high",
		Target:     "http://127.0.0.1:3/x",
		Verdict:    "confirmed",
		StatusCode: &status,
		Request:    "GET /x HTTP/1.1",
		Response:   "HTTP/1.1 200 OK",
		Evidence:   "matched",
	}); err != nil {
		t.Fatal(err)
	}
	records, err := d.ListExploitRecords(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Verdict != "confirmed" || records[0].Request == "" {
		t.Errorf("record fields not persisted: %+v", records[0])
	}

	wafStatus := 403
	if _, err := d.AddWAFBypassResult(WAFBypassResult{
		TaskID:      task.ID,
		Target:      "http://127.0.0.1:3/",
		WAFDetected: true,
		WAFVendor:   "Cloudflare",
		Variant:     "urlencode",
		VariantDesc: "URL 编码",
		Method:      "GET",
		Path:        "/?id=1%27",
		StatusCode:  &wafStatus,
		Verdict:     "blocked",
	}); err != nil {
		t.Fatal(err)
	}
	results, err := d.ListWAFBypassResults(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 waf result, got %d", len(results))
	}
	if !results[0].WAFDetected || results[0].WAFVendor != "Cloudflare" {
		t.Errorf("waf fields not persisted: %+v", results[0])
	}
}

func TestScanAutoStatsAndSummaryMerge(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	scan, err := d.CreateScanTask(ScanTaskInput{
		Name: "auto stats", Targets: []string{"http://127.0.0.1:9/"}, Mode: "auto",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM scan_tasks WHERE id = $1`, scan.ID)
	if ok, err := d.ClaimScanTask(scan.ID); err != nil || !ok {
		t.Fatalf("claim scan: ok=%v err=%v", ok, err)
	}

	// A deep task left over from an earlier run must not be counted.
	stale, err := d.CreateDeepTask(DeepTaskInput{
		Kind: DeepTaskExploit, Target: "http://127.0.0.1:9/", ScanTaskID: &scan.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE deep_tasks SET status='done', created_at=now()-interval '1 hour' WHERE id=$1`, stale.ID); err != nil {
		t.Fatal(err)
	}

	task, err := d.CreateDeepTask(DeepTaskInput{
		Kind: DeepTaskExploit, Target: "http://127.0.0.1:9/", ScanTaskID: &scan.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"confirmed", "not_reproduced"} {
		if _, err := d.AddExploitRecord(ExploitRecord{
			TaskID: task.ID, Mode: "verify", TemplateID: "t-" + v, Target: task.Target, Verdict: v,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Exec(`UPDATE deep_tasks SET status='running' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.FinishDeepTask(task.ID, "done", "done", "", map[string]any{"confirmed": 1}); err != nil {
		t.Fatal(err)
	}

	st, err := d.ScanAutoStats(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := ScanAutoStats{Tasks: 1, Done: 1, Records: 2, Confirmed: 1}
	if st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}

	if err := d.MergeScanTaskSummary(scan.ID, map[string]any{
		"auto_tasks": st.Tasks, "auto_done": st.Done, "auto_confirmed": st.Confirmed,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetScanTask(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary["auto_tasks"] != float64(1) || got.Summary["auto_confirmed"] != float64(1) {
		t.Errorf("summary not merged: %v", got.Summary)
	}
}

func TestLinkScanTaskResultBindsDeepFinding(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	scan, err := d.CreateScanTask(ScanTaskInput{
		Name: "deep link", Targets: []string{"http://127.0.0.1:9/"}, Mode: "auto",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM scan_tasks WHERE id = $1`, scan.ID)

	dedupe := fmt.Sprintf("test-scan-link-%d", time.Now().UnixNano())
	link, err := func() (int64, error) {
		id, _, err := d.UpsertFinding(0, 0, "sqli-probe", "SQL 注入", "high",
			"深挖确认", "证据", "deep:test", nil, dedupe)
		return id, err
	}()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id = $1`, link)

	// The scan never recorded this match; the deep task's row is inserted.
	deepResult := ScanTaskResult{
		TemplateID: "sqli-probe", Name: "SQL 注入", Severity: "high",
		Host: "http://127.0.0.1:9/", MatchedAt: "http://127.0.0.1:9/item?id=1",
		Type: "verify", Extracted: []string{"id 参数"},
		Raw: map[string]any{"source": "deep", "deep_task_id": 1},
	}
	if err := d.LinkScanTaskResult(scan.ID, link, deepResult); err != nil {
		t.Fatal(err)
	}
	results, findings, err := d.ScanTaskResultCounts(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if results != 1 || findings != 1 {
		t.Fatalf("counts after link = %d/%d, want 1/1", results, findings)
	}

	// Re-linking the same match must not duplicate the row.
	if err := d.LinkScanTaskResult(scan.ID, link, deepResult); err != nil {
		t.Fatal(err)
	}
	list, err := d.ListScanTaskResults(scan.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].FindingID == nil || *list[0].FindingID != link {
		t.Fatalf("linked results = %+v", list)
	}

	// A result the scan stored without a finding gets the finding attached
	// instead of a second row.
	empty := ScanTaskResult{TemplateID: "xss-probe", Severity: "medium",
		MatchedAt: "http://127.0.0.1:9/search?q=1"}
	if _, err := d.AddScanTaskResult(scan.ID, 0, empty); err != nil {
		t.Fatal(err)
	}
	link2, _, err := d.UpsertFinding(0, 0, "xss-probe", "XSS", "medium",
		"深挖确认", "证据", "deep:test", nil, dedupe+"-2")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id = $1`, link2)
	if err := d.LinkScanTaskResult(scan.ID, link2, empty); err != nil {
		t.Fatal(err)
	}
	results, findings, err = d.ScanTaskResultCounts(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if results != 2 || findings != 2 {
		t.Fatalf("counts after attach = %d/%d, want 2/2", results, findings)
	}
}

func TestWebshellV2SecretLifecycle(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	shell, err := d.CreateWebshell(WebshellInput{
		Name:          "v2 shell",
		URL:           "http://127.0.0.1:4/v2.php",
		ShellType:     "php",
		Protocol:      "v2",
		Secret:        "v1:sealed-secret",
		Carrier:       "X-Ab12Cd34Ef",
		PayloadSHA256: "abc123",
		KeyVersion:    1,
		Target:        "http://127.0.0.1:4/",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM webshells WHERE id = $1`, shell.ID)

	if shell.Protocol != "v2" || !shell.HasSecret || shell.HasPassword {
		t.Fatalf("unexpected v2 shell flags: %+v", shell)
	}
	if shell.Carrier != "X-Ab12Cd34Ef" || shell.PayloadSHA256 != "abc123" || shell.KeyVersion != 1 {
		t.Fatalf("v2 fields not persisted: %+v", shell)
	}

	// Empty password on update must not wipe a stored secret or protocol.
	if err := d.UpdateWebshell(shell.ID, WebshellInput{Name: "改名", URL: shell.URL, ShellType: "php"}); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetWebshell(shell.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != "v2" || got.Secret != "v1:sealed-secret" || got.Carrier != shell.Carrier {
		t.Fatalf("update touched server-managed fields: %+v", got)
	}

	if err := d.UpdateWebshellSecret(shell.ID, "v1:rotated", "jw_NewCarrier1", "def456", 2); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetWebshell(shell.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != "v1:rotated" || got.Carrier != "jw_NewCarrier1" ||
		got.PayloadSHA256 != "def456" || got.KeyVersion != 2 {
		t.Fatalf("rotation not persisted: %+v", got)
	}
}

func TestWebshellCRUD(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	shell, err := d.CreateWebshell(WebshellInput{
		Name:      "测试 shell",
		URL:       "http://127.0.0.1:4/shell.php",
		ShellType: "php",
		Password:  "pw",
		Target:    "http://127.0.0.1:4/",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM webshells WHERE id = $1`, shell.ID)

	if shell.Status != "unknown" {
		t.Errorf("expected unknown status, got %q", shell.Status)
	}

	if err := d.UpdateWebshellState(shell.ID, "alive", "uid=0", "ok"); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetWebshell(shell.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "alive" || got.LastOutput != "uid=0" || got.LastChecked == nil {
		t.Errorf("state update not persisted: %+v", got)
	}

	if err := d.UpdateWebshell(shell.ID, WebshellInput{Name: "改名", URL: shell.URL, ShellType: "php"}); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetWebshell(shell.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "改名" {
		t.Errorf("update not persisted: %+v", got)
	}

	shells, total, err := d.ListWebshells("", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total < 1 || len(shells) == 0 {
		t.Errorf("expected at least one webshell, total=%d", total)
	}

	ok, err := d.DeleteWebshell(shell.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected delete to succeed")
	}
	if _, err := d.GetWebshell(shell.ID); err == nil {
		t.Error("deleted webshell still readable")
	}
}
