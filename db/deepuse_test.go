package db

import (
	"testing"
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
