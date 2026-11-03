package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

func TestParseRawRequestKeepsQueryString(t *testing.T) {
	raw := "GET /api/query?id=1%27+union+select HTTP/1.1\r\nHost: example.com\r\nUser-Agent: jingwei\r\n\r\n"
	req, err := parseRawRequest(raw, "http://127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	want := "http://127.0.0.1:18080/api/query?id=1%27+union+select"
	if req.URL != want {
		t.Errorf("URL = %q, want %q", req.URL, want)
	}
	if req.Method != "GET" {
		t.Errorf("method = %q", req.Method)
	}
	if req.Headers["User-Agent"] != "jingwei" {
		t.Errorf("headers not parsed: %v", req.Headers)
	}
}

func TestParseRawRequestRelativePathAndBody(t *testing.T) {
	raw := "POST admin/login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nuser=admin&pass=admin"
	req, err := parseRawRequest(raw, "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if req.URL != "https://example.com/admin/login" {
		t.Errorf("URL = %q", req.URL)
	}
	if req.Method != "POST" {
		t.Errorf("method = %q", req.Method)
	}
	if req.Body != "user=admin&pass=admin" {
		t.Errorf("body = %q", req.Body)
	}
}

func TestParseRawRequestAbsoluteURL(t *testing.T) {
	raw := "GET https://other.example/x?y=1 HTTP/1.1\nHost: other.example\n\n"
	req, err := parseRawRequest(raw, "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if req.URL != "https://other.example/x?y=1" {
		t.Errorf("URL = %q", req.URL)
	}
}

func TestParseRawRequestRejectsBadInput(t *testing.T) {
	if _, err := parseRawRequest("GET", "http://x"); err == nil {
		t.Error("expected error for missing request line parts")
	}
	if _, err := parseRawRequest("GET / HTTP/1.1\n\n", ""); err == nil {
		t.Error("expected error when no target and relative path")
	}
}

// A proven injection must not be able to end up as a verdict nobody receives:
// the tool result says so when no finding took the write-back.
func TestProbeWriteBackNoteFiresOnlyWhenNothingLanded(t *testing.T) {
	probe := func(summary, params map[string]any) *db.DeepTask {
		return &db.DeepTask{Kind: db.DeepTaskSQLiProbe, Summary: summary, Params: params}
	}
	confirmed := map[string]any{"confirmed": float64(2)}

	if note := probeWriteBackNote(&db.DeepTask{Kind: db.DeepTaskExploit, Summary: confirmed}); note != "" {
		t.Errorf("generic exploit got a probe note: %q", note)
	}
	if note := probeWriteBackNote(probe(map[string]any{"confirmed": float64(0), "not_reproduced": float64(2)}, nil)); note != "" {
		t.Errorf("unconfirmed run got a write-back note: %q", note)
	}
	if note := probeWriteBackNote(probe(map[string]any{"confirmed": float64(2), "findings_confirmed": float64(2)}, nil)); note != "" {
		t.Errorf("linked findings still warned: %q", note)
	}
	if note := probeWriteBackNote(probe(confirmed, map[string]any{"write_finding": true})); note != "" {
		t.Errorf("self-written finding still warned: %q", note)
	}
	note := probeWriteBackNote(probe(confirmed, map[string]any{"points": []any{map[string]any{"url": "http://192.0.2.4/vul/sqli/sqli_str.php?name=1"}}}))
	if note == "" || !strings.Contains(note, "finding_ids") {
		t.Fatalf("orphan verdict not reported to the agent: %q", note)
	}
}

// The agent may name injection points and their findings at the top level; each
// point has to carry both, or the tool verdict cannot find the finding to update.
func TestProbePointsCarryTopLevelFindingIDs(t *testing.T) {
	var in deepToolInput
	raw := `{"urls":["http://192.0.2.4/vul/xss/xss_reflected_get.php?message=a","http://192.0.2.4/vul/sqli/sqli_id.php?id=1"],
	 "params":["message"],"finding_ids":[3418],
	 "points":[{"url":"http://192.0.2.4/vul/sqli/wide.php?id=1","method":"post","data":"id=1","finding_ids":[3419]}]}`
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	pts := in.probePoints()
	if len(pts) != 3 {
		t.Fatalf("points = %d, want 3", len(pts))
	}
	if got := pts[0]["method"]; got != "POST" || pts[0]["data"] != "id=1" {
		t.Errorf("explicit point lost its body: %v", pts[0])
	}
	if ids, _ := pts[0]["finding_ids"].([]int64); len(ids) != 1 || ids[0] != 3419 {
		t.Errorf("explicit point lost its finding ids: %v", pts[0]["finding_ids"])
	}
	for _, p := range pts[1:] {
		ids, _ := p["finding_ids"].([]int64)
		if len(ids) != 1 || ids[0] != 3418 {
			t.Errorf("url point did not inherit top-level finding ids: %v", p)
		}
		if params, _ := p["params"].([]string); len(params) != 1 || params[0] != "message" {
			t.Errorf("url point did not inherit top-level params: %v", p)
		}
	}
}

// queue_only lets an agent under a wall-clock deadline still get sqlmap/dalfox
// coverage instead of skipping verification because waiting would eat the intent.
// The note has to say what happens next — and warn when nothing will be written
// back because no finding was linked.
func TestQueuedProbeNoteTracksFindingLinks(t *testing.T) {
	linked := deepToolInput{FindingIDs: []int64{6442}}
	note := queuedProbeNote(db.DeepTaskSQLiProbe, 191, linked)
	if !strings.Contains(note, "已排队") || !strings.Contains(note, "#191") || !strings.Contains(note, "get_deep_task(task_id=191)") {
		t.Fatalf("queued note missing handle: %q", note)
	}
	if strings.Contains(note, "没有传 finding_ids") {
		t.Fatalf("linked probe warned anyway: %q", note)
	}
	if strings.Contains(queuedProbeNote(db.DeepTaskSQLiProbe, 191, deepToolInput{}), "不会回写") == false {
		t.Fatal("unlinked probe did not warn")
	}
	perPoint := deepToolInput{Points: []struct {
		URL        string   `json:"url"`
		Method     string   `json:"method"`
		Data       string   `json:"data"`
		TemplateID string   `json:"template_id"`
		Params     []string `json:"params"`
		FindingIDs []int64  `json:"finding_ids"`
	}{{URL: "http://x/p.php?a=1", FindingIDs: []int64{7}}}}
	if strings.Contains(queuedProbeNote(db.DeepTaskXSSProbe, 192, perPoint), "没有传 finding_ids") {
		t.Fatalf("per-point links ignored: %q", queuedProbeNote(db.DeepTaskXSSProbe, 192, perPoint))
	}
	if note := queuedProbeNote(db.DeepTaskExploit, 193, deepToolInput{}); strings.Contains(note, "finding_ids") {
		t.Fatalf("non-probe kind got probe advice: %q", note)
	}
}

// A scan whose POC pass found nothing can still get its first finding from an
// automatic SQLi/XSS deep task. The scan summary must then stop saying 0/0,
// otherwise the UI hides the finding and disables the report export.
func TestSyncScanAutoSummaryIncludesDeepFinding(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.OpenTestSchema(dsn, "jingwei_test_server")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	scan, err := d.CreateScanTask(db.ScanTaskInput{
		Name: "deep sync", Targets: []string{"http://127.0.0.1:9/"}, Mode: "auto",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM scan_tasks WHERE id=$1`, scan.ID) })
	if ok, err := d.ClaimScanTask(scan.ID); err != nil || !ok {
		t.Fatalf("claim scan: ok=%v err=%v", ok, err)
	}
	deep, err := d.CreateDeepTask(db.DeepTaskInput{
		Kind: db.DeepTaskSQLiProbe, Target: "http://127.0.0.1:9/", ScanTaskID: &scan.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE deep_tasks SET status='running' WHERE id=$1`, deep.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.FinishDeepTask(deep.ID, "done", "done", "", map[string]any{"confirmed": 1}); err != nil {
		t.Fatal(err)
	}

	id, _, err := d.UpsertFinding(0, 0, "sqli-probe", "SQL 注入", "high",
		"扫描未命中，深挖确认", "证据", "deep:test", nil,
		fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, id) })
	if err := d.LinkScanTaskResult(scan.ID, id, db.ScanTaskResult{
		TemplateID: "sqli-probe", Name: "SQL 注入", Severity: "high",
		Host: "http://127.0.0.1:9/", MatchedAt: "http://127.0.0.1:9/item?id=1", Type: "sqli_probe",
	}); err != nil {
		t.Fatal(err)
	}

	syncScanAutoSummary(d, scan.ID)
	got, err := d.GetScanTask(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary["results"] != float64(1) || got.Summary["findings"] != float64(1) {
		t.Fatalf("summary results/findings = %v/%v, want 1/1: %v",
			got.Summary["results"], got.Summary["findings"], got.Summary)
	}
	if got.Summary["auto_tasks"] != float64(1) {
		t.Fatalf("auto_tasks = %v, want 1: %v", got.Summary["auto_tasks"], got.Summary)
	}
}
