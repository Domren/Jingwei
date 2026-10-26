package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

func evidenceFixture(t *testing.T) (*Store, db.RecordFindingInput, string) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN is required for evidence integration tests")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	capturedSince := time.Now().UTC()
	task, err := pg.CreateTask("evidence integration "+t.Name(), "local fixtures", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { purgeEvidenceFixture(t, pg, task.ID, capturedSince) })
	dir := t.TempDir()
	tr, err := traffic.Open(filepath.Join(dir, "traffic"), ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	store := New(pg, tr, filepath.Join(dir, "evidence"))
	in := db.RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Worker: "test", VulnClass: "TEST", Name: "Evidence fixture", Severity: "low", Summary: "local test"}
	return store, in, dir
}

// purgeEvidenceFixture removes a fixture task and everything that outlives it by
// design: findings keep their row when the task goes (task_id falls back to NULL)
// and traffic snapshots have no FK at all, so a plain DeleteTask leaves test
// evidence behind in whichever database the suite points at.
//
// capturedSince is the moment the fixture opened its pool: a snapshot has no task
// column, so the only handle on the ones a test captured and never bound is the
// time it was written.
func purgeEvidenceFixture(t *testing.T, pg *db.DB, taskID int64, capturedSince time.Time) {
	t.Helper()
	var snapshotIDs []string
	if err := pg.QueryRow(`SELECT COALESCE(array_agg(DISTINCT b.snapshot_id), '{}'::text[])::text[]
FROM finding_traffic_bindings b JOIN findings f ON f.id=b.finding_id WHERE f.task_id=$1`, taskID).Scan(&snapshotIDs); err != nil {
		t.Logf("读取夹具快照失败(task=%d): %v", taskID, err)
	}
	// The event payload keeps the task id even after the test deleted the finding
	// itself, so the join alone would miss those events.
	if _, err := pg.Exec(`DELETE FROM notification_events
WHERE finding_id IN (SELECT id FROM findings WHERE task_id=$1) OR snapshot->>'task_id' = $2`,
		taskID, fmt.Sprint(taskID)); err != nil {
		t.Logf("清理夹具推送事件失败(task=%d): %v", taskID, err)
	}
	// llm_records is created lazily (only a booting server ensures it), so asking
	// the cascade to clean it would abort the whole delete on a fresh test database.
	if _, err := pg.DeleteTaskCascade(taskID, true, true); err != nil {
		t.Logf("清理任务夹具失败(task=%d): %v", taskID, err)
	}
	// Bindings are gone with the findings, so a snapshot still bound belongs to
	// another task's evidence and must stay.
	if _, err := pg.Exec(`DELETE FROM traffic_evidence_snapshots s
WHERE (s.id = ANY($1::text[]) OR s.created_at >= $2)
  AND NOT EXISTS (SELECT 1 FROM finding_traffic_bindings b WHERE b.snapshot_id = s.id)`,
		snapshotIDs, capturedSince); err != nil {
		t.Logf("清理夹具快照失败(task=%d): %v", taskID, err)
	}
}

func seedExchange(t *testing.T, s *Store, id string, body []byte, spill bool) {
	t.Helper()
	var blob any
	inline := body
	if spill {
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])
		blob = hash
		path := filepath.Join(filepath.Dir(s.Dir), "traffic", "_blobs", "sha256", hash[:2], hash+".bin")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		inline = []byte("TRUNCATED PREVIEW")
	}
	_, err := s.Traffic.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES(?,?,'fixture.local','POST','/test',?,200,'application/octet-stream',2,?,'')`, id, time.Now().Unix(), "https://fixture.local/"+id, len(body))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Traffic.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body,resp_blob) VALUES(?,?,?, ?,?,?)`, id, "POST /test HTTP/1.1\nHost: fixture.local\n", []byte("{}"), "HTTP 200\nContent-Type: application/octet-stream\n", inline, blob)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceBindingLifecycle(t *testing.T) {
	s, in, _ := evidenceFixture(t)
	ctx := context.Background()
	large := bytes.Repeat([]byte{0, 1, 2, 255, 'a', 'b'}, 180000)
	for i := 0; i < 3; i++ {
		seedExchange(t, s, fmt.Sprint(i), large, i == 2)
	}
	refs := []db.TrafficRef{{TrafficID: "0", Role: "baseline", Note: "normal"}, {TrafficID: "1", Role: "proof", Note: "proof"}, {TrafficID: "2", Role: "verification", Note: "binary"}}
	r, err := s.Record(ctx, in, refs)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Traffic.Bindings) != 3 || r.Traffic.Version != 1 {
		t.Fatalf("record=%+v", r)
	}
	again, err := s.Bind(ctx, r.FindingID, []db.TrafficRef{{TrafficID: "1", Note: "must not overwrite"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Bindings) != 3 || again.Version != 1 || again.Bindings[1].Note != "proof" {
		t.Fatalf("duplicate changed bindings: %+v", again)
	}
	other, err := s.Record(ctx, in, []db.TrafficRef{refs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if other.Traffic.Bindings[0].SnapshotID != r.Traffic.Bindings[2].SnapshotID {
		t.Fatal("snapshot was not shared")
	}
	if _, err = s.Traffic.DeleteHost("fixture.local"); err != nil {
		t.Fatal(err)
	}
	for _, binding := range r.Traffic.Bindings {
		if err = s.WithBinding(ctx, r.FindingID, binding.ID, func(b db.FindingTrafficBinding) error {
			f, _, err := s.OpenBody(b.Snapshot, "response")
			if err != nil {
				return err
			}
			defer f.Close()
			got, err := io.ReadAll(f)
			if !bytes.Equal(got, large) {
				t.Fatal("body was truncated/changed")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	v := again.Version
	if _, err = s.DB.SetFindingReportVersionByNodeID(ctx, r.NodeID, "report", &v); err != nil {
		t.Fatal(err)
	}
	note := "updated"
	if err = s.DB.EditFindingTraffic(ctx, r.FindingID, again.Bindings[0].ID, v, nil, &note, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.SetFindingReportVersionByNodeID(ctx, r.NodeID, "stale report", &v); !errors.Is(err, db.ErrEvidenceConflict) {
		t.Fatalf("stale report: %v", err)
	}
	f, err := s.DB.GetFinding(r.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if f.Report != "report" || f.EvidenceVersion == f.ReportEvidenceVersion || f.TrafficCount != 3 {
		t.Fatalf("finding versions: %+v", f)
	}
	if err = s.DB.EditFindingTraffic(ctx, r.FindingID, again.Bindings[0].ID, v, nil, nil, true, nil); !errors.Is(err, db.ErrEvidenceConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if _, err = s.DB.SetFindingReportByNodeID(r.NodeID, "legacy report"); err != nil {
		t.Fatal(err)
	}
	f, err = s.DB.GetFinding(r.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if f.ReportEvidenceVersion != -1 {
		t.Fatal("legacy write claimed current evidence")
	}
	if _, err = s.DB.DeleteFinding(r.FindingID); err != nil {
		t.Fatal(err)
	}
	if err = s.Collect(ctx, time.Now().Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = s.WithBinding(ctx, other.FindingID, other.Traffic.Bindings[0].ID, func(b db.FindingTrafficBinding) error {
		f, _, err := s.OpenBody(b.Snapshot, "response")
		if f != nil {
			f.Close()
		}
		return err
	}); err != nil {
		t.Fatal("GC removed shared body:", err)
	}
}

func TestEvidenceAtomicFailuresAndLegacy(t *testing.T) {
	s, in, dir := evidenceFixture(t)
	ctx := context.Background()
	seedExchange(t, s, "valid", []byte("OK"), false)
	counts := func() (findings, nodes int) {
		s.DB.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, in.TaskID).Scan(&findings)
		s.DB.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='finding'`, in.ExplorationID).Scan(&nodes)
		return
	}
	for _, kind := range []string{"missing_id", "missing_body", "disk_failure", "database_failure"} {
		t.Run(kind, func(t *testing.T) {
			input := in
			refs := []db.TrafficRef{{TrafficID: "valid"}, {TrafficID: "absent"}}
			local := *s
			switch kind {
			case "missing_body":
				seedExchange(t, s, "broken", []byte("more than preview"), false)
				s.Traffic.DB().Exec(`UPDATE exchange_bodies SET resp_body=? WHERE id='broken'`, []byte("x"))
				refs = []db.TrafficRef{{TrafficID: "valid"}, {TrafficID: "broken"}}
			case "disk_failure":
				local.Dir = filepath.Join(dir, "file-not-dir")
				if err := os.WriteFile(local.Dir, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				refs = refs[:1]
			case "database_failure":
				input.AssetIDs = []int64{9223372036854775807}
				refs = refs[:1]
			}
			if _, err := local.Record(ctx, input, refs); err == nil {
				t.Fatal("expected failure")
			}
			if f, n := counts(); f != 0 || n != 0 {
				t.Fatalf("partial record: findings=%d nodes=%d", f, n)
			}
		})
	}
	legacy := filepath.Join(dir, "traffic", "legacy")
	os.MkdirAll(legacy, 0o700)
	os.WriteFile(filepath.Join(legacy, "request.http"), []byte("GET / HTTP/1.1\nHost: old.local\n"), 0o600)
	os.WriteFile(filepath.Join(legacy, "response.http"), []byte("HTTP 200\n\nlegacy body"), 0o600)
	_, err := s.Traffic.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES('old',1,'old.local','GET','/','http://old.local/',200,'text/plain',0,11,'legacy')`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Record(ctx, in, []db.TrafficRef{{TrafficID: "old"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Record(ctx, in, nil); err != nil {
		t.Fatal("legacy no-traffic report failed:", err)
	}
}

func TestEvidenceConcurrentBindAndDelete(t *testing.T) {
	s, in, _ := evidenceFixture(t)
	ctx := context.Background()
	seedExchange(t, s, "race", bytes.Repeat([]byte("large"), 90000), true)
	r, err := s.Record(ctx, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Bind(ctx, r.FindingID, []db.TrafficRef{{TrafficID: "race"}})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.DB.GetFindingTraffic(ctx, r.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Bindings) != 1 || list.Version != 1 {
		t.Fatalf("concurrent duplicates: %+v", list)
	}
	// Race a new capture copy with source deletion: either the full copy commits
	// or nothing does. An already-bound snapshot remains readable in both cases.
	wg.Add(2)
	go func() { defer wg.Done(); s.Bind(ctx, r.FindingID, []db.TrafficRef{{TrafficID: "race"}}) }()
	go func() { defer wg.Done(); s.Traffic.DeleteHost("fixture.local") }()
	wg.Wait()
	if err = s.WithBinding(ctx, r.FindingID, list.Bindings[0].ID, func(b db.FindingTrafficBinding) error {
		f, _, err := s.OpenBody(b.Snapshot, "response")
		if f != nil {
			f.Close()
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceGCGraceAndActiveRestore(t *testing.T) {
	s, in, _ := evidenceFixture(t)
	ctx := context.Background()
	seedExchange(t, s, "gc", []byte("unique unreferenced gc body"), false)
	f, err := s.Record(ctx, in, []db.TrafficRef{{TrafficID: "gc"}})
	if err != nil {
		t.Fatal(err)
	}
	snap := f.Traffic.Bindings[0].Snapshot
	archive := t.TempDir()
	if err = s.CopySnapshots(ctx, []db.TrafficEvidenceSnapshot{snap}, archive); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.DeleteFinding(f.FindingID); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err = s.Collect(ctx, now); err != nil {
		t.Fatal(err)
	}
	path, err := hashPath(s.Dir, snap.RespHash)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Collect(ctx, now.Add(23*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("GC grace ignored", err)
	}
	if err = s.Collect(ctx, now.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("orphan was not collected", err)
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- s.WithInstalledSnapshots(ctx, []db.TrafficEvidenceSnapshot{snap}, archive, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	err = s.Collect(short, now.Add(72*time.Hour))
	cancel()
	close(release)
	if err == nil {
		t.Fatal("GC entered during active restore")
	}
	if err = <-finished; err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("active restore lost body", err)
	}
	// A portable package cannot substitute metadata while retaining its old ID.
	bad := snap
	bad.URL = "http://tampered.local/"
	if err = s.InstallSnapshots(ctx, []db.TrafficEvidenceSnapshot{bad}, archive); err == nil {
		t.Fatal("accepted tampered snapshot")
	}
}

func TestSaveRawExchangesPersistsReproductionSequence(t *testing.T) {
	s, in, _ := evidenceFixture(t)
	ctx := context.Background()
	rec, err := s.Record(ctx, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	exchanges := []RawExchange{
		{
			Request:  "POST /exploit HTTP/1.1\r\nHost: fixture.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nx=1",
			Response: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nqueued",
			Role:     "supporting",
			Note:     "exploit request",
		},
		{
			Request:  "GET /proof HTTP/1.1\r\nHost: fixture.local\r\n\r\n",
			Response: "HTTP/1.1 200 OK\r\n\r\nsecret",
			Role:     "proof",
			Note:     "proof request",
		},
	}
	if err = s.SaveRawExchanges(ctx, rec.FindingID, exchanges); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveRawExchanges(ctx, rec.FindingID, exchanges); err != nil {
		t.Fatal(err)
	}
	ft, err := s.DB.GetFindingTraffic(ctx, rec.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ft.Bindings) != 2 {
		t.Fatalf("want 2 deduplicated bindings, got %d", len(ft.Bindings))
	}
	for _, b := range ft.Bindings {
		if b.Snapshot.Method == "GET" && b.Snapshot.URL != "http://fixture.local/proof" {
			t.Fatalf("URL not parsed: %#v", b.Snapshot)
		}
		if b.Snapshot.Status != 200 || b.Snapshot.ContentType == "" && b.Snapshot.Method == "POST" {
			t.Fatalf("status/content-type not parsed: %#v", b.Snapshot)
		}
		f, _, err := s.OpenBody(b.Snapshot, "response")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if b.Role == "proof" && !bytes.Contains(body, []byte("secret")) {
			t.Fatalf("proof body missing: %q", body)
		}
		if b.Role == "supporting" && !bytes.Contains(body, []byte("queued")) {
			t.Fatalf("supporting body missing: %q", body)
		}
	}
}
