package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	actool "github.com/Autumn-27/norma/tool"
)

// ---------------------------------------------------------------------------
// 落地地址被重复投放：上传已经把目标上的文件换掉了，旧记录描述的载荷不再存在。
// 再插一行会让撤离去自删除一个不存在的文件、让绑在旧 id 上的会话每条命令都对不
// 上密钥，所以同一地址只能有一条记录，且覆盖必须留下证据。
// ---------------------------------------------------------------------------

const (
	reinjectLandURL   = "http://10.253.77.98/reinject/shell.php"
	reinjectUploadURL = "http://10.253.77.98/reinject/upload.php"
)

func reinjectFixture(t *testing.T) (*Server, *db.DB, int64) {
	t.Helper()
	pg := prescanTestDB(t)
	// webshells.task_id points at deep_tasks, which is what evacuation walks.
	deep, err := pg.CreateDeepTask(db.DeepTaskInput{
		Name: "webshell reinject fixture", Kind: db.DeepTaskWebshellInject, Target: "10.253.77.98",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM managed_resources
WHERE kind='webshell' AND (endpoint=$1 OR metadata->>'webshell_id' IN
    (SELECT id::text FROM webshells WHERE url=$1))`, reinjectLandURL)
		_, _ = pg.Exec(`DELETE FROM intranet_session_events WHERE session_id IN
    (SELECT id FROM intranet_sessions WHERE webshell_id IN (SELECT id FROM webshells WHERE url=$1))`, reinjectLandURL)
		_, _ = pg.Exec(`DELETE FROM intranet_sessions WHERE webshell_id IN (SELECT id FROM webshells WHERE url=$1)`, reinjectLandURL)
		_, _ = pg.Exec(`DELETE FROM webshells WHERE url=$1`, reinjectLandURL)
		_, _ = pg.Exec(`DELETE FROM deep_tasks WHERE id=$1`, deep.ID)
	})
	s := &Server{m: &Manager{pg: pg}, jwtKey: []byte("test-jwt-signing-key-32-bytes!!")}
	s.resourceMgr = newResourceManager(s)
	return s, pg, deep.ID
}

// reinjectMaterial builds a fresh v2 registration for the fixture URL. Each call
// gets its own key and fingerprint, exactly like a second inject run would.
func reinjectMaterial(t *testing.T, s *Server, taskID int64, name string) db.WebshellInput {
	t.Helper()
	id := taskID
	in := db.WebshellInput{
		Name: name, URL: reinjectLandURL, ShellType: "php",
		Target: "10.253.77.98", Source: "inject", TaskID: &id,
	}
	if _, bad, err := s.buildWebshellMaterial(&in); err != nil || bad {
		t.Fatalf("build material: bad=%v err=%v", bad, err)
	}
	return in
}

func countWebshellRows(t *testing.T, pg *db.DB, url string) int {
	t.Helper()
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM webshells WHERE url=$1`, url).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func webshellResources(t *testing.T, pg *db.DB, status string) []*db.ManagedResource {
	t.Helper()
	rows, _, err := pg.ListManagedResources("webshell", status, 200, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mine []*db.ManagedResource
	for _, row := range rows {
		if row.Endpoint == reinjectLandURL {
			mine = append(mine, row)
		}
	}
	return mine
}

func TestStoreManagedWebshellRefusesSecondRecordForSameURL(t *testing.T) {
	s, pg, taskID := reinjectFixture(t)

	first, err := s.storeManagedWebshell(pg, reinjectMaterial(t, s, taskID, "shell-first.php"), reinjectUploadURL, reinjectLandURL)
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if got := countWebshellRows(t, pg, reinjectLandURL); got != 1 {
		t.Fatalf("webshell rows = %d, want 1", got)
	}

	second, err := s.storeManagedWebshell(pg, reinjectMaterial(t, s, taskID, "shell-second.php"), reinjectUploadURL, reinjectLandURL)
	var taken *webshellURLTaken
	if !errors.As(err, &taken) {
		t.Fatalf("a duplicate land_url must be reported, got err=%v shell=%+v", err, second)
	}
	if second == nil || second.ID != first.ID {
		t.Fatalf("the taken error must hand back the owning record, got %+v", second)
	}
	if !strings.Contains(err.Error(), "已登记为壳 #"+strconv.FormatInt(first.ID, 10)) {
		t.Fatalf("error should name the record that owns the URL: %v", err)
	}
	if got := countWebshellRows(t, pg, reinjectLandURL); got != 1 {
		t.Fatalf("a duplicate registration must not add a row, webshell rows = %d", got)
	}
}

func TestReclaimRegisteredWebshellKeepsIDAndLedger(t *testing.T) {
	s, pg, taskID := reinjectFixture(t)

	firstIn := reinjectMaterial(t, s, taskID, "shell-first.php")
	first, err := s.storeManagedWebshell(pg, firstIn, reinjectUploadURL, reinjectLandURL)
	if err != nil {
		t.Fatal(err)
	}
	firstResource := webshellResources(t, pg, db.ManagedActive)
	if len(firstResource) != 1 {
		t.Fatalf("first registration should hold one active ledger row, got %d", len(firstResource))
	}

	reclaimedIn := reinjectMaterial(t, s, taskID, "shell-reinjected.php")
	reclaimedIn.Note = "上传接口返回 200"
	existing := findRegisteredWebshell(pg, reinjectLandURL)
	if existing == nil || existing.ID != first.ID {
		t.Fatalf("lookup by land_url returned %+v", existing)
	}
	shell, err := s.reclaimRegisteredWebshell(pg, existing, reclaimedIn, reinjectUploadURL)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	// The id is the whole point: sessions and ledger rows are bound to it.
	if shell.ID != first.ID {
		t.Fatalf("reclaim changed the record id: %d -> %d", first.ID, shell.ID)
	}
	if got := countWebshellRows(t, pg, reinjectLandURL); got != 1 {
		t.Fatalf("reclaim must not insert a second row, got %d", got)
	}
	if shell.PayloadSHA256 != reclaimedIn.PayloadSHA256 || shell.Carrier != reclaimedIn.Carrier {
		t.Fatalf("record still describes the old payload: sha=%s carrier=%s", shell.PayloadSHA256, shell.Carrier)
	}
	if shell.PayloadSHA256 == first.PayloadSHA256 {
		t.Fatal("the fingerprint did not move to the new payload")
	}
	if shell.Status != "unknown" {
		t.Fatalf("a just-replaced file has not been spoken to yet, status = %q", shell.Status)
	}
	if !strings.Contains(shell.Note, "覆盖") || !strings.Contains(shell.Note, first.PayloadSHA256) {
		t.Fatalf("the note must record what was overwritten: %q", shell.Note)
	}
	oldKey, derr := openShellSecret(s.jwtKey, first.Secret)
	if derr != nil {
		t.Fatalf("open the first sealed secret: %v", derr)
	}
	freshKey, ferr := openShellSecret(s.jwtKey, shell.Secret)
	if ferr != nil {
		t.Fatalf("open the reclaimed sealed secret: %v", ferr)
	}
	if oldKey == freshKey {
		t.Fatal("re-injection kept the previous key, so the record cannot open the new payload")
	}

	// One live file on the target means one active ledger row; the previous one
	// stays visible as released-with-reason, which is what evacuation reads.
	if active := webshellResources(t, pg, db.ManagedActive); len(active) != 1 {
		t.Fatalf("active ledger rows = %d, want exactly 1", len(active))
	}
	released := webshellResources(t, pg, db.ManagedReleased)
	if len(released) != 1 || !strings.Contains(released[0].Note, "覆盖") {
		t.Fatalf("the superseded row must stay as evidence, got %+v", released)
	}
}

func TestCreateWebshellRejectsDuplicateURL(t *testing.T) {
	s, pg, taskID := reinjectFixture(t)
	if _, err := s.storeManagedWebshell(pg, reinjectMaterial(t, s, taskID, "shell-first.php"), reinjectUploadURL, reinjectLandURL); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"url": reinjectLandURL, "shell_type": "php"})
	req := httptest.NewRequest("POST", "/api/deep/webshells", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	s.createWebshell(rec, req)
	if rec.Code != 400 {
		t.Fatalf("a hand-written duplicate must be a 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "已登记为壳") {
		t.Fatalf("response should point at the record that owns the URL: %s", rec.Body.String())
	}
	if got := countWebshellRows(t, pg, reinjectLandURL); got != 1 {
		t.Fatalf("the rejected call still wrote: rows = %d", got)
	}
}

func TestWebshellRegisterToolReportsExistingRegistration(t *testing.T) {
	s, pg, taskID := reinjectFixture(t)
	first, err := s.storeManagedWebshell(pg, reinjectMaterial(t, s, taskID, "shell-first.php"), reinjectUploadURL, reinjectLandURL)
	if err != nil {
		t.Fatal(err)
	}

	var tool actool.CoreTool
	for _, t0 := range s.deepTools() {
		if t0.Name() == "webshell_register" {
			tool = t0
		}
	}
	if tool == nil {
		t.Fatal("webshell_register is not registered in deepTools()")
	}
	res, err := tool.Call(context.Background(), json.RawMessage(
		`{"url":"`+reinjectLandURL+`","shell_type":"php","task_id":`+strconv.FormatInt(taskID, 10)+`,"verify":false}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("registering an already managed URL should answer, not fail: %q", res.Content[0].Text)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].Text), &out); err != nil {
		t.Fatalf("result is not JSON: %q", res.Content[0].Text)
	}
	if out["already_registered"] != true {
		t.Fatalf("result must say the URL was already registered: %#v", out)
	}
	if id, _ := out["webshell_id"].(float64); int64(id) != first.ID {
		t.Fatalf("webshell_id = %v, want the owning record %d", out["webshell_id"], first.ID)
	}
	if got := countWebshellRows(t, pg, reinjectLandURL); got != 1 {
		t.Fatalf("a repeated registration must not add a row, got %d", got)
	}
	if text, _ := out["next_step"].(string); !strings.Contains(text, "deploy_path") {
		t.Fatalf("the worker needs to be told how to replace the file: %q", text)
	}
}
