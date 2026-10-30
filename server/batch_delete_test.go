package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

const batchDeleteVulnclass = "__test_vc_batch_delete_route__"

func newBatchDeleteRequest(t *testing.T, handler http.HandlerFunc, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// TestDeleteFindingsBatchRoute 覆盖批量删除漏洞路由：一次事务删掉多条记录、
// 参数校验（空/非法/超限）都以 4xx 返回。
func TestDeleteFindingsBatchRoute(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	s := newAdmissionTestServer(m, nil)

	task, err := m.CreateTask("批量删除漏洞路由", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer purgeTaskNow(t, m.pg, taskID)

	es := m.pg.Exploration(mustTaskExplorationID(t, m, taskID))
	ids := make([]int64, 0, 3)
	for i := 0; i < 3; i++ {
		nodeID, err := es.AddNode(db.KindFinding, map[string]any{"summary": "x", "severity": "high"}, 5, "confirmed", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		id, err := m.pg.AddFinding(taskID, nodeID, batchDeleteVulnclass, fmt.Sprintf("批量删除 %d", i), "high", "摘要", "证据", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	rec := newBatchDeleteRequest(t, s.deleteFindingsBatch, map[string]any{
		"ids": []int64{ids[0], ids[1], ids[1]},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Deleted   int64 `json:"deleted"`
		Requested int   `json:"requested"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Requested != 2 || got.Deleted != 2 {
		t.Fatalf("unexpected response: %+v", got)
	}
	for _, id := range ids[:2] {
		if f, _ := m.pg.GetFinding(id); f != nil {
			t.Fatalf("finding %d should be gone, got %+v", id, f)
		}
	}
	if f, _ := m.pg.GetFinding(ids[2]); f == nil {
		t.Fatal("unlisted finding must survive")
	}

	for _, payload := range []any{
		map[string]any{"ids": []int64{}},
		map[string]any{"ids": []int64{0}},
		map[string]any{"ids": oversizedFindingIDs()},
	} {
		rec = newBatchDeleteRequest(t, s.deleteFindingsBatch, payload)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
		}
	}
}

func oversizedFindingIDs() []int64 {
	ids := make([]int64, maxFindingDeleteBatch+1)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	return ids
}

// TestDeleteTasksBatchRoute 覆盖批量删除任务路由：一次请求删除多个任务并聚合
// 计数，去重后每个任务只处理一次，非法 id 与超限选择直接 400。
func TestDeleteTasksBatchRoute(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	s := newAdmissionTestServer(m, nil)

	first, err := m.CreateTask("批量删除任务一", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.CreateTask("批量删除任务二", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A failed assertion must not leave the pair behind in the dev database.
	defer func() {
		for _, id := range []string{first.ID, second.ID} {
			n, parseErr := strconv.ParseInt(id, 10, 64)
			if parseErr == nil {
				purgeTaskNow(t, m.pg, n)
			}
		}
	}()

	rec := newBatchDeleteRequest(t, s.deleteTasksBatch, map[string]any{
		"ids":             []string{first.ID, second.ID, first.ID},
		"delete_findings": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got deleteTasksBatchResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Deleted != 2 || got.Failed != 0 || len(got.Items) != 2 {
		t.Fatalf("unexpected response: %+v", got)
	}
	for _, item := range got.Items {
		if !item.OK || item.Error != "" {
			t.Fatalf("item should have succeeded: %+v", item)
		}
	}
	for _, id := range []string{first.ID, second.ID} {
		if _, ok := m.Task(id); ok {
			t.Fatalf("task %s should be gone", id)
		}
	}

	rec = newBatchDeleteRequest(t, s.deleteTasksBatch, map[string]any{"ids": []string{"bad-id"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid id status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	over := make([]string, maxTaskDeleteBatch+1)
	for i := range over {
		over[i] = strconv.Itoa(i + 1)
	}
	rec = newBatchDeleteRequest(t, s.deleteTasksBatch, map[string]any{"ids": over})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
}

func mustTaskExplorationID(t *testing.T, m *Manager, taskID int64) int64 {
	t.Helper()
	task, err := m.pg.GetTask(taskID)
	if err != nil || task == nil {
		t.Fatalf("task %d: %v", taskID, err)
	}
	return task.ExplorationID
}

// TestDeleteAssetsBatchValidatesBeforeTouchingDatabase 钉住 DELETE /api/assets 的请求契约：
// 故意不给 manager 挂数据库——非法请求必须在 400 就被挡掉，只有合法请求才允许报 503。
func TestDeleteAssetsBatchValidatesBeforeTouchingDatabase(t *testing.T) {
	s := &Server{m: &Manager{}}
	oversized := `{"ids":[` + strings.Repeat("1,", maxAssetDeleteBatch) + `1]}`
	cases := []struct {
		name   string
		body   string
		status int
		msg    string
	}{
		{"empty ids", `{"ids":[]}`, http.StatusBadRequest, "ids 不能为空"},
		{"non-positive id", `{"ids":[0]}`, http.StatusBadRequest, "资产 id 0 无效"},
		{"negative id", `{"ids":[-3]}`, http.StatusBadRequest, "资产 id -3 无效"},
		{"over cap", oversized, http.StatusBadRequest, "一次最多删除 500 条资产"},
		{"malformed json", `{"ids":`, http.StatusBadRequest, "invalid JSON"},
		{"valid ids", `{"ids":[7,7]}`, http.StatusServiceUnavailable, "database unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.deleteAssets(w, httptest.NewRequest(http.MethodDelete, "/api/assets", strings.NewReader(c.body)))
			if w.Code != c.status {
				t.Fatalf("status=%d body=%s, want %d", w.Code, w.Body.String(), c.status)
			}
			if !strings.Contains(w.Body.String(), c.msg) {
				t.Errorf("body=%s, want it to mention %q", w.Body.String(), c.msg)
			}
		})
	}
}

func TestNormalizeAssetIDsDedupesKeepingOrder(t *testing.T) {
	got, err := normalizeAssetIDs([]int64{5, 3, 5, 1, 3})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []int64{5, 3, 1}) {
		t.Fatalf("got %v, want [5 3 1]", got)
	}
}
