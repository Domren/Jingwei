package server

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// TestDeleteCompaniesBatchValidatesBeforeTouchingDatabase pins the request contract
// of POST /api/companies/delete/batch. The manager has no database on purpose: a
// rejected request must fail with 400 before the delete path is reached, and only a
// valid one is allowed to report the missing store.
func TestDeleteCompaniesBatchValidatesBeforeTouchingDatabase(t *testing.T) {
	s := &Server{m: &Manager{}}
	oversized := `{"ids":[` + strings.Repeat("1,", maxCompanyDeleteBatch) + `1]}`

	cases := []struct {
		name   string
		body   string
		status int
		msg    string
	}{
		{"empty ids", `{"ids":[]}`, http.StatusBadRequest, "ids 不能为空"},
		{"non-positive id", `{"ids":[0]}`, http.StatusBadRequest, "企业 id 0 无效"},
		{"negative id", `{"ids":[-3]}`, http.StatusBadRequest, "企业 id -3 无效"},
		{"over cap", oversized, http.StatusBadRequest, "一次最多删除 200 个企业"},
		{"malformed json", `{"ids":`, http.StatusBadRequest, "invalid JSON"},
		{"valid ids", `{"ids":[7,7]}`, http.StatusServiceUnavailable, "database unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.deleteCompaniesBatch(w, httptest.NewRequest(http.MethodPost, "/api/companies/delete/batch", strings.NewReader(c.body)))
			if w.Code != c.status {
				t.Fatalf("status=%d body=%s, want %d", w.Code, w.Body.String(), c.status)
			}
			if !strings.Contains(w.Body.String(), c.msg) {
				t.Errorf("body=%s, want it to mention %q", w.Body.String(), c.msg)
			}
		})
	}
}

func TestNormalizeCompanyIDsDedupesKeepingOrder(t *testing.T) {
	got, err := normalizeCompanyIDs([]int64{5, 3, 5, 1, 3})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []int64{5, 3, 1}) {
		t.Fatalf("got %v, want [5 3 1]", got)
	}
}
