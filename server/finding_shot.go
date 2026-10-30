package server

import (
	"encoding/json"
	"net/http"
)

// autoFindingScreenshot renders the forensic panel of a finding from the
// traffic already bound to it and stores the PNG as an evidence screenshot.
// The agent does this automatically when a finding is confirmed; this endpoint
// exists so an operator can backfill images for older findings.
func (s *Server) autoFindingScreenshot(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	sid, err := s.evidenceStore().CaptureShot(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": sid})
}

// pageFindingScreenshot screenshots the rendered target page — the "what the
// user sees" half of the evidence, next to the packet panel.
func (s *Server) pageFindingScreenshot(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	sid, err := s.evidenceStore().CapturePageShot(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": sid})
}

// autoFindingScreenshots backfills forensic panels for a batch of findings.
// One failing finding never stops the batch — the response reports each id.
func (s *Server) autoFindingScreenshots(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if len(body.IDs) == 0 {
		writeErr(w, 400, "ids 不能为空")
		return
	}
	if len(body.IDs) > 200 {
		writeErr(w, 400, "一次最多补拍 200 条")
		return
	}
	store := s.evidenceStore()
	ok := make([]int64, 0, len(body.IDs))
	failed := make([]map[string]any, 0)
	for _, id := range body.IDs {
		if id <= 0 {
			continue
		}
		sid, err := store.CaptureShot(r.Context(), id)
		if err != nil {
			failed = append(failed, map[string]any{"finding_id": id, "error": err.Error()})
			continue
		}
		ok = append(ok, sid)
	}
	writeJSON(w, 200, map[string]any{
		"screenshot_ids": ok,
		"failed":         failed,
		"ok":             len(ok),
		"total":          len(body.IDs),
	})
}
