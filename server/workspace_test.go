package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "outside.txt")
	if err := os.WriteFile(secret, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	s := &Server{m: &Manager{dir: root}}
	for _, rel := range []string{"link/outside.txt", "link/new.txt", "../outside.txt", "/outside.txt"} {
		if path, ok := s.wsResolve(rel); ok {
			t.Errorf("wsResolve(%q) allowed %q", rel, path)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/workspace/write", bytes.NewBufferString("{\"path\":\"link/outside.txt\",\"content\":\"changed\"}"))
	rec := httptest.NewRecorder()
	s.wsWrite(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("write status = %d, want 400", rec.Code)
	}
	data, err := os.ReadFile(secret)
	if err != nil || string(data) != "untouched" {
		t.Fatalf("outside changed: %q, %v", data, err)
	}
	if path, ok := s.wsResolve("nested/new.txt"); !ok || path != filepath.Join(root, "nested", "new.txt") {
		t.Fatalf("valid new path: %q, %v", path, ok)
	}
}
