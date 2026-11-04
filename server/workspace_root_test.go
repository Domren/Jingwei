package server

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// A checked directory can be swapped for a symlink before the actual I/O.
// Root-relative operations must still stay under the pinned workspace.
func TestWorkspaceRootSurvivesSymlinkSwap(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, "inside"), 0755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(filepath.Join(workspace, "inside"), filepath.Join(workspace, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "inside")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := root.OpenFile("inside/escape.txt", os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		t.Fatal("swapped symlink allowed write")
	}
	if _, err := os.Stat(filepath.Join(outside, "escape.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside file created: %v", err)
	}
	if err := root.RemoveAll("inside/escape.txt"); err == nil {
		if _, err := os.Stat(filepath.Join(outside, "escape.txt")); !os.IsNotExist(err) {
			t.Fatalf("outside file deleted: %v", err)
		}
	}
}

func TestWorkspaceRootUploadDoesNotFollowSymlink(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Symlink(outside, filepath.Join(workspace, "uploads")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, "content"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if err := req.ParseMultipartForm(1024); err != nil {
		t.Fatal(err)
	}
	if err := saveUploadRoot(root, req.MultipartForm.File["file"][0], "uploads/file.txt"); err == nil {
		t.Fatal("upload followed external symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "file.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside upload appeared: %v", err)
	}
}
