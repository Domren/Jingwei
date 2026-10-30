package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

func TestNormalizeScanWebshellDisabled(t *testing.T) {
	req := &db.ScanTaskInput{WebshellInject: false, WebshellParams: map[string]any{"upload_path": "/x.php"}}
	if err := normalizeScanWebshell(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(req.WebshellParams) != 0 {
		t.Fatalf("params should be cleared, got %v", req.WebshellParams)
	}
}

func TestNormalizeScanWebshellDefaults(t *testing.T) {
	req := &db.ScanTaskInput{
		WebshellInject: true,
		WebshellParams: map[string]any{"upload_path": " /upload.php ", "shell_type": "PHP"},
	}
	if err := normalizeScanWebshell(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.WebshellParams["upload_path"] != "/upload.php" {
		t.Fatalf("upload_path = %v", req.WebshellParams["upload_path"])
	}
	if req.WebshellParams["shell_type"] != "php" {
		t.Fatalf("shell_type = %v", req.WebshellParams["shell_type"])
	}
	if req.WebshellParams["field_name"] != "file" {
		t.Fatalf("field_name = %v", req.WebshellParams["field_name"])
	}
	pw, _ := req.WebshellParams["password"].(string)
	if !strings.HasPrefix(pw, "jw") || len(pw) != 10 {
		t.Fatalf("password = %q", pw)
	}
}

func TestNormalizeScanWebshellRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"missing upload path", map[string]any{}},
		{"relative upload path", map[string]any{"upload_path": "upload.php"}},
		{"relative land path", map[string]any{"upload_path": "/upload.php", "land_path": "shell.php"}},
		{"unsupported shell type", map[string]any{"upload_path": "/upload.php", "shell_type": "war"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &db.ScanTaskInput{WebshellInject: true, WebshellParams: tc.params}
			if err := normalizeScanWebshell(req); err == nil {
				t.Fatalf("expected error for %v", tc.params)
			}
		})
	}
}
