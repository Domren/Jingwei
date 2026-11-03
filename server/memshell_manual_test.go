package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// TestLiveJavaMemshellAPI is a manual end-to-end probe of the HTTP handlers
// against a real Tomcat. It only runs when JW_LIVE_TOMCAT_WEBAPP points at a
// webapps directory served by JW_LIVE_TOMCAT_URL (default 8081).
func TestLiveJavaMemshellAPI(t *testing.T) {
	webapp := os.Getenv("JW_LIVE_TOMCAT_WEBAPP")
	if webapp == "" {
		t.Skip("JW_LIVE_TOMCAT_WEBAPP not set")
	}
	baseURL := os.Getenv("JW_LIVE_TOMCAT_URL")
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8081"
	}
	pg := prescanTestDB(t)
	ctx := context.Background()
	s := &Server{ctx: ctx, m: &Manager{pg: pg}, jwtKey: []byte("live-memshell-api-test-key-32b!")}

	payload, sealed, err := s.newV2ShellMaterial("jsp", 1)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(webapp, "live-ms.jsp")
	if err := os.WriteFile(file, []byte(payload.Content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(file) })

	shell, err := pg.CreateWebshell(db.WebshellInput{
		Name: "live-ms-parent", URL: baseURL + "/live-ms.jsp", ShellType: "jsp",
		Protocol: scanner.ShellProtocolV2, Secret: sealed, Carrier: payload.Carrier,
		PayloadSHA256: payload.SHA256, KeyVersion: 1, Target: "127.0.0.1", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.DeleteWebshell(shell.ID) })
	shellID := strconv.FormatInt(shell.ID, 10)

	for _, typ := range []string{"filter", "servlet", "listener", "valve", "agent"} {
		t.Run(typ, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"type": typ})
			req := httptest.NewRequest(http.MethodPost, "/api/deep/webshells/"+shellID+"/memshells", bytes.NewReader(body))
			req.SetPathValue("id", shellID)
			rec := httptest.NewRecorder()
			s.deployJavaMemshell(rec, req)
			if rec.Code != http.StatusCreated {
				t.Fatalf("deploy = %d %s", rec.Code, rec.Body.String())
			}
			var created struct {
				Memshell *db.JavaMemshell `json:"memshell"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Memshell == nil {
				t.Fatalf("deploy body = %s err=%v", rec.Body.String(), err)
			}
			ms := created.Memshell
			t.Cleanup(func() { _, _ = pg.DeleteJavaMemshell(ms.ID) })
			if ms.Secret != "" || !ms.HasSecret {
				t.Fatalf("secret leaked or missing: %+v", ms)
			}
			if ms.Type != typ {
				t.Fatalf("deployed type = %s want %s", ms.Type, typ)
			}

			id := strconv.FormatInt(ms.ID, 10)
			check := httptest.NewRecorder()
			req = httptest.NewRequest(http.MethodPost, "/api/deep/memshells/"+id+"/check", nil)
			req.SetPathValue("id", id)
			s.checkJavaMemshell(check, req)
			if check.Code != http.StatusOK {
				t.Fatalf("check = %d %s", check.Code, check.Body.String())
			}

			exec := httptest.NewRecorder()
			req = httptest.NewRequest(http.MethodPost, "/api/deep/memshells/"+id+"/exec", bytes.NewBufferString(`{"command":"id"}`))
			req.SetPathValue("id", id)
			s.execJavaMemshell(exec, req)
			if exec.Code != http.StatusOK {
				t.Fatalf("exec = %d %s", exec.Code, exec.Body.String())
			}
			var out struct {
				Output string `json:"output"`
			}
			_ = json.Unmarshal(exec.Body.Bytes(), &out)
			if out.Output == "" {
				t.Fatalf("exec output empty: %s", exec.Body.String())
			}

			del := httptest.NewRecorder()
			req = httptest.NewRequest(http.MethodDelete, "/api/deep/memshells/"+id, nil)
			req.SetPathValue("id", id)
			s.deleteJavaMemshell(del, req)
			if del.Code != http.StatusOK {
				t.Fatalf("delete = %d %s", del.Code, del.Body.String())
			}
			var deleted struct {
				Removed bool `json:"removed"`
			}
			_ = json.Unmarshal(del.Body.Bytes(), &deleted)
			if !deleted.Removed {
				t.Fatalf("delete could not confirm removal: %s", del.Body.String())
			}
			if _, err := pg.GetJavaMemshell(ms.ID); err == nil {
				t.Fatal("memshell record survived verified removal")
			}
		})
	}
}
