package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// appDiscoverFixture serves one origin where a catch-all handler answers every
// unknown path with the index page (soft-404), while a handful of real
// applications live under distinct paths.
func appDiscoverFixture(t *testing.T) *httptest.Server {
	t.Helper()
	var serverURL string
	real := map[string]string{
		"/admin":         "<html><head><title>Admin Console</title></head><body>management area</body></html>",
		"/secret-dir":    "<html><head><title>Secret</title></head><body>internal</body></html>",
		"/from-sitemap":  "<html><head><title>Sitemap Entry</title></head><body>listed</body></html>",
		"/api/v2/orders": `{"orders":[]}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /secret-dir\n"))
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		// One same-origin loc (by spec sitemap URLs are absolute) plus one
		// cross-origin loc that must be ignored.
		w.Write([]byte(`<urlset>` +
			`<url><loc>` + serverURL + `/from-sitemap</loc></url>` +
			`<url><loc>http://example.invalid/other</loc></url>` +
			`</urlset>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`var r="/api/v2/orders"; fetch("/api/v2/orders");`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if body, ok := real[r.URL.Path]; ok {
			if strings.HasPrefix(body, "{") {
				w.Header().Set("Content-Type", "application/json")
			}
			w.Write([]byte(body))
			return
		}
		// Soft-404: same index page for every unknown path.
		w.Write([]byte("<html><head><title>Main Site</title></head><body><a href='/admin'>admin</a><script src='/app.js'></script></body></html>"))
	})
	srv := httptest.NewServer(mux)
	serverURL = srv.URL
	return srv
}

func TestAppDiscoverFindsPathLevelSystems(t *testing.T) {
	srv := appDiscoverFixture(t)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	svc := WebService{URL: srv.URL, Host: host, IP: "127.0.0.1", Port: 80, Scheme: "http"}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	systems, err := AppDiscover(ctx, []WebService{svc}, AppDiscoverOptions{
		MaxCandidates: 200, Concurrency: 4, Timeout: 3 * time.Second,
		Logf: func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("AppDiscover: %v", err)
	}
	byPath := map[string]AppSystem{}
	for _, s := range systems {
		byPath[s.Path] = s
	}
	for _, want := range []struct{ path, source string }{
		{"/admin", "dictionary"},
		{"/secret-dir", "robots"},
		{"/from-sitemap", "sitemap"},
		{"/api/v2/orders", "js"},
	} {
		got, ok := byPath[want.path]
		if !ok {
			t.Errorf("path %s not discovered; systems=%v", want.path, byPath)
			continue
		}
		if got.Source != want.source {
			t.Errorf("path %s source=%s, want %s", want.path, got.Source, want.source)
		}
		if got.StatusCode != 200 {
			t.Errorf("path %s status=%d, want 200", want.path, got.StatusCode)
		}
		if got.URL != srv.URL+want.path {
			t.Errorf("path %s url=%s", want.path, got.URL)
		}
	}
	// Off-origin sitemap loc must not produce a system.
	if _, ok := byPath["/other"]; ok {
		t.Errorf("cross-origin sitemap entry should be dropped")
	}
	// Dictionary paths answered by the catch-all (soft-404) must be filtered.
	for _, p := range []string{"/test", "/dev", "/demo", "/api", "/backup"} {
		if _, ok := byPath[p]; ok {
			t.Errorf("soft-404 path %s should be filtered", p)
		}
	}
	if s, ok := byPath["/admin"]; ok && s.Title != "Admin Console" {
		t.Errorf("/admin title=%q", s.Title)
	}
}

func TestAppDiscoverDeadService(t *testing.T) {
	// A service that is no longer answering must return no systems and no error.
	svc := WebService{URL: "http://127.0.0.1:1", Host: "127.0.0.1", IP: "127.0.0.1", Port: 1, Scheme: "http"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	systems, err := AppDiscover(ctx, []WebService{svc}, AppDiscoverOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("AppDiscover: %v", err)
	}
	if len(systems) != 0 {
		t.Fatalf("dead service produced %d systems", len(systems))
	}
}

func TestNormalizeAppPath(t *testing.T) {
	cases := map[string]string{
		"/admin":       "/admin",
		"/a?x=1":       "/a",
		"/b#frag":      "/b",
		"relative":     "",
		"../escape":    "",
		"/double//sep": "",
		"":             "",
	}
	for in, want := range cases {
		if got := normalizeAppPath(in); got != want {
			t.Errorf("normalizeAppPath(%q)=%q want %q", in, got, want)
		}
	}
}
