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

func TestAppDiscoverCatchAllAndAliases(t *testing.T) {
	rootPage := "<html><head><title>Home Page</title></head><body>" +
		"<a href='/'>home</a><a href='/index.php'>index</a>" +
		"<a href='/manager'>manager</a><a href='/manager/index.php'>manager index</a>" +
		"<a href='/real-app'>app</a></body></html>"
	adminShell := "<html><head><title>Admin SPA</title></head><body><div id='app'></div></body></html>"
	managerPage := "<html><head><title>Manager Console</title></head><body><h1>Manager</h1></body></html>"
	realPage := "<html><head><title>Real App</title></head><body><p>real application</p></body></html>"
	exact := map[string]string{
		"/manager":           managerPage,
		"/manager/":          managerPage,
		"/manager/index.php": managerPage,
		"/real-app":          realPage,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" || r.URL.Path == "/index.php":
			w.Write([]byte(rootPage))
		case r.URL.Path == "/index.php/admin":
			// Same script reached through PATH_INFO: same title and template,
			// different size (no query parameter, so a block is missing).
			w.Write([]byte(rootPage + "<div class='admin-settings'>admin settings panel</div>"))
		case r.URL.Path == "/server-status":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center></body></html>"))
		case r.URL.Path == "/manager/html":
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("<html><head><title>401 Unauthorized</title></head><body>auth required</body></html>"))
		case r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/"):
			// Prefix catch-all: every /admin/* path answers the SPA shell.
			w.Write([]byte(adminShell))
		default:
			if body, ok := exact[r.URL.Path]; ok {
				w.Write([]byte(body))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("<html><head><title>Not Found</title></head><body>missing</body></html>"))
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	svc := WebService{URL: srv.URL, Host: host, IP: "127.0.0.1", Port: 80, Scheme: "http"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	systems, err := AppDiscover(ctx, []WebService{svc}, AppDiscoverOptions{
		MaxCandidates: 200, Concurrency: 4, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("AppDiscover: %v", err)
	}
	byPath := map[string]AppSystem{}
	for _, s := range systems {
		byPath[s.Path] = s
		if s.StatusCode == http.StatusNotFound {
			t.Errorf("404 response registered as system: %+v", s)
		}
	}
	// /admin/** is a catch-all, /index.php duplicates the root, /index.php/admin
	// is the same script under PATH_INFO (same title, different size),
	// /manager/* aliases collapse into /manager, the stock 403 page is a server
	// refusal rather than a system, and "/" itself is the service root.
	for _, bogus := range []string{"/admin", "/admin/", "/index.php", "/index.php/admin", "/server-status", "/manager/", "/manager/index.php", "/"} {
		if _, ok := byPath[bogus]; ok {
			t.Errorf("alias/catch-all path %s should be dropped; systems=%v", bogus, byPath)
		}
	}
	// A real auth wall (401) is still a system.
	for _, want := range []string{"/manager", "/real-app", "/manager/html"} {
		if _, ok := byPath[want]; !ok {
			t.Errorf("real system %s missing; systems=%v", want, byPath)
		}
	}
	if len(systems) != 3 {
		t.Errorf("systems=%d, want 3: %v", len(systems), byPath)
	}
}

func TestAppBodySimilar(t *testing.T) {
	head := "<html><head><title>T</title><script src='/big.js'></script></head><body>" +
		"<nav>menu home docs community downloads support about contact</nav><main>"
	tail := "</main><footer>copyright 2026 example all rights reserved</footer></body></html>"
	body := "<h1>integer injection challenge</h1>" +
		"<p>please enter a number in the form below and submit the query to see the result</p>" +
		"<form action='/index.php'><input name='id'><button>submit</button></form>"
	root := []byte(head + body + "<table><tbody><tr><td>1</td><td>admin</td><td>result row content here</td></tr></tbody></table>" + tail)
	variant := []byte(head + body + "<p>warning missing id parameter notice undefined array key</p>" + tail)
	if !appBodySimilar(root, variant) {
		t.Fatal("same template with a missing/extra block should be similar")
	}
	distinct := []byte(head + "<h2>admin console</h2><p>username password sign in required</p>" + tail)
	if appBodySimilar(root, distinct) {
		t.Fatal("distinct page sharing only the template must not be similar")
	}
	if appBodySimilar(nil, root) || appBodySimilar(root, []byte("<html></html>")) {
		t.Fatal("empty pages must not match")
	}
}

func TestAppBareForbidden(t *testing.T) {
	for _, title := range []string{"", "403", "403 Forbidden", "Forbidden", " forbidden "} {
		if !appBareForbidden(http.StatusForbidden, title) {
			t.Errorf("stock 403 title %q should be treated as a server refusal", title)
		}
	}
	for _, c := range []struct {
		status int
		title  string
	}{
		{http.StatusForbidden, "Admin Portal Login"},
		{http.StatusUnauthorized, "401 Unauthorized"},
		{http.StatusOK, "403 Forbidden"},
	} {
		if appBareForbidden(c.status, c.title) {
			t.Errorf("status %d title %q must be kept", c.status, c.title)
		}
	}
}

func TestAppDiscoverEchoSoft404(t *testing.T) {
	// Every unknown path answers 200 with a body that echoes the path. Raw
	// sizes differ per path, but the path-adjusted sizes are identical, so the
	// whole site is one soft-404 handler and must yield no systems.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte("<html><head><title>Echo Site</title></head><body><a href='/echo-app'>app</a></body></html>"))
			return
		}
		w.Write([]byte("Not found: " + r.URL.Path))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	svc := WebService{URL: srv.URL, Host: host, IP: "127.0.0.1", Port: 80, Scheme: "http"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	systems, err := AppDiscover(ctx, []WebService{svc}, AppDiscoverOptions{
		MaxCandidates: 120, Concurrency: 4, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("AppDiscover: %v", err)
	}
	if len(systems) != 0 {
		t.Fatalf("echo soft-404 site produced systems: %+v", systems)
	}
}

func TestAppSamePage(t *testing.T) {
	echo := func(path string) appResponse {
		return appResponse{status: 200, length: int64(len("Not found: " + path))}
	}
	if !appSamePage(echo("/admin"), "/admin", echo("/jingwei-notexist-abcdef"), "/jingwei-notexist-abcdef") {
		t.Fatal("path-echo soft-404 not recognized")
	}
	if appSamePage(appResponse{status: 200, length: 20}, "/admin", appResponse{status: 404, length: 20}, "/x") {
		t.Fatal("different status codes must not match")
	}
	if !appSamePage(appResponse{status: 500, length: 1}, "/a", appResponse{status: 500, length: 900}, "/b") {
		t.Fatal("server errors should match regardless of body")
	}
	root := appResponse{status: 200, length: 120, title: "Home"}
	if !appRootAlias(appResponse{status: 200, length: 120, title: "Home"}, "/index.php", root) {
		t.Fatal("root alias not recognized")
	}
	if appRootAlias(appResponse{status: 200, length: 120, title: "Admin"}, "/admin", root) {
		t.Fatal("different title must not be a root alias")
	}
}

func TestAppDedupeSystemsAliases(t *testing.T) {
	systems := []AppSystem{
		{Path: "/admin/", StatusCode: 200, Title: "Admin", ContentLength: 120},
		{Path: "/admin", StatusCode: 200, Title: "Admin", ContentLength: 120},
		{Path: "/portal", StatusCode: 200, Title: "Admin", ContentLength: 240},
		{Path: "/api", StatusCode: 200, ContentLength: 2},
		{Path: "/api/v1", StatusCode: 200, ContentLength: 2},
		{Path: "/manager/html", StatusCode: 401, Title: "401 Unauthorized", ContentLength: 90},
		{Path: "/host-manager/html", StatusCode: 401, Title: "401 Unauthorized", ContentLength: 90},
	}
	got := map[string]bool{}
	for _, s := range appDedupeSystems(systems) {
		got[s.Path] = true
	}
	for _, want := range []string{"/admin", "/portal", "/api", "/api/v1", "/manager/html", "/host-manager/html"} {
		if !got[want] {
			t.Errorf("path %s missing after dedupe: %v", want, got)
		}
	}
	if got["/admin/"] {
		t.Errorf("trailing-slash alias kept: %v", got)
	}
	if len(got) != 6 {
		t.Errorf("dedupe result: %v", got)
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
