package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const harvestSample = `<html><head><link rel="stylesheet" href="/static/app.css?v=3"></head><body>
<a href="/vul/sqli/sqli_iu/sqli_login.php?username=1">login sqli</a>
<a href="?page=2">next</a>
<a href="http://other.example.com/x?id=9">external</a>
<a href="/js/app.js?v=1">script</a>
<form method="post" action="/vul/sqli/sqli_blind_b.php">
  <input name="id" type="text" value="1">
  <input name="submit" type="submit" value="Query">
  <input name="csrf_token" type="hidden" value="deadbeef">
  <input name="password" type="password">
  <select name="sort"><option value="a">A</option></select>
</form>
<form method="get" action="/vul/xss/xss_r.php">
  <input name="name" type="text">
  <button type="submit">go</button>
</form>
<form method="post" action="login.php">
  <input name="username" type="text"><input name="password" type="password">
</form>
<script>fetch("/api/user/list?uid=" + id)</script>
</body></html>`

func TestExtractParamPoints(t *testing.T) {
	page := "http://127.0.0.1:8080/index.php"
	pts := ExtractParamPoints(page, harvestSample)
	byKey := map[string]ParamPoint{}
	for _, p := range pts {
		byKey[p.Method+"|"+p.URL] = p
	}

	post, ok := byKey["POST|http://127.0.0.1:8080/vul/sqli/sqli_blind_b.php"]
	if !ok {
		t.Fatalf("post form point missing, got %v", keysOf(byKey))
	}
	if strings.Contains(post.Body, "csrf_token") || strings.Contains(post.Body, "password") ||
		strings.Contains(post.Body, "submit") {
		t.Fatalf("post body keeps a skipped field: %s", post.Body)
	}
	if !strings.Contains(post.Body, "id=1") || !strings.Contains(post.Body, "sort=1") {
		t.Fatalf("post body lost a real field: %s", post.Body)
	}
	if post.Score <= byKey["POST|http://127.0.0.1:8080/login.php"].Score {
		t.Fatalf("login form should rank below a data endpoint: %d vs %d", post.Score,
			byKey["POST|http://127.0.0.1:8080/login.php"].Score)
	}

	get, ok := byKey["GET|http://127.0.0.1:8080/vul/xss/xss_r.php?name=1"]
	if !ok {
		t.Fatalf("get form point missing, got %v", keysOf(byKey))
	}
	if get.Body != "" {
		t.Fatalf("GET form must not carry a body: %q", get.Body)
	}

	if _, ok := byKey["GET|http://127.0.0.1:8080/index.php?page=2"]; !ok {
		t.Fatalf("bare ?page=2 link missing: %v", keysOf(byKey))
	}
	if _, ok := byKey["GET|http://127.0.0.1:8080/vul/sqli/sqli_iu/sqli_login.php?username=1"]; !ok {
		t.Fatalf("login-scoped link missing (the endpoint is the injection point): %v", keysOf(byKey))
	}

	for _, p := range pts {
		if strings.Contains(p.URL, "other.example.com") {
			t.Fatalf("cross-host reference leaked into points: %s", p.URL)
		}
		if strings.HasSuffix(p.URL, ".js") || strings.HasSuffix(p.URL, ".css") {
			t.Fatalf("static asset became a point: %s", p.URL)
		}
	}
	if _, ok := byKey["GET|http://127.0.0.1:8080/api/user/list?uid="]; !ok {
		t.Fatalf("script-built route missing: %v", keysOf(byKey))
	}
}

func TestRankParamPointsOrdersAndCaps(t *testing.T) {
	pts := []ParamPoint{
		{URL: "http://h/a.php?id=1", Method: "GET", Params: []string{"id"}, Score: 10},
		{URL: "http://h/a.php?id=1", Method: "GET", Params: []string{"id"}, Score: 65},
		{URL: "http://h/b.php?q=1", Method: "GET", Params: []string{"q"}, Score: 90},
		{URL: "http://h/c.php", Method: "POST", Body: "x=1", Params: []string{"x"}, Score: 20},
	}
	got := rankParamPoints(pts, 2)
	if len(got) != 2 {
		t.Fatalf("cap ignored: %d points", len(got))
	}
	if got[0].URL != "http://h/b.php?q=1" || got[1].URL != "http://h/a.php?id=1" {
		t.Fatalf("order wrong: %v", got)
	}
	if got[1].Score != 65 {
		t.Fatalf("duplicate kept the lower-scoring provenance: %+v", got[1])
	}
}

func TestHarvestParamsReadsSeedsAndKeepsSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc123", Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><body><a href="/p.php?id=1">link</a>`)
			io.WriteString(w, `<form method="post" action="/p.php"><input name="id"></form></body></html>`)
		case "/p.php":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><body>no parameters here</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "not found")
		}
	}))
	defer srv.Close()

	pts := HarvestParams(context.Background(), []string{srv.URL + "/", "  "}, HarvestOptions{MaxPages: 4, MaxPoints: 10})
	if len(pts) == 0 {
		t.Fatal("no points harvested")
	}
	var sawLink, sawForm bool
	for _, p := range pts {
		if !strings.HasPrefix(p.Cookie, "PHPSESSID=abc123") {
			t.Fatalf("point %s lost the session cookie: %q", p.URL, p.Cookie)
		}
		if p.Source == "link" {
			sawLink = true
		}
		if p.Source == "form" && p.Method == "POST" {
			sawForm = true
		}
	}
	if !sawLink || !sawForm {
		t.Fatalf("missing provenance: link=%v form=%v (%+v)", sawLink, sawForm, pts)
	}

	if got := HarvestParams(context.Background(), nil, HarvestOptions{}); len(got) != 0 {
		t.Fatalf("no seeds must yield no points, got %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := HarvestParams(ctx, []string{srv.URL + "/"}, HarvestOptions{}); len(got) != 0 {
		t.Fatalf("canceled context must yield nothing, got %v", got)
	}
}

func TestHarvestResolveRef(t *testing.T) {
	page := "http://h.example.com/a/b.html"
	for _, tc := range []struct{ in, want string }{
		{"?id=1", "http://h.example.com/a/b.html?id=1"},
		{"/c/d.php?id=2", "http://h.example.com/c/d.php?id=2"},
		{"../c/d.php?id=2", "http://h.example.com/c/d.php?id=2"},
		{"//other.example.com/d.php?id=2", ""},
		{"http://h.example.com/e.php?id=3", "http://h.example.com/e.php?id=3"},
		{"https://h.example.com/e.php?id=3", "https://h.example.com/e.php?id=3"},
		{"javascript:go('?id=1')", ""},
		{"#frag?id=1", ""},
	} {
		if got := resolveRef(page, tc.in); got != tc.want {
			t.Errorf("resolveRef(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func keysOf(m map[string]ParamPoint) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
