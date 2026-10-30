package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSameHostResolve(t *testing.T) {
	cases := []struct {
		base, ref, want string
	}{
		{"http://h/", "vul/burteforce/bf_form.php", "http://h/vul/burteforce/bf_form.php"},
		{"http://h/a/b.php", "../c.php", "http://h/c.php"},
		{"http://h/", "/login.php", "http://h/login.php"},
		{"http://h/", "https://evil.com/", ""},
		{"http://h/", "javascript:void(0)", ""},
		{"http://h/", "", ""},
	}
	for _, c := range cases {
		if got := sameHostResolve(c.base, c.ref); got != c.want {
			t.Errorf("sameHostResolve(%q,%q)=%q want %q", c.base, c.ref, got, c.want)
		}
	}
}

func TestDiscoverLoginForms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><a href="login.php">login</a><a href="https://evil.com/x">x</a><a href="assets/app.css">css</a></html>`))
		case "/login.php":
			w.Write([]byte(`<form method="post"><input type="text" name="user"><input type="password" name="pass"></form>`))
		case "/assets/app.css":
			w.Write([]byte(`body{}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	svc := WebService{URL: srv.URL, IP: "127.0.0.1"}
	forms := DiscoverLoginForms(context.Background(), []WebService{svc}, nil, LoginFormOptions{})
	found := false
	for _, f := range forms {
		if strings.HasSuffix(f, "/login.php") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected /login.php in forms, got %v", forms)
	}
}
