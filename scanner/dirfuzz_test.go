package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// C1：软 404 基线、状态码过滤、同长同码去重、扩展名组合与字节证据。
func TestDirFuzzBasics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(200)
			_, _ = w.Write([]byte("admin-page"))
		case "/backup.zip":
			w.WriteHeader(200)
			_, _ = w.Write([]byte("admin-page")) // 与 /admin 同码同长 → 应被抑制
		case "/config.php":
			w.WriteHeader(403)
			_, _ = w.Write([]byte("no"))
		case "/login":
			http.Redirect(w, r, "/login/", http.StatusMovedPermanently)
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte("not found"))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	entries, err := DirFuzz(t.Context(), srv.URL, DirFuzzOptions{
		Words:       []string{"admin", "backup.zip", "config.php", "login", "missing"},
		Extensions:  []string{"php"},
		Concurrency: 4,
		Budget:      10_000_000_000,
		MaxRequests: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]DirEntry{}
	for _, e := range entries {
		byPath[e.Path] = e
	}
	if e, ok := byPath["/admin"]; !ok || e.Status != 200 || len(e.Request) == 0 || len(e.Response) == 0 {
		t.Fatalf("/admin 未命中或缺少字节证据: %+v", entries)
	}
	if _, ok := byPath["/backup.zip"]; ok {
		t.Fatalf("同长同码条目未被抑制: %+v", entries)
	}
	if e, ok := byPath["/config.php"]; !ok || e.Source != "dict-forbidden" {
		t.Fatalf("403 未保留或来源标记错误: %+v", entries)
	}
	if e, ok := byPath["/login"]; !ok || e.Status != 301 || e.Location == "" {
		t.Fatalf("重定向未保留 Location: %+v", entries)
	}
	if _, ok := byPath["/missing"]; ok {
		t.Fatal("404 未被过滤")
	}
	// 扩展名组合：admin.php 返回 404，不应出现。
	if _, ok := byPath["/admin.php"]; ok {
		t.Fatal("扩展名候选未按 404 过滤")
	}
}

func TestDirCandidates(t *testing.T) {
	got := dirCandidates([]string{"admin", "uploads/", "config.php", "admin"}, []string{"php", ".bak"})
	want := map[string]bool{"admin": true, "admin.php": true, "admin.bak": true, "uploads/": true, "config.php": true}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v", got)
	}
	for _, c := range got {
		if !want[c] {
			t.Fatalf("多余候选 %q", c)
		}
	}
	if strings.Contains(strings.Join(got, ","), "uploads/.php") {
		t.Fatal("目录条目不应追加扩展名")
	}
}
