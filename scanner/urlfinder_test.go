package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// C2：提取要与真实页面形状一致——链接、内联 fetch、外链 JS 三层都要覆盖，
// 本站过滤、静态资源剔除、数字/UUID 归一化与去重缺一不可。
func TestExtractURLsFromText(t *testing.T) {
	page := `<html>
<a href="/admin/login.php">login</a>
<script src="/static/app.js"></script>
<script>fetch('/api/v1/users'); axios.get("/api/orders/123"); x.open('GET', '/v2/items/550e8400-e29b-41d4-a716-446655440000');</script>
<img src="https://cdn.example.net/logo.png">
<a href="https://other.example.org/api/secret">x</a>
<a href="/static/site.css">css</a>
</html>`
	items := ExtractURLsFromText(page, "http://target.local/", "page", 1, true)
	byPath := map[string]ExtractedURL{}
	for _, it := range items {
		byPath[it.Path] = it
	}
	for _, want := range []string{"/admin/login.php", "/api/v1/users", "/api/orders/123", "/v2/items/550e8400-e29b-41d4-a716-446655440000", "/static/app.js"} {
		if _, ok := byPath[want]; !ok {
			t.Fatalf("缺 %s，得到 %+v", want, items)
		}
	}
	if _, ok := byPath["/api/secret"]; ok {
		t.Fatal("外站 URL 未过滤")
	}
	if _, ok := byPath["/static/site.css"]; ok {
		t.Fatal("静态资源算进了条目")
	}
	if byPath["/api/orders/123"].Pattern != "/api/orders/{id}" {
		t.Fatalf("数字段未归一: %q", byPath["/api/orders/123"].Pattern)
	}
	if byPath["/v2/items/550e8400-e29b-41d4-a716-446655440000"].Pattern != "/v2/items/{uuid}" {
		t.Fatalf("UUID 未归一: %q", byPath["/v2/items/550e8400-e29b-41d4-a716-446655440000"].Pattern)
	}
	if byPath["/api/v1/users"].Kind != "api" || byPath["/static/app.js"].Kind != "js" {
		t.Fatalf("kind 判定错误: %+v", byPath)
	}
}

// 深入模式要跟进页面链接并抓取外链 JS；单层模式只抓种子页与它的 JS。
func TestFindURLsDepthAndJS(t *testing.T) {
	pages := map[string]string{
		"http://lab.local/":       `<a href="/next">n</a><script src="/app.js"></script>`,
		"http://lab.local/next":   `<a href="/deep">d</a>`,
		"http://lab.local/deep":   `<a href="/deeper">d</a>`,
		"http://lab.local/app.js": `fetch('/api/report/${id}/export'); fetch('/api/health');`,
	}
	fetch := func(_ context.Context, u string) (int, []byte, error) {
		if b, ok := pages[u]; ok {
			return 200, []byte(b), nil
		}
		return 404, nil, nil
	}
	shallow := FindURLs(context.Background(), "http://lab.local/", URLFinderOptions{Fetch: fetch, Deep: false, SameHost: true})
	has := func(items []ExtractedURL, path string) bool {
		for _, it := range items {
			if it.Path == path {
				return true
			}
		}
		return false
	}
	if !has(shallow, "/api/report/{id}/export") && !has(shallow, "/api/report/123/export") {
		// 模式归一后 Path 保留原样，Pattern 是 /api/report/{id}/export
		found := false
		for _, it := range shallow {
			if it.Pattern == "/api/report/{id}/export" {
				found = true
			}
		}
		if !found {
			t.Fatalf("JS 里的模板接口没提取到: %+v", shallow)
		}
	}
	// 单层模式：种子页上的链接（/next）会被**列出**，但不会被抓取，
	// 所以只在 /next 里出现的 /deep 不应出现。
	if has(shallow, "/next") {
		t.Log("单层模式列出了种子页链接（预期）")
	}
	if has(shallow, "/deep") {
		t.Fatalf("单层模式跟进了页面: %+v", shallow)
	}
	deep := FindURLs(context.Background(), "http://lab.local/", URLFinderOptions{Fetch: fetch, Deep: true, MaxDepth: 2, SameHost: true})
	if !has(deep, "/next") || !has(deep, "/deep") {
		t.Fatalf("深入模式没跟进页面: %+v", deep)
	}
	// MaxDepth=2：种子(1) → /next(2)；/deep 只在更下一页里，不应被抓到。
	if has(deep, "/deeper") {
		t.Fatalf("层数上限失效: %+v", deep)
	}
	// 同一模式只保留一条。
	count := 0
	for _, it := range deep {
		if it.Pattern == "/api/report/{id}/export" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("同一接口模式被重复计数: %d", count)
	}
}

func TestNormalizeURLPattern(t *testing.T) {
	cases := map[string]string{
		"/api/orders/123":           "/api/orders/{id}",
		"/api/orders/123/items/456": "/api/orders/{id}/items/{id}",
		"/user/abc-def":             "/user/abc-def",
		"/users/${userId}/profile":  "/users/{id}/profile",
		"/users/:id/posts":          "/users/{id}/posts",
	}
	for in, want := range cases {
		if got := NormalizeURLPattern(in); got != want {
			t.Errorf("NormalizeURLPattern(%q) = %q want %q", in, got, want)
		}
	}
	_ = fmt.Sprint
	_ = strings.TrimSpace
}
