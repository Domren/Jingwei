package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// tailInterpIndex 返回第一个「尾部拼接」插值的下标——即不紧跟在「/」之后的 ${…}，
// 它拼的是路径片段之外的东西（查询串、?task= 之类）。没有则返回 -1。
func tailInterpIndex(p string) int {
	for i := 0; i+1 < len(p); i++ {
		if p[i] == '$' && p[i+1] == '{' && (i == 0 || p[i-1] != '/') {
			return i
		}
	}
	return -1
}

// 前端调的每个路径都必须在 mux 上注册。
//
// 为什么单独钉这件事：这一批功能的用例是**直接调 handler** 写的（handler 逻辑没问题、
// 测试全绿），但路由一次都没注册，界面上点「客户授权清单」「信息收集」只会拿到 404。
// 功能在代码里、在测试里、就是不在产品里——只有把请求真打到产品上才会露出来。
func TestUIEndpointsAreRouted(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	td := t.TempDir()
	s := newTestServer(t, m, td, td, td)
	s.Handler() // 构造路由表（顺带记下 s.apiMux）
	if s.apiMux == nil {
		t.Fatal("Handler() 没有记下 apiMux")
	}

	// ── 1. 逐条点名（路径取自 web/src/lib/api.ts）────────────────────────
	named := []struct{ method, path string }{
		{"GET", "/api/authorizations"},
		{"POST", "/api/authorizations"},
		{"DELETE", "/api/authorizations/1"},
		{"GET", "/api/intranet/scripts"},
		{"GET", "/api/intranet/sessions/1/scripts"},
		{"POST", "/api/intranet/sessions/1/scripts"},
		{"GET", "/api/credscan/protocols"},
		{"GET", "/api/credscan/dicts"},
		{"POST", "/api/credscan/dicts"},
		{"DELETE", "/api/credscan/dicts/builtin"},
		{"GET", "/api/credscan/tasks"},
		{"POST", "/api/credscan/tasks"},
		{"GET", "/api/credscan/tasks/1"},
		{"POST", "/api/credscan/tasks/1/cancel"},
		{"DELETE", "/api/credscan/tasks/1"},
		{"GET", "/api/credscan/tasks/1/results"},
		{"GET", "/api/credscan/tasks/1/report"},
		{"GET", "/api/scans/1/diff"},
	}
	for _, c := range named {
		r := httptest.NewRequest(c.method, c.path, nil)
		if _, pattern := s.apiMux.Handler(r); pattern == "" {
			t.Errorf("%s %s 没有注册路由（界面上会 404）", c.method, c.path)
		}
	}

	// ── 2. 全量扫描 api.ts：每个路径至少得有一种方法注册过 ────────────────
	src, err := os.ReadFile("../web/src/lib/api.ts")
	if err != nil {
		t.Fatalf("读 api.ts 失败: %v", err)
	}
	var (
		literal = regexp.MustCompile("`(/[A-Za-z0-9_./-]*(?:\\$\\{[^{}]*\\}[A-Za-z0-9_./-]*)*)`")
		plain   = regexp.MustCompile(`"(/[A-Za-z0-9_./-]+)"`)
		subs    = regexp.MustCompile(`\$\{[^{}]*\}`)
		seen    = map[string]bool{}
		paths   []string
		skipped int
	)
	collect := func(re *regexp.Regexp, body string) {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			p := m[1]
			// 模板插值有两种：路径段（/${id}/）与尾部拼接（${tq(task)}、查询串）。
			// 尾部拼接不改变「这个接口存不存在」，从那里截断；路径段代入 1。
			if cut := tailInterpIndex(p); cut >= 0 {
				p = p[:cut]
			}
			p = subs.ReplaceAllString(p, "1")
			// 整段动态的前缀（/${scope}/…）认不出具体注册名，跳过并计数。
			if strings.HasPrefix(p, "/1") {
				skipped++
				continue
			}
			p = strings.SplitN(p, "?", 2)[0]
			p = strings.TrimRight(p, "/")
			if p == "" {
				continue
			}
			if !strings.HasPrefix(p, "/api") {
				p = "/api" + p
			}
			if p == "/api" || seen[p] {
				continue
			}
			seen[p] = true
			paths = append(paths, p)
		}
	}
	// 只取紧跟在请求助手之后的那一段，避免把注释里的路径、工作区相对路径算进来。
	helper := regexp.MustCompile(`(?:\bget|\bpost|\bput|\bpatch|\bdel|\bdelRaw|\bpostForm|\bstream)\s*(?:<[^<>]*>)?\s*\(\s*(` + "`" + `[^` + "`" + `]*` + "`" + `|"[^"]*")`)
	for _, m := range helper.FindAllStringSubmatch(string(src), -1) {
		for _, re := range []*regexp.Regexp{literal, plain} {
			collect(re, m[1])
		}
	}
	if len(paths) < 100 {
		t.Fatalf("只从 api.ts 里认出 %d 个路径，解析八成坏了", len(paths))
	}
	sort.Strings(paths)
	var unrouted []string
	for _, p := range paths {
		matched := false
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			if _, pattern := s.apiMux.Handler(httptest.NewRequest(method, p, nil)); pattern != "" {
				matched = true
				break
			}
		}
		if !matched {
			unrouted = append(unrouted, p)
		}
	}
	t.Logf("api.ts 里的 %d 个路径，未注册 %d 个（另有 %d 个首段动态、认不出具体注册名）",
		len(paths), len(unrouted), skipped)
	for _, p := range unrouted {
		t.Errorf("前端会调 %s，但服务端没有注册路由", p)
	}

	// ── 3. 再走一遍真实的鉴权链路：清单读得到才算功能可用 ──────────────────
	tok, err := testAuthToken(t, s)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	for _, p := range []string{"/api/authorizations", "/api/intranet/scripts", "/api/credscan/protocols"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", p, rec.Code, rec.Body.String())
		}
	}
}
