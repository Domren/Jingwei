package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 应用层发现（app-layer discovery）：同一 Web 服务（scheme://host:port）下
// 识别挂在子路径上的其他系统。三个来源，全部只读目标自身内容、无外联：
//   1. 内置常见应用路径字典（后台/中间件/API 入口）
//   2. 目标自述的入口：robots.txt、sitemap.xml、根页面里的链接与脚本
//   3. 脚本内容里的路由字符串（SPA / 前端接口路径）
// 每个候选路径独立 HTTP 探测并跑指纹（复用 Prober），用随机路径的 soft-404
// 基线过滤「全路径同响应」的站点，再对通过初筛的候选补探一个随机子路径，
// 排除挂在某个前缀下的 catch-all（SPA router / 自定义 404）；与根页面或
// 彼此内容完全相同的别名路径（/, /index.php, /admin, /admin/）只保留一个。
// 与根页面同标题但长度不同的 PATH_INFO 变体（如 /index.php/admin）再比正文
// 相似度，服务器自带的「403 Forbidden」拒绝页直接丢弃。
// ---------------------------------------------------------------------------

// AppSystem is one distinct application found under a service path.
type AppSystem struct {
	// URL is the full entry URL (scheme://host:port/path).
	URL string `json:"url"`
	// Path is the URL path portion ("/admin").
	Path string `json:"path"`
	// Host/Port/IP mirror the parent WebService for convenience.
	Host          string   `json:"host"`
	IP            string   `json:"ip"`
	Port          int      `json:"port"`
	Scheme        string   `json:"scheme"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	Server        string   `json:"server"`
	Technologies  []string `json:"technologies"`
	ContentLength int64    `json:"content_length"`
	// Source says where the path came from: dictionary / robots / sitemap /
	// page / js（多个来源命中时取第一个登记的来源）。
	Source string `json:"source"`
}

// AppDiscoverOptions caps the app-layer phase.
type AppDiscoverOptions struct {
	// MaxCandidates caps probes per service (dictionary + enumerated entries).
	MaxCandidates int
	// MaxJSFiles caps same-origin scripts fetched for route extraction.
	MaxJSFiles  int
	Concurrency int
	Timeout     time.Duration
	Proxy       string
	Logf        func(format string, args ...any)
}

// appPathDictionary lists common application / admin / middleware entry paths.
// Deliberately short and high-signal: this phase is about finding *systems*,
// not directory brute-forcing. Extend freely; entries must start with "/".
var appPathDictionary = []string{
	"/admin", "/admin/", "/administrator", "/manager", "/manager/html",
	"/console", "/login", "/signin", "/api", "/api/", "/api/v1",
	"/graphql", "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html",
	"/api-docs", "/v2/api-docs", "/v3/api-docs", "/openapi.json",
	"/actuator", "/actuator/health", "/druid", "/druid/index.html",
	"/jenkins", "/jenkins/login", "/solr", "/solr/#/", "/kibana", "/elasticsearch",
	"/phpmyadmin", "/pma", "/adminer.php", "/mysql", "/sql",
	"/weblogic", "/wls-wsat", "/console/login/LoginForm.jsp",
	"/tomcat", "/host-manager", "/host-manager/html",
	"/nacos", "/nacos/", "/eureka", "/config", "/config.json",
	"/grafana", "/grafana/login", "/prometheus", "/metrics",
	"/kibana/app/home", "/zentao", "/gitlab", "/gitlab/users/sign_in",
	"/jenkins/script", "/api/swagger.json", "/debug", "/debug/vars", "/vars",
	"/status", "/server-status", "/info", "/phpinfo.php", "/info.php",
	"/backup", "/bak", "/dump", "/db.sql", "/database.sql",
	"/upload", "/uploads", "/file", "/files", "/static",
	"/.git/", "/.git/config", "/.svn/", "/.env", "/.DS_Store",
	"/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
	"/readme", "/readme.html", "/readme.md", "/README.md", "/CHANGELOG.md",
	"/install", "/install.php", "/setup", "/setup.php", "/wizard",
	"/monitor", "/monitoring", "/health", "/healthz", "/ping",
	"/sso", "/oauth", "/oauth/authorize", "/cas/login", "/shiro",
	"/seeyon", "/weaver", "/oa", "/login.do", "/main.do",
	"/ueditor", "/kindeditor", "/fckeditor", "/ckeditor",
	"/wp-admin", "/wp-login.php", "/wp-json", "/xmlrpc.php",
	"/administrator/index.php", "/index.php/admin",
	"/user/login", "/member/login", "/admincp", "/cpadmin",
	"/test", "/dev", "/demo", "/old", "/new", "/tmp",
	"/cgi-bin/", "/examples", "/docs", "/doc", "/javadoc",
}

var (
	reRobotsPath    = regexp.MustCompile(`(?im)^(?:disallow|allow|sitemap):\s*(\S+)`)
	reSitemapLoc    = regexp.MustCompile(`(?is)<loc>\s*([^<\s]+)\s*</loc>`)
	rePageRef       = regexp.MustCompile(`(?is)(?:href|src|action)\s*=\s*["']([^"'\s]+)["']`)
	reScriptSrc     = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"'\s]+)["']`)
	reJSRouteString = regexp.MustCompile("(?:[\"'`]/(?:[a-z0-9_-]{2,32})(?:/[a-z0-9_{}$.-]{1,32}){0,4}/?[\"'`])")

	// Page-text normalization for root-alias comparison: inline scripts/styles
	// are dropped (identical bundles across unrelated pages would dominate the
	// token sets), tags are stripped, and words/CJK runs become the tokens.
	reAppScriptBlock = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	reAppStyleBlock  = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style>`)
	reAppTag         = regexp.MustCompile(`(?s)<[^>]*>`)
	reAppToken       = regexp.MustCompile(`[\p{Han}]+|[[:alnum:]_]{2,}`)
)

func appDefault(opts AppDiscoverOptions) AppDiscoverOptions {
	if opts.MaxCandidates <= 0 {
		opts.MaxCandidates = 240
	}
	if opts.MaxJSFiles <= 0 {
		opts.MaxJSFiles = 20
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}
	return opts
}

// AppDiscover probes every WebService for path-level applications.
func AppDiscover(ctx context.Context, services []WebService, opts AppDiscoverOptions) ([]AppSystem, error) {
	opts = appDefault(opts)
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	prober := NewProberWithProxy(opts.Timeout, opts.Proxy)
	var mu sync.Mutex
	var out []AppSystem
	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Concurrency)
	for i := range services {
		svc := services[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			sys, err := appDiscoverService(ctx, prober, svc, opts)
			if err != nil {
				opts.Logf("%s 应用层发现失败: %v", svc.URL, err)
				return
			}
			if len(sys) == 0 {
				return
			}
			mu.Lock()
			out = append(out, sys...)
			mu.Unlock()
			opts.Logf("%s 应用层发现：子路径系统 %d 个", svc.URL, len(sys))
		}()
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out, nil
}

// appRawResponse is a raw GET result used for entry enumeration and catch-all
// checks, where fingerprinting is unnecessary.
type appRawResponse struct {
	status int
	length int64
	title  string
	body   []byte
}

// appResponse briefly carries the root body too, so a same-title candidate with
// a different size can be compared against what the root page actually renders.
type appResponse struct {
	status int
	length int64
	title  string
	body   []byte
	svc    *WebService
}

func appDiscoverService(ctx context.Context, prober *Prober, svc WebService, opts AppDiscoverOptions) ([]AppSystem, error) {
	base := strings.TrimSuffix(svc.URL, "/")
	if base == "" {
		return nil, nil
	}
	// soft-404 baseline: a random path that certainly does not exist.
	baselinePath := "/" + appRandomToken()
	baseline := appProbePath(ctx, prober, base, baselinePath, svc.IP)
	if baseline == nil {
		// Even a random path errors out (or the root is dead): nothing to probe.
		return nil, nil
	}

	entries, root := appEnumerateEntries(ctx, prober, base, svc, opts)

	type candidate struct {
		path   string
		source string
	}
	seen := map[string]string{}
	var cands []candidate
	addCand := func(path, source string) {
		if p := normalizeAppPath(path); p != "" {
			if prev, ok := seen[p]; ok {
				if prev == "dictionary" || source == "dictionary" {
					seen[p] = "dictionary"
				}
				return
			}
			seen[p] = source
			cands = append(cands, candidate{p, source})
		}
	}
	for _, p := range appPathDictionary {
		addCand(p, "dictionary")
	}
	for _, e := range entries {
		addCand(e.path, e.source)
	}
	if len(cands) > opts.MaxCandidates {
		// Dictionary entries first (highest prior), then target-provided entries.
		sort.SliceStable(cands, func(i, j int) bool {
			return cands[i].source == "dictionary" && cands[j].source != "dictionary"
		})
		cands = cands[:opts.MaxCandidates]
	}

	var mu sync.Mutex
	var systems []AppSystem
	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Concurrency)
	for _, c := range cands {
		wg.Add(1)
		go func(c candidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if c.path == "/" {
				// The service root is already registered by discovery.
				return
			}
			resp := appProbePath(ctx, prober, base, c.path, svc.IP)
			if resp == nil || resp.status == http.StatusNotFound || resp.status == http.StatusGone {
				return
			}
			if appBareForbidden(resp.status, resp.title) {
				// nginx/Apache stock refusals ("403 Forbidden") are not systems:
				// there is no login form or parameter surface behind them.
				return
			}
			if appSamePage(*resp, c.path, *baseline, baselinePath) {
				return
			}
			if root != nil && root.title != "" && resp.title == root.title {
				if appRootAlias(*resp, c.path, *root) || appRootBodyAlias(ctx, prober, base, c.path, svc.IP, *resp, *root) {
					return
				}
			}
			// Only 2xx landing pages are catch-all checked: auth walls (401/403)
			// answer every child path by design and are real systems.
			if resp.status >= 200 && resp.status < 300 && appPathCatchAll(ctx, prober, base, c.path, svc.IP, *resp) {
				return
			}
			ws := resp.svc
			mu.Lock()
			systems = append(systems, AppSystem{
				URL: ws.URL, Path: c.path,
				Host: svc.Host, IP: svc.IP, Port: svc.Port, Scheme: svc.Scheme,
				StatusCode: ws.StatusCode, Title: ws.Title, Server: ws.Server,
				Technologies: ws.Technologies, ContentLength: ws.ContentLength,
				Source: c.source,
			})
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	systems = appDedupeSystems(systems)
	sort.Slice(systems, func(i, j int) bool { return systems[i].Path < systems[j].Path })
	return systems, nil
}

// appEnumerateEntries pulls target-provided entries: robots.txt, sitemap.xml,
// root page links and same-origin JS routes. The root response is returned too
// so the caller can recognize aliases of the service root page.
func appEnumerateEntries(ctx context.Context, prober *Prober, base string, svc WebService, opts AppDiscoverOptions) ([]struct{ path, source string }, *appResponse) {
	type entry = struct{ path, source string }
	var out []entry
	var root *appResponse
	seen := map[string]bool{}
	add := func(raw, source string) {
		if p := relativeAppPath(raw, base); p != "" && !seen[p] {
			seen[p] = true
			out = append(out, entry{p, source})
		}
	}

	for _, src := range []struct {
		path   string
		source string
	}{
		{"/robots.txt", "robots"},
		{"/sitemap.xml", "sitemap"},
		{"/", "page"},
	} {
		resp := appRawFetch(ctx, prober, base+src.path, svc.IP)
		if resp == nil || resp.status >= 400 || len(resp.body) == 0 {
			continue
		}
		if src.source == "page" {
			root = &appResponse{status: resp.status, length: resp.length, title: resp.title, body: resp.body}
		}
		switch src.source {
		case "robots":
			for _, m := range reRobotsPath.FindAllStringSubmatch(string(resp.body), -1) {
				add(m[1], "robots")
			}
		case "sitemap":
			for _, m := range reSitemapLoc.FindAllStringSubmatch(string(resp.body), -1) {
				add(m[1], "sitemap")
			}
		case "page":
			body := string(resp.body)
			for _, m := range rePageRef.FindAllStringSubmatch(body, -1) {
				add(m[1], "page")
			}
			// Same-origin scripts get fetched once for route strings.
			scripts := map[string]bool{}
			for _, m := range reScriptSrc.FindAllStringSubmatch(body, -1) {
				if u := absoluteAppURL(base, m[1]); u != "" && !scripts[u] {
					scripts[u] = true
				}
			}
			if len(scripts) > opts.MaxJSFiles {
				for u := range scripts {
					if len(scripts) <= opts.MaxJSFiles {
						break
					}
					delete(scripts, u)
				}
			}
			for u := range scripts {
				jr := appRawFetch(ctx, prober, u, svc.IP)
				if jr == nil || jr.status >= 400 {
					continue
				}
				for _, m := range reJSRouteString.FindAllStringSubmatch(string(jr.body), -1) {
					add(strings.Trim(m[0], "\"'`"), "js")
				}
			}
		}
	}
	return out, root
}

// appProbePath GETs base+path through the Prober and returns the fingerprinted
// response, or nil when the request failed.
func appProbePath(ctx context.Context, prober *Prober, base, path, ip string) *appResponse {
	ws, err := prober.Probe(ctx, base+path, ip)
	if err != nil || ws == nil {
		return nil
	}
	return &appResponse{status: ws.StatusCode, length: ws.ContentLength, title: ws.Title, svc: ws}
}

// appRawResponse is a raw GET result used for entry enumeration and catch-all
// checks, where fingerprinting is unnecessary.
// appRawFetch GETs one URL with the Prober's client, so the same redirect
// policy applies (same-host only) and enumerated refs can never pull in a
// third-party origin.
func appRawFetch(ctx context.Context, prober *Prober, rawURL, ip string) *appRawResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", probeUserAgent)
	resp, err := prober.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := &appRawResponse{status: resp.StatusCode, length: int64(len(body)), body: body}
	if resp.ContentLength >= 0 {
		out.length = resp.ContentLength
	}
	if m := reTitle.FindStringSubmatch(string(body)); len(m) == 2 {
		out.title = strings.TrimSpace(decodeEntities(m[1]))
	}
	return out
}

// appRandomToken returns a path fragment that no real handler should serve.
func appRandomToken() string {
	return fmt.Sprintf("jingwei-notexist-%x", time.Now().UnixNano()&0xffffff)
}

// appSamePage reports whether two responses are the same page in the soft-404
// sense: equal status and either a shared non-empty title or a matching size.
// Sizes are compared raw and with the requested path subtracted, because many
// catch-all handlers echo the path, so two nonexistent paths of different
// lengths still produce a size difference that is exactly the path difference.
func appSamePage(a appResponse, aPath string, b appResponse, bPath string) bool {
	if a.status != b.status {
		return false
	}
	if a.status >= 500 {
		return true
	}
	if a.title != "" && a.title == b.title {
		return true
	}
	return appLengthClose(a.length, aPath, b.length, bPath)
}

func appLengthClose(aLen int64, aPath string, bLen int64, bPath string) bool {
	if aLen == bLen {
		return true
	}
	if bLen > 0 {
		diff := aLen - bLen
		if diff < 0 {
			diff = -diff
		}
		if diff <= bLen/20 { // within 5%
			return true
		}
	}
	aAdj := aLen - int64(len(aPath))
	bAdj := bLen - int64(len(bPath))
	if aAdj < 0 || bAdj < 0 {
		return false
	}
	diff := aAdj - bAdj
	if diff < 0 {
		diff = -diff
	}
	// Path-echo bodies differ only by the path length, so the adjusted sizes
	// must match almost exactly; a wide tolerance would swallow small real
	// pages that merely sit near the 404 page's size.
	tol := bAdj / 50
	if tol < 8 {
		tol = 8
	}
	return diff <= tol
}

// appRootAlias reports whether a candidate serves the service root page under
// another path (/, /index.php, ...). Both a non-empty equal title and a
// matching size are required so a coincidental size match cannot hide a real
// system.
func appRootAlias(resp appResponse, path string, root appResponse) bool {
	if resp.status != root.status || root.title == "" || resp.title != root.title {
		return false
	}
	return appLengthClose(resp.length, path, root.length, "/")
}

// appRootBodyAlias catches same-title PATH_INFO variants whose size differs
// from the root page even though they render the same script (e.g.
// /index.php/admin without the query parameter: same template, an extra
// warning, or a missing result block). The extra raw fetch is paid only for
// candidates that already share the root title, so ordinary probes stay at one
// request.
func appRootBodyAlias(ctx context.Context, prober *Prober, base, path, ip string, resp, root appResponse) bool {
	if resp.status != root.status || len(root.body) == 0 {
		return false
	}
	cand := appRawFetch(ctx, prober, base+path, ip)
	if cand == nil || len(cand.body) == 0 {
		return false
	}
	return appBodySimilar(root.body, cand.body)
}

// appBodySimilar reports whether two pages are the same page in substance.
// Visible text is compared: exact containment covers small pages and
// same-content variants, while a high unique-token overlap covers pages that
// gained or lost a block (SQL warning, empty result table) without sharing a
// contiguous prefix.
func appBodySimilar(a, b []byte) bool {
	ta, tb := appVisibleText(a), appVisibleText(b)
	if ta == "" || tb == "" {
		return false
	}
	if len(ta) >= 16 && len(tb) >= 16 && (strings.Contains(ta, tb) || strings.Contains(tb, ta)) {
		return true
	}
	sa, sb := appTokenSet(ta), appTokenSet(tb)
	if len(sa) < 24 || len(sb) < 24 {
		return false
	}
	common := 0
	for t := range sa {
		if _, ok := sb[t]; ok {
			common++
		}
	}
	small := len(sa)
	if len(sb) < small {
		small = len(sb)
	}
	return float64(common)/float64(small) >= 0.85
}

// appVisibleText strips script/style blocks and tags, then collapses whitespace
// so containment and token comparisons ignore markup formatting.
func appVisibleText(body []byte) string {
	s := reAppScriptBlock.ReplaceAllString(string(body), " ")
	s = reAppStyleBlock.ReplaceAllString(s, " ")
	s = reAppTag.ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(s), " ")
}

func appTokenSet(text string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, tok := range reAppToken.FindAllString(text, -1) {
		out[strings.ToLower(tok)] = struct{}{}
	}
	return out
}

// appBareForbidden reports whether a 403 is the server's stock refusal page
// rather than an application entry. Stock pages (nginx/Apache) carry only the
// status text as their title, and behind them there is no login form or
// parameter surface for the baselines to test.
func appBareForbidden(status int, title string) bool {
	if status != http.StatusForbidden {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(title)) {
	case "", "403", "403 forbidden", "forbidden":
		return true
	}
	return false
}

// appPathCatchAll confirms that a candidate is a real page rather than a
// prefix-scoped catch-all: a random child of the candidate path must not get
// the same response. SPA routers and custom 404 handlers often answer every
// path under a prefix with one shell page.
func appPathCatchAll(ctx context.Context, prober *Prober, base, path, ip string, resp appResponse) bool {
	probePath := strings.TrimSuffix(path, "/") + "/" + appRandomToken()
	sibling := appRawFetch(ctx, prober, base+probePath, ip)
	if sibling == nil {
		return false // cannot confirm; keep the candidate
	}
	return appSamePage(resp, path, appResponse{status: sibling.status, length: sibling.length, title: sibling.title}, probePath)
}

// appDedupeSystems collapses alias paths that serve the identical page
// (e.g. /index.php next to /, or /admin next to /admin/). The shortest path is
// kept as the canonical entry. Identical title AND byte size are required, so
// distinct systems that merely share a generic title survive; non-2xx answers
// are never merged (a shared auth wall repeats by design).
func appDedupeSystems(systems []AppSystem) []AppSystem {
	sort.SliceStable(systems, func(i, j int) bool {
		a, b := systems[i], systems[j]
		if len(a.Path) != len(b.Path) {
			return len(a.Path) < len(b.Path)
		}
		aSlash := strings.HasSuffix(a.Path, "/")
		bSlash := strings.HasSuffix(b.Path, "/")
		if aSlash != bSlash {
			return !aSlash
		}
		return a.Path < b.Path
	})
	out := systems[:0]
	for _, s := range systems {
		alias := false
		for _, kept := range out {
			if appAliasPage(kept, s) {
				alias = true
				break
			}
		}
		if !alias {
			out = append(out, s)
		}
	}
	return out
}

func appAliasPage(a, b AppSystem) bool {
	if a.StatusCode < 200 || a.StatusCode >= 300 || a.StatusCode != b.StatusCode {
		return false
	}
	return a.Title != "" && a.Title == b.Title && a.ContentLength == b.ContentLength
}

// normalizeAppPath canonicalizes a candidate path: leading "/", no query/anchor,
// no "//", no traversal.
func normalizeAppPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return ""
	}
	if strings.Contains(raw, "..") || strings.Contains(raw, "//") {
		return ""
	}
	if len(raw) > 96 {
		return ""
	}
	return raw
}

// relativeAppPath turns a robots/sitemap/page reference into a same-origin
// path. Absolute URLs are accepted only when they point back at the same
// origin (sitemap <loc> entries are absolute by spec); anything off-origin,
// protocol-relative, or non-page is dropped.
func relativeAppPath(raw, base string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if raw != base && !strings.HasPrefix(raw, base+"/") {
			return ""
		}
		u := raw[len(base):]
		if u == "" {
			return "/"
		}
		return normalizeAppPath(u)
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "data:") ||
		strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "javascript:") {
		return ""
	}
	return normalizeAppPath(raw)
}

// absoluteAppURL resolves a script src against base, returning "" when the
// reference points off-origin.
func absoluteAppURL(base, ref string) string {
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		if strings.HasPrefix(ref, base+"/") || ref == base {
			return ref
		}
		return ""
	}
	if p := normalizeAppPath(ref); p != "" {
		return strings.TrimSuffix(base, "/") + p
	}
	return ""
}
