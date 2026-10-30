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
// 每个候选路径独立 HTTP 探测并跑指纹（复用 Prober），先取随机路径的
// soft-404 基线把「全路径同响应」的站点过滤掉，避免 SPA fallback 刷屏。
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
	prober := NewProber(opts.Timeout)
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

// appResponse is a lightweight probe result used for baseline comparison.
type appResponse struct {
	status int
	length int64
	title  string
	svc    *WebService
}

func appDiscoverService(ctx context.Context, prober *Prober, svc WebService, opts AppDiscoverOptions) ([]AppSystem, error) {
	base := strings.TrimSuffix(svc.URL, "/")
	if base == "" {
		return nil, nil
	}
	// soft-404 baseline: a random path that certainly does not exist.
	nonexistent := "/jingwei-notexist-" + fmt.Sprintf("%x", time.Now().UnixNano()&0xffffff)
	baseline := appProbePath(ctx, prober, base, nonexistent, svc.IP)
	if baseline == nil {
		// Even a random path errors out (or the root is dead): nothing to probe.
		return nil, nil
	}

	entries := appEnumerateEntries(ctx, prober, base, svc, opts)

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
			resp := appProbePath(ctx, prober, base, c.path, svc.IP)
			if resp == nil || appIsSoft404(*resp, *baseline) {
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
	sort.Slice(systems, func(i, j int) bool { return systems[i].Path < systems[j].Path })
	return systems, nil
}

// appEnumerateEntries pulls target-provided entries: robots.txt, sitemap.xml,
// root page links and same-origin JS routes.
func appEnumerateEntries(ctx context.Context, prober *Prober, base string, svc WebService, opts AppDiscoverOptions) []struct{ path, source string } {
	type entry = struct{ path, source string }
	var out []entry
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
		resp := appFetch(ctx, prober, base+src.path, svc.IP)
		if resp == nil || len(resp.body) == 0 {
			continue
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
				jr := appFetch(ctx, prober, u, svc.IP)
				if jr == nil {
					continue
				}
				for _, m := range reJSRouteString.FindAllStringSubmatch(string(jr.body), -1) {
					add(strings.Trim(m[0], "\"'`"), "js")
				}
			}
		}
	}
	return out
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

// appFetch is a raw GET used for robots/sitemap/page/JS bodies; fingerprinting
// is unnecessary here so only the body matters. Same redirect policy as the
// Prober (same-host only), so enumerated refs can never pull in a third-party
// origin.
func appFetch(ctx context.Context, prober *Prober, rawURL, ip string) *struct{ body []byte } {
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
	if resp.StatusCode >= 400 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return &struct{ body []byte }{body: body}
}

// appIsSoft404 reports whether a response matches the random-path baseline:
// same status AND (same title or near-identical length). SPA routers and
// catch-all error pages answer every path this way.
func appIsSoft404(resp, baseline appResponse) bool {
	if resp.status != baseline.status {
		return false
	}
	if resp.status >= 500 {
		return true
	}
	if resp.title != "" && baseline.title != "" && resp.title == baseline.title {
		return true
	}
	if baseline.length > 0 {
		diff := resp.length - baseline.length
		if diff < 0 {
			diff = -diff
		}
		if diff <= baseline.length/20 { // within 5%
			return true
		}
	}
	return false
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
