package scanner

import (
	"context"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// JS / 页面里的 URL 与接口提取（对标 UrlFinder 的可用子集）：
// 单层与深入两种模式、层数/页面数/JS 文件数上限、本站过滤、按「归一化模式」去重。
//
// 输出不是「一堆字符串」而是带来源、层级与归一化模式的条目：
//   - /api/orders/123 与 /api/orders/456 归一成 /api/orders/{id}，接口清单才不会
//     被同一接口的不同 id 淹掉；
//   - 模式与示例 URL 同时保留——前者用于去重与统计，后者用于实际探测。
//
// 提取只读目标自身内容，不访问外站（SameHost 默认 true），也不把静态资源算进接口数。

type URLFinderOptions struct {
	Deep       bool
	MaxDepth   int // 深入模式的最大层级（含种子页），<=0 用 2
	MaxPages   int // 最多抓取的页面数，<=0 用 40
	MaxJSFiles int // 最多抓取的 JS 文件数，<=0 用 30
	MaxResults int // 结果上限，<=0 用 500
	SameHost   bool
	// Fetch 由调用方提供（扫描器已有带代理与超时的抓取器）。
	Fetch func(ctx context.Context, rawURL string) (status int, body []byte, err error)
	Logf  func(format string, args ...any)
}

type ExtractedURL struct {
	URL     string `json:"url"`
	Path    string `json:"path"`
	Source  string `json:"source"` // page / js / deep
	Kind    string `json:"kind"`   // page / api / js
	Depth   int    `json:"depth"`
	Pattern string `json:"pattern"` // 归一化模式，用于去重与接口清单
	// Query 保留查询串；探测时按原样使用。
	Query string `json:"query,omitempty"`
}

var (
	// 引号里的绝对 URL 或站点内路径。刻意不抓相对路径（无前导 /）：它依赖上下文，
	// 猜错基准会把同一个接口记成两条。
	reQuotedURL = regexp.MustCompile("[\"'`](https?://[^\"'`\\s<>]{4,300}|/[^\"'`\\s<>]{1,200})[\"'`]")
	// 模板字面量里的插值：${id}、{id}、:id 都归一成 {id}。
	reTemplateVar = regexp.MustCompile(`\$\{[^}]{1,40}\}|\{[a-zA-Z0-9_.-]{1,40}\}|:[a-zA-Z_][a-zA-Z0-9_]{0,30}`)
	reNumericSeg  = regexp.MustCompile(`^\d{1,12}$`)
	reUUIDSeg     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reAPIKind     = regexp.MustCompile(`(?i)^/(api|rest|graphql|v[0-9]+|openapi|swagger)(/|$)`)
)

var urlStaticExt = map[string]bool{
	".css": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".webp": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".mp3": true, ".map": true, ".pdf": true, ".zip": true, ".gz": true,
}

func urlFinderDefaults(o URLFinderOptions) URLFinderOptions {
	if o.MaxDepth <= 0 {
		o.MaxDepth = 2
	}
	if o.MaxPages <= 0 {
		o.MaxPages = 40
	}
	if o.MaxJSFiles <= 0 {
		o.MaxJSFiles = 30
	}
	if o.MaxResults <= 0 {
		o.MaxResults = 500
	}
	return o
}

// NormalizeURLPattern 把示例 URL 归一成接口模式：
// /api/orders/123 → /api/orders/{id}；/user/550e8400-… → /user/{uuid}；
// 模板插值（${id}、:id、{id}）统一成 {id}。
func NormalizeURLPattern(raw string) string {
	u, err := url.Parse(raw)
	p := raw
	if err == nil && u.Path != "" {
		p = u.Path
	}
	p = reTemplateVar.ReplaceAllString(p, "{id}")
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		switch {
		case seg == "":
		case reUUIDSeg.MatchString(seg):
			segs[i] = "{uuid}"
		case reNumericSeg.MatchString(seg):
			segs[i] = "{id}"
		}
	}
	p = strings.Join(segs, "/")
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

func urlKindFor(p string) string {
	lower := strings.ToLower(p)
	if ext := path.Ext(lower); ext != "" && urlStaticExt[ext] {
		return "static"
	}
	if ext := path.Ext(lower); ext == ".js" {
		return "js"
	}
	if reAPIKind.MatchString(lower) {
		return "api"
	}
	return "page"
}

// ExtractURLsFromText 从一段 HTML/JS 文本里提取站点内 URL。
// base 用于判断是否同站；source 标记来源（page / js）；depth 是抓取层级。
func ExtractURLsFromText(text, base, source string, depth int, sameHost bool) []ExtractedURL {
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil
	}
	host := baseURL.Host
	// 根相对路径要按「源」解析，不能拼在当前文档的完整路径后面：
	// 从 /app.js 里提取到的 /api/health 必须以 http://host/api/health 落地，
	// 而不是 http://host/app.js/api/health。
	origin := baseURL.Scheme + "://" + baseURL.Host
	out := []ExtractedURL{}
	seen := map[string]bool{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "//") || strings.Contains(raw, " ") {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
			return
		}
		if u.Host != "" && u.Host != host {
			if sameHost {
				return
			}
		}
		abs := raw
		if u.Scheme == "" {
			if strings.HasPrefix(raw, "/") {
				abs = origin + raw
			} else {
				abs = strings.TrimRight(base, "/") + "/" + raw
			}
		}
		pu, err := url.Parse(abs)
		if err != nil || pu.Host != host {
			if sameHost {
				return
			}
		}
		p := pu.Path
		if p == "" {
			p = "/"
		}
		kind := urlKindFor(p)
		if kind == "static" {
			return
		}
		if seen[abs] {
			return
		}
		seen[abs] = true
		out = append(out, ExtractedURL{
			URL: abs, Path: p, Source: source, Kind: kind, Depth: depth,
			Pattern: NormalizeURLPattern(abs), Query: pu.RawQuery,
		})
	}
	for _, m := range reQuotedURL.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	return out
}

// FindURLs 抓取种子页并按模式深入，返回去重后的 URL 清单。
func FindURLs(ctx context.Context, seed string, opts URLFinderOptions) []ExtractedURL {
	opts = urlFinderDefaults(opts)
	if opts.Fetch == nil {
		return nil
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if _, err := url.Parse(seed); err != nil {
		return nil
	}

	type page struct {
		url   string
		depth int
	}
	queue := []page{{url: seed, depth: 1}}
	visitedPage := map[string]bool{seed: true}
	visitedJS := map[string]bool{}
	resultByPattern := map[string]int{} // pattern|kind → index
	results := []ExtractedURL{}
	addResult := func(u ExtractedURL) {
		key := u.Kind + "|" + u.Pattern
		if idx, ok := resultByPattern[key]; ok {
			// 同一接口模式保留示例 URL 与更高的层级（深入模式的证据更完整），
			// 但不再重复计数。
			if u.Depth < results[idx].Depth {
				results[idx].Depth = u.Depth
			}
			return
		}
		if len(results) >= opts.MaxResults {
			return
		}
		resultByPattern[key] = len(results)
		results = append(results, u)
	}

	jsCount, pageCount := 0, 0
	for len(queue) > 0 && pageCount < opts.MaxPages {
		cur := queue[0]
		queue = queue[1:]
		status, body, err := opts.Fetch(ctx, cur.url)
		if err != nil || status >= 400 || len(body) == 0 {
			continue
		}
		pageCount++
		source := "page"
		if cur.depth > 1 {
			source = "deep"
		}
		items := ExtractURLsFromText(string(body), cur.url, source, cur.depth, opts.SameHost)
		for _, it := range items {
			addResult(it)
			switch it.Kind {
			case "js":
				if jsCount < opts.MaxJSFiles && !visitedJS[it.URL] {
					visitedJS[it.URL] = true
					jsCount++
					st, jsBody, jerr := opts.Fetch(ctx, it.URL)
					if jerr == nil && st < 400 && len(jsBody) > 0 {
						for _, jit := range ExtractURLsFromText(string(jsBody), it.URL, "js", cur.depth+1, opts.SameHost) {
							addResult(jit)
						}
					}
				}
			case "page":
				if opts.Deep && cur.depth < opts.MaxDepth && !visitedPage[it.URL] {
					visitedPage[it.URL] = true
					queue = append(queue, page{url: it.URL, depth: cur.depth + 1})
				}
			}
		}
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Kind != results[j].Kind {
			return results[i].Kind < results[j].Kind
		}
		return results[i].Pattern < results[j].Pattern
	})
	apis := 0
	for _, r := range results {
		if r.Kind == "api" {
			apis++
		}
	}
	logf("URL 提取：页面 %d 个、JS %d 个、接口 %d 条、条目合计 %d（深入=%v，同站=%v）",
		pageCount, jsCount, apis, len(results), opts.Deep, opts.SameHost)
	return results
}
