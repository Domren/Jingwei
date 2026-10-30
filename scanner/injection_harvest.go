package scanner

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 注入点枚举（parameter harvesting）：固定渗透基线的第一步。
// POC 命中只证明「某个响应看起来有趣」，SQL/XSS 需要工具证明参数确实是注入点，
// 而工具要有得跑，前提是拿到参数位置。这里只做只读解析：抓取已发现的页面，
// 抽出带查询串的链接与表单字段，作为 sqlmap/dalfox 的参数位置。
// 不提交任何表单、不跟随跨主机链接、不写任何数据。
// ---------------------------------------------------------------------------

// ParamPoint is one parameter location read off a discovered page.
type ParamPoint struct {
	URL    string   `json:"url"`
	Method string   `json:"method"`
	Body   string   `json:"body,omitempty"`
	Params []string `json:"params"`
	// Cookie carries the anonymous session the page issued (PHPSESSID and
	// friends). Without it a session-bound endpoint answers with a redirect and
	// the tool's negative verdict describes a missing login, not a safe parameter.
	Cookie string `json:"cookie,omitempty"`
	// Source says how the point was read: url / link / form.
	Source string `json:"source"`
	Score  int    `json:"score"`
	// Page is the document the point was lifted from.
	Page string `json:"page,omitempty"`
}

// HarvestOptions bounds the read-only enumeration phase.
type HarvestOptions struct {
	MaxPages     int
	MaxPoints    int
	Concurrency  int
	Timeout      time.Duration
	MaxBodyBytes int64
	Logf         func(format string, args ...any)
}

const (
	harvestDefaultPages         = 24
	harvestDefaultPoints        = 80
	harvestDefaultConcur        = 4
	harvestDefaultTimeout       = 8 * time.Second
	harvestDefaultBody    int64 = 600 << 10
	maxHarvestForms             = 12
	maxHarvestFields            = 40
	maxHarvestRefs              = 400
	maxFormChunk                = 24 << 10
)

func harvestDefault(opts HarvestOptions) HarvestOptions {
	if opts.MaxPages <= 0 {
		opts.MaxPages = harvestDefaultPages
	}
	if opts.MaxPoints <= 0 {
		opts.MaxPoints = harvestDefaultPoints
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = harvestDefaultConcur
	}
	if opts.Timeout <= 0 {
		opts.Timeout = harvestDefaultTimeout
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = harvestDefaultBody
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return opts
}

var (
	reHarvestForm   = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	reHarvestField  = regexp.MustCompile(`(?is)<(input|select|textarea)\b([^>]*)>`)
	reHarvestAttr   = regexp.MustCompile(`(?i)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'` + "`" + `>]+))`)
	reHarvestRef    = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'<>\s]{2,512})["']`)
	reHarvestQuoted = regexp.MustCompile("[\"'`]([^\"'`<>#]{1,256}\\?[^\"'`<>#]{1,192})[\"'`]")
	// harvestSkipField drops credential and anti-CSRF fields: a token is not an
	// injection point, and a login form already has its own baseline step.
	harvestSkipField = regexp.MustCompile(`(?i)(pass(word|wd)?|pwd|csrf|xsrf|token|captcha|verif|auth|secret|signature|otp|nonce)`)
	// harvestHotParam marks names that reach a query, a file or a template, so
	// the bounded budget lands on the parameters worth a tool run.
	harvestHotParam = regexp.MustCompile(`(?i)^(id|ids|uid|user|username|name|q|query|search|s|k|key|keyword|keywords|page|p|cat|category|product|item|file|path|dir|url|uri|redirect|return|next|lang|locale|order|sort|by|limit|offset|num|no|code|table|col|column|content|text|value|input|msg|message|title|host|ip|port|year|month|date)$`)
	// harvestDynamicPath marks endpoints backed by code rather than a static file.
	harvestDynamicPath = regexp.MustCompile(`(?i)\.(php[0-9]?|phtml|asp|aspx|ashx|jsp|jspx|do|action|cgi|pl|py|json|xml|api)(/|$)|/(api|rest|v[0-9]+)/`)
	harvestStaticExt   = []string{
		".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
		".bmp", ".tif", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".avi",
		".mp3", ".wav", ".ogg", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".rar", ".7z", ".tar",
		".exe", ".dll", ".so", ".apk", ".dmg", ".iso", ".swf",
	}
)

// HarvestParams fetches the seed pages and returns the parameter locations they
// expose, best candidates first. Only the seeds the caller already scoped are
// requested, and only same-host references are followed.
func HarvestParams(ctx context.Context, seeds []string, opts HarvestOptions) []ParamPoint {
	opts = harvestDefault(opts)
	client := newHarvestClient(opts.Timeout)
	sem := make(chan struct{}, opts.Concurrency)
	var mu sync.Mutex
	var out []ParamPoint
	var wg sync.WaitGroup
	pages := 0
	for _, seed := range harvestDedupe(seeds) {
		if ctx.Err() != nil {
			break
		}
		mu.Lock()
		blocked := pages >= opts.MaxPages || len(out) >= opts.MaxPoints
		if !blocked {
			pages++
		}
		mu.Unlock()
		if blocked {
			break
		}
		wg.Add(1)
		go func(rawURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			body, _, err := fetchHarvestPage(ctx, client, rawURL, opts.MaxBodyBytes)
			if err != nil {
				opts.Logf("%s 取页失败（%v），跳过该页的注入点枚举", rawURL, err)
				return
			}
			var pts []ParamPoint
			if looksLikeHTMLPage(body) {
				pts = ExtractParamPoints(rawURL, body)
			} else if point := urlPoint(rawURL, rawURL); len(point.Params) > 0 {
				// A JSON or plain endpoint still carries its own query parameters.
				point.Source = "url"
				pts = []ParamPoint{point}
			}
			if len(pts) == 0 {
				return
			}
			mu.Lock()
			out = append(out, pts...)
			mu.Unlock()
		}(seed)
	}
	wg.Wait()
	for i := range out {
		out[i].Cookie = clientCookie(client, out[i].URL)
	}
	return rankParamPoints(out, opts.MaxPoints)
}

// ExtractParamPoints reads the parameter locations one document exposes: its own
// query string, same-host links that carry one, and every form field set.
func ExtractParamPoints(pageURL, body string) []ParamPoint {
	out := []ParamPoint{}
	add := func(p ParamPoint) {
		if len(p.Params) == 0 || p.URL == "" {
			return
		}
		p.Method = strings.ToUpper(strings.TrimSpace(p.Method))
		if p.Method == "" {
			p.Method = "GET"
		}
		p.Page = pageURL
		p.Score = harvestScore(p.Method, p.URL, p.Body, p.Params)
		out = append(out, p)
	}
	// The seed URL itself is a point: a fingerprinted entry page that already has
	// ?id=1 is exactly the parameter a tool should look at.
	if withQuery(pageURL) != "" {
		add(urlPoint(pageURL, pageURL))
	}
	for _, ref := range harvestRefs(pageURL, body) {
		if p := urlPoint(pageURL, ref); p.URL != "" {
			add(p)
		}
	}
	for _, form := range harvestForms(pageURL, body) {
		add(form)
	}
	return out
}

func harvestRefs(pageURL, body string) []string {
	seen := map[string]bool{}
	out := []string{}
	push := func(raw string) {
		if len(out) >= maxHarvestRefs {
			return
		}
		// Either a path plus query, or a bare "?page=2" that re-targets the page
		// itself. Anything else is a JS fragment, not a request target.
		if !strings.Contains(raw, "?") {
			return
		}
		if !strings.HasPrefix(raw, "?") && !strings.Contains(raw, "/") {
			return
		}
		abs := resolveRef(pageURL, raw)
		if abs == "" || seen[abs] {
			return
		}
		seen[abs] = true
		out = append(out, abs)
	}
	for _, m := range reHarvestRef.FindAllStringSubmatch(body, -1) {
		push(decodeEntities(m[1]))
	}
	for _, m := range reHarvestQuoted.FindAllStringSubmatch(body, -1) {
		push(decodeEntities(m[1]))
	}
	return out
}

// harvestForms turns each form's field set into one parameter location. Fields
// are never submitted; only the endpoint and the names are recorded.
func harvestForms(pageURL, body string) []ParamPoint {
	out := []ParamPoint{}
	for _, span := range reHarvestForm.FindAllStringIndex(body, maxHarvestForms) {
		head := harvestAttrs(body[span[0]:span[1]])
		chunk := body[span[1]:]
		if i := indexFold(chunk, "</form>"); i >= 0 && i <= len(chunk) {
			chunk = chunk[:i]
		}
		if len(chunk) > maxFormChunk {
			chunk = chunk[:maxFormChunk]
		}
		fields := harvestFieldNames(chunk)
		if len(fields) == 0 {
			continue
		}
		method := strings.ToUpper(head["method"])
		if method == "" {
			method = "GET"
		}
		if method != "POST" && method != "GET" {
			// A PUT/DELETE form still posts through the method-override field, so
			// treat it as a body-carrying point instead of dropping it.
			method = "POST"
		}
		action := strings.TrimSpace(head["action"])
		target := pageURL
		if action != "" {
			if resolved := resolveRef(pageURL, action); resolved != "" {
				target = resolved
			}
		}
		if isStaticTarget(target) {
			continue
		}
		encoded := harvestEncode(fields)
		point := ParamPoint{Method: method, Params: fields, Source: "form"}
		if method == "GET" {
			point.URL = mergeQuery(target, encoded)
		} else {
			if withQuery(target) != "" {
				point.URL = target
			} else {
				point.URL = stripQuery(target)
			}
			point.Body = encoded
		}
		if point.URL == "" {
			continue
		}
		point.Page = pageURL
		point.Score = harvestScore(point.Method, point.URL, point.Body, point.Params)
		out = append(out, point)
	}
	return out
}

func harvestFieldNames(chunk string) []string {
	names := []string{}
	seen := map[string]bool{}
	for _, m := range reHarvestField.FindAllStringSubmatch(chunk, maxHarvestFields) {
		attrs := harvestAttrs(m[2])
		name := strings.TrimSpace(attrs["name"])
		if name == "" || seen[strings.ToLower(name)] {
			continue
		}
		switch strings.ToLower(attrs["type"]) {
		case "", "text", "hidden", "number", "search", "email", "tel", "url", "password", "radio", "checkbox", "date":
		default:
			continue // submit/button/image/reset/file and anything exotic
		}
		if harvestSkipField.MatchString(name) {
			continue
		}
		seen[strings.ToLower(name)] = true
		names = append(names, name)
	}
	return names
}

func harvestAttrs(raw string) map[string]string {
	attrs := map[string]string{}
	for _, m := range reHarvestAttr.FindAllStringSubmatch(raw, -1) {
		key := strings.ToLower(m[1])
		if _, ok := attrs[key]; ok {
			continue
		}
		value := firstNonEmpty(m[2], m[3], m[4])
		attrs[key] = decodeEntities(value)
	}
	return attrs
}

func urlPoint(pageURL, target string) ParamPoint {
	query := withQuery(target)
	if query == "" || isStaticTarget(target) {
		return ParamPoint{}
	}
	names := queryParamNames(query)
	if len(names) == 0 {
		return ParamPoint{}
	}
	return ParamPoint{URL: target, Method: "GET", Params: names, Source: "link"}
}

func queryParamNames(query string) []string {
	names := []string{}
	seen := map[string]bool{}
	for _, part := range strings.Split(strings.TrimPrefix(query, "?"), "&") {
		key, _, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(decodeEntities(key))
		if key == "" || seen[strings.ToLower(key)] || harvestSkipField.MatchString(key) {
			continue
		}
		seen[strings.ToLower(key)] = true
		names = append(names, key)
	}
	return names
}

func harvestEncode(names []string) string {
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, url.QueryEscape(name)+"=1")
	}
	return strings.Join(parts, "&")
}

func harvestScore(method, rawURL, body string, names []string) int {
	path := rawURL
	if u, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		path = u.Path
	}
	lower := strings.ToLower(path)
	score := 20
	switch {
	case harvestDynamicPath.MatchString(lower):
		score += 30
	case strings.HasSuffix(lower, "/") || !strings.Contains(path[strings.LastIndex(path, "/")+1:], "."):
		score += 15
	}
	if strings.EqualFold(method, "POST") && strings.Contains(body, "=") {
		score += 10
	}
	for _, name := range names {
		if harvestHotParam.MatchString(name) {
			score += 25
			break
		}
	}
	if len(names) > 1 {
		score += 5
	}
	if strings.Contains(lower, "login") || strings.Contains(lower, "logout") {
		score -= 60 // credential endpoints belong to the weak-password baseline
	}
	if strings.Contains(lower, "search") || strings.Contains(lower, "sqli") || strings.Contains(lower, "xss") {
		score += 20
	}
	return score
}

func rankParamPoints(pts []ParamPoint, max int) []ParamPoint {
	index := map[string]int{}
	out := []ParamPoint{}
	for _, p := range pts {
		key := p.Method + "|" + strings.ToLower(p.URL) + "|" + p.Body
		if i, ok := index[key]; ok {
			// Keep the higher-scoring provenance; the point itself is identical.
			if p.Score > out[i].Score {
				out[i] = p
			}
			continue
		}
		index[key] = len(out)
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if len(out[i].Params) != len(out[j].Params) {
			return len(out[i].Params) < len(out[j].Params)
		}
		return out[i].URL < out[j].URL
	})
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func isStaticTarget(rawURL string) bool {
	path := strings.ToLower(rawURL)
	if u, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		path = strings.ToLower(u.Path)
	}
	for _, ext := range harvestStaticExt {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func resolveRef(pageURL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		return ""
	}
	for _, dead := range []string{"javascript:", "data:", "mailto:", "tel:", "ftp:", "file:", "jar:"} {
		if strings.HasPrefix(strings.ToLower(ref), dead) {
			return ""
		}
	}
	base, err := url.Parse(strings.TrimSpace(pageURL))
	if err != nil || base.Host == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil || u.Host != "" && u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	// ResolveReference covers the three shapes a page mixes in: absolute URL,
	// protocol-relative //host/path (the page scheme carries over) and
	// ?page=2, which targets the page itself with a different parameter.
	resolved := base.ResolveReference(u)
	resolved.Fragment = ""
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	// Same-host only: a scan must not wander to a host the task never declared.
	if !strings.EqualFold(resolved.Hostname(), base.Hostname()) {
		return ""
	}
	return resolved.String()
}

func withQuery(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return u.RawQuery
}

func stripQuery(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func mergeQuery(rawURL, query string) string {
	if query == "" {
		return rawURL
	}
	trimmed := strings.TrimRight(rawURL, "?&")
	if strings.Contains(trimmed, "?") {
		return trimmed + "&" + query
	}
	return trimmed + "?" + query
}

func indexFold(haystack, needle string) int {
	return strings.Index(strings.ToLower(haystack), strings.ToLower(needle))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func looksLikeHTMLPage(body string) bool {
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	head = strings.ToLower(head)
	return strings.Contains(head, "<html") || strings.Contains(head, "<form") ||
		strings.Contains(head, "<input") || strings.Contains(head, "<a ") || strings.Contains(head, "href=")
}

func harvestDedupe(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func newHarvestClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Transport: tr,
		Jar:       jar,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func fetchHarvestPage(ctx context.Context, client *http.Client, rawURL string, limit int64) (string, int, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "", 0, context.DeadlineExceeded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", probeUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return string(body), resp.StatusCode, err
}

// clientCookie renders the session the shared client holds for one URL, so a
// point behind a session-scoped endpoint stays reachable for the tools.
func clientCookie(client *http.Client, rawURL string) string {
	if client == nil || client.Jar == nil {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}
	pairs := []string{}
	for _, c := range client.Jar.Cookies(u) {
		if c.Value == "" || strings.ContainsAny(c.Value, "\n\r") {
			continue
		}
		pairs = append(pairs, c.Name+"="+c.Value)
		if len(pairs) >= 8 {
			break
		}
	}
	return strings.Join(pairs, "; ")
}
