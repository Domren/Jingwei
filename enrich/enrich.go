// Package enrich is the engine-side (non-AI) asset auto-completion layer described
// in docs/资产模型与自动关联设计.md §5: an async worker pool that resolves domains
// (dnsx) and probes web assets (HTTP, through the recording proxy) and writes the
// results back into the asset graph — creating IP/port nodes, resolves/exposes
// edges, and filling attrs.dns / attrs.http. DNS is ungated; HTTP probing is gated
// by RoE (§5.2).
package enrich

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Domren/jingwei/db"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

type jobKind int

const (
	jobDNS  jobKind = iota // resolve a domain
	jobHTTP                // probe a web asset (site)
	// P8 被动线索（默认关）：域名走固定 API，不接受任意 URL。
	jobCTLog      // certificate transparency log
	jobDNSHistory // passive DNS history
)

type job struct {
	kind jobKind
	id   int64  // asset id (domain for DNS, site for HTTP)
	arg  string // host (DNS) or url (HTTP)
}

// Engine owns the resolver, the proxy-routed HTTP client, and the worker pool.
type Engine struct {
	as     *db.AssetStore
	resolv *dnsx.DNSX
	client *http.Client

	jobs   chan job
	cool   sync.Map // dedup/cooldown: "kind:id" -> time.Time (last run)
	once   sync.Once
	closed chan struct{}

	// P8：被动线索默认关。passiveOn 为 nil 或未开启时，查询直接拒绝并写审计。
	passiveOn    func() bool
	passiveAudit func(kind, target string, fields []string, allowed bool, reason string)
}

const (
	cooldown    = 5 * time.Minute
	httpTimeout = 12 * time.Second
	queueSize   = 1024
)

// P8 · 被动线索固定 API。接口固定不可填：用户只提供域名，拼进 query 时用
// url.Values.Encode 转义；任何 scheme/host/path 由用户提供都会先被校验拒绝。
// 用例可通过下面两个包内变量换成 httptest 服务；生产代码不改它们。
const (
	ctLogDefaultURL      = "https://crt.sh/"
	dnsHistoryDefaultURL = "https://api.hackertarget.com/hostsearch/"
)

var (
	ctLogBaseURL      = ctLogDefaultURL
	dnsHistoryBaseURL = dnsHistoryDefaultURL
)

// New builds the engine. proxy() returns the recording-proxy address to route HTTP
// probes through (so they land in the traffic store), evaluated per request so the
// runtime traffic-capture toggle takes effect live; "" = direct. Returns a usable
// engine even if the resolver fails to init (DNS becomes a no-op).
func New(as *db.AssetStore, proxy func() string, workers int) *Engine {
	if workers <= 0 {
		workers = 4
	}
	resolv, err := dnsx.New(dnsx.Options{
		BaseResolvers: dnsx.DefaultResolvers,
		MaxRetries:    3,
		QuestionTypes: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME},
		Timeout:       4 * time.Second,
	})
	if err != nil {
		log.Printf("[enrich] dnsx 初始化失败，DNS 解析停用：%v", err)
		resolv = nil
	}
	e := &Engine{
		as:     as,
		resolv: resolv,
		client: buildClient(proxy),
		jobs:   make(chan job, queueSize),
		closed: make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		go e.worker()
	}
	return e
}

// buildClient returns an HTTP client that dials via the recording proxy (resolved
// per-request via proxy(), so the traffic-capture toggle applies live) and skips
// TLS verification (the proxy re-signs with its MITM CA; targets are often
// self-signed — this is a pentest probe).
func buildClient(proxy func() string) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: httpTimeout,
	}
	if proxy != nil {
		tr.Proxy = func(*http.Request) (*url.URL, error) {
			p := proxy()
			if p == "" {
				return nil, nil // direct
			}
			return url.Parse(p)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   httpTimeout,
		// cap redirects; keep them within scope by re-checking at probe time
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ResolveDomain enqueues a DNS resolution for a domain asset (ungated). host is the
// FQDN. No-op for an empty engine.
func (e *Engine) ResolveDomain(id int64, host string) { e.enqueue(job{jobDNS, id, host}) }

// ProbeSite enqueues an HTTP probe for a web-asset (site). rawURL is the site URL.
func (e *Engine) ProbeSite(id int64, rawURL string) { e.enqueue(job{jobHTTP, id, rawURL}) }

// SetPassiveGate 配置 P8 被动线索开关与审计回调。on 为 nil 时永远关闭（默认）。
// 审计回调只收固定 API 的 host 与查询字段名，绝不收用户提供的任意 URL。
func (e *Engine) SetPassiveGate(on func() bool, audit func(kind, target string, fields []string, allowed bool, reason string)) {
	if e == nil {
		return
	}
	e.passiveOn = on
	e.passiveAudit = audit
}

// QueryCTLog 请求证书透明日志被动线索（默认关）。domain 必须是纯域名。
func (e *Engine) QueryCTLog(id int64, domain string) {
	if err := ValidatePassiveDomain(domain); err != nil {
		e.auditPassive("ct_log", ctLogHost(), []string{"domain"}, false, "域名校验失败："+err.Error())
		return
	}
	e.enqueue(job{jobCTLog, id, domain})
}

// QueryDNSHistory 请求被动 DNS 历史（默认关）。domain 必须是纯域名。
func (e *Engine) QueryDNSHistory(id int64, domain string) {
	if err := ValidatePassiveDomain(domain); err != nil {
		e.auditPassive("dns_history", dnsHistoryHost(), []string{"domain"}, false, "域名校验失败："+err.Error())
		return
	}
	e.enqueue(job{jobDNSHistory, id, domain})
}

func (e *Engine) auditPassive(kind, target string, fields []string, allowed bool, reason string) {
	if e != nil && e.passiveAudit != nil {
		e.passiveAudit(kind, target, fields, allowed, reason)
	}
}

// passiveAllowed 检查默认关开关；关闭时也写一条拒绝审计（便于回答「有没有试过」）。
func (e *Engine) passiveAllowed(kind, target string) bool {
	if e == nil || e.passiveOn == nil || !e.passiveOn() {
		e.auditPassive(kind, target, []string{"domain"}, false, "被动线索默认关闭")
		return false
	}
	return true
}

var rePassiveLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidatePassiveDomain 只接受纯域名：禁止 scheme、路径、查询、端口、userinfo、IP、
// localhost。这是防 SSRF 的第一道门，用户永远不能决定出网的 scheme/host/path。
func ValidatePassiveDomain(raw string) error {
	d := strings.TrimSpace(strings.ToLower(raw))
	if d == "" || len(d) > 253 {
		return errors.New("域名为空或过长")
	}
	if strings.ContainsAny(d, ":/?#@\\ \t\r\n") {
		return errors.New("域名含 scheme/路径/端口/userinfo/空白")
	}
	if net.ParseIP(d) != nil {
		return errors.New("不接受 IP 字面量")
	}
	if d == "localhost" || strings.HasSuffix(d, ".localhost") {
		return errors.New("不接受 localhost")
	}
	labels := strings.Split(strings.TrimSuffix(d, "."), ".")
	if len(labels) < 2 {
		return errors.New("域名至少需要两级标签")
	}
	for _, label := range labels {
		if !rePassiveLabel.MatchString(label) {
			return fmt.Errorf("非法域名标签 %q", label)
		}
	}
	return nil
}

func ctLogHost() string {
	u, _ := url.Parse(ctLogBaseURL)
	if u == nil {
		return ""
	}
	return u.Host
}

func dnsHistoryHost() string {
	u, _ := url.Parse(dnsHistoryBaseURL)
	if u == nil {
		return ""
	}
	return u.Host
}

// passiveRedirectGuard 复用子域名枚举口径：重定向只认同一个 host（固定 API 被
// 中间人改了不该把查询带到别处），最多 3 跳。
func passiveRedirectGuard(base *url.URL) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != base.Host {
			return fmt.Errorf("被动线索 API 把查询重定向到了其它主机 %s，已中止", req.URL.Host)
		}
		if len(via) >= 3 {
			return errors.New("被动线索 API 重定向次数过多，已中止")
		}
		return nil
	}
}

func (e *Engine) enqueue(j job) {
	if e == nil || id0(j.id) || j.arg == "" {
		return
	}
	select {
	case e.jobs <- j:
	default: // queue full → drop (best-effort enrichment)
		log.Printf("[enrich] 队列已满，丢弃任务 kind=%d id=%d", j.kind, j.id)
	}
}

func id0(id int64) bool { return id <= 0 }

// Close stops the workers (idempotent).
func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.once.Do(func() { close(e.closed) })
}

func (e *Engine) worker() {
	for {
		select {
		case <-e.closed:
			return
		case j := <-e.jobs:
			if e.onCooldown(j) {
				continue
			}
			switch j.kind {
			case jobDNS:
				e.doDNS(j.id, j.arg)
			case jobHTTP:
				e.doHTTP(j.id, j.arg)
			case jobCTLog:
				e.doPassive(j.id, j.arg, "ct_log", ctLogBaseURL)
			case jobDNSHistory:
				e.doPassive(j.id, j.arg, "dns_history", dnsHistoryBaseURL)
			}
		}
	}
}

// onCooldown returns true (skip) if this (kind,id) ran within the cooldown window.
func (e *Engine) onCooldown(j job) bool {
	key := string(rune(j.kind)) + ":" + itoa(j.id)
	if v, ok := e.cool.Load(key); ok {
		if t, ok := v.(time.Time); ok && time.Since(t) < cooldown {
			return true
		}
	}
	e.cool.Store(key, time.Now())
	return false
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ---- DNS ----

func (e *Engine) doDNS(id int64, host string) {
	if e.resolv == nil {
		return
	}
	data, err := e.resolv.QueryMultiple(host)
	if err != nil || data == nil {
		return
	}
	ips := uniq(append(append([]string{}, data.A...), data.AAAA...))
	// Upsert resolved IPs into the asset store.
	for _, ip := range ips {
		_, _ = e.as.UpsertIP(db.UpsertIPReq{
			IP:           ip,
			BoundDomains: []string{host},
		})
	}
	// Record A records as subdomains if host looks like a subdomain.
	for _, a := range data.A {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "A",
			RecordValue: []string{a},
		})
	}
	for _, aaaa := range data.AAAA {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "AAAA",
			RecordValue: []string{aaaa},
		})
	}
	for _, cname := range data.CNAME {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "CNAME",
			RecordValue: []string{cname},
		})
	}
}

// ---- HTTP probe ----

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (e *Engine) doHTTP(id int64, rawURL string) {
	host := hostOf(rawURL)
	if host == "" {
		return
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "jingwei-enrich/1.0")
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap 1 MiB
	statusCode := resp.StatusCode
	bodyLen := int64(len(body))
	title := extractTitle(body)
	_, _ = e.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL:           rawURL,
		StatusCode:    &statusCode,
		ContentLength: &bodyLen,
		PageTitle:     title,
	})
}

func extractTitle(body []byte) string {
	m := reTitle.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ---- P8 被动线索 ----

// doPassive 从固定 API 查询被动线索。base 是包内固定常量（用例可替换），
// domain 只作为 query 值参与，绝不拼进 host/path；跨主机重定向直接拒绝。
func (e *Engine) doPassive(id int64, domain, kind, base string) {
	host := hostOfBase(base)
	if !e.passiveAllowed(kind, host) {
		return
	}
	if err := ValidatePassiveDomain(domain); err != nil {
		e.auditPassive(kind, host, []string{"domain"}, false, "域名校验失败："+err.Error())
		return
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		e.auditPassive(kind, host, []string{"domain"}, false, "固定 API 配置无效")
		return
	}
	q := url.Values{}
	q.Set("q", domain)
	if kind == "ct_log" {
		q.Set("output", "json")
	}
	u.RawQuery = q.Encode() // 转义：用户提供的域名不能改写 query 结构

	client := *e.client
	client.CheckRedirect = passiveRedirectGuard(u)
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		e.auditPassive(kind, u.Host, []string{"domain"}, false, err.Error())
		return
	}
	req.Header.Set("User-Agent", "jingwei-enrich-passive/1.0")
	resp, err := client.Do(req)
	if err != nil {
		e.auditPassive(kind, u.Host, []string{"domain"}, false, err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		e.auditPassive(kind, u.Host, []string{"domain"}, false,
			fmt.Sprintf("API 返回 %d（跨主机重定向已拒绝）", resp.StatusCode))
		return
	}
	// 从被动线索里抽出可能的子域名并登记；不做主动探测（§6 不做测绘）。
	if e.as != nil {
		for _, name := range uniq(passiveNames(body, domain)) {
			_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
				Domain: domain, RecordType: "PASSIVE", RecordValue: []string{name},
			})
		}
	}
	e.auditPassive(kind, u.Host, []string{"domain"}, true, "")
}

func hostOfBase(base string) string {
	u, err := url.Parse(base)
	if err != nil || u == nil {
		return ""
	}
	return u.Host
}

// passiveNames 从 JSON/文本响应里抽取包含目标域的名字（去重、限长）。
func passiveNames(body []byte, domain string) []string {
	re := regexp.MustCompile(`(?i)[a-z0-9][a-z0-9.-]*\.` + regexp.QuoteMeta(strings.ToLower(domain)))
	seen := map[string]bool{}
	out := []string{}
	for _, m := range re.FindAllString(string(body), 200) {
		m = strings.ToLower(strings.Trim(m, "."))
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}
