package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// PortFinding is one open TCP port with optional passive fingerprint data.
type PortFinding struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	// BannerRaw carries the unmodified bytes read from the port; it is never
	// persisted as JSON, only used to build the report's raw protocol packet.
	BannerRaw []byte `json:"-"`
	TLS       bool   `json:"tls,omitempty"`
	CertCN    string `json:"cert_cn,omitempty"`
}

// WebService is one reachable HTTP(S) service discovered during the scan.
type WebService struct {
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	IP            string   `json:"ip"`
	Port          int      `json:"port"`
	Scheme        string   `json:"scheme"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title,omitempty"`
	Server        string   `json:"server,omitempty"`
	Technologies  []string `json:"technologies"`
	ContentLength int64    `json:"content_length"`
}

// DiscoverOptions controls the port/probe phase.
type DiscoverOptions struct {
	Ports       string
	Concurrency int
	Timeout     time.Duration
	// MaxProbes caps HTTP probe candidates (default 3000) so a CIDR with many
	// vhosts and web ports cannot explode the probe phase.
	MaxProbes int
	// MaxPortChecks caps the IP x port cross product (default 200000) so one
	// task cannot launch millions of TCP connects.
	MaxPortChecks int
	// Logf receives human-readable progress messages.
	Logf func(format string, args ...any)
}

// DiscoverResult is the output of asset discovery.
type DiscoverResult struct {
	Resolved *Resolved     `json:"resolved"`
	Ports    []PortFinding `json:"ports"`
	Services []WebService  `json:"services"`
	PortList []int         `json:"-"`
}

// Discover resolves targets, scans TCP ports and probes HTTP services.
func Discover(ctx context.Context, targets []Target, opts DiscoverOptions) (*DiscoverResult, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ports, err := ParsePortSpec(opts.Ports)
	if err != nil {
		return nil, err
	}
	resolved, err := Resolve(ctx, targets, 256)
	if err != nil {
		return nil, err
	}
	logf("解析目标：%d 个 IP、%d 个域名、%d 个固定 URL", len(resolved.IPs), len(resolved.Domains), len(resolved.FixedURLs))

	maxChecks := opts.MaxPortChecks
	if maxChecks <= 0 {
		maxChecks = 200000
	}
	if len(resolved.IPs)*len(ports) > maxChecks {
		return nil, fmt.Errorf("端口扫描量过大：%d 个 IP × %d 个端口 = %d 次探测，上限 %d；请缩小目标范围或减少端口",
			len(resolved.IPs), len(ports), len(resolved.IPs)*len(ports), maxChecks)
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 200
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 900 * time.Millisecond
	}
	open, err := ScanPorts(ctx, resolved.IPs, ports, concurrency, timeout, func(done, total int) {
		if done == total || done%500 == 0 {
			logf("端口扫描进度 %d/%d", done, total)
		}
	})
	if err != nil {
		return nil, err
	}
	logf("端口扫描完成：开放 %d 个端口", len(open))

	prober := NewProber(10 * time.Second)
	services := probeAll(ctx, resolved, open, prober, opts.MaxProbes, logf)
	logf("HTTP 探测完成：发现 %d 个 Web 服务", len(services))
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Classify the remaining non-HTTP ports passively (banner + TLS), then give
	// HTTP/TLS-ish ports a second HTTP probe. This finds web apps on odd ports
	// without blindly sending GET requests to every open service.
	fingerprints := FingerprintPorts(ctx, open, CoveredServicePorts(services, resolved.DomainsByIP), logf)
	applyFingerprints(open, fingerprints)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	extra := probeExtraPorts(ctx, resolved, open, fingerprints, services, opts.MaxProbes, logf)
	if len(extra) > 0 {
		services = append(services, extra...)
		sort.Slice(services, func(i, j int) bool { return services[i].URL < services[j].URL })
		logf("补充 HTTP 探测：在非 Web 端口新增 %d 个 Web 服务", len(extra))
	}
	return &DiscoverResult{Resolved: resolved, Ports: open, Services: services, PortList: ports}, nil
}

// applyFingerprints copies passive fingerprint data back onto the open-port list
// so persisted IP assets carry service names, banners and TLS certificates.
func applyFingerprints(open []PortFinding, fps map[string]ServiceFingerprint) {
	for i := range open {
		fp, ok := fps[fingerprintKey(open[i].IP, open[i].Port)]
		if !ok {
			continue
		}
		if fp.Service != "" {
			open[i].Service = fp.Service
		}
		open[i].Banner = fp.Banner
		open[i].BannerRaw = fp.BannerRaw
		open[i].TLS = fp.TLS
		open[i].CertCN = fp.CertCN
	}
}

// probeExtraPorts HTTP-probes non-web ports whose fingerprint allows it. Domain
// (vhost) URLs are tried before the bare IP, mirroring probeAll.
func probeExtraPorts(ctx context.Context, res *Resolved, open []PortFinding, fps map[string]ServiceFingerprint,
	services []WebService, maxProbes int, logf func(string, ...any)) []WebService {
	covered := CoveredServicePorts(services, res.DomainsByIP)
	type candidate struct {
		ip   string
		port int
		urls []string
	}
	candidates := []candidate{}
	for _, pf := range open {
		if covered[fingerprintKey(pf.IP, pf.Port)] {
			continue
		}
		fp, ok := fps[fingerprintKey(pf.IP, pf.Port)]
		if !ok || definitelyNotHTTP(fp.Service) {
			continue
		}
		schemes := schemeOrder(pf.Port)
		if fp.TLS {
			schemes = []string{"https", "http"}
		}
		hosts := res.DomainsByIP[pf.IP]
		if len(hosts) == 0 {
			hosts = []string{pf.IP}
		}
		urls := make([]string, 0, len(hosts)*len(schemes))
		for _, scheme := range schemes {
			for _, host := range hosts {
				urls = append(urls, buildURL(scheme, host, pf.Port))
			}
			if hosts[0] != pf.IP {
				urls = append(urls, buildURL(scheme, pf.IP, pf.Port))
			}
		}
		candidates = append(candidates, candidate{ip: pf.IP, port: pf.Port, urls: urls})
	}
	if len(candidates) == 0 {
		return nil
	}
	if maxProbes > 0 && len(candidates) > maxProbes {
		logf("非 Web 端口 HTTP 探测候选 %d 个，超过上限 %d，已截断", len(candidates), maxProbes)
		candidates = candidates[:maxProbes]
	}
	prober := NewProber(4 * time.Second)
	type result struct {
		svc *WebService
	}
	results := make(chan result, len(candidates))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, c := range candidates {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			for _, u := range c.urls {
				svc, err := prober.Probe(ctx, u, c.ip)
				if err == nil && svc != nil {
					results <- result{svc: svc}
					return
				}
				if ctx.Err() != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	close(results)
	out := []WebService{}
	for r := range results {
		if r.svc != nil {
			out = append(out, *r.svc)
		}
	}
	return out
}

// definitelyNotHTTP lists banner-identified protocols that never speak HTTP on
// the same port, so the extra probe pass does not bother them.
func definitelyNotHTTP(service string) bool {
	switch service {
	case "ssh", "ssh-alt", "ftp", "smtp", "smtps", "pop3", "pop3s", "imap", "imaps",
		"rdp", "vnc", "vnc-alt", "mysql", "postgresql", "mssql", "oracle",
		"redis", "mongodb", "mongodb-alt", "memcached", "amqp", "mqtt", "telnet",
		"smb", "dns", "etcd", "etcd-peer", "zookeeper", "kafka", "cassandra",
		"cassandra-thrift", "nfs", "iscsi", "ldap", "ldaps", "winrm", "winrm-tls",
		"rpcbind", "netbios", "adb", "pptp", "svn", "rsync", "socks", "kerberos",
		"rmi", "epmd", "activemq-openwire", "hdfs", "kubelet", "zabbix":
		return true
	}
	return false
}

// ScanPorts performs a TCP connect scan over the cross product of ips and ports.
func ScanPorts(ctx context.Context, ips []string, ports []int, concurrency int, timeout time.Duration, progress func(done, total int)) ([]PortFinding, error) {
	if concurrency <= 0 {
		concurrency = 200
	}
	if concurrency > 500 {
		concurrency = 500
	}
	if timeout <= 0 {
		timeout = 900 * time.Millisecond
	}
	total := len(ips) * len(ports)
	if total == 0 {
		return []PortFinding{}, nil
	}
	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job)
	var mu sync.Mutex
	var wg sync.WaitGroup
	open := []PortFinding{}
	done := 0
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := net.Dialer{Timeout: timeout}
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(j.ip, fmt.Sprintf("%d", j.port)))
				if err == nil {
					_ = conn.Close()
					mu.Lock()
					open = append(open, PortFinding{IP: j.ip, Port: j.port, Service: PortLabel(j.port)})
					mu.Unlock()
				}
				mu.Lock()
				done++
				n := done
				mu.Unlock()
				if progress != nil && (n == total || n%200 == 0) {
					progress(n, total)
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range ips {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{ip: ip, port: port}:
				}
			}
		}
	}()
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(open, func(i, j int) bool {
		if open[i].IP != open[j].IP {
			return open[i].IP < open[j].IP
		}
		return open[i].Port < open[j].Port
	})
	return open, nil
}

// Prober is a reusable HTTP client for web fingerprinting.
type Prober struct {
	client       *http.Client
	cacheMu      sync.Mutex
	faviconCache map[string]faviconCacheEntry
}

type faviconCacheEntry struct {
	mmh3 int32
	md5  string
	ok   bool
}

const (
	probeUserAgent                  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
	faviconFetchTechThreshold       = 5
	faviconFetchTimeout             = 3 * time.Second
	faviconMaxBytes           int64 = 1 << 20
)

// NewProber builds a prober that follows same-host redirects and ignores TLS
// certificate errors (targets are frequently self-signed).
func NewProber(timeout time.Duration) *Prober {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	return &Prober{
		client: &http.Client{
			Transport: tr,
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
		},
		faviconCache: map[string]faviconCacheEntry{},
	}
}

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Probe fetches one URL and extracts status, title, server and technologies.
func (p *Prober) Probe(ctx context.Context, rawURL, ip string) (*WebService, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", probeUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	u, _ := url.Parse(rawURL)
	port := 80
	scheme := "http"
	if u != nil {
		scheme = u.Scheme
		if u.Port() != "" {
			fmt.Sscanf(u.Port(), "%d", &port)
		} else if scheme == "https" {
			port = 443
		}
	}
	bodyStr := string(body)
	title := ""
	if m := reTitle.FindStringSubmatch(bodyStr); len(m) == 2 {
		title = strings.TrimSpace(decodeEntities(m[1]))
	}
	if title == "" {
		if t := resp.Header.Get("X-Page-Title"); t != "" {
			title = t
		}
	}
	hits := detectPageHits(resp.Header, bodyStr, rawURL)
	if len(finalizeTechHits(hits)) < faviconFetchTechThreshold {
		if mmh3, md5Hex, ok := p.fetchFaviconHashes(ctx, rawURL); ok {
			hits = append(hits, detectFaviconHits(mmh3, md5Hex)...)
		}
	}
	svc := &WebService{
		URL:           rawURL,
		Host:          req.URL.Host,
		IP:            ip,
		Port:          port,
		Scheme:        scheme,
		StatusCode:    resp.StatusCode,
		Title:         title,
		Server:        resp.Header.Get("Server"),
		Technologies:  finalizeTechHits(hits),
		ContentLength: int64(len(body)),
	}
	if resp.ContentLength >= 0 {
		svc.ContentLength = resp.ContentLength
	}
	return svc, nil
}

func (p *Prober) fetchFaviconHashes(ctx context.Context, rawURL string) (int32, string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return 0, "", false
	}
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	p.cacheMu.Lock()
	if entry, ok := p.faviconCache[origin]; ok {
		p.cacheMu.Unlock()
		return entry.mmh3, entry.md5, entry.ok
	}
	p.cacheMu.Unlock()

	entry := p.downloadFaviconHashes(ctx, origin)
	p.cacheMu.Lock()
	p.faviconCache[origin] = entry
	p.cacheMu.Unlock()
	return entry.mmh3, entry.md5, entry.ok
}

func (p *Prober) downloadFaviconHashes(ctx context.Context, origin string) faviconCacheEntry {
	reqCtx, cancel := context.WithTimeout(ctx, faviconFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, origin+"/favicon.ico", nil)
	if err != nil {
		return faviconCacheEntry{}
	}
	req.Header.Set("User-Agent", probeUserAgent)
	resp, err := p.client.Do(req)
	if err != nil {
		return faviconCacheEntry{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return faviconCacheEntry{}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, faviconMaxBytes))
	if err != nil || len(data) == 0 {
		return faviconCacheEntry{}
	}
	mmh3, md5Hex := faviconHashes(data)
	return faviconCacheEntry{mmh3: mmh3, md5: md5Hex, ok: true}
}

func decodeEntities(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'", "&nbsp;", " ")
	return r.Replace(s)
}

type probeCandidate struct {
	url string
	ip  string
}

func probeAll(ctx context.Context, res *Resolved, open []PortFinding, p *Prober, maxProbes int, logf func(string, ...any)) []WebService {
	if maxProbes <= 0 {
		maxProbes = 3000
	}
	// Fixed URLs (explicit http/https targets) always get probed.
	candidates := []probeCandidate{}
	seen := map[string]bool{}
	for _, u := range res.FixedURLs {
		ip := ""
		if parsed, err := url.Parse(u); err == nil {
			if parsedIP := net.ParseIP(parsed.Hostname()); parsedIP != nil {
				ip = parsedIP.String()
			}
		}
		if !seen[u] {
			seen[u] = true
			candidates = append(candidates, probeCandidate{url: u, ip: ip})
		}
	}

	openSet := map[string]map[int]bool{}
	for _, pf := range open {
		if openSet[pf.IP] == nil {
			openSet[pf.IP] = map[int]bool{}
		}
		openSet[pf.IP][pf.Port] = true
	}

	// Domain candidates first (virtual host), IP fallback only when no domain
	// probe on that IP:port succeeds.
	domainTried := map[string]bool{}
	for _, ip := range res.IPs {
		domains := res.DomainsByIP[ip]
		for port := range openSet[ip] {
			if !IsWebPort(port) {
				continue
			}
			for _, scheme := range schemeOrder(port) {
				if len(domains) == 0 {
					u := buildURL(scheme, ip, port)
					key := u + "|" + ip
					if !seen[key] {
						seen[key] = true
						candidates = append(candidates, probeCandidate{url: u, ip: ip})
					}
					continue
				}
				for _, domain := range domains {
					u := buildURL(scheme, domain, port)
					key := u + "|" + ip
					if !seen[key] {
						seen[key] = true
						candidates = append(candidates, probeCandidate{url: u, ip: ip})
						domainTried[fmt.Sprintf("%s|%d", ip, port)] = true
					}
				}
			}
		}
	}

	if len(candidates) > maxProbes {
		logf("HTTP 探测候选 %d 个，超过上限 %d，已截断；请缩小目标或端口范围", len(candidates), maxProbes)
		candidates = candidates[:maxProbes]
	}

	type result struct {
		svc *WebService
		key string
	}
	results := make(chan result, len(candidates))
	sem := make(chan struct{}, 24)
	var wg sync.WaitGroup
	for _, c := range candidates {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			svc, err := p.Probe(ctx, c.url, c.ip)
			if err != nil {
				return
			}
			results <- result{svc: svc, key: c.url}
		}()
	}
	wg.Wait()
	close(results)

	byURL := map[string]WebService{}
	for r := range results {
		if r.svc == nil {
			continue
		}
		if prev, ok := byURL[r.key]; !ok || len(r.svc.Technologies) > len(prev.Technologies) {
			byURL[r.key] = *r.svc
		}
	}

	// IP fallback for web ports where domain probing produced nothing.
	fallbackBudget := maxProbes
	for _, ip := range res.IPs {
		if fallbackBudget <= 0 {
			break
		}
		if len(res.DomainsByIP[ip]) == 0 {
			continue
		}
		for port := range openSet[ip] {
			if fallbackBudget <= 0 {
				break
			}
			if !IsWebPort(port) {
				continue
			}
			key := fmt.Sprintf("%s|%d", ip, port)
			if !domainTried[key] {
				continue
			}
			portOK := false
			for u := range byURL {
				if parsed, err := url.Parse(u); err == nil && parsed.Hostname() != "" && parsed.Port() == fmt.Sprintf("%d", port) {
					if containsFold(res.DomainsByIP[ip], parsed.Hostname()) {
						portOK = true
						break
					}
				}
			}
			if portOK {
				continue
			}
			for _, scheme := range schemeOrder(port) {
				u := buildURL(scheme, ip, port)
				if seen[u+"|"+ip] {
					continue
				}
				fallbackBudget--
				svc, err := p.Probe(ctx, u, ip)
				if err == nil && svc != nil {
					seen[u+"|"+ip] = true
					byURL[u] = *svc
					break
				}
				if fallbackBudget <= 0 {
					break
				}
			}
		}
	}

	out := make([]WebService, 0, len(byURL))
	for _, svc := range byURL {
		out = append(out, svc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func schemeOrder(port int) []string {
	switch port {
	case 443, 4443, 8443, 9043, 9443:
		return []string{"https", "http"}
	default:
		return []string{"http", "https"}
	}
}

func buildURL(scheme, host string, port int) string {
	defaultPort := (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
	if defaultPort {
		return scheme + "://" + host + "/"
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, host, port)
}
