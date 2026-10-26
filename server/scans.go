package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/artex/scanner"
)

const (
	maxScanTargets       = 100
	maxScanPOCs          = 2000
	maxAutoTemplates     = 500
	maxFullTemplates     = 10000
	maxScanNucleiTargets = 3000
	maxScanPortChecks    = 200000

	// 原始报文可能非常大；保留足够复现的头部与正文，避免单条命中撑爆 findings。
	maxStoredHTTPRequest  = 64 << 10
	maxStoredHTTPResponse = 128 << 10
)

// scanManager serializes LLM-free scan tasks inside the server process. Tasks
// are persisted in PostgreSQL, so queued work survives a restart and a single
// executor keeps network load predictable.
type scanManager struct {
	s    *Server
	wake chan struct{}

	mu     sync.Mutex
	cancel map[int64]context.CancelFunc
}

func newScanManager(s *Server) *scanManager {
	return &scanManager{s: s, wake: make(chan struct{}, 1), cancel: map[int64]context.CancelFunc{}}
}

func (m *scanManager) start(ctx context.Context) {
	if m == nil || m.s.m.pg == nil {
		return
	}
	if n, err := m.s.m.pg.RecoverInterruptedScanTasks(); err != nil {
		log.Printf("[scan] recover interrupted tasks: %v", err)
	} else if n > 0 {
		log.Printf("[scan] 启动时将 %d 个中断的扫描任务标记为失败", n)
	}
	go m.loop(ctx)
}

func (m *scanManager) wakeup() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *scanManager) loop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		for {
			task, err := m.s.m.pg.ClaimNextScanTask()
			if err != nil {
				log.Printf("[scan] claim queued task: %v", err)
				break
			}
			if task == nil {
				break
			}
			m.run(ctx, task)
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-ticker.C:
		}
	}
}

func (m *scanManager) run(parent context.Context, task *db.ScanTask) {
	timeout := time.Duration(task.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	m.mu.Lock()
	m.cancel[task.ID] = cancel
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.cancel, task.ID)
		m.mu.Unlock()
	}()

	run := &scanRun{s: m.s, pg: m.s.m.pg, task: task, ctx: ctx, progress: map[string]any{}}
	status, stage, errMsg, summary := run.execute()
	if summary == nil {
		summary = map[string]any{}
	}
	if err := m.s.m.pg.FinishScanTask(task.ID, status, stage, errMsg, summary); err != nil {
		log.Printf("[scan %d] finish: %v", task.ID, err)
	}
	log.Printf("[scan %d] %s (%s)", task.ID, status, stage)
}

func (m *scanManager) cancelTask(id int64) {
	m.mu.Lock()
	cancel := m.cancel[id]
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

type scanRun struct {
	s    *Server
	pg   *db.DB
	task *db.ScanTask
	ctx  context.Context

	mu       sync.Mutex
	progress map[string]any
}

func (r *scanRun) logf(stage, format string, args ...any) {
	line := fmt.Sprintf("[%s] %s", stage, fmt.Sprintf(format, args...))
	log.Printf("[scan %d] %s", r.task.ID, line)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.pg.UpdateScanProgress(r.task.ID, stage, r.progress, line); err != nil {
		log.Printf("[scan %d] update progress: %v", r.task.ID, err)
	}
}

func (r *scanRun) setProgress(stage string, values map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range values {
		r.progress[k] = v
	}
	if err := r.pg.UpdateScanProgress(r.task.ID, stage, r.progress, ""); err != nil {
		log.Printf("[scan %d] update progress: %v", r.task.ID, err)
	}
}

func (r *scanRun) execute() (status, stage, errMsg string, summary map[string]any) {
	summary = map[string]any{"mode": r.task.Mode}
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[scan %d] panic: %v\n%s", r.task.ID, rec, debug.Stack())
			status, stage, errMsg = "failed", "failed", fmt.Sprintf("扫描内部错误: %v", rec)
			summary = map[string]any{"mode": r.task.Mode}
		}
	}()

	targets, err := scanner.ParseTargets(r.task.Targets)
	if err != nil {
		return "failed", "failed", err.Error(), summary
	}
	rules, err := r.pg.ListAssetInterceptRules()
	if err != nil {
		return "failed", "failed", "加载资产拦截规则失败: " + err.Error(), summary
	}
	if reason, blocked := scanTargetBlockReason(rules, targets); blocked {
		return "failed", "failed", "目标命中资产拦截规则，已拒绝扫描：" + reason, summary
	}

	r.logf("discover", "开始资产发现：%d 个目标，端口策略 %s", len(targets), r.task.Ports)
	res, err := scanner.Discover(r.ctx, targets, scanner.DiscoverOptions{
		Ports:         r.task.Ports,
		Concurrency:   200,
		Timeout:       900 * time.Millisecond,
		MaxProbes:     3000,
		MaxPortChecks: maxScanPortChecks,
		Logf:          func(format string, args ...any) { r.logf("discover", format, args...) },
	})
	if err != nil {
		return r.aborted("资产发现失败: "+err.Error(), summary)
	}
	if r.ctx.Err() != nil {
		return r.aborted("扫描已中断", summary)
	}
	summary["resolved_ips"] = len(res.Resolved.IPs)
	summary["open_ports"] = len(res.Ports)
	summary["services"] = len(res.Services)
	r.setProgress("discover", map[string]any{
		"resolved_ips": len(res.Resolved.IPs),
		"open_ports":   len(res.Ports),
		"services":     len(res.Services),
	})

	assets, assetCount, exposureFindings := r.persistDiscovery(res)
	summary["assets"] = assetCount
	summary["exposure_findings"] = exposureFindings

	r.logf("match", "结合 %d 个 Web 服务的指纹匹配 POC", len(res.Services))
	templates, err := r.selectTemplates(res.Services)
	if err != nil {
		return "failed", "failed", err.Error(), summary
	}
	summary["templates"] = len(templates)
	if len(templates) == 0 {
		if r.task.Mode == "auto" {
			r.logf("match", "未匹配到可用的 POC 模板，扫描结束")
			summary["targets"] = 0
			summary["results"] = 0
			summary["findings"] = exposureFindings
			return "done", "done", "", summary
		}
		return "failed", "failed", "没有可执行的 POC 模板", summary
	}

	scanTargets := r.nucleiTargets(res, targets)
	summary["targets"] = len(scanTargets)
	if len(scanTargets) == 0 {
		r.logf("scan", "未发现可扫描的 Web 服务或端口，扫描结束")
		summary["results"] = 0
		summary["findings"] = exposureFindings
		return "done", "done", "", summary
	}

	r.logf("scan", "开始 nuclei 扫描：%d 个 POC × %d 个目标（并发 %d，限速 %d/s）",
		len(templates), len(scanTargets), r.task.Concurrency, r.task.RateLimit)
	r.setProgress("scan", map[string]any{"templates": len(templates), "targets": len(scanTargets)})
	nrun := scanner.RunNuclei(r.ctx, templates, scanTargets, scanner.NucleiOptions{
		RateLimit:   r.task.RateLimit,
		Concurrency: r.task.Concurrency,
	})
	summary["nuclei_elapsed_ms"] = nrun.Elapsed.Milliseconds()
	if nrun.Chains > 0 {
		r.logf("scan", "链式模板 %d 条降为并发 %d 执行（多步 POC 会改写会话/上传目录，全并发会互相覆盖结果），单发模板 %d 条按并发 %d 执行",
			nrun.Chains, scanner.StatefulChainConcurrency, nrun.Singles, r.task.Concurrency)
	}
	if nrun.RawTargets > 0 {
		r.logf("scan", "非 Web 端口目标 %d 个仅用 network/javascript/ssl 类 POC 直接探测（%d 条模板），HTTP POC 不再包装原始端口",
			nrun.RawTargets, nrun.RawTemplates)
	}

	stored, findings, findingIDs := r.persistResults(nrun.Results, assets)
	summary["results"] = stored
	summary["findings"] = findings + exposureFindings
	r.setProgress("scan", map[string]any{"results": stored, "findings": findings + exposureFindings})

	if nrun.TimedOut {
		r.logf("scan", "nuclei 执行超时（%ds），保留已产出的结果", r.task.TimeoutSeconds)
		return "failed", "failed", fmt.Sprintf("扫描超时（%ds），已保留 %d 条结果", r.task.TimeoutSeconds, stored), summary
	}
	if r.ctx.Err() != nil {
		return r.aborted("扫描已中断", summary)
	}
	if nrun.Err != nil {
		msg := nucleiErrorMessage(nrun)
		r.logf("scan", "nuclei 执行出错：%s", msg)
		if stored == 0 {
			return "failed", "failed", msg, summary
		}
		r.autoExploit(nrun.Results, findingIDs, summary)
		return "done", "done", msg, summary
	}
	r.logf("scan", "扫描完成：%d 条结果，%d 条写入发现", stored, findings)
	r.autoExploit(nrun.Results, findingIDs, summary)
	return "done", "done", "", summary
}

func (r *scanRun) aborted(errMsg string, summary map[string]any) (string, string, string, map[string]any) {
	if st, err := r.pg.GetScanTask(r.task.ID); err == nil && st.Status == "canceled" {
		return "canceled", "canceled", "已手动停止", summary
	}
	if errors.Is(r.ctx.Err(), context.DeadlineExceeded) {
		return "failed", "failed", fmt.Sprintf("扫描超时（%ds）", r.task.TimeoutSeconds), summary
	}
	return "failed", "failed", errMsg, summary
}

func nucleiErrorMessage(run scanner.NucleiRun) string {
	if run.Err == nil {
		return ""
	}
	detail := strings.TrimSpace(run.Stderr)
	if i := strings.LastIndex(detail, "\n"); i >= 0 {
		detail = detail[i+1:]
	}
	if len(detail) > 300 {
		detail = detail[:300]
	}
	if detail != "" {
		return "nuclei 执行失败: " + detail
	}
	return "nuclei 执行失败: " + run.Err.Error()
}

// scanTargetBlockReason enforces the global asset blocklist before any packet is
// sent. CIDR blocks are expanded (<=256 addresses) and checked per address.
func scanTargetBlockReason(rules []db.AssetInterceptRule, targets []scanner.Target) (string, bool) {
	for _, t := range targets {
		if t.Kind == scanner.KindCIDR {
			ips, err := cidrIPs(t.Host)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				if rule, value, ok := db.MatchAssetInterceptRules(rules, nil, []string{ip}, nil); ok {
					return fmt.Sprintf("%s（网段内 %s，%s）", t.Raw, value, rule.Reason()), true
				}
			}
			continue
		}
		domains, ips, urls := t.InterceptCandidates()
		if rule, value, ok := db.MatchAssetInterceptRules(rules, domains, ips, urls); ok {
			return fmt.Sprintf("%s（%s）", value, rule.Reason()), true
		}
	}
	return "", false
}

func cidrIPs(raw string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(raw)
	if err != nil {
		return nil, err
	}
	base := ip.Mask(ipnet.Mask).To4()
	if base == nil {
		return nil, fmt.Errorf("仅支持 IPv4 CIDR")
	}
	out := []string{}
	for cur := append(net.IP(nil), base...); ipnet.Contains(cur); incIP(cur) {
		out = append(out, cur.String())
		if len(out) > 256 {
			break
		}
	}
	return out, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

type scanAssetIndex struct {
	byURL      map[string]int64
	byHost     map[string]int64
	byIP       map[string]int64
	byHostPort map[string]int64
}

func newScanAssetIndex() *scanAssetIndex {
	return &scanAssetIndex{
		byURL:      map[string]int64{},
		byHost:     map[string]int64{},
		byIP:       map[string]int64{},
		byHostPort: map[string]int64{},
	}
}

func hostPortKey(host string, port int) string {
	return strings.ToLower(host) + "|" + strconv.Itoa(port)
}

func (idx *scanAssetIndex) addService(rawURL string, id int64) {
	idx.byURL[normalizeScanURL(rawURL)] = id
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	if h := strings.ToLower(u.Host); h != "" {
		idx.byHost[h] = id
	}
	port := 0
	if u.Port() != "" {
		port, _ = strconv.Atoi(u.Port())
	} else if u.Scheme == "https" {
		port = 443
	} else if u.Scheme == "http" {
		port = 80
	}
	if h := strings.ToLower(u.Hostname()); h != "" && port > 0 {
		idx.byHost[h] = id
		idx.byHostPort[hostPortKey(h, port)] = id
	}
}

func (idx *scanAssetIndex) addOtherService(host string, port int, id int64) {
	if host != "" && port > 0 {
		idx.byHostPort[hostPortKey(host, port)] = id
	}
}

func (idx *scanAssetIndex) idsFor(matchedAt, host string) []int64 {
	seen := map[int64]bool{}
	out := []int64{}
	add := func(id int64) {
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if id := idx.byURL[normalizeScanURL(matchedAt)]; id > 0 {
		add(id)
	}
	candidates := []string{strings.ToLower(host)}
	if u, err := url.Parse(matchedAt); err == nil && u.Host != "" {
		candidates = append(candidates, strings.ToLower(u.Host), strings.ToLower(u.Hostname()))
	}
	if u, err := url.Parse(host); err == nil && u.Host != "" {
		candidates = append(candidates, strings.ToLower(u.Host), strings.ToLower(u.Hostname()))
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if id := idx.byHost[c]; id > 0 {
			add(id)
		}
		// host:port candidates link both HTTP and non-HTTP service assets.
		if hostname, port, ok := splitHostPortLoose(c); ok {
			if id := idx.byHostPort[hostPortKey(hostname, port)]; id > 0 {
				add(id)
			}
		}
		if parsed, err := url.Parse("//" + c); err == nil {
			hostname := parsed.Hostname()
			if id := idx.byHost[hostname]; id > 0 {
				add(id)
			}
			if ip := net.ParseIP(hostname); ip != nil {
				if id := idx.byIP[ip.String()]; id > 0 {
					add(id)
				}
			}
		}
	}
	return out
}

// splitHostPortLoose parses "host:port" and also tolerates a missing scheme or
// bracketed IPv6 without a port (returns ok=false in that case).
func splitHostPortLoose(raw string) (string, int, bool) {
	raw = strings.TrimPrefix(raw, "//")
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return "", 0, false
	}
	return host, port, true
}

func normalizeScanURL(raw string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), "/")
}

func (r *scanRun) persistDiscovery(res *scanner.DiscoverResult) (*scanAssetIndex, int, int) {
	idx := newScanAssetIndex()
	exposureFindings := 0
	portsByIP := map[string][]db.PortService{}
	for _, pf := range res.Ports {
		label := pf.Service
		if label == "" {
			label = "tcp"
		}
		portsByIP[pf.IP] = append(portsByIP[pf.IP], db.PortService{Port: pf.Port, Service: label})
	}
	serviceIPs := map[string]bool{}
	for _, svc := range res.Services {
		if svc.IP != "" {
			serviceIPs[svc.IP] = true
		}
	}

	linked := 0
	for _, ip := range res.Resolved.IPs {
		ports := portsByIP[ip]
		if len(ports) == 0 && !serviceIPs[ip] {
			continue
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		id, err := r.pg.Assets().UpsertIP(db.UpsertIPReq{IP: ip, OpenPorts: ports})
		if err != nil {
			r.logf("discover", "写入 IP 资产失败 %s: %v", ip, err)
			continue
		}
		idx.byIP[ip] = id
		note := "端口探测"
		if len(ports) > 0 {
			parts := make([]string, 0, len(ports))
			for _, p := range ports {
				parts = append(parts, strconv.Itoa(p.Port))
			}
			note = "开放端口: " + strings.Join(parts, ",")
		}
		if err := r.pg.AddScanTaskAsset(r.task.ID, db.ScanTaskAsset{
			AssetID: id, AssetType: "ip", Host: ip, Note: note,
		}); err != nil {
			r.logf("discover", "关联 IP 资产失败 %s: %v", ip, err)
			continue
		}
		linked++
	}

	for _, svc := range res.Services {
		status := svc.StatusCode
		length := svc.ContentLength
		id, err := r.pg.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{
			URL:           svc.URL,
			Technologies:  svc.Technologies,
			StatusCode:    &status,
			ContentLength: &length,
			PageTitle:     svc.Title,
			IP:            svc.IP,
		})
		if err != nil {
			r.logf("discover", "写入 Web 资产失败 %s: %v", svc.URL, err)
			continue
		}
		idx.addService(svc.URL, id)
		note := ""
		if svc.Server != "" {
			note = "Server: " + svc.Server
		}
		if err := r.pg.AddScanTaskAsset(r.task.ID, db.ScanTaskAsset{
			AssetID: id, AssetType: "service", Host: svc.Host, URL: svc.URL, Note: note,
			StatusCode: &status, PageTitle: svc.Title, Technologies: svc.Technologies,
		}); err != nil {
			r.logf("discover", "关联 Web 资产失败 %s: %v", svc.URL, err)
			continue
		}
		linked++
	}

	// Non-HTTP services (SSH, databases, Redis, TLS endpoints...) become their
	// own service assets so asset mapping covers the whole attack surface, not
	// just web apps. Banner/TLS data is stored in extra for hosts, scripts and
	// reports to reuse.
	httpCovered := map[string]bool{}
	for _, svc := range res.Services {
		httpCovered[hostPortKey(svc.IP, svc.Port)] = true
	}
	for _, pf := range res.Ports {
		if httpCovered[hostPortKey(pf.IP, pf.Port)] {
			continue
		}
		name := pf.Service
		if name == "" {
			name = "unknown"
		}
		extra := map[string]any{"source": "scan"}
		if pf.Banner != "" {
			extra["banner"] = pf.Banner
		}
		if pf.TLS {
			extra["tls"] = true
			if pf.CertCN != "" {
				extra["cert_cn"] = pf.CertCN
			}
		}
		id, err := r.pg.Assets().UpsertOtherService(db.UpsertOtherServiceReq{
			IP: pf.IP, Port: pf.Port, ServiceName: name, Extra: extra, TaskID: r.task.ID,
		})
		if err != nil {
			r.logf("discover", "写入服务资产失败 %s:%d: %v", pf.IP, pf.Port, err)
			continue
		}
		idx.addOtherService(pf.IP, pf.Port, id)
		note := fmt.Sprintf("%s 端口 %d", name, pf.Port)
		if pf.Banner != "" {
			note += " · " + pf.Banner
			if len(note) > 160 {
				note = note[:160]
			}
		}
		if err := r.pg.AddScanTaskAsset(r.task.ID, db.ScanTaskAsset{
			AssetID: id, AssetType: "service", Host: pf.IP, Note: note,
		}); err != nil {
			r.logf("discover", "关联服务资产失败 %s:%d: %v", pf.IP, pf.Port, err)
			continue
		}
		linked++
		if r.recordExposedService(pf, name, id) {
			exposureFindings++
		}
	}
	r.logf("discover", "资产入库完成：关联 %d 个资产，服务暴露发现 %d 条", linked, exposureFindings)
	return idx, linked, exposureFindings
}

// exposedServiceProfiles maps non-HTTP service labels to deterministic findings
// so a scan reports reachable high-risk services even when no POC template
// applies. Keyed by scanner service labels from target.go.
var exposedServiceProfiles = map[string]struct {
	name     string
	severity string
	risk     string
}{
	"mysql":         {"MySQL 数据库服务对外暴露", "medium", "数据库端口可从扫描网络直接连接，弱口令或未授权访问会导致业务数据泄露"},
	"postgresql":    {"PostgreSQL 数据库服务对外暴露", "medium", "数据库端口可从扫描网络直接连接，需确认认证与访问控制"},
	"mssql":         {"Microsoft SQL Server 服务对外暴露", "medium", "数据库端口可从扫描网络直接连接，需确认认证与访问控制"},
	"oracle":        {"Oracle 数据库服务对外暴露", "medium", "数据库监听端口可从扫描网络直接连接，需确认认证与访问控制"},
	"redis":         {"Redis 服务对外暴露", "high", "Redis 未授权访问可读取或篡改数据，并可能借助模块扩展执行命令"},
	"mongodb":       {"MongoDB 服务对外暴露", "high", "MongoDB 未授权访问可直接读写业务数据"},
	"mongodb-alt":   {"MongoDB 服务对外暴露", "high", "MongoDB 未授权访问可直接读写业务数据"},
	"memcached":     {"Memcached 服务对外暴露", "high", "Memcached 无认证，暴露后可用于缓存投毒与数据泄露"},
	"elasticsearch": {"Elasticsearch 服务对外暴露", "high", "Elasticsearch 暴露后可能被未授权读写索引数据"},
	"docker":        {"Docker Remote API 对外暴露", "critical", "Docker API 暴露等同于宿主机控制权，攻击者可创建特权容器逃逸"},
	"telnet":        {"Telnet 明文管理服务对外暴露", "high", "Telnet 以明文传输凭据，可被嗅探并用于管理端登录"},
	"ftp":           {"FTP 服务对外暴露", "low", "FTP 以明文传输凭据，且常允许匿名访问，需确认业务必要性"},
	"smb":           {"SMB 文件共享服务对外暴露", "medium", "SMB 暴露会增加横向移动与漏洞利用面，需确认访问控制"},
	"rdp":           {"RDP 远程桌面服务对外暴露", "medium", "RDP 暴露会增加暴力破解与远程漏洞利用风险"},
	"vnc":           {"VNC 服务对外暴露", "high", "VNC 常缺少认证或使用弱口令，暴露后可直接接管桌面"},
	"vnc-alt":       {"VNC 服务对外暴露", "high", "VNC 常缺少认证或使用弱口令，暴露后可直接接管桌面"},
	"etcd":          {"etcd 服务对外暴露", "high", "etcd 暴露可能导致集群配置与密钥泄露"},
	"zookeeper":     {"ZooKeeper 服务对外暴露", "medium", "ZooKeeper 未授权访问可读取集群元数据"},
	"couchdb":       {"CouchDB 服务对外暴露", "medium", "CouchDB 暴露后可被未授权读取或写入数据库"},
	"kubernetes":    {"Kubernetes API 对外暴露", "high", "Kubernetes API 暴露后需确认认证与鉴权配置"},
}

// recordExposedService persists one exposure finding plus its scan-task result
// row. It returns true when a finding was created or merged.
func (r *scanRun) recordExposedService(pf scanner.PortFinding, service string, assetID int64) bool {
	profile, ok := exposedServiceProfiles[strings.ToLower(service)]
	if !ok {
		return false
	}
	hostPort := net.JoinHostPort(pf.IP, strconv.Itoa(pf.Port))
	templateID := "exposed-service-" + strings.ToLower(service)
	// Banner 是端口探测唯一真实抓到的协议字节，渲染成 hexdump 后即可逐字节复现，
	// 所以写入发现的原始报文列，而不是让报告落到「未采集到原始报文」。
	packet := scanner.ProtocolBannerPacket(service, hostPort, pf.BannerRaw)
	evidence := strings.Builder{}
	fmt.Fprintf(&evidence, "服务暴露: %s %d/tcp\n类型: %s\n主机: %s\n", service, pf.Port, service, hostPort)
	if pf.Banner != "" {
		banner := cleanHTTPText(pf.Banner, 2048)
		fmt.Fprintf(&evidence, "Banner: %s\n", banner)
	}
	if pf.TLS {
		fmt.Fprintf(&evidence, "TLS: 是")
		if pf.CertCN != "" {
			fmt.Fprintf(&evidence, "（证书 CN: %s）", pf.CertCN)
		}
		evidence.WriteString("\n")
	}
	fmt.Fprintf(&evidence, "探测方式: TCP 端口探测 + 服务 Banner 指纹识别\n风险说明: %s\n", profile.risk)

	var findingID int64
	if r.task.CreateFindings {
		if minRank := severityRank(r.task.MinSeverity); minRank <= 0 || severityRank(profile.severity) >= minRank {
			summary := fmt.Sprintf("%s（%s），端口探测确认该服务可从扫描网络直接访问（自动化漏扫 #%d）", profile.name, hostPort, r.task.ID)
			id, created, err := r.pg.UpsertFinding(0, 0, templateID, profile.name, profile.severity, summary, evidence.String(),
				fmt.Sprintf("scan:%d", r.task.ID), []int64{assetID},
				fmt.Sprintf("exposure:%s:%s", templateID, hostPort))
			if err != nil {
				r.logf("discover", "写入服务暴露发现失败 %s: %v", hostPort, err)
			} else {
				findingID = id
				autoReport := report.BuildFindingReport(report.FindingReportInput{
					FindingID:       id,
					Name:            profile.name,
					VulnClass:       templateID,
					Severity:        profile.severity,
					Status:          db.FindingPending,
					Summary:         summary,
					Evidence:        evidence.String(),
					TaskDescription: fmt.Sprintf("#%d %s", r.task.ID, r.task.Name),
					Source:          fmt.Sprintf("自动化漏扫任务 #%d（端口探测与服务指纹）", r.task.ID),
					TemplateID:      templateID,
					Host:            hostPort,
					MatchedAt:       hostPort,
					Type:            strings.ToLower(service),
					HTTPResponse:    packet,
					GeneratedAt:     time.Now(),
				})
				if err := r.pg.SetFindingHTTPArtifactsAndAutoReport(id, "", packet, autoReport); err != nil {
					r.logf("discover", "保存服务暴露报告失败 %s: %v", hostPort, err)
				}
				if created {
					r.logf("discover", "新增服务暴露发现 #%d：%s（%s）", id, profile.name, hostPort)
				}
			}
		}
	}
	extracted := []string{}
	if pf.Banner != "" {
		extracted = append(extracted, cleanHTTPText(pf.Banner, 512))
	}
	if _, err := r.pg.AddScanTaskResult(r.task.ID, findingID, db.ScanTaskResult{
		TemplateID: templateID,
		Name:       profile.name,
		Severity:   profile.severity,
		Host:       pf.IP,
		MatchedAt:  hostPort,
		Type:       "service-exposure",
		Extracted:  extracted,
		Raw:        map[string]any{"service": service, "port": pf.Port, "banner": pf.Banner},
	}); err != nil {
		r.logf("discover", "保存服务暴露结果失败 %s: %v", hostPort, err)
	}
	return findingID > 0
}

func (r *scanRun) selectTemplates(services []scanner.WebService) ([]scanner.NucleiTemplate, error) {
	task := r.task
	minRank := severityRank(task.MinSeverity)
	if task.MinSeverity != "" && minRank < 0 {
		return nil, fmt.Errorf("无效的最低危险等级: %s", task.MinSeverity)
	}
	var pocs []db.POCTemplate
	var err error
	switch task.Mode {
	case "auto":
		if !task.Fingerprint {
			r.logf("match", "自动匹配已关闭（fingerprint=false），不加载 POC")
			return nil, nil
		}
		techSet := map[string]bool{}
		for _, svc := range services {
			for _, tech := range svc.Technologies {
				techSet[tech] = true
			}
		}
		techs := make([]string, 0, len(techSet))
		for tech := range techSet {
			techs = append(techs, tech)
		}
		sort.Strings(techs)
		r.logf("match", "识别技术指纹 %d 个：%s", len(techs), strings.Join(techs, ", "))
		if len(techs) == 0 {
			return nil, nil
		}
		metas, err := r.pg.ListEnabledPOCMetadata()
		if err != nil {
			return nil, fmt.Errorf("加载 POC 元数据失败: %w", err)
		}
		rankByID := make(map[int64]int, len(metas))
		smeta := make([]scanner.TemplateMeta, 0, len(metas))
		for _, p := range metas {
			if p.Protocol == "workflow" {
				continue
			}
			rank := severityRank(p.Severity)
			if minRank > 0 && rank < minRank {
				continue
			}
			rankByID[p.ID] = rank
			smeta = append(smeta, scanner.TemplateMeta{ID: p.ID, TemplateID: p.TemplateID, Name: p.Name, Tags: p.Tags})
		}
		ids := scanner.MatchTemplates(techs, smeta)
		prioritizeAutoTemplates(ids, rankByID)
		matched := len(ids)
		if matched > maxAutoTemplates {
			ids = ids[:maxAutoTemplates]
		}
		if matched == 0 {
			r.logf("match", "指纹未命中任何 POC")
			return nil, nil
		}
		r.logf("match", "指纹命中 %d 个 POC，按危险等级优先选取 %d 个（最低等级：%s）",
			matched, len(ids), severityLabel(task.MinSeverity))
		pocs, err = r.pg.POCTemplatesByIDs(ids)
	case "selected":
		pocs, err = r.pg.POCTemplatesByIDs(task.POCIDs)
	case "full":
		var enabledTotal int
		pocs, enabledTotal, err = r.pg.ListEnabledPOCContents(maxFullTemplates)
		if err == nil && enabledTotal > len(pocs) {
			r.logf("match", "启用 POC 共 %d 个，超出全量上限 %d：按危险等级优先加载，最低等级的 %d 个本轮不执行",
				enabledTotal, len(pocs), enabledTotal-len(pocs))
		}
		r.logf("match", "全量模式加载 %d 个启用的 POC（按危险等级优先）", len(pocs))
	default:
		return nil, fmt.Errorf("未知扫描模式: %s", task.Mode)
	}
	if err != nil {
		return nil, fmt.Errorf("加载 POC 失败: %w", err)
	}
	out := make([]scanner.NucleiTemplate, 0, len(pocs))
	seen := map[string]bool{}
	for _, p := range pocs {
		if p.Protocol == "workflow" || strings.TrimSpace(p.Content) == "" {
			continue
		}
		if minRank > 0 && severityRank(p.Severity) < minRank {
			continue
		}
		if seen[p.TemplateID] {
			continue
		}
		seen[p.TemplateID] = true
		out = append(out, scanner.NucleiTemplate{ID: p.TemplateID, Content: p.Content})
	}
	r.logf("match", "准备执行 %d 个 POC（最低等级：%s）", len(out), severityLabel(task.MinSeverity))
	return out, nil
}

// prioritizeAutoTemplates sorts matched IDs by severity (critical first) so the
// auto-mode cap keeps high-value templates instead of an arbitrary ID slice.
func prioritizeAutoTemplates(ids []int64, rankByID map[int64]int) {
	sort.SliceStable(ids, func(i, j int) bool {
		ri, rj := rankByID[ids[i]], rankByID[ids[j]]
		if ri != rj {
			return ri > rj
		}
		return ids[i] < ids[j]
	})
}

func severityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "", "all":
		return 0
	case "info":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	default:
		return -1
	}
}

func severityLabel(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "":
		return "不限"
	case "info":
		return "info"
	case "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "critical":
		return "critical"
	}
	return sev
}

func (r *scanRun) nucleiTargets(res *scanner.DiscoverResult, raw []scanner.Target) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, svc := range res.Services {
		add(svc.URL)
	}
	hasServices := len(out) > 0
	if hasServices {
		for _, pf := range res.Ports {
			if scanner.IsWebPort(pf.Port) {
				continue
			}
			add(net.JoinHostPort(pf.IP, strconv.Itoa(pf.Port)))
		}
	} else {
		for _, t := range raw {
			if t.Kind == scanner.KindURL {
				add(t.URL)
			} else if t.Kind != scanner.KindCIDR {
				add(t.Host)
			}
		}
		for _, pf := range res.Ports {
			add(net.JoinHostPort(pf.IP, strconv.Itoa(pf.Port)))
		}
	}
	for ip, domains := range res.Resolved.DomainsByIP {
		for _, domain := range domains {
			for _, pf := range res.Ports {
				if pf.IP != ip || scanner.IsWebPort(pf.Port) {
					continue
				}
				add(net.JoinHostPort(domain, strconv.Itoa(pf.Port)))
			}
		}
	}
	if len(out) > maxScanNucleiTargets {
		r.logf("scan", "扫描目标 %d 个，超过上限 %d，已截断", len(out), maxScanNucleiTargets)
		out = out[:maxScanNucleiTargets]
	}
	return out
}

func (r *scanRun) persistResults(results []scanner.NucleiResult, assets *scanAssetIndex) (int, int, map[string]int64) {
	stored, findingCount, createdCount, merged := 0, 0, 0, 0
	findingIDs := map[string]int64{}
	seen := map[string]bool{}
	for i, res := range results {
		if r.ctx.Err() != nil {
			break
		}
		key := scanResultKey(res)
		if seen[key] {
			continue
		}
		seen[key] = true
		sev := strings.ToLower(strings.TrimSpace(res.Severity))
		rawPacket := report.IsRawProtocolType(res.Type)
		httpReq := cleanPacketText(res.Request, maxStoredHTTPRequest, rawPacket)
		httpResp := cleanPacketText(res.Response, maxStoredHTTPResponse, rawPacket)
		var findingID int64
		if r.task.CreateFindings && db.ValidSeverity(sev) {
			evidence := formatScanEvidence(res)
			summary := fmt.Sprintf("%s 在 %s 命中（自动化漏扫 #%d）", displayOr(res.Name, res.TemplateID), displayOr(res.MatchedAt, res.Host), r.task.ID)
			dedupeKey := findingDedupeKey(res.TemplateID, displayOr(res.MatchedAt, res.Host))
			id, created, err := r.pg.UpsertFinding(0, 0, res.TemplateID, res.Name, sev, summary, evidence,
				fmt.Sprintf("scan:%d", r.task.ID), assets.idsFor(res.MatchedAt, res.Host), dedupeKey)
			if err != nil {
				r.logf("finalize", "写入发现失败 %s: %v", res.TemplateID, err)
			} else {
				findingID = id
				findingIDs[key] = id
				findingCount++
				if created {
					createdCount++
				} else {
					merged++
				}
				autoReport := report.BuildFindingReport(report.FindingReportInput{
					FindingID:       id,
					Name:            res.Name,
					VulnClass:       res.TemplateID,
					Severity:        sev,
					Status:          db.FindingPending,
					Summary:         summary,
					Evidence:        evidence,
					TaskDescription: fmt.Sprintf("#%d %s", r.task.ID, r.task.Name),
					Source:          fmt.Sprintf("自动化漏扫任务 #%d（nuclei 模板 %s）", r.task.ID, res.TemplateID),
					TemplateID:      res.TemplateID,
					Host:            res.Host,
					MatchedAt:       res.MatchedAt,
					Type:            res.Type,
					Curl:            res.Curl,
					Extracted:       res.Extracted,
					HTTPRequest:     httpReq,
					HTTPResponse:    httpResp,
					GeneratedAt:     time.Now(),
				})
				if err := r.pg.SetFindingHTTPArtifactsAndAutoReport(id, httpReq, httpResp, autoReport); err != nil {
					r.logf("finalize", "保存原始 HTTP/报告失败 %s: %v", res.TemplateID, err)
				}
				r.attachReproductionSequence(res, id)
			}
		}
		raw := sanitizeNucleiRaw(res.Raw)
		id, err := r.pg.AddScanTaskResult(r.task.ID, findingID, db.ScanTaskResult{
			TemplateID: res.TemplateID,
			Name:       res.Name,
			Severity:   sev,
			Host:       res.Host,
			MatchedAt:  res.MatchedAt,
			Type:       res.Type,
			Curl:       res.Curl,
			Extracted:  res.Extracted,
			Raw:        raw,
		})
		if err != nil {
			r.logf("finalize", "保存扫描结果失败 %s: %v", res.TemplateID, err)
			continue
		}
		if id > 0 {
			stored++
		}
		if (i+1)%20 == 0 {
			r.setProgress("finalize", map[string]any{"results": stored, "findings": findingCount})
		}
	}
	if merged > 0 {
		r.logf("finalize", "%d 条命中合并到既有发现（按模板+主机+路径去重），新增 %d 条", merged, createdCount)
	}
	return stored, findingCount, findingIDs
}

// attachReproductionSequence stores every request/response nuclei recorded for
// a hit as finding evidence. Reports can then show the exploit request in
// addition to the matched proof request instead of only the final check.
func (r *scanRun) attachReproductionSequence(res scanner.NucleiResult, findingID int64) {
	if findingID <= 0 || len(res.Exchanges) == 0 {
		return
	}
	raws := make([]evidence.RawExchange, 0, len(res.Exchanges))
	for _, ex := range res.Exchanges {
		req := cleanHTTPText(ex.Request, maxStoredHTTPRequest)
		resp := cleanHTTPText(ex.Response, maxStoredHTTPResponse)
		if strings.TrimSpace(req) == "" {
			continue
		}
		role, note := "supporting", "nuclei 模板复现序列中的报文"
		if ex.Request == res.Request && ex.Response == res.Response {
			role, note = "proof", "nuclei 命中的验证报文"
		}
		raws = append(raws, evidence.RawExchange{Request: req, Response: resp, Role: role, Note: note})
	}
	if err := r.s.evidenceStore().SaveRawExchanges(r.ctx, findingID, raws); err != nil {
		r.logf("finalize", "保存复现报文序列失败 %s: %v", res.TemplateID, err)
	}
}

// scanResultKey identifies one hit within a scan run. It matches the key used
// for the finding-ID index handed to automatic exploitation.
func scanResultKey(res scanner.NucleiResult) string {
	key := res.TemplateID + "|" + res.MatchedAt
	if res.MatchedAt == "" {
		key = res.TemplateID + "|" + res.Host
	}
	return key
}

func formatScanEvidence(res scanner.NucleiResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "匹配地址: %s\n", displayOr(res.MatchedAt, res.Host))
	if res.Host != "" && res.Host != res.MatchedAt {
		fmt.Fprintf(&b, "主机: %s\n", res.Host)
	}
	fmt.Fprintf(&b, "模板: %s (%s)\n等级: %s\n", displayOr(res.Name, res.TemplateID), res.TemplateID, displayOr(res.Severity, "unknown"))
	if res.Type != "" {
		fmt.Fprintf(&b, "类型: %s\n", res.Type)
	}
	if len(res.Extracted) > 0 {
		fmt.Fprintf(&b, "提取结果: %s\n", strings.Join(res.Extracted, ", "))
	}
	if cred := scanCredentialHint(res.Raw); cred != "" {
		fmt.Fprintf(&b, "验证通过的口令: %s\n", cred)
	}
	if res.Request != "" || res.Response != "" {
		proto, suffix := "HTTP", "报文"
		if report.IsRawProtocolType(res.Type) {
			proto, suffix = strings.ToUpper(strings.TrimSpace(res.Type)), "数据"
		}
		b.WriteString("\n")
		if line := firstPacketLine(res.Request); line != "" {
			fmt.Fprintf(&b, "请求%s: %s\n", suffix, line)
		}
		if line := firstPacketLine(res.Response); line != "" {
			fmt.Fprintf(&b, "响应%s: %s\n", suffix, line)
		}
		fmt.Fprintf(&b, "原始 %s 请求/响应%s已保存，见漏洞详情的「证据 / PoC」与详细报告。\n", proto, suffix)
	}
	return b.String()
}

// firstPacketLine returns the request or status line of a raw HTTP packet so the
// evidence text carries the actual wire facts without embedding a curl command.
func firstPacketLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

// scanCredentialHint surfaces the pair a default-login template proved, so the
// finding states what actually worked instead of only naming the template.
func scanCredentialHint(raw map[string]any) string {
	meta, ok := raw["meta"].(map[string]any)
	if !ok {
		return ""
	}
	user, _ := meta["username"].(string)
	pass, _ := meta["password"].(string)
	if strings.TrimSpace(user) == "" || pass == "" {
		return ""
	}
	return user + " / " + pass
}

func cleanHTTPText(s string, limit int) string {
	return cleanPacketText(s, limit, false)
}

// cleanPacketText makes a captured packet storable and applies the storage cap.
// Raw protocol packets skip trimming because their trailing CRLF is part of the
// wire payload a human must resend.
func cleanPacketText(s string, limit int, raw bool) string {
	s = scanner.PacketText(s)
	if !raw {
		s = strings.TrimSpace(s)
	}
	if limit > 0 && len(s) > limit {
		s = scanner.PacketText(s[:limit])
		s += "\n\n[报文过长，已截断]"
	}
	return s
}

func sanitizeNucleiRaw(raw map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range raw {
		switch k {
		case "request", "response", "template", "template-encoded":
			continue
		}
		out[k] = v
	}
	return out
}

func displayOr(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

// ---------- HTTP API ----------

func (s *Server) listScanTasks(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	tasks, total, err := pg.ListScanTasks(atoiDefault(q.Get("limit"), 50), atoiDefault(q.Get("offset"), 0))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, t := range tasks {
		t.Log = ""
	}
	writeJSON(w, 200, map[string]any{"scans": tasks, "total": total})
}

func (s *Server) createScanTask(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req db.ScanTaskInput
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	targets, err := scanner.ParseTargets(cleanTargets(req.Targets))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(targets) > maxScanTargets {
		writeErr(w, 400, fmt.Sprintf("单次最多 %d 个目标", maxScanTargets))
		return
	}
	ipEstimate := 0
	for _, t := range targets {
		if t.Kind == scanner.KindCIDR {
			ips, err := cidrIPs(t.Host)
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			ipEstimate += len(ips)
		} else {
			ipEstimate++
		}
	}
	if ipEstimate > 256 {
		writeErr(w, 400, "目标展开后最多 256 个 IP，请缩小 CIDR 或减少目标")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "auto"
	}
	switch mode {
	case "auto", "selected", "full":
	default:
		writeErr(w, 400, "扫描模式必须是 auto、selected 或 full")
		return
	}
	req.Ports = strings.TrimSpace(req.Ports)
	if req.Ports == "" {
		req.Ports = "top1000"
	}
	ports, err := scanner.ParsePortSpec(req.Ports)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if checks := ipEstimate * len(ports); checks > maxScanPortChecks {
		writeErr(w, 400, fmt.Sprintf("端口扫描量过大：%d 个 IP × %d 个端口 = %d 次探测，上限 %d；请缩小目标范围或减少端口",
			ipEstimate, len(ports), checks, maxScanPortChecks))
		return
	}
	req.MinSeverity = strings.ToLower(strings.TrimSpace(req.MinSeverity))
	if req.MinSeverity != "" && severityRank(req.MinSeverity) < 2 {
		writeErr(w, 400, "最低危险等级必须是 low、medium、high 或 critical")
		return
	}
	if mode == "auto" {
		req.Fingerprint = true
	}
	if mode == "selected" {
		ids := uniqueIDs(req.POCIDs)
		if len(ids) == 0 {
			writeErr(w, 400, "专项扫描请至少选择一个 POC")
			return
		}
		if len(ids) > maxScanPOCs {
			writeErr(w, 400, fmt.Sprintf("单次最多选择 %d 个 POC", maxScanPOCs))
			return
		}
		req.POCIDs = ids
	} else {
		req.POCIDs = nil
	}
	if req.RateLimit <= 0 {
		req.RateLimit = 50
	}
	if req.RateLimit > 1000 {
		req.RateLimit = 1000
	}
	if req.Concurrency <= 0 {
		req.Concurrency = 25
	}
	if req.Concurrency > 100 {
		req.Concurrency = 100
	}
	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = 600
	}
	if req.TimeoutSeconds < 30 {
		req.TimeoutSeconds = 30
	}
	if req.TimeoutSeconds > 7200 {
		req.TimeoutSeconds = 7200
	}
	if err := normalizeScanWebshell(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Mode = mode
	req.Targets = make([]string, 0, len(targets))
	for _, t := range targets {
		req.Targets = append(req.Targets, t.Raw)
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = "自动化漏扫 " + time.Now().Format("01-02 15:04") + " " + targets[0].Raw
	}

	pg := s.pg(w)
	if pg == nil {
		return
	}
	rules, err := pg.ListAssetInterceptRules()
	if err != nil {
		writeErr(w, 500, "加载资产拦截规则失败: "+err.Error())
		return
	}
	if reason, blocked := scanTargetBlockReason(rules, targets); blocked {
		writeErr(w, 400, "目标命中资产拦截规则，已拒绝创建："+reason)
		return
	}
	if mode == "selected" {
		pocs, err := pg.POCTemplatesByIDs(req.POCIDs)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		runnable := 0
		for _, p := range pocs {
			if p.Protocol != "workflow" {
				runnable++
			}
		}
		if runnable == 0 {
			writeErr(w, 400, "所选 POC 不存在、已禁用或均为 workflow")
			return
		}
	}
	task, err := pg.CreateScanTask(req)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if s.scanMgr != nil {
		s.scanMgr.wakeup()
	}
	writeJSON(w, 201, task)
}

// normalizeScanWebshell validates the optional webshell-injection settings and
// fills sensible defaults. Paths are kept relative so the same setting can be
// applied to every host discovered by the scan.
func normalizeScanWebshell(req *db.ScanTaskInput) error {
	if !req.WebshellInject {
		req.WebshellParams = map[string]any{}
		return nil
	}
	if req.WebshellParams == nil {
		req.WebshellParams = map[string]any{}
	}
	uploadPath := strings.TrimSpace(stringParam(req.WebshellParams, "upload_path"))
	if uploadPath == "" {
		return errors.New("启用 Webshell 注入时必须填写上传路径")
	}
	if !strings.HasPrefix(uploadPath, "/") {
		return errors.New("上传路径必须是以 / 开头的相对路径，例如 /upload.php")
	}
	landPath := strings.TrimSpace(stringParam(req.WebshellParams, "land_path"))
	if landPath != "" && !strings.HasPrefix(landPath, "/") {
		return errors.New("落地路径必须是以 / 开头的相对路径")
	}
	shellType := strings.ToLower(strings.TrimSpace(stringParam(req.WebshellParams, "shell_type")))
	switch shellType {
	case "":
		shellType = "php"
	case "php", "jsp", "aspx":
	default:
		return errors.New("Webshell 类型必须是 php、jsp 或 aspx")
	}
	password := strings.TrimSpace(stringParam(req.WebshellParams, "password"))
	if password == "" {
		password = randomShellPassword()
	}
	fieldName := strings.TrimSpace(stringParam(req.WebshellParams, "field_name"))
	if fieldName == "" {
		fieldName = "file"
	}
	req.WebshellParams["upload_path"] = uploadPath
	req.WebshellParams["land_path"] = landPath
	req.WebshellParams["shell_type"] = shellType
	req.WebshellParams["password"] = password
	req.WebshellParams["field_name"] = fieldName
	return nil
}

func randomShellPassword() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("jw%d", time.Now().UnixNano())
	}
	return "jw" + hex.EncodeToString(b)
}

// getScanAuto returns the deep tasks spawned by a scan plus their evidence.
func (s *Server) getScanAuto(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的扫描任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	tasks, err := pg.ListDeepTasksByScan(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	records := []*db.ExploitRecord{}
	wafResults := []*db.WAFBypassResult{}
	for _, t := range tasks {
		t.Log = ""
		if rs, err := pg.ListExploitRecords(t.ID); err == nil {
			records = append(records, rs...)
		}
		if rs, err := pg.ListWAFBypassResults(t.ID); err == nil {
			wafResults = append(wafResults, rs...)
		}
	}
	writeJSON(w, 200, map[string]any{
		"tasks":       tasks,
		"records":     records,
		"waf_results": wafResults,
	})
}

func (s *Server) getScanTask(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的扫描任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	task, err := pg.GetScanTask(id)
	if errors.Is(err, db.ErrScanTaskNotFound) {
		writeErr(w, 404, "扫描任务不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, task)
}

func (s *Server) listScanTaskAssets(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的扫描任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	assets, err := pg.ListScanTaskAssets(id, atoiDefault(r.URL.Query().Get("limit"), 2000))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"assets": assets})
}

func (s *Server) listScanTaskResults(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的扫描任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	results, err := pg.ListScanTaskResults(id, atoiDefault(r.URL.Query().Get("limit"), 2000))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

func (s *Server) cancelScanTask(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的扫描任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	canceled, err := pg.CancelScanTask(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !canceled {
		writeErr(w, 409, "任务已结束，无法停止")
		return
	}
	if s.scanMgr != nil {
		s.scanMgr.cancelTask(id)
	}
	writeJSON(w, 200, map[string]any{"canceled": true})
}

func (s *Server) rerunScanTask(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的扫描任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	queued, err := pg.QueueScanTask(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !queued {
		writeErr(w, 409, "仅已结束的扫描任务可以重跑")
		return
	}
	if s.scanMgr != nil {
		s.scanMgr.wakeup()
	}
	task, err := pg.GetScanTask(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, task)
}

func (s *Server) deleteScanTask(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的扫描任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	deleted, err := pg.DeleteScanTask(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !deleted {
		writeErr(w, 409, "任务不存在或仍在运行，无法删除")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": 1})
}
