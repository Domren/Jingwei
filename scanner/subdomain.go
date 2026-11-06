package scanner

// 子域名枚举（C3）：字典爆破 + 可选第三方公开接口 + A/AAAA/CNAME 解析。
//
// 这一层只做「名字与记录」，不碰资产库也不向目标发包：DNS 查询发往本机配置的解析器，
// 公开接口是一个明确固定的第三方地址。端口探测由调用方拿着解析结果去做——
// 「枚举到什么」和「对它做了什么」在报告里是两件事，不互相冒充。
//
// 三条判据是这个引擎存在的理由，缺一条结果就不可信：
//
//  1. **泛解析检测**。很多域名配了 `*.example.com`，字典爆破会把每一个候选词都「解析成功」，
//     一次爆破能造出几千条假子域名且全指向同一个 IP。做法：对每个根先查三个随机名字，
//     答得出来就认定该根有泛解析并记下答复指纹；与基线一致的命中不计入发现，只计数并写明。
//  2. **未判定不等于不存在**。解析超时、SERVFAIL、网络不可达都不是「这个子域名不存在」。
//     把它们静默当成 NXDOMAIN，报告就会说「没有别的子域名了」——那是假话。
//     未判定的条数与样本名字必须出现在结论里。
//  3. **预算**。字典 × 根域名的乘积很容易上十万。到点就停，并写明停在哪一段，
//     不悄悄截断（截断的覆盖面是假的，与漏扫丢模板是同一类错误）。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// 记录类型。CNAME 单列：它常常指向 CDN/托管平台（*.cloudfront.net 这类），
// 是「这个子域名活着但不在客户机房里」的判断依据，不能和 A 记录混成一条。
const (
	SubdomainRecordA     = "A"
	SubdomainRecordAAAA  = "AAAA"
	SubdomainRecordCNAME = "CNAME"
)

// 发现来源。
const (
	SubdomainSourceInput  = "input"  // 用户直接给出的名字（含根域名本身）
	SubdomainSourceDict   = "dict"   // 字典爆破命中
	SubdomainSourcePublic = "public" // 第三方公开接口给出
)

const (
	subDefaultConcurrency = 16
	subDefaultTimeout     = 3 * time.Second
	subDefaultMaxQueries  = 20000
	subDefaultMaxNames    = 5000
	subWildcardProbes     = 3
	// 连续失败到这个数就停：容器里没有 DNS 时，继续问五万次也只会得到五万个「未判定」。
	subDefaultStopAfterFailures = 50
	// crt.sh 的公开接口地址。它不是用户可填项（填得出去就是 SSRF），
	// 用例通过同包的 crtshBaseURL 变量换成 httptest 服务。
	crtshDefaultURL = "https://crt.sh/"
	// 公开接口一次最多取多少名字：热门域名能返回几万条证书，全收下既没必要也会拖死解析阶段。
	subPublicMaxNames = 5000
	subPublicMaxBody  = 8 << 20
	// 公开接口的超时单独放宽：crt.sh 是出了名的慢（实测 25–40 秒才回头），
	// 跟着 DNS 的 3 秒默认值走等于这一路永远失败。
	subPublicTimeout = 90 * time.Second
)

// crtshBaseURL 是用例注入点；生产代码不改它。
var crtshBaseURL = crtshDefaultURL

// SubdomainRecord 是一个名字的一种记录。
type SubdomainRecord struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

// SubdomainFinding 是一个确认存在的子域名。
type SubdomainFinding struct {
	Name    string            `json:"name"`
	Root    string            `json:"root"`
	Source  string            `json:"source"`
	Records []SubdomainRecord `json:"records"`
	// IPs 是 A/AAAA 记录的合集（去重排序），给端口探测当输入。
	IPs []string `json:"ips"`
	// Wildcard 表示这条记录与泛解析基线一致——它不是这个域名自己的子域名，而是 `*` 的答复。
	// 默认不返回这种结果；打开 KeepWildcard 时带着标记返回。
	Wildcard bool `json:"wildcard"`
}

// SubdomainOptions 控制一轮枚举。
type SubdomainOptions struct {
	Words       []string
	Concurrency int
	Timeout     time.Duration
	MaxQueries  int
	MaxNames    int
	// Sources 是公开接口名单，目前只有 "crtsh"；空表示完全不碰第三方。
	Sources []string
	// KeepWildcard 保留与泛解析基线一致的命中（只打标，不丢）。
	KeepWildcard bool
	// Resolver 与 HTTPClient 是用例注入点；为 nil 时用系统解析器与默认客户端。
	Resolver    SubdomainResolver
	HTTPClient  *http.Client
	OnProgress  func(queries, found int)
	Logf        func(format string, args ...any)
	RetainNames int
}

// SubdomainOutcome 是一轮枚举的全部产出，包括没成功的那部分。
type SubdomainOutcome struct {
	Found []SubdomainFinding `json:"found"`
	Roots []string           `json:"roots"`
	// Candidates 是进入队列的名字总数（含字典组合），Queried 是真正问出去的次数：
	// 两者不等就说明预算截断了什么。
	Queried    int `json:"queried"`
	Candidates int `json:"candidates"`
	// WildcardRoots 是检测到泛解析的根；WildcardDropped 是因基线一致而丢弃的条数。
	WildcardRoots   []string `json:"wildcard_roots"`
	WildcardDropped int      `json:"wildcard_dropped"`
	// Unresolved 是「判不出来」的次数（超时/SERVFAIL/网络错误），不等于不存在；
	// Samples 给几条样本名字。
	Unresolved int      `json:"unresolved"`
	Samples    []string `json:"samples,omitempty"`
	// 公开接口：PublicOn 说明这一轮开没开，PublicNames 是拿回的名字数，PublicErrors 是失败次数。
	PublicOn      bool `json:"public_on"`
	PublicNames   int  `json:"public_names"`
	PublicErrors  int  `json:"public_errors"`
	PublicSkipped int  `json:"public_skipped"`
	// Stopped 非空说明这一轮不完整：budget（预算）/ canceled（手动停止）/
	// resolver-unavailable（解析连续失败）。
	Stopped string `json:"stopped,omitempty"`
}

// SubdomainResolver 把「查一个名字的记录」抽成接口：真实实现走系统解析器，
// 用例里换成假解析器——枚举的正确性不该依赖外网 DNS 此刻怎么答。
type SubdomainResolver interface {
	Resolve(ctx context.Context, name string) ([]SubdomainRecord, error)
}

// SystemSubdomainResolver 用本机配置的 DNS 解析，保留 IPv6，并且尊重 context 取消。
//
// 注：查询发往的是**这台机器配置的解析器**，不是客户的 DNS。用公共/运营商 DNS 时，
// 被查询的域名会出现在它的日志里——这与「向目标发包」是两种外泄，报告里分开写。
type SystemSubdomainResolver struct {
	Resolver *net.Resolver
	Timeout  time.Duration
}

// NewSystemSubdomainResolver 返回走系统配置的解析器实现。
func NewSystemSubdomainResolver(timeout time.Duration) *SystemSubdomainResolver {
	if timeout <= 0 {
		timeout = subDefaultTimeout
	}
	return &SystemSubdomainResolver{Resolver: net.DefaultResolver, Timeout: timeout}
}

// Resolve 查 A / AAAA / CNAME。NXDOMAIN 返回空记录且 err=nil（「不存在」是确定的答复），
// 其它错误原样返回，由调用方记为未判定——这两种情况在报告里必须分开。
func (r *SystemSubdomainResolver) Resolve(ctx context.Context, name string) ([]SubdomainRecord, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = subDefaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := resolver.LookupIPAddr(cctx, name)
	if err != nil && !isNotFoundErr(err) {
		return nil, err
	}
	var v4, v6 []string
	for _, a := range addrs {
		if ip := a.IP.To4(); ip != nil {
			v4 = append(v4, ip.String())
			continue
		}
		v6 = append(v6, a.IP.String()) // IPv6 一律保留，不在这里丢掉（C6 的账不该由引擎重演）
	}
	out := make([]SubdomainRecord, 0, 3)
	if len(v4) > 0 {
		out = append(out, SubdomainRecord{Type: SubdomainRecordA, Values: dedupeSortedStrings(v4)})
	}
	if len(v6) > 0 {
		out = append(out, SubdomainRecord{Type: SubdomainRecordAAAA, Values: dedupeSortedStrings(v6)})
	}
	if cname, cerr := resolver.LookupCNAME(cctx, name); cerr == nil {
		c := normalizeDomain(cname)
		if c != "" && c != normalizeDomain(name) {
			out = append(out, SubdomainRecord{Type: SubdomainRecordCNAME, Values: []string{c}})
		}
	}
	return out, nil
}

func isNotFoundErr(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// normalizeDomain 去空白、末尾点、首部 `*.`，转小写。
func normalizeDomain(raw string) string {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.Trim(d, ".")
	d = strings.TrimPrefix(d, "*.")
	return strings.Trim(d, ".")
}

// ValidSubdomainRoot 判断一个输入能不能当根域名用。这里拦的是「看着像域名其实是别的东西」：
// 带协议、带端口、带路径、只有一个标签的都不能拿来爆破。
func ValidSubdomainRoot(candidate string) bool {
	d := normalizeDomain(candidate)
	if d == "" || strings.ContainsAny(d, "@/:?# \\") {
		return false
	}
	if net.ParseIP(d) != nil {
		return false // 全数字标签在语法上是合法域名，但「admin.1.2.3.4」不是任何人的子域名
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for i := range len(l) {
			c := l[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

// RootDomainOf 猜一个域名的「注册域」：只按标签数粗判（两段就是根，三段以上去掉最左一段）。
// 公共后缀列表（co.uk 之类）不在这里解决——猜错最多让枚举范围偏一段，不会把别人的域名
// 当成目标，所以宁可保守地少切一段。
func RootDomainOf(host string) (string, bool) {
	d := normalizeDomain(host)
	if d == "" {
		return "", false
	}
	labels := strings.Split(d, ".")
	if len(labels) <= 2 {
		return d, len(labels) == 2
	}
	return strings.Join(labels[1:], "."), true
}

// SubdomainRootsFromTargets 从任务目标里挑出可用的根域名：URL、host、纯域名都认，
// IP 与 CIDR 不认（它们没有「子域名」这件事）。
func SubdomainRootsFromTargets(raw []string) ([]string, error) {
	targets, err := ParseTargets(raw)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var roots []string
	for _, t := range targets {
		host := normalizeDomain(t.Host)
		if host == "" || net.ParseIP(host) != nil {
			continue
		}
		root := host
		if r, ok := RootDomainOf(host); ok {
			root = r
		}
		if !ValidSubdomainRoot(root) || seen[root] {
			continue
		}
		seen[root] = true
		roots = append(roots, root)
	}
	if len(roots) == 0 {
		return nil, errors.New("目标里没有可用的根域名：子域名枚举要的是域名（example.com 或 www.example.com），IP 与 CIDR 不参与")
	}
	sort.Strings(roots)
	return roots, nil
}

// SubdomainWordlist 是内置的精简子域名字典：高信号优先，不做全量爆破。
// 全量爆破该由操作员自己导字典；默认给的是「十分钟内跑得完且值得看」的那一批。
var SubdomainWordlist = []string{
	"www", "mail", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "dns", "mx",
	"api", "api2", "gateway", "gw", "dev", "test", "staging", "stage", "pre", "prod",
	"uat", "sit", "sandbox", "demo", "poc", "beta", "canary", "internal", "intranet", "extranet",
	"admin", "adm", "manage", "manager", "console", "panel", "cp", "control", "dashboard", "backoffice",
	"erp", "crm", "oa", "hr", "finance", "pay", "payment", "shop", "store", "mall",
	"cms", "blog", "news", "portal", "wiki", "docs", "doc", "git", "gitlab", "gitea",
	"svn", "jira", "confluence", "zentao", "nextcloud", "drive",
	"vpn", "proxy", "jump", "bastion", "remote", "rdp", "ssh",
	"jenkins", "ci", "build", "deploy", "runner", "harbor", "registry", "nexus", "artifactory",
	"nacos", "apollo", "eureka", "consul", "config", "sentinel", "seata", "dubbo", "zipkin", "skywalking",
	"mysql", "db", "database", "redis", "mongo", "mongodb", "postgres", "pgsql", "oracle", "mssql",
	"elasticsearch", "es", "kibana", "logstash", "graylog", "clickhouse", "tidb", "doris",
	"rabbitmq", "kafka", "rocketmq", "zookeeper", "zk", "mqtt", "emqx", "minio", "oss",
	"monitor", "prometheus", "grafana", "zabbix", "nagios", "alert", "metric", "trace", "log", "logs",
	"file", "files", "upload", "download", "img", "image", "static", "cdn", "assets", "res",
	"m", "mobile", "wap", "app", "h5", "mini", "weixin", "wx",
	"open", "oauth", "sso", "auth", "login", "account", "passport", "user",
	"test1", "test2", "temp", "tmp", "old", "new", "backup", "bak",
	"status", "health", "metrics", "swagger", "graphql", "rest", "rpc", "ws",
	"report", "bi", "data", "bigdata", "dw", "etl", "spark", "hive", "flink",
}

func subOptionsDefault(o SubdomainOptions) SubdomainOptions {
	if len(o.Words) == 0 {
		o.Words = SubdomainWordlist
	}
	if o.Concurrency <= 0 {
		o.Concurrency = subDefaultConcurrency
	}
	if o.Timeout <= 0 {
		o.Timeout = subDefaultTimeout
	}
	if o.MaxQueries <= 0 {
		o.MaxQueries = subDefaultMaxQueries
	}
	if o.MaxNames <= 0 {
		o.MaxNames = subDefaultMaxNames
	}
	if o.Resolver == nil {
		o.Resolver = NewSystemSubdomainResolver(o.Timeout)
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	if o.RetainNames <= 0 {
		o.RetainNames = 5
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// SubdomainSourceNames 是支持的公开接口。界面、文档与校验都从这里取，别处不再抄一份。
func SubdomainSourceNames() []string { return []string{"crtsh"} }

// subState 是并发阶段的共享计数，全部由 mu 保护。
type subState struct {
	mu sync.Mutex
	// cancel 在第一次记下停止原因时触发。投料循环只认 context：不取消它就会出现
	// 「工人已经收工、投料的还在往没人看的队列里塞」的死等。
	cancel          context.CancelFunc
	queried         int
	unresolved      int
	consecutiveFail int
	dropped         int
	samples         []string
	findings        []SubdomainFinding
	stopReason      string
}

// EnumerateSubdomains 跑一轮枚举。roots 会被规范化并去重；即使返回错误，outcome 里也带着
// 已经拿到的部分——中途停掉的任务，前半段结论仍然要能交付。
func EnumerateSubdomains(ctx context.Context, roots []string, opts SubdomainOptions) (SubdomainOutcome, error) {
	var out SubdomainOutcome
	var clean []string
	seen := map[string]bool{}
	for _, r := range roots {
		d := normalizeDomain(r)
		if d == "" {
			continue
		}
		if !ValidSubdomainRoot(d) {
			return out, fmt.Errorf("根域名 %q 不可用：子域名枚举要的是域名，不接受 IP、CIDR 或带协议的地址", r)
		}
		if !seen[d] {
			seen[d] = true
			clean = append(clean, d)
		}
	}
	if len(clean) == 0 {
		return out, errors.New("没有可用的根域名")
	}
	opts = subOptionsDefault(opts)
	out.Roots = clean
	sort.Strings(out.Roots)
	st := &subState{}

	// 1) 公开接口先把「别人已经登记过的名字」捞一遍：比字典准得多，且只花几个请求。
	candidates := map[string]string{}
	for _, root := range clean {
		candidates[root] = SubdomainSourceInput
		candidates["www."+root] = SubdomainSourceInput
	}
	for _, src := range opts.Sources {
		if src != "crtsh" {
			out.PublicSkipped++
			opts.Logf("未知的公开接口来源 %q，已跳过（不假装查过）", src)
			continue
		}
		out.PublicOn = true
		names, err := fetchCrtshNames(ctx, opts, clean)
		if err != nil {
			out.PublicErrors++
			opts.Logf("公开接口 crt.sh 查询失败：%v（这一轮只跑字典，结论里会写明）", err)
			continue
		}
		out.PublicNames += len(names)
		for _, n := range names {
			if _, ok := candidates[n]; !ok {
				candidates[n] = SubdomainSourcePublic
			}
		}
	}

	// 2) 泛解析基线：先知道「这个根的 * 答什么」，后面的命中才有对照。
	wildcard := map[string][]string{}
	for _, root := range clean {
		if fps, ok := detectWildcard(ctx, opts, root); ok {
			wildcard[root] = fps
			out.WildcardRoots = append(out.WildcardRoots, root)
			opts.Logf("根域名 %s 存在泛解析：与基线一致的字典命中不计入发现", root)
		}
	}

	// 3) 解析队列：先公开接口的名字（准），再字典组合（广）。
	names := make([]string, 0, len(candidates))
	for n := range candidates {
		names = append(names, n)
	}
	sort.Strings(names)

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st.cancel = cancel
	queue := make(chan subJob, opts.Concurrency*4)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go subWorker(cctx, opts, clean, wildcard, st, queue, &wg)
	}

	queued := make(map[string]bool, len(names))
	for _, n := range names {
		queued[n] = true
	}
	total := len(names) + len(opts.Words)*len(clean)
	out.Candidates = total
	issued := 0
feed:
	for _, n := range names {
		if issued >= opts.MaxQueries {
			st.markStopped("budget")
			break
		}
		issued++
		select {
		case queue <- subJob{name: n, source: candidates[n]}:
		case <-cctx.Done():
			break feed
		}
	}
	if st.stopped() == "" {
	wordloop:
		for _, root := range clean {
			for _, w := range opts.Words {
				prefix := normalizeDomain(w)
				if prefix == "" || strings.ContainsAny(prefix, "/: .") {
					continue
				}
				dictName := prefix + "." + root
				// 公开接口或用户已经给过这个名字：再问一次只会产出第二条同样的发现，
				// 来源还会被后写入的那个盖掉。
				if queued[dictName] {
					continue
				}
				queued[dictName] = true
				if issued >= opts.MaxQueries {
					st.markStopped("budget")
					break wordloop
				}
				issued++
				select {
				case queue <- subJob{name: dictName, source: SubdomainSourceDict}:
				case <-cctx.Done():
					break wordloop
				}
			}
		}
	}
	close(queue)
	wg.Wait()

	if ctx.Err() != nil && st.stopped() == "" {
		st.markStopped("canceled")
	}
	out.Found = st.findings
	out.Queried = st.queried
	out.WildcardDropped = st.dropped
	out.Unresolved = st.unresolved
	out.Samples = st.samples
	out.Stopped = st.stopped()
	if len(out.Found) > opts.MaxNames {
		out.Found = out.Found[:opts.MaxNames]
		out.Stopped = "budget"
	}
	sort.Slice(out.Found, func(i, j int) bool {
		if out.Found[i].Name == out.Found[j].Name {
			return out.Found[i].Source < out.Found[j].Source
		}
		return out.Found[i].Name < out.Found[j].Name
	})
	return out, nil
}

// subWorker 消费一个名字：解析、判泛解析、记发现。共享计数全部走 subState 的锁。
func subWorker(ctx context.Context, opts SubdomainOptions, roots []string,
	wildcard map[string][]string, st *subState, queue <-chan subJob, wg *sync.WaitGroup) {
	defer wg.Done()
	for j := range queue {
		records, err := opts.Resolver.Resolve(ctx, j.name)
		st.mu.Lock()
		st.queried++
		if err != nil {
			st.unresolved++
			st.consecutiveFail++
			failures := st.consecutiveFail
			if len(st.samples) < opts.RetainNames {
				st.samples = append(st.samples, j.name)
			}
			st.mu.Unlock()
			if failures >= subDefaultStopAfterFailures {
				// 解析器整体不可用（容器里没 DNS、上游挂了）：继续问下去只会把
				// 「未判定」刷成更大的数字，停下来把原因说清楚才是有用的结论。
				st.markStopped("resolver-unavailable")
				return
			}
			continue
		}
		st.consecutiveFail = 0
		root := rootOfKnown(j.name, roots)
		st.mu.Unlock()
		if root == "" {
			continue // 不在本次根域名下：不是这次授权的对象
		}
		if len(records) == 0 {
			continue // NXDOMAIN：确定不存在
		}
		fp := recordFingerprint(records)
		isWild := sameAs(wildcard[root], fp)
		if isWild && !opts.KeepWildcard {
			st.mu.Lock()
			st.dropped++
			st.mu.Unlock()
			continue
		}
		finding := SubdomainFinding{
			Name: j.name, Root: root, Source: j.source, Records: records, Wildcard: isWild,
		}
		for _, rec := range records {
			if rec.Type == SubdomainRecordA || rec.Type == SubdomainRecordAAAA {
				finding.IPs = append(finding.IPs, rec.Values...)
			}
		}
		finding.IPs = dedupeSortedStrings(finding.IPs)
		st.mu.Lock()
		found := len(st.findings)
		st.findings = append(st.findings, finding)
		over := found >= opts.MaxNames
		queried := st.queried
		st.mu.Unlock()
		if opts.OnProgress != nil {
			opts.OnProgress(queried, found+1)
		}
		if over {
			st.markStopped("budget")
			return
		}
	}
}

// markStopped 只记第一个停止原因：后面的原因都是被第一个原因带出来的后果，不是原因本身。
// 记下的同时取消 context——投料循环只看 context，不取消它就会堵在没人消费的队列上永远不返回。
func (st *subState) markStopped(reason string) {
	st.mu.Lock()
	first := st.stopReason == ""
	if first {
		st.stopReason = reason
	}
	cancel := st.cancel
	st.mu.Unlock()
	if first && cancel != nil {
		cancel()
	}
}

func (st *subState) stopped() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.stopReason
}

// subJob 是解析队列里的一项。
type subJob struct {
	name   string
	source string
}

// rootOfKnown 找出一个名字属于哪个根。不在任何根下的名字一律拒绝：公开接口偶尔返回
// 同名但不同根的名字，那是别人的资产。
func rootOfKnown(name string, roots []string) string {
	for _, r := range roots {
		if name == r || strings.HasSuffix(name, "."+r) {
			return r
		}
	}
	return ""
}

// recordFingerprint 把记录压成可比较的串：类型 + 排序后的值。
func recordFingerprint(records []SubdomainRecord) string {
	if len(records) == 0 {
		return ""
	}
	parts := make([]string, 0, len(records))
	for _, r := range records {
		parts = append(parts, r.Type+"="+strings.Join(r.Values, ","))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func sameAs(baseline []string, fp string) bool {
	for _, b := range baseline {
		if b == fp {
			return true
		}
	}
	return false
}

// detectWildcard 用几个随机名字问一次：答得出来就说明这个根有泛解析。
// 返回的指纹可能不止一个（不同随机名答得不一样），全都留着当对照基线。
func detectWildcard(ctx context.Context, opts SubdomainOptions, root string) ([]string, bool) {
	var fps []string
	for i := 0; i < subWildcardProbes; i++ {
		records, err := opts.Resolver.Resolve(ctx, randomSubLabel()+"."+root)
		if err != nil {
			// 问不出结果就按「没有泛解析」处理：误判成「有」会把真子域名整批丢掉，
			// 误判成「没有」只是多留几条待人工确认的记录——后者损失小得多。
			continue
		}
		if len(records) == 0 {
			continue
		}
		fp := recordFingerprint(records)
		if !sameAs(fps, fp) {
			fps = append(fps, fp)
		}
	}
	return fps, len(fps) > 0
}

func randomSubLabel() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("jw%d", time.Now().UnixNano())
	}
	return "jw-" + hex.EncodeToString(buf)
}

// crtshEntry 是 crt.sh 的 output=json 里关心的几个字段。
type crtshEntry struct {
	Name       string `json:"common_name"`
	NameValue  string `json:"name_value"`
	SanEntries string `json:"san_entries"`
}

// fetchCrtshNames 向 crt.sh 查询根域名的证书透明度记录。
//
// 这一步把**客户的根域名发给一个第三方公开服务**——授权清单管不住这条外发，所以它只在
// 显式开启时执行，失败不影响其它来源，日志与结论里都会写明查过。地址固定为 crt.sh，
// 不接受用户填写：能填 URL 的枚举接口就是一个 SSRF 跳板。
func fetchCrtshNames(ctx context.Context, opts SubdomainOptions, roots []string) ([]string, error) {
	if len(roots) == 0 {
		return nil, nil
	}
	base, err := url.Parse(crtshBaseURL)
	if err != nil {
		return nil, err
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	// 重定向只认同一个 host：crt.sh 挂了或被中间人改了都不该把查询带到别处去。
	host := base.Host
	redirectGuard := func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != host {
			return errors.New("crt.sh 把查询重定向到了其它主机，已中止")
		}
		if len(via) >= 3 {
			return errors.New("crt.sh 重定向次数过多，已中止")
		}
		return nil
	}
	clone := *client
	clone.CheckRedirect = redirectGuard
	clone.Timeout = subPublicTimeout

	query := url.Values{"output": []string{"json"}}
	for _, r := range roots {
		query.Add("q", "*."+r) // 通配符必须转义：手拼的 "%.example.com" 会让查询参数整个丢掉
	}
	base.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := clone.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, subPublicMaxBody))
	if err != nil {
		return nil, err
	}
	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("响应不是预期的 JSON 数组：%v", err)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(entries))
	split := func(r rune) bool { return r == '\n' || r == ',' || r == ' ' || r == ';' }
	for _, e := range entries {
		for _, n := range strings.FieldsFunc(e.Name+"\n"+e.NameValue+"\n"+e.SanEntries, split) {
			name := normalizeDomain(n)
			if name == "" || seen[name] || rootOfKnown(name, roots) == "" {
				continue // 不是本次授权范围内的根，直接丢
			}
			seen[name] = true
			out = append(out, name)
			if len(out) >= subPublicMaxNames {
				opts.Logf("公开接口返回的名字超过 %d 条，只取前 %d 条", subPublicMaxNames, subPublicMaxNames)
				return out, nil
			}
		}
	}
	return out, nil
}

func dedupeSortedStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// SubdomainSummary 是给任务台账与报告用的结构化结论。
func (o SubdomainOutcome) SubdomainSummary() map[string]any {
	return map[string]any{
		"roots":            o.Roots,
		"candidates":       o.Candidates,
		"queried":          o.Queried,
		"found":            len(o.Found),
		"wildcard_roots":   o.WildcardRoots,
		"wildcard_dropped": o.WildcardDropped,
		"unresolved":       o.Unresolved,
		"samples":          o.Samples,
		"public_on":        o.PublicOn,
		"public_names":     o.PublicNames,
		"public_errors":    o.PublicErrors,
		"public_skipped":   o.PublicSkipped,
		"stopped":          o.Stopped,
	}
}

// SubdomainText 把「这一轮不完整」的部分写成一句人话，供任务日志与报告直接引用。
// 一项都不省略：预算截断、泛解析、未判定、公开接口失败，各自都会改变覆盖面。
func (o SubdomainOutcome) SubdomainText() string {
	var parts []string
	switch o.Stopped {
	case "budget":
		parts = append(parts, fmt.Sprintf("预算用尽（已问 %d 次 / 候选 %d 个），剩下的没有问过", o.Queried, o.Candidates))
	case "canceled":
		parts = append(parts, "任务被手动停止，本轮不完整")
	case "resolver-unavailable":
		parts = append(parts, "解析连续失败，已停止后续查询（未判定的名字不等于不存在）")
	}
	if len(o.WildcardRoots) > 0 {
		parts = append(parts, fmt.Sprintf("%s 存在泛解析，与基线一致的 %d 条已剔除",
			strings.Join(o.WildcardRoots, "、"), o.WildcardDropped))
	}
	if o.Unresolved > 0 {
		parts = append(parts, fmt.Sprintf("%d 次解析未判定（超时或 SERVFAIL，不等于不存在）", o.Unresolved))
	}
	if o.PublicOn && o.PublicErrors > 0 {
		parts = append(parts, fmt.Sprintf("公开接口失败 %d 次，那部分覆盖面缺失", o.PublicErrors))
	}
	if o.PublicSkipped > 0 {
		parts = append(parts, fmt.Sprintf("%d 个公开接口来源不认识，已跳过", o.PublicSkipped))
	}
	if !o.PublicOn {
		parts = append(parts, "未使用第三方公开接口（只跑字典与直接给出的名字，根域名没有外发给第三方）")
	}
	if len(parts) == 0 {
		return "本轮枚举完整"
	}
	return strings.Join(parts, "；")
}
