package server

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// 经隧道/代理的扫描并发预算（F6）。
//
// 为什么要单独一层：一条 chisel/ssh 隧道是**单通道转发**，它的吞吐由那条 channel
// 决定，不由发起端调多并发决定。而一次漏扫在隧道上会同时做几件事——端口探测（原先
// 写死 200 并发）、nuclei（默认并发 25）、以及并行跑着的深挖任务里的 sqlmap/dalfox——
// 塞爆之后的现象不是「慢」，是超时潮：探测报「连不上」、POC 大面积不命中、专项验证判
// 「无法判定」，报告于是据一个被自己挤死的通道说这一片没问题。
//
// 两个旋钮，都可调、可整体关掉（关掉即回到 1.5.0 的行为）：
//   - 任务数上限：同一条隧道上同时允许几个重任务（默认 1）。超出的**留在队列里等**，
//     不判失败——队列不动是因为隧道忙，不是因为它坏了，任务列表会写明等待原因。
//   - 请求并发上限：隧道内单次运行的并发（默认 4）。nuclei 的 -concurrency/-rate-limit
//     按它收敛，端口探测并发按它放大 tunnelProbeFactor 倍推导。
const (
	settingTunnelConcurrencyOn = "tunnel_concurrency_enabled"
	settingTunnelTaskLimit     = "tunnel_concurrency_limit"
	settingTunnelRequestLimit  = "tunnel_request_concurrency_limit"
	// 未登记成隧道的代理端点（手写的 socks5://ip:port）是否也按隧道对待。默认按：
	// 分不清是不是单通道时，保守的一方是不把结论建在超时潮上。
	settingTunnelBudgetAnyProxy = "tunnel_budget_any_proxy"

	defaultTunnelTaskLimit    = 1
	defaultTunnelRequestLimit = 4
	tunnelProbeFactor         = 4
	tunnelRatePerRequest      = 10
	maxTunnelTaskLimit        = 32
	maxTunnelRequestLimit     = 64
)

// proxyBudget 是一次运行在隧道上该用的并发口径。ok=false 表示不受预算约束
// （没填代理、开关关着，或该端点不被当作隧道），按任务自己的并发跑。
type proxyBudget struct {
	ok         bool
	endpoint   string
	requests   int
	probes     int
	rateLimit  int
	taskLimit  int
	fromRecord bool // 这个端点是不是平台登记过的隧道
}

// proxyEndpoint 把代理地址摊成「host:port」的隧道身份。缺端口时按 scheme 补默认值：
// socks5://10.0.0.5 与 socks5://10.0.0.5:1080 是同一条通道，分成两个名额就漏了。
func proxyEndpoint(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.ToLower(raw)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "socks5", "socks5h", "socks", "socks4":
			port = "1080"
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	if strings.Contains(host, ":") { // IPv6 字面量带回方括号，否则 host:port 无法还原
		host = "[" + host + "]"
	}
	return strings.ToLower(host + ":" + port)
}

// tunnelSettings 读出预算开关与上限，全部钳制到合法区间。没有数据库时视为关闭：
// 「没有配置源就没有这一层」，与本仓库其它策略源的语义一致。
func (s *Server) tunnelSettings() (on bool, taskLimit, reqLimit int, anyProxy bool) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return false, defaultTunnelTaskLimit, defaultTunnelRequestLimit, true
	}
	on = s.m.pg.GetBool(settingTunnelConcurrencyOn, true)
	anyProxy = s.m.pg.GetBool(settingTunnelBudgetAnyProxy, true)
	taskLimit = settingIntClamped(s.m.pg, settingTunnelTaskLimit, defaultTunnelTaskLimit, 1, maxTunnelTaskLimit)
	reqLimit = settingIntClamped(s.m.pg, settingTunnelRequestLimit, defaultTunnelRequestLimit, 1, maxTunnelRequestLimit)
	return on, taskLimit, reqLimit, anyProxy
}

func settingIntClamped(getter interface {
	GetSetting(string) (string, bool, error)
}, key string, def, lo, hi int) int {
	raw, ok, err := getter.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	return min(max(n, lo), hi)
}

// budget 给出这一轮的并发口径。
func (s *Server) budget(rawProxy string) proxyBudget {
	endpoint := proxyEndpoint(rawProxy)
	on, taskLimit, reqLimit, anyProxy := s.tunnelSettings()
	if !on || endpoint == "" {
		return proxyBudget{endpoint: endpoint, taskLimit: taskLimit}
	}
	// 只认「平台登记且状态可用」的隧道记录。这里不能复用 intranetTunnelIdentity：
	// 它为了把目标解析到隧道另一头，会把任何非本机地址都当成隧道远端，拿来判身份
	// 就会把手写的 socks5://ip:port 也说成平台登记的隧道。
	fromRecord := false
	if s != nil && s.m != nil && s.m.pg != nil {
		if host, port, ok := splitHostPortLoose(endpoint); ok {
			if t, err := s.m.pg.LiveIntranetTunnelByListen(host, port); err == nil && t != nil {
				fromRecord = true
			}
		}
	}
	if !anyProxy && !fromRecord {
		return proxyBudget{endpoint: endpoint, taskLimit: taskLimit}
	}
	return proxyBudget{
		ok: true, endpoint: endpoint, requests: reqLimit,
		probes: reqLimit * tunnelProbeFactor, rateLimit: reqLimit * tunnelRatePerRequest,
		taskLimit: taskLimit, fromRecord: fromRecord,
	}
}

// clampNuclei 把一次 nuclei 调用的并发与限速收进预算里；不受约束时原样返回。
func (pb proxyBudget) clampNuclei(concurrency, rateLimit int) (int, int) {
	if !pb.ok {
		return concurrency, rateLimit
	}
	if concurrency <= 0 || concurrency > pb.requests {
		concurrency = pb.requests
	}
	if rateLimit <= 0 || rateLimit > pb.rateLimit {
		rateLimit = pb.rateLimit
	}
	return concurrency, rateLimit
}

// clampProbes 同理管住端口探测并发：200 个并发拨号灌进一条隧道，先垮的是隧道，
// 于是「哪些端口开放」这个结论本身就不成立了。
func (pb proxyBudget) clampProbes(concurrency int) int {
	if !pb.ok {
		return concurrency
	}
	return min(concOr(concurrency, pb.probes), pb.probes)
}

func concOr(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

func (pb proxyBudget) logLine() string {
	if !pb.ok {
		return ""
	}
	kind := "代理端点"
	if pb.fromRecord {
		kind = "平台登记的隧道"
	}
	return "本轮走" + kind + " " + pb.endpoint + "：nuclei 并发/限速收敛到 " +
		strconv.Itoa(pb.requests) + " / " + strconv.Itoa(pb.rateLimit) +
		"，端口探测并发收敛到 " + strconv.Itoa(pb.probes) +
		"，同一条隧道同时最多 " + strconv.Itoa(pb.taskLimit) + " 个重任务（超出的排队等待，不算失败）"
}

// tunnelBudget 是进程内的隧道占用表。只做进程内计数是有意的：部署形态是单实例容器，
// 重启时正在跑的任务会被 RecoverInterrupted* 判失败重跑，占用表随之清零正好；跨进程
// 共享需要数据库顾问锁，那会把「排队」变成谁抢到谁跑的隐式行为，不如现在这样可解释。
type tunnelBudget struct {
	mu   sync.Mutex
	used map[string]int
}

func newTunnelBudget() *tunnelBudget {
	return &tunnelBudget{used: map[string]int{}}
}

// acquire 占一个名额；false 表示这条隧道满了，调用方应当继续排队。
func (t *tunnelBudget) acquire(pb proxyBudget) bool {
	if !pb.ok {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.used[pb.endpoint] >= max(pb.taskLimit, 1) {
		return false
	}
	t.used[pb.endpoint]++
	return true
}

func (t *tunnelBudget) release(pb proxyBudget) {
	if !pb.ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if n := t.used[pb.endpoint] - 1; n > 0 {
		t.used[pb.endpoint] = n
	} else {
		delete(t.used, pb.endpoint)
	}
}

func (t *tunnelBudget) snapshot() []map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := []map[string]any{}
	for endpoint, used := range t.used {
		out = append(out, map[string]any{"endpoint": endpoint, "used": used})
	}
	return out
}

// occupancy 报某条端点上当前的占用数，给「为什么在排队」那句话用。
func (t *tunnelBudget) occupancy(endpoint string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.used[endpoint]
}

// queueNote 是给运维看的一句话：任务停在队列里是因为隧道忙，不是因为平台坏了。
func queueNote(pb proxyBudget, used int) string {
	if pb.endpoint == "" {
		return ""
	}
	return "隧道/代理 " + pb.endpoint + " 上已有 " + strconv.Itoa(used) + " 个任务在跑（预算 " +
		strconv.Itoa(pb.taskLimit) + "），排队等待；要放宽就调高「隧道并发预算」"
}

// SetTunnelConcurrency 保存预算。nil 字段表示不动当前值（表单是部分提交的）。
// 越界的数字被钳制到合法区间而不是整个请求被拒：UI 上一个手抖的 0 不该把预算
// 变成「不限」，也不该让保存失败得莫名其妙。
func (s *Server) SetTunnelConcurrency(on *bool, taskLimit, reqLimit *int, anyProxy *bool) error {
	if s == nil || s.m == nil || s.m.pg == nil {
		return fmt.Errorf("隧道并发预算需要数据库配置源")
	}
	pg := s.m.pg
	if on != nil {
		if err := pg.SetSetting(settingTunnelConcurrencyOn, strconv.FormatBool(*on)); err != nil {
			return err
		}
	}
	if anyProxy != nil {
		if err := pg.SetSetting(settingTunnelBudgetAnyProxy, strconv.FormatBool(*anyProxy)); err != nil {
			return err
		}
	}
	if taskLimit != nil {
		if err := pg.SetSetting(settingTunnelTaskLimit, strconv.Itoa(min(max(*taskLimit, 1), maxTunnelTaskLimit))); err != nil {
			return err
		}
	}
	if reqLimit != nil {
		if err := pg.SetSetting(settingTunnelRequestLimit, strconv.Itoa(min(max(*reqLimit, 1), maxTunnelRequestLimit))); err != nil {
			return err
		}
	}
	// 调高上限后立刻催一轮认领：排队的原因刚刚消失，不该等下一个 20~30 秒的 tick。
	if s.scanMgr != nil {
		s.scanMgr.wakeup()
	}
	if s.deepMgr != nil {
		s.deepMgr.wakeup()
	}
	return nil
}
