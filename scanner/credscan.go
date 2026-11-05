// Package-level 定位（对外一律叫「弱口令检测」，内部标识符保留 credscan）：
//
//	本模块只负责测出并记下这一条事实——某资产的某协议存在某组可用凭据。
//	它不编排别的模块，不自动触发任何动作，不自动复用凭据。
//
// 「联动」= 数据可见，不是流程耦合：资产页/拓扑看到 service 行、发现列表拿到一条带原始
// 协议字节的 weak-credential finding、凭据库多一条 source=weakpass 的记录、LLM 通过已有的
// 资产/凭据查询工具自己读到「这条路可走」、报告自动进弱口令章节。用不用这些凭据，由人决定。
//
// 端口决策三级优先（CredPlan 实现的就是这三条）：
//  1. 输入显式带端口（ip:port / [ipv6]:port / domain:port）→ 只用该端口，不再猜别的端口；
//  2. 未带端口，但端口探测/指纹已判定 host:port 属于某服务 → 按该服务测；
//  3. 只给 IP/域名且探测无结果 → 用协议默认端口表挑「要测哪些端口」。
//
// 硬约束：默认端口表**只用于决定测哪个端口，绝不用于推断该端口是什么协议**。协议判定只认
// banner/指纹或握手确认（CredEndpoint.ProtocolConfirmed），否则 2222 上的 HTTP 会被当 SSH
// 打字典——那份证据从此是假的，比不测更坏。
package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// CredOutcome 是一次「host:port × 协议 × 凭据」尝试的结果。六个态里只有 hit/deny 是
// 非黑即白；其余四个态存在的意义是：报告必须能区分「验证过不存在弱口令」与「没测出来」。
// 少一个态，就只能把没测的写成测过的。
type CredOutcome string

const (
	CredHit          CredOutcome = "hit"          // 凭据可用（有握手层证据）
	CredDeny         CredOutcome = "deny"         // 服务明确拒绝该凭据
	CredUnreachable  CredOutcome = "unreachable"  // 连不上/传输层中断，谈不上认证
	CredLocked       CredOutcome = "locked"       // 目标提示账号锁定或触发锁定策略，立即停手
	CredInconclusive CredOutcome = "inconclusive" // 不可判定：预算耗尽、超时、握手无法完成
	CredUnsupported  CredOutcome = "unsupported"  // 该协议的握手形态本平台不实现，不发起任何连接
)

// Credential 是一组待验证的用户名口令。
type Credential struct {
	Username string
	Password string
}

// CredService 是端口探测/指纹给出的「host:port 属于这个服务」这一事实。
type CredService struct {
	Host     string
	Port     int
	Protocol string
	// Banner 是判定依据。空 banner 不算判定过——协议名不能凭空填。
	Banner string
}

// CredEndpoint 是一个待测目标端口，带上了「协议是怎么知道的」。
type CredEndpoint struct {
	Host     string
	Port     int
	Protocol string
	// ProtocolSource 记录协议来源：explicit（输入带端口且指纹确认）、fingerprint、default_table。
	ProtocolSource string
	// ProtocolConfirmed 为 false 时，适配器必须先做握手识别，认不出来就报 inconclusive；
	// 引擎绝不允许「按默认端口表猜的协议」直接进字典循环。
	ProtocolConfirmed bool
	// Params 是协议自己的额外参数（PostgreSQL/MongoDB 的库名、MongoDB 的 authSource）。
	// 用约定键名，不给每个协议加字段：适配器不认识的键必须被忽略而不是报错。
	Params map[string]string
}

// CredParamDatabase / CredParamAuthSource 是 Params 的约定键名。
const (
	CredParamDatabase   = "database"
	CredParamAuthSource = "auth_source"
	// CredParamMechanism 用来点名认证机制（SCRAM-SHA-1 与 SCRAM-SHA-256 这类）。
	// 一个协议里的不同机制是不同数学，验一个不等于验全部，所以必须能被显式指定。
	CredParamMechanism = "mechanism"
	// CredParamPath 是 HTTP 家族（Basic / WebDAV / 控制台）的登录路径：
	// 后台经常挂在 /manager、/dav 这类前缀下，路径写死会让适配器只测首页。
	CredParamPath = "path"
)

// CredParam 取协议参数，缺省回落到 def（Params 为 nil 也要能用，所以是函数而不是方法）。
func CredParam(ep CredEndpoint, key, def string) string {
	if v := strings.TrimSpace(ep.Params[key]); v != "" {
		return v
	}
	return def
}

const (
	CredProtocolSourceExplicit    = "explicit"
	CredProtocolSourceFingerprint = "fingerprint"
	CredProtocolSourceDefaultPort = "default_table"
)

// credDefaultPorts 是第三级用的默认端口表：key 是协议名，value 是该协议最常见的端口。
// 再强调一次：这张表只回答「去测哪个端口」，不回答「那个端口是什么协议」。
var credDefaultPorts = map[string]int{
	"ssh": 22, "mysql": 3306, "postgresql": 5432, "redis": 6379, "mongodb": 27017,
	"ftp": 21, "telnet": 23, "socks5": 1080, "memcached": 11211, "elasticsearch": 9200,
	"vnc": 5900, "zookeeper": 2181, "smtp": 25, "pop3": 110, "imap": 143,
	"smtp-ssl": 465, "pop3-ssl": 995, "imap-ssl": 993, "ldap": 389, "ldaps": 636,
	"snmp": 161, "http-basic": 80, "webdav": 80, "tomcat-console": 8080,
}

// credUnsupportedProtocols 是三档：握手不透明或版本差异太大，第一版显式报「不支持」。
// 报不支持比给一个不可信的结果好——后者会进报告、进资产页、进人的决策。
var credUnsupportedProtocols = map[string]bool{
	"rdp": true, "weblogic-console": true, "jboss-console": true,
}

// CredDefaultPort 返回协议的常见端口（0 表示没有默认端口，例如纯 HTTP 形态）。
func CredDefaultPort(protocol string) int {
	return credDefaultPorts[strings.ToLower(strings.TrimSpace(protocol))]
}

// CredProtocolKnown 报告该协议名是否是本模块认识的协议。
func CredProtocolKnown(protocol string) bool {
	p := strings.ToLower(strings.TrimSpace(protocol))
	if p == "" {
		return false
	}
	if _, ok := credDefaultPorts[p]; ok {
		return true
	}
	return CredAdapterFor(p) != nil
}

// CredProtocolSupported 区分「认识但不实现」与「认识且能测」。
func CredProtocolSupported(protocol string) bool {
	return !credUnsupportedProtocols[strings.ToLower(strings.TrimSpace(protocol))]
}

// CredAttempt 是一次尝试的完整记录，含证据字节。
type CredAttempt struct {
	Host     string      `json:"host"`
	Port     int         `json:"port"`
	Protocol string      `json:"protocol"`
	Cred     Credential  `json:"cred"`
	Outcome  CredOutcome `json:"outcome"`
	Banner   string      `json:"banner,omitempty"`
	// TLS 为真时上面的字节是 TLS 通道内的明文。不标出来，复现命令就会写成一条裸 socket
	// ——照着发必然拿不到同样的响应。
	TLS     bool   `json:"tls,omitempty"`
	RawReq  []byte `json:"-"`
	RawResp []byte `json:"-"`
	// EvidenceText 非空时 Evidence 直接用它。SSH 这类「KEX 之后全是密文」的协议需要
	// 自己写证据，套通用模板会生成一条照做也复现不出结论的裸 socket 命令。
	EvidenceText string        `json:"-"`
	Attempts     int           `json:"attempts"`
	Elapsed      time.Duration `json:"elapsed_ms"`
	Reason       string        `json:"reason,omitempty"`
}

// Evidence 出证据文本。非 HTTP 协议走 #81 定下的原始字节通道：请求与响应都要能逐字节复现。
// 两条通道不能混用：只有响应字节（Identify 阶段被动读 banner）才用 banner 格式，一旦发过
// 请求字节，banner 格式那句「扫描器未发送任何应用层请求字节」就成了假记录。
// 口令在这里是明文——它本来就是「可用凭据」这份发现的内容，脱敏会删掉结论本身。
func (a CredAttempt) Evidence() string {
	if strings.TrimSpace(a.EvidenceText) != "" {
		return a.EvidenceText
	}
	if len(a.RawReq) == 0 && len(a.RawResp) == 0 {
		// 没有字节的结果只能是「没测出来」，此时 reason 就是全部可解释的信息。
		if strings.TrimSpace(a.Reason) == "" {
			return ""
		}
		return a.Reason
	}
	addr := net.JoinHostPort(a.Host, fmt.Sprint(a.Port))
	head := ProtocolBannerPacket(a.Protocol, addr, a.RawResp)
	if len(a.RawReq) > 0 {
		head = ProtocolExchangePacket(a.Protocol, addr, a.RawReq, a.RawResp)
	}
	tail := "\n凭据: " + a.Cred.Username + " / " + a.Cred.Password
	if a.TLS {
		tail += "\n以上字节是 TLS 通道内的明文；复现要用支持 TLS 的客户端（psql / mysql --ssl-mode / openssl s_client），裸 socket 发不出去"
	}
	if r := strings.TrimSpace(a.Reason); r != "" {
		tail += "\n判定说明: " + r
	}
	return head + tail
}

// CredAdapter 是一个协议的认证探针实现。实现者的三条纪律：
//
//  1. 只有拿到握手层的「接受」信号才返回 hit；连接断了、TLS 没起来、超时，一律
//     unreachable/inconclusive，不能因为「试了没报错」就算命中。
//  2. 观察到锁定语义（错误码/文案）时返回 locked，引擎会立刻对该端点停手。
//  3. 每次尝试都要留下可复现的字节（RawReq/RawResp），否则这条结果无法进报告。
type CredAdapter interface {
	Protocol() string
	// Identify 在字典循环之前确认端口上的协议。返回 confirmed=false 时引擎不得继续猜测。
	Identify(ctx context.Context, ep CredEndpoint) (confirmed bool, banner string, err error)
	// Try 验证一组凭据。实现不得在 ctx 已取消时返回 hit。
	//
	// 收整个端点而不是地址串：库名、MongoDB 的 authSource 这类协议参数挂在端点上，
	// 只给 addr 的话适配器就拿不到它们，只能靠调用方改全局状态——那是并发结果互相污染的起点。
	Try(ctx context.Context, ep CredEndpoint, cred Credential) (CredAttempt, error)
}

var (
	credAdapterMu sync.RWMutex
	credAdapters  = map[string]CredAdapter{}
)

// RegisterCredAdapter 注册协议适配器（由各协议文件在 init 中调用）。重复注册是编程错误：
// 两个实现同时存在时，谁生效取决于注册顺序，字典会在两个协议实现间随机漂移。
func RegisterCredAdapter(a CredAdapter) {
	if a == nil {
		return
	}
	key := strings.ToLower(strings.TrimSpace(a.Protocol()))
	credAdapterMu.Lock()
	defer credAdapterMu.Unlock()
	if prev, dup := credAdapters[key]; dup && prev != a {
		panic("credscan: 协议适配器重复注册 " + key)
	}
	credAdapters[key] = a
}

// CredAdapterFor 取适配器；nil 表示该协议没有实现（调用方应落 unsupported，而不是跳过）。
func CredAdapterFor(protocol string) CredAdapter {
	key := strings.ToLower(strings.TrimSpace(protocol))
	credAdapterMu.RLock()
	defer credAdapterMu.RUnlock()
	return credAdapters[key]
}

// CredAdapters 列出已注册的协议名（前端协议选择器与「不支持」提示都以此为准）。
func CredAdapters() []string {
	credAdapterMu.RLock()
	defer credAdapterMu.RUnlock()
	out := make([]string, 0, len(credAdapters))
	for k := range credAdapters {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CredPlan 按三级优先把「解析后的目标 + 已探测到的服务」变成待测端点列表。
//
// 第一级里，输入带端口但没人知道端口上是什么协议时，Protocol 留空、ProtocolConfirmed=false：
// 让引擎去 Identify，而不是拿端口号去猜一个协议。
func CredPlan(targets []Target, services []CredService, protocols []string) ([]CredEndpoint, error) {
	if len(targets) == 0 {
		return nil, errors.New("至少需要一个有效目标")
	}
	want := map[string]bool{}
	for _, p := range protocols {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			want[p] = true
		}
	}
	byHost := map[string][]CredService{}
	for _, s := range services {
		h := strings.ToLower(strings.TrimSpace(s.Host))
		if h == "" || s.Port <= 0 || strings.TrimSpace(s.Protocol) == "" {
			// 没有 banner/协议名的「服务」不是一次判定结果，不能当第二级用。
			continue
		}
		byHost[h] = append(byHost[h], s)
	}

	seen := map[string]bool{}
	out := []CredEndpoint{}
	add := func(e CredEndpoint) {
		key := fmt.Sprintf("%s|%d|%s|%s", strings.ToLower(e.Host), e.Port, e.Protocol, e.ProtocolSource)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, e)
	}

	for _, t := range targets {
		host := strings.ToLower(strings.TrimSpace(t.Host))
		if host == "" {
			continue
		}
		// 第一级：输入显式带端口。
		if t.Port > 0 {
			confirmed := false
			proto := ""
			for _, s := range byHost[host] {
				if s.Port == t.Port {
					proto, confirmed = strings.ToLower(s.Protocol), true
					break
				}
			}
			if len(want) > 0 {
				if confirmed && !want[proto] {
					// 指纹说这个端口是 A 协议，而用户只勾了 B：不测，而不是把 B 的字典
					// 打到 A 上。这是「不靠端口猜协议」的另一半。
					continue
				}
				if !confirmed {
					// 未确认协议时按勾选逐个建端点，由引擎在连接后 Identify 决定谁真的在听。
					for p := range want {
						add(CredEndpoint{Host: host, Port: t.Port, Protocol: p,
							ProtocolSource: CredProtocolSourceExplicit})
					}
					continue
				}
			}
			add(CredEndpoint{Host: host, Port: t.Port, Protocol: proto,
				ProtocolSource: CredProtocolSourceExplicit, ProtocolConfirmed: confirmed})
			continue
		}
		// 第二级：探测与指纹已经说了 host:port 属于哪个服务。
		found := false
		for _, s := range byHost[host] {
			p := strings.ToLower(s.Protocol)
			if len(want) > 0 && !want[p] {
				continue
			}
			found = true
			add(CredEndpoint{Host: host, Port: s.Port, Protocol: p,
				ProtocolSource: CredProtocolSourceFingerprint, ProtocolConfirmed: true})
		}
		if found {
			continue
		}
		// 第三级：默认端口表。协议名要么来自勾选，要么来自已注册适配器；两者都没有时
		// 不产出端点，而不是随便挑一个协议。
		list := []string{}
		if len(want) > 0 {
			for p := range want {
				list = append(list, p)
			}
		} else {
			list = CredAdapters()
		}
		for _, p := range list {
			port := CredDefaultPort(p)
			if port <= 0 {
				continue
			}
			add(CredEndpoint{Host: host, Port: port, Protocol: p,
				ProtocolSource: CredProtocolSourceDefaultPort})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Protocol < out[j].Protocol
	})
	if len(out) == 0 {
		return nil, errors.New("没有可测端点：目标上没有探测到服务，且未指定协议")
	}
	return out, nil
}

// CredOptions 是引擎的运行边界。零值都有明确含义，不做「0 表示无限」。
type CredOptions struct {
	Concurrency int           // 同时进行的端点数，<=0 用默认
	RateLimit   int           // 每秒发起的尝试数，<=0 表示不限速
	Budget      time.Duration // 整个任务的墙钟预算，<=0 用默认
	// StopLossAfter 是同一端点连续多少次传输层失败后放弃该端点（<=0 用默认）。
	StopLossAfter int
	// StopAfterDenies 是同一账号连续多少次「明确拒绝」后停止再试该账号（<=0 用默认）。
	// 防的是账号锁定：拒绝是「这组口令不对」，连着错 N 次就可能把账号锁死，
	// 余下的口令组只能记「没测」，不能拿别人的账号去赌。
	StopAfterDenies int
}

const (
	credDefaultConcurrency = 16
	credDefaultBudget      = 10 * time.Minute
	credDefaultStopLoss    = 3
	credDefaultDenyStop    = 5
)

func (o CredOptions) normalized() CredOptions {
	if o.Concurrency <= 0 {
		o.Concurrency = credDefaultConcurrency
	}
	if o.Concurrency > 128 {
		o.Concurrency = 128
	}
	if o.Budget <= 0 {
		o.Budget = credDefaultBudget
	}
	if o.StopLossAfter <= 0 {
		o.StopLossAfter = credDefaultStopLoss
	}
	if o.StopAfterDenies <= 0 {
		o.StopAfterDenies = credDefaultDenyStop
	}
	return o
}

// CredRun 对每个端点按凭据顺序做认证尝试，边跑边通过 emit 交出结果。
//
// 三条止损纪律，都是为了让报告不说谎：
//   - 预算耗尽：剩余端点/凭据逐个落 inconclusive（reason 写明 budget），不静默跳过；
//   - 同一端点连续 StopLossAfter 次传输层失败：该端点余下凭据落不可判定并停止连接；
//   - 任何一次 locked：该端点立即停止（账号锁定不是可以靠重试克服的障碍）。
//
// emit 由引擎**串行**调用（内部有序列化锁），实现方不必自己加锁；多次结果之间的先后
// 不保证（端点是并发的），但 CredRun 返回时全部结果都已交出——任务状态与结果行不能有两张皮。
// 每个 (endpoint, credential) 恰好出一次结果；例外是该端点先命中或触发锁定，那时余下凭据
// 根本不该再去试。
func CredRun(ctx context.Context, plan []CredEndpoint, creds []Credential, opts CredOptions,
	emit func(CredAttempt)) error {
	if emit == nil {
		return errors.New("credscan: 缺少结果回调")
	}
	if len(plan) == 0 {
		return errors.New("credscan: 没有待测端点")
	}
	if len(creds) == 0 {
		return errors.New("credscan: 没有可用凭据（字典为空不构成「已验证不存在弱口令」）")
	}
	opts = opts.normalized()
	// 预算用「派生 context + 非阻塞检查」实现，不是在 select 里等定时器：等定时器会把
	// 整个循环卡在第一次 select 上，默认预算 10 分钟就变成「什么都不测，干等 10 分钟」。
	// 派生 context 还顺带把预算交给适配器——在途的那次握手到点就会被掐断。
	runCtx, cancelRun := context.WithTimeout(ctx, opts.Budget)
	defer cancelRun()

	var emitMu sync.Mutex
	serialEmit := func(a CredAttempt) {
		emitMu.Lock()
		defer emitMu.Unlock()
		emit(a)
	}

	var rate <-chan time.Time
	if opts.RateLimit > 0 {
		tick := time.NewTicker(time.Second / time.Duration(opts.RateLimit))
		defer tick.Stop()
		rate = tick.C
	}

	// 每个端点自己决定何时不再连接，锁在 per-endpoint 状态里而不是全局计数——
	// 一台机器的 22 端口连不上，不该让它同机的 3306 也一起放弃。
	states := make([]*credEndpointState, len(plan))
	for i := range states {
		states[i] = &credEndpointState{}
	}

	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	// 收尾只补「还没交出去的端点」：启动严格按序，检查点在 i 时 0..i-1 都已归 goroutine 负责，
	// 再补一行等于把同一次尝试在报告里记两遍。
	skipFrom := func(i int, reason string) {
		for ; i < len(plan); i++ {
			for _, c := range creds {
				serialEmit(CredAttempt{Host: plan[i].Host, Port: plan[i].Port, Protocol: plan[i].Protocol,
					Cred: c, Outcome: CredInconclusive, Reason: reason})
			}
		}
	}
	budgetReason := fmt.Sprintf("budget: 任务预算 %s 已耗尽，未发起连接", opts.Budget)
	cancelReason := "任务已取消，未发起连接"
	budgeted := false

	for i := range plan {
		if ctx.Err() != nil {
			skipFrom(i, cancelReason)
			break
		}
		if runCtx.Err() != nil {
			budgeted = true
			skipFrom(i, budgetReason)
			break
		}
		endpoint := plan[i]
		state := states[i]
		// 取空位可能一直阻塞，但每次尝试都受 runCtx 的预算约束，到点必然返回、空位必然释放。
		sem <- struct{}{}
		wg.Add(1)
		go func(endpoint CredEndpoint, state *credEndpointState) {
			defer wg.Done()
			defer func() { <-sem }()
			runCredEndpoint(ctx, runCtx, endpoint, creds, opts, rate, state, serialEmit)
		}(endpoint, state)
	}
	wg.Wait()
	if budgeted || ctx.Err() == nil {
		// 预算耗尽不是失败：每个端点×凭据都留下了判定行，调用方按行渲染即可。
		return nil
	}
	return ctx.Err()
}

// credEndpointState 是一个端点自己的止损状态。abandoned/locked 一旦置位就对该端点生效到
// 任务结束：锁定与「这台机器这个端口不通」都不是重试能解决的。
type credEndpointState struct {
	mu        sync.Mutex
	consec    int
	abandoned bool
	locked    bool
	// denyUser 记「这个用户名连续被拒了几次」。按账号而不是按端点计数：
	// root 错了 5 次不代表 admin 也会被锁，为 root 停手不该牺牲 admin 的覆盖。
	denyUser map[string]int
	// blockedUser 是已经停手的目标账号，余下口令组记不可判定。
	blockedUser map[string]bool
}

// runCredEndpoint 跑完一个端点，并保证「要么发起尝试，要么留下一行交代为什么没试」——
// 少了行，报告就成了「这个端口测过了」。
// ctx 是调用方的取消上下文，runCtx 是叠上预算的执行上下文：两者要分开，否则预算到点会被
// 写成「任务已取消」，读者分不清是自己停的手还是时间用完了。
func runCredEndpoint(ctx, runCtx context.Context, endpoint CredEndpoint, creds []Credential,
	opts CredOptions, rate <-chan time.Time, state *credEndpointState, emit func(CredAttempt)) {
	attemptNo := 0
	stopReason := func() string {
		switch {
		case ctx.Err() != nil:
			return "任务已取消，未发起该次尝试"
		case runCtx.Err() != nil:
			return fmt.Sprintf("任务预算 %s 已耗尽，该组凭据未尝试", opts.Budget)
		}
		return ""
	}

	// 不支持的协议：一个包都不发。前端与报告据此写「该协议暂不支持」，
	// 而不是留一个空结果让人以为测过了。
	if !CredProtocolSupported(endpoint.Protocol) {
		for _, c := range creds {
			emit(CredAttempt{Host: endpoint.Host, Port: endpoint.Port, Protocol: endpoint.Protocol,
				Cred: c, Outcome: CredUnsupported, Reason: "该协议的握手形态本平台不实现，未发起连接"})
		}
		return
	}
	adapter := CredAdapterFor(endpoint.Protocol)
	if adapter == nil {
		// 认不出实现＝没测。落 unsupported 而不是 deny，否则报告里就成了「已验证无弱口令」。
		for _, c := range creds {
			emit(CredAttempt{Host: endpoint.Host, Port: endpoint.Port, Protocol: endpoint.Protocol,
				Cred: c, Outcome: CredUnsupported, Reason: "该协议尚未实现，未发起连接"})
		}
		return
	}

	// 协议确认：默认端口表挑出来的端口必须先问「你真的是这个协议吗」。
	// 认不出来就整批 inconclusive——继续打字典只会产出无法复现的假证据。
	if !endpoint.ProtocolConfirmed {
		if rate != nil {
			waitCredRate(runCtx, rate)
		}
		// 单次尝试的上限归引擎，不归适配器：一个卡住的握手如果不被掐掉，就会把整批
		// 预算吃掉，剩下的端点全部记成「预算耗尽」——那些行跟这台机器没关系。
		ictx, icancel := context.WithTimeout(runCtx, credAttemptTimeout)
		confirmed, banner, err := adapter.Identify(ictx, endpoint)
		icancel()
		if err != nil || !confirmed {
			reason := "端口上没有确认出该协议的握手特征"
			if err != nil {
				reason = "协议识别失败：" + err.Error()
			}
			for _, c := range creds {
				attemptNo++
				emit(CredAttempt{Host: endpoint.Host, Port: endpoint.Port, Protocol: endpoint.Protocol,
					Cred: c, Outcome: CredInconclusive, Banner: strings.TrimSpace(banner),
					Attempts: attemptNo, Reason: reason})
			}
			return
		}
		endpoint.ProtocolConfirmed = true
	}

	for _, cred := range creds {
		if reason := stopReason(); reason != "" {
			emit(CredAttempt{Host: endpoint.Host, Port: endpoint.Port, Protocol: endpoint.Protocol,
				Cred: cred, Outcome: CredInconclusive, Reason: reason})
			continue
		}
		state.mu.Lock()
		done := state.locked || state.abandoned
		consec, locked := state.consec, state.locked
		userBlocked := state.blockedUser[cred.Username]
		userDenies := state.denyUser[cred.Username]
		state.mu.Unlock()
		if done {
			reason := "该端点已触发账号锁定，余下凭据不再尝试"
			if !locked {
				reason = fmt.Sprintf("该端点连续 %d 次传输层失败，已放弃", consec)
			}
			emit(CredAttempt{Host: endpoint.Host, Port: endpoint.Port, Protocol: endpoint.Protocol,
				Cred: cred, Outcome: CredInconclusive, Reason: reason})
			continue
		}
		if userBlocked {
			// 账号已经连续被拒到达上限：再试可能把它锁死。余下的口令组是「没测」，
			// 不是「也错了」——拒绝只能由服务端亲口说。
			emit(CredAttempt{Host: endpoint.Host, Port: endpoint.Port, Protocol: endpoint.Protocol,
				Cred: cred, Outcome: CredInconclusive, Attempts: 0,
				Reason: fmt.Sprintf("账号 %q 连续 %d 次认证失败，为避免触发账号锁定已停止尝试该账号", cred.Username, userDenies)})
			continue
		}
		if rate != nil {
			waitCredRate(runCtx, rate)
		}
		attemptNo++
		start := time.Now()
		tctx, tcancel := context.WithTimeout(runCtx, credAttemptTimeout)
		res, err := adapter.Try(tctx, endpoint, cred)
		tcancel()
		res.Host, res.Port, res.Protocol, res.Cred = endpoint.Host, endpoint.Port, endpoint.Protocol, cred
		res.Attempts = attemptNo
		res.Elapsed = time.Since(start).Truncate(time.Millisecond)
		if res.Outcome == "" {
			// 适配器没给态就是没测出来，绝不能默认 deny（deny 在报告里等于「这组口令被明确拒绝」）。
			res.Outcome = CredInconclusive
			if strings.TrimSpace(res.Reason) == "" {
				res.Reason = "适配器未给出判定"
			}
		}
		if err != nil && res.Outcome != CredHit {
			res.Reason = strings.TrimSpace(res.Reason + "：" + err.Error())
		}
		switch res.Outcome {
		case CredUnreachable:
			state.mu.Lock()
			state.consec++
			if state.consec >= opts.StopLossAfter {
				state.abandoned = true
			}
			state.mu.Unlock()
		case CredLocked:
			state.mu.Lock()
			state.locked = true
			state.mu.Unlock()
		case CredDeny:
			state.mu.Lock()
			state.consec = 0
			if state.denyUser == nil {
				state.denyUser = map[string]int{}
			}
			state.denyUser[cred.Username]++
			if state.denyUser[cred.Username] >= opts.StopAfterDenies {
				if state.blockedUser == nil {
					state.blockedUser = map[string]bool{}
				}
				state.blockedUser[cred.Username] = true
			}
			state.mu.Unlock()
		case CredHit:
			state.mu.Lock()
			state.consec = 0
			delete(state.denyUser, cred.Username)
			state.mu.Unlock()
		}
		emit(res)
		if res.Outcome == CredHit || res.Outcome == CredLocked {
			// 命中就停这个端点（继续试只会多打一遍日志），锁定更要停手。
			break
		}
	}
}

func waitCredRate(ctx context.Context, rate <-chan time.Time) {
	if rate == nil {
		return
	}
	select {
	case <-rate:
	case <-ctx.Done():
	}
}
