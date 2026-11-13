package llmrec

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"
)

// 错误分类（R21 §5.4 ③）。不把错误分类，就只能统一重试，于是「中转端流被重置」
// 「账户欠费」「DNS 把域名解析到回环」在系统里看起来一模一样——实测里这几种各占
// 了不少轮次，处置完全不同（该重试 / 该换端点 / 该修解析器 / 该改模型名）。
//
// 分类只看两类证据：调用方给出的错误，以及我们自己的墙钟。**不从自由文本里猜语义**，
// 只认协议层可观察的形态（HTTP 状态码、net 错误链、明确的传输错误串）。
//
// 2026-11-12 重做（R21 缺口①）：先前的实现拿 `strings.Contains(msg,"401")` 这类
// 裸数字去匹配，会把端口号、token 片段、body 里的业务数字一并命中；而且没有
// 「端点不可达」与「上游 5xx」两类，实测 5 种处置完全不同的故障全落进 `other`。
type ErrorClass string

const (
	ErrClassTransportReset ErrorClass = "transport_reset" // HTTP/2 stream reset、连接被对端重置
	ErrClassStalled        ErrorClass = "stalled"         // 建连成功但 T1 内无首帧
	ErrClassRateLimited    ErrorClass = "rate_limited"    // 429 / Retry-After
	ErrClassAccountInvalid ErrorClass = "account_invalid" // 401/402/403（欠费/未订阅/鉴权失败）
	ErrClassUnreachable    ErrorClass = "unreachable"     // DNS 解析失败 / 连接被拒 / 无路由
	ErrClassUpstream5xx    ErrorClass = "upstream_5xx"    // 502/503/504 网关与上游故障
	ErrClassModelNotFound  ErrorClass = "model_not_found" // 404 模型名不被该分组支持
	ErrClassEmptyResponse  ErrorClass = "empty_response"  // 完成但无内容块
	ErrClassTimeout        ErrorClass = "timeout"         // 我们主动设的墙钟/首帧超时
	ErrClassOther          ErrorClass = "other"
)

// AllErrorClasses 是判据里「必须能分开」的类别清单，夹具与前端共用，
// 避免两边各写一份字符串。
var AllErrorClasses = []ErrorClass{
	ErrClassTransportReset, ErrClassStalled, ErrClassRateLimited, ErrClassAccountInvalid,
	ErrClassUnreachable, ErrClassUpstream5xx, ErrClassModelNotFound,
	ErrClassEmptyResponse, ErrClassTimeout, ErrClassOther,
}

// 状态码只认「标准形态」，不认裸数字：`status 502`、`HTTP 502`、`502 Bad Gateway`、
// `code=502` 都算，而 `:5021` 这种端口、`token 502a` 这类不算。
//
// 只对 4xx/5xx 生效——2xx/3xx 出现在错误文本里通常不是本次调用的状态码。
var statusCodeRe = regexp.MustCompile(`(?i)(?:\bstatus\b|\bhttp(?:/\d(?:\.\d)?)?\b|\bcode\b|^|\s)[\s:=]*(\d{3})\b`)

// ClassifyError 把一次 LLM 调用的错误归到一类。
//
// 判据顺序（确定性从强到弱）：
//  1. 我们自己 cancel 的超时 —— 这不是对端的问题，优先判出来，否则会被
//     下游包装成 `context canceled` 而落进 other（实测缺口⑧的另一半）。
//  2. HTTP 状态码 —— 协议层事实，最可靠。
//  3. net 错误链 —— 解析/拨号/DNS，处置是「修解析器或换端点」而不是重试。
//  4. 文本形态 —— 只在没有前三种证据时兜底，且只认强特征串。
func ClassifyError(err, wallErr error) ErrorClass {
	if err == nil && wallErr == nil {
		return ""
	}
	// ① 我们自己的墙钟/首帧超时：先于一切。注意调用方可能把 ctx 错误包了一层，
	// 所以 err 与 wallErr 两边都要看。
	if isOwnDeadline(err) || isOwnDeadline(wallErr) {
		return ErrClassTimeout
	}
	// 我们自己 cancel（stalled 路径）被下游包成 context.Canceled 时，归到 stalled
	// 由调用方显式指定；这里不猜，交给 stalled 的记账点。

	if err == nil {
		return ErrClassOther
	}

	// ② 状态码。
	if code := statusCodeOf(err); code > 0 {
		switch {
		case code == 404:
			// 404 有两种：模型名不被支持（该改模型名）与端点路径写错（该改 base_url）。
			// 前者在中转端有明确文案，这里能分就分，分不出仍归 404 但让文案带上下文。
			if looksLikeModelNotFound(err) {
				return ErrClassModelNotFound
			}
			return ErrClassModelNotFound
		case code == 401 || code == 402 || code == 403:
			return ErrClassAccountInvalid
		case code == 429:
			return ErrClassRateLimited
		case code == 408 || code == 504:
			// 504 是上游网关超时：对端接住了请求但后端没按时回，处置是重试/换端点，
			// 不是「我们等太久」——所以不能判成 timeout。
			return ErrClassUpstream5xx
		case code >= 500:
			return ErrClassUpstream5xx
		}
	}

	// ③ net 错误链：DNS / 拨号 / 路由。这类重试没有意义（同一条解析器还是坏），
	// 必须让运维一眼看出「该修解析器还是该换端点」。
	if isUnreachable(err) {
		return ErrClassUnreachable
	}

	msg := strings.ToLower(err.Error())

	// ④ 文本兜底：只认强特征。
	for _, tok := range []string{"insufficient_quota", "insufficient quota", "billing", "payment required", "invalid api key", "no available subscription"} {
		if strings.Contains(msg, tok) {
			return ErrClassAccountInvalid
		}
	}
	for _, tok := range []string{"rate limit", "too many requests", "retry-after", "upstream rate limit"} {
		if strings.Contains(msg, tok) {
			return ErrClassRateLimited
		}
	}
	for _, tok := range []string{"upstream request failed", "bad gateway", "gateway timeout", "service unavailable", "upstream connect error"} {
		if strings.Contains(msg, tok) {
			return ErrClassUpstream5xx
		}
	}
	for _, tok := range []string{"model_not_found", "model not found", "is not supported by any configured account", "does not exist", "no such model"} {
		if strings.Contains(msg, tok) {
			return ErrClassModelNotFound
		}
	}
	for _, tok := range []string{"stream error", "stream id", "internal_error", "connection reset by peer", "broken pipe", "http2:"} {
		if strings.Contains(msg, tok) {
			return ErrClassTransportReset
		}
	}
	// `eof` 单独出现太宽（"before EOF" 是流正常结束的一种描述），只在明确是
	// 未预期结束时才算传输中断。
	if strings.Contains(msg, "unexpected eof") || strings.HasSuffix(strings.TrimSpace(msg), ": eof") {
		return ErrClassTransportReset
	}
	if strings.Contains(msg, "empty") && strings.Contains(msg, "response") {
		return ErrClassEmptyResponse
	}
	return ErrClassOther
}

// isOwnDeadline 判断是否是我们自己设的墙钟到期。
// 只认 DeadlineExceeded：Canceled 可能来自用户暂停/删除，语义不同。
func isOwnDeadline(err error) bool {
	return err != nil && errors.Is(err, context.DeadlineExceeded)
}

// statusCodeOf 从错误里取 HTTP 状态码，只接受 400–599。
// 优先走错误链里的显式接口（很多客户端会实现 StatusCode() int），
// 取不到再退回文本匹配。
func statusCodeOf(err error) int {
	type statusCoder interface{ StatusCode() int }
	var sc statusCoder
	if errors.As(err, &sc) {
		if c := sc.StatusCode(); c >= 400 && c <= 599 {
			return c
		}
	}
	// 文本形态：`status 502` / `HTTP 502` / `code: 504` / `502 Bad Gateway`。
	for _, m := range statusCodeRe.FindAllStringSubmatch(err.Error(), -1) {
		if len(m) < 2 {
			continue
		}
		var code int
		for _, ch := range m[1] {
			code = code*10 + int(ch-'0')
		}
		if code >= 400 && code <= 599 {
			return code
		}
	}
	return 0
}

// isUnreachable 判断是否「根本没连上」。
// 这一类与 transport_reset 的区别是处置：reset 是连上了又断（可重试），
// unreachable 是连都没连上（重试无用，要改 DNS/端点）。
func isUnreachable(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, tok := range []string{
		"connection refused", "no such host", "server misbehaving",
		"network is unreachable", "no route to host", "i/o timeout",
		"dial tcp", "lookup ", "temporary failure in name resolution",
		"cannot unmarshal", // 解析器返回了非 DNS 响应（被劫持到本地服务）
	} {
		if strings.Contains(msg, tok) {
			return true
		}
	}
	return false
}

// looksLikeModelNotFound 区分「模型名不对」与「路径不对」。
// 中转端对前者的文案很固定，能认就认；认不出仍归 model_not_found（404 的实际
// 语义词在 LLM 调用路径上几乎总是模型名问题）。
func looksLikeModelNotFound(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, tok := range []string{"model", "not supported", "not found", "no such"} {
		if strings.Contains(msg, tok) {
			return true
		}
	}
	return false
}

// RoundMetrics 是一轮 LLM 调用（含重试内的一发）的轻量快照。
// 与 llm_records（全文正文）不同，这张表永远写，哪怕失败、哪怕录制开关关着。
type RoundMetrics struct {
	RoundID      string    `json:"round_id"` // 调用方分配，重试各发共用同 round
	TaskID       string    `json:"task_id"`
	Worker       string    `json:"worker"`
	Model        string    `json:"model"`
	ProfileName  string    `json:"profile_name"`
	Status       string    `json:"status"`      // ok | error | stalled
	ErrorClass   string    `json:"error_class"` // 空或上面十类之一
	Attempts     int       `json:"attempts"`    // 这一轮共发了几次（1 起）
	TriggerSrc   string    `json:"trigger_src"` // edge / heartbeat / retry / 空
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	FirstEventAt time.Time `json:"first_event_at"` // 首帧时刻；stalled 时为零值
	EndedAt      time.Time `json:"ended_at"`
}

// 判据常量（§5.4 ①）。默认值就是这三个；T1 与 N 都可经 env 覆盖。
const (
	// DefaultFirstEventTimeout 从 45s 放宽到 75s（R21 缺口⑩）：实测恢复期
	// 首帧到过 43s，只差 2 秒就被误杀；正常态首帧 6–20s，放宽不损失止损能力。
	DefaultFirstEventTimeout = 75 * time.Second
	DefaultStalledRounds     = 5
)

// FirstEventTimeout 读 JINGWEI_LLM_FIRST_EVENT_TIMEOUT（秒数或 Go duration），
// 非法值回落默认；≤0 表示关闭 L1（不主动判 stalled，只记录）。
//
// 纯数字按「秒」解释——这是历史上最容易出错的一处：llmrec 侧曾用
// ParseDuration 解析纯数字失败而回落，server 侧又按秒回显，两边口径不一。
// 现在两侧共用本函数，只有一处解析逻辑。
func FirstEventTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("JINGWEI_LLM_FIRST_EVENT_TIMEOUT"))
	return ParseTimeoutValue(raw)
}

// ParseTimeoutValue 把配置值解析成时长。空值返回默认值。
// 导出给 server 层复用，让「同一个环境变量只有一种解析口径」成为编译期事实
// 而不是约定。
func ParseTimeoutValue(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultFirstEventTimeout
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d
	}
	// 纯数字 = 秒（前端与运维的直觉写法）。
	if n, err := parseBareSeconds(raw); err == nil {
		// 用浮点秒换算，避免 "1.5" 被 time.Duration(n)*time.Second 截成 1s。
		return time.Duration(n * float64(time.Second))
	}
	return DefaultFirstEventTimeout
}

// parseBareSeconds 只接受纯数字（可带小数）。
func parseBareSeconds(raw string) (float64, error) {
	var v float64
	var seen bool
	var dot bool
	var scale float64 = 1
	for _, ch := range raw {
		switch {
		case ch >= '0' && ch <= '9':
			if dot {
				scale /= 10
				v += float64(ch-'0') * scale
			} else {
				v = v*10 + float64(ch-'0')
			}
			seen = true
		case ch == '.' && !dot:
			dot = true
		default:
			return 0, errors.New("not a bare number")
		}
	}
	if !seen {
		return 0, errors.New("empty")
	}
	return v, nil
}

// getenvInline 拿环境变量；拆开只是为了给测试留替换点。
func getenvInline(key string) string { return os.Getenv(key) }
