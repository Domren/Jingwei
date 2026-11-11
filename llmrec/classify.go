package llmrec

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

// 错误五分类（R21 §5.4 ③）。不把错误分类，就只能统一重试，于是「中转端流被重置」
// 和「账户欠费」在系统里看起来一模一样——实测里这两种各占了不少轮次，处置完全不同。
//
// 分类只看一类证据：调用方给出的错误。不从文本猜，因为流错误正文的格式会因
// 中转端而异；本层按可观察的信号归类，不在报文正文里找关键词。
type ErrorClass string

const (
	ErrClassTransportReset ErrorClass = "transport_reset" // HTTP/2 stream reset、连接被对端重置
	ErrClassStalled        ErrorClass = "stalled"         // 建连成功但 T1 内无首帧
	ErrClassRateLimited    ErrorClass = "rate_limited"    // 429 / Retry-After
	ErrClassAccountInvalid ErrorClass = "account_invalid" // 401/402/403（欠费/未订阅/鉴权失败）
	ErrClassEmptyResponse  ErrorClass = "empty_response"  // 完成但无内容块
	ErrClassTimeout        ErrorClass = "timeout"         // 我们主动设的墙钟/首帧超时
	ErrClassOther          ErrorClass = "other"
)

// ClassifyError 把一次 LLM 调用的错误归到五类之一。
// err 是调用方返回的错误；wallErr 是我们自己加的墙钟/首帧超时。
// 判据按确定性从强到弱：账户类 → 限流 → 主动超时 → 流重置 → 其它。
func ClassifyError(err, wallErr error) ErrorClass {
	if err == nil {
		return ""
	}
	// 我们主动取消的两种超时优先判，因为它们意味着"不是对端的问题"。
	if wallErr != nil && errors.Is(wallErr, context.DeadlineExceeded) {
		return ErrClassTimeout
	}
	msg := err.Error()
	// 账户/鉴权：这类不会自愈，重试只会继续烧钱，必须切链或停任务。
	for _, tok := range []string{"401", "402", "403", "unauthorized", "invalid api key", "insufficient_quota", "billing", "payment required"} {
		if strings.Contains(msg, tok) {
			return ErrClassAccountInvalid
		}
	}
	// 限流：不是宕机，不计入熔断；但要留出独立类别（不与其他失败混算）。
	for _, tok := range []string{"429", "rate limit", "too many requests", "retry-after"} {
		if strings.Contains(msg, tok) {
			return ErrClassRateLimited
		}
	}
	// 流重置：HTTP/2 的常见形态是 "stream error: stream ID N; INTERNAL_ERROR"，按这个形态判。
	// 不进 err 链匹配，因为各中转端包装不一；只用文本指纹。
	for _, tok := range []string{"stream error", "stream id", "internal_error", "connection reset by peer", "broken pipe", "eof", "http2:"} {
		if strings.Contains(strings.ToLower(msg), tok) {
			return ErrClassTransportReset
		}
	}
	// 完成但没有内容块，由调用方给空响应标记。
	if strings.Contains(strings.ToLower(msg), "empty") && strings.Contains(strings.ToLower(msg), "response") {
		return ErrClassEmptyResponse
	}
	return ErrClassOther
}

// RoundMetrics 是一轮 LLM 调用（含重试内的一发）的轻量快照。
// 与 llm_records（全文正文）不同，这张表永远写，哪怕失败、哪怕录制开关关着。
type RoundMetrics struct {
	RoundID      string    `json:"round_id"` // 调用方分配，重试各发共用同 round
	TaskID       string    `json:"task_id"`
	Worker       string    `json:"worker"`
	Model        string    `json:"model"`
	ProfileName  string    `json:"profile_name"`
	Status       string    `json:"status"`      // ok | error
	ErrorClass   string    `json:"error_class"` // 空或五类之一
	Attempts     int       `json:"attempts"`    // 这一发是第几次重试（1 起）
	TriggerSrc   string    `json:"trigger_src"` // edge / heartbeat / retry / 空
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	FirstEventAt time.Time `json:"first_event_at"` // 首帧时刻；stalled 时为零值
	EndedAt      time.Time `json:"ended_at"`
}

// 判据常量（§5.4 ①）。做成可配（后续经 settings），默认值就是这三个。
const (
	DefaultFirstEventTimeout = 45 * time.Second
	DefaultStalledRounds     = 5
)

// FirstEventTimeout 读 JINGWEI_LLM_FIRST_EVENT_TIMEOUT（秒或 Go duration），
// 非法值回落默认；≤0 表示关闭 L1（不主动判 stalled，只记录）。
func FirstEventTimeout() time.Duration {
	return envDur(os.Getenv("JINGWEI_LLM_FIRST_EVENT_TIMEOUT"), DefaultFirstEventTimeout)
}

func envDur(raw string, def time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d
	}
	return def
}

// getenvInline 拿环境变量；拆开只是为了给测试留替换点。
func getenvInline(key string) string { return os.Getenv(key) }
