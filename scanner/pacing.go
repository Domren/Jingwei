package scanner

// P4 · 请求节奏自适应（前置 P2）：按响应特征（放行 / 限速 / 挑战页）自动降速
// 并标记切出口；节奏参数按目标独立，一个目标的慢节奏不拖垮别的任务。
//
// 分类复用 DetectWAF 体系里的 classifyBlockFeature / BlockRateLimit 与
// captchaRateMarker：429 / Retry-After 归「限速」，验证码/滑块/人机验证归「挑战」，
// 其余归「放行」。挑战比限速降得更狠，并置 RotateEgress 供调用方切出口。

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PaceMode 是目标当前所处的节奏形态。
type PaceMode int

const (
	PaceOpen      PaceMode = iota // 放行：基础节奏
	PaceThrottled                 // 限速：429 / Retry-After / 频率限制
	PaceChallenge                 // 挑战页：验证码 / 滑块 / 人机验证
)

func (m PaceMode) String() string {
	switch m {
	case PaceThrottled:
		return "throttled"
	case PaceChallenge:
		return "challenge"
	default:
		return "open"
	}
}

// TargetPace 是单个目标的节奏参数快照（可被夹具逐字段核对）。
type TargetPace struct {
	Mode         PaceMode      `json:"mode"`
	ModeName     string        `json:"mode_name"`
	Interval     time.Duration `json:"interval"`      // 两次请求之间的等待
	Burst        int           `json:"burst"`         // 允许的突发请求数（降速后收敛到 1）
	Failures     int           `json:"failures"`      // 连续被限/挑战次数
	RotateEgress bool          `json:"rotate_egress"` // 是否应切换出口
}

// AdaptivePacer 按目标维护节奏状态。waitFn 可注入，便于无真实睡眠的夹具。
type AdaptivePacer struct {
	mu       sync.Mutex
	states   map[string]*TargetPace
	base     time.Duration
	max      time.Duration
	waitFn   func(context.Context, time.Duration) error
	observes int
}

// NewAdaptivePacer 创建节奏器。base<=0 时用 200ms；max<base 时抬到 base。
func NewAdaptivePacer(base, max time.Duration) *AdaptivePacer {
	if base <= 0 {
		base = 200 * time.Millisecond
	}
	if max < base {
		max = base
	}
	return &AdaptivePacer{states: map[string]*TargetPace{}, base: base, max: max}
}

// SetWaitFunc 注入等待函数（测试用），返回之前的函数。
func (p *AdaptivePacer) SetWaitFunc(fn func(context.Context, time.Duration) error) func(context.Context, time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	old := p.waitFn
	p.waitFn = fn
	return old
}

// ObserveCount 返回 Observe 被调用的次数（含放行响应）。
func (p *AdaptivePacer) ObserveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.observes
}

// Observe 用一次响应更新目标节奏。分类复用 detectWAF 的特征判定。
func (p *AdaptivePacer) Observe(target string, resp DeepResponse) {
	target = normalizePaceTarget(target)
	if target == "" {
		return
	}
	mode := classifyPaceFeature(resp)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.observes++
	st := p.states[target]
	if st == nil {
		st = &TargetPace{Mode: PaceOpen, Interval: p.base, Burst: 1}
		p.states[target] = st
	}
	switch mode {
	case PaceThrottled, PaceChallenge:
		st.Failures++
		st.Mode = mode
		st.Burst = 1
		st.RotateEgress = true
		// 指数退避：限速 2^n，挑战再从 2^2 起步；统一封顶到 max。
		shift := st.Failures
		if mode == PaceChallenge {
			shift += 2
		}
		if shift > 8 {
			shift = 8
		}
		st.Interval = p.base * (1 << uint(shift))
		if st.Interval > p.max {
			st.Interval = p.max
		}
	case PaceOpen:
		// 成功响应逐步恢复，不是一次清零——真实目标往往需要几个请求才放全速。
		if st.Failures > 0 {
			st.Failures--
		}
		if st.Failures == 0 {
			st.Mode = PaceOpen
			st.RotateEgress = false
			st.Burst = 4
		}
		st.Interval = p.base * (1 << uint(st.Failures))
		if st.Interval > p.max {
			st.Interval = p.max
		}
	}
}

// Wait 在发请求前按目标节奏等待。关键：锁内只读取参数，等待在锁外执行，
// 所以一个目标的 30s 退避不会把其它目标的请求卡在互斥锁上。
func (p *AdaptivePacer) Wait(ctx context.Context, target string) error {
	target = normalizePaceTarget(target)
	if target == "" {
		return nil
	}
	p.mu.Lock()
	st := p.states[target]
	interval := p.base
	if st != nil {
		interval = st.Interval
	}
	fn := p.waitFn
	p.mu.Unlock()

	if interval <= 0 {
		return nil
	}
	if fn != nil {
		return fn(ctx, interval)
	}
	t := time.NewTimer(interval)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// PaceFor 返回目标节奏快照。未观测过的目标给基础值。
func (p *AdaptivePacer) PaceFor(target string) TargetPace {
	target = normalizePaceTarget(target)
	p.mu.Lock()
	defer p.mu.Unlock()
	if st := p.states[target]; st != nil {
		out := *st
		out.ModeName = st.Mode.String()
		return out
	}
	return TargetPace{Mode: PaceOpen, ModeName: PaceOpen.String(), Interval: p.base, Burst: 4}
}

// ShouldRotateEgress 报告目标是否因限速/挑战被标记需要切出口，并消费该标记。
func (p *AdaptivePacer) ShouldRotateEgress(target string) bool {
	target = normalizePaceTarget(target)
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.states[target]
	if st == nil || !st.RotateEgress {
		return false
	}
	st.RotateEgress = false
	return true
}

// Targets 返回当前所有目标（排序后），便于审计/展示。
func (p *AdaptivePacer) Targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.states))
	for k := range p.states {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// classifyPaceFeature 把响应归到三种节奏形态，复用 deepuse.go 的 BlockRateLimit
// 分类，再用验证码/挑战标记区分「限速」与「挑战页」。
func classifyPaceFeature(resp DeepResponse) PaceMode {
	if resp.StatusCode == 0 && resp.Error != "" {
		return PaceOpen // 传输失败交给 P2 出口层处理，不算目标限速
	}
	if classifyBlockFeature(resp) != BlockRateLimit {
		return PaceOpen
	}
	if captchaRateMarker.MatchString(resp.Body) {
		return PaceChallenge
	}
	return PaceThrottled
}

// normalizePaceTarget 从 URL 取 host[:port]；传入非 URL 时按原文本归一化。
func normalizePaceTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return strings.ToLower(u.Host)
	}
	return strings.ToLower(s)
}

// paceWaitErr 供注入的 waitFn 包装上下文取消错误，保持调用方 errors.Is 可用。
func paceWaitErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("节奏等待中断: %w", err)
}
