package scanner

// P2 · 多出口代理池（前置 P1）：按任务绑定出口、健康探测、失败自动轮换，
// 且出口与任务的绑定全程留痕。
//
// 安全口径：出口 URL 里可能带 user:pass 凭据。本文件里原始 ProxyURL 只用于
// 构造 http.Transport，**从不**进入事件、返回值或错误消息；对外一律只暴露
// 出口 ID 与脱敏后的主机。绑定表保证任务 A 永远拿不到任务 B 的出口。

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// EgressEndpoint 是池里的一个出口。ProxyURL 允许带凭据，但只在进程内使用。
type EgressEndpoint struct {
	ID       string // 稳定标识（事件/绑定只用它，不暴露凭据）
	TaskID   string // 归属任务；空串=共享出口，任何任务都可用
	Name     string // 可读别名
	ProxyURL string // http/https/socks5，可带 user:pass；空串=直连

	Healthy   bool   // 由健康探测与失败上报维护
	Failures  int    // 连续失败次数
	LastError string // 脱敏后的最近一次错误
}

// EgressEvent 是一条出口审计事件。字段里没有任何原始代理 URL/口令。
type EgressEvent struct {
	TS             time.Time `json:"ts"`
	TaskID         string    `json:"task_id"`
	Action         string    `json:"action"` // bind | rotate | fail | probe_fail
	EndpointID     string    `json:"endpoint_id"`
	FromEndpointID string    `json:"from_endpoint_id,omitempty"`
	Detail         string    `json:"detail,omitempty"` // 已脱敏
}

// EgressPool 是线程安全的出口池 + 任务绑定表。
type EgressPool struct {
	mu        sync.Mutex
	endpoints []*EgressEndpoint
	bindings  map[string]string // taskID -> endpoint ID（绑定留痕）
	events    []EgressEvent
	probe     func(proxyURL string) error // 可选健康探测；nil 时只看 Health 标记
	clients   map[string]*http.Client     // 出口 id+代理 → 复用底层 client
}

// ---- 构造与配置 ----

// NewEgressPool 创建空出口池。
func NewEgressPool() *EgressPool {
	return &EgressPool{
		bindings: map[string]string{},
		clients:  map[string]*http.Client{},
	}
}

// SetProbe 注入健康探测函数。入参是原始代理 URL（仅供探测方使用），返回 nil
// 表示出口健康。未设置时以 Endpoint.Healthy 为准，便于纯函数夹具测试。
func (p *EgressPool) SetProbe(fn func(proxyURL string) error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.probe = fn
	p.mu.Unlock()
}

// Register 注册一个出口。相同 ID 重复注册会更新其配置（幂等），并保留健康状态
// 以外的绑定关系；重复 ID 不会在池里产生两份。
func (p *EgressPool) Register(ep EgressEndpoint) error {
	if p == nil {
		return fmt.Errorf("egress pool is nil")
	}
	ep.ID = strings.TrimSpace(ep.ID)
	ep.TaskID = strings.TrimSpace(ep.TaskID)
	ep.Name = strings.TrimSpace(ep.Name)
	ep.ProxyURL = strings.TrimSpace(ep.ProxyURL)
	if ep.ID == "" {
		return fmt.Errorf("出口 id 不能为空")
	}
	if ep.ProxyURL != "" {
		if _, err := url.Parse(ep.ProxyURL); err != nil {
			return fmt.Errorf("出口 %s 的代理地址无效: %w", ep.ID, err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, existing := range p.endpoints {
		if existing.ID == ep.ID {
			// 重复注册只更新配置，健康状态沿用池里的现状（避免在故障轮换后
			// 被一次无关的重注册重新标成健康）。
			ep.Healthy = existing.Healthy
			ep.Failures = existing.Failures
			ep.LastError = existing.LastError
			p.endpoints[i] = &ep
			return nil
		}
	}
	if ep.Name == "" {
		ep.Name = ep.ID
	}
	ep.Healthy = true
	p.endpoints = append(p.endpoints, &ep)
	return nil
}

// HTTPClientFor 返回绑定到某出口的底层 http.Client（按出口+代理缓存）。
// 原始代理 URL 只用于构造 Transport，不作为 key 之外的任何输出。
func (p *EgressPool) HTTPClientFor(ep EgressEndpoint, timeout time.Duration) *http.Client {
	key := ep.ID + "\x00" + ep.ProxyURL
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.clients[key]; c != nil {
		return c
	}
	c := newDeepHTTPClient(timeout, ep.ProxyURL)
	p.clients[key] = c
	return c
}

// Bind 显式把一个出口绑到任务并留痕。跨任务绑定被拒绝——这是「不串用」的核心。
func (p *EgressPool) Bind(taskID, endpointID string) error {
	if p == nil {
		return fmt.Errorf("egress pool is nil")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return fmt.Errorf("task id 不能为空")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ep := p.findLocked(endpointID)
	if ep == nil {
		return fmt.Errorf("出口 %q 不存在", endpointID)
	}
	if ep.TaskID != "" && ep.TaskID != taskID {
		return fmt.Errorf("出口 %q 属于任务 %s，不能绑到任务 %s", endpointID, ep.TaskID, taskID)
	}
	if !ep.Healthy {
		return fmt.Errorf("出口 %q 不健康", endpointID)
	}
	old := p.bindings[taskID]
	p.bindings[taskID] = endpointID
	p.recordLocked(taskID, "bind", endpointID, old, "显式绑定")
	return nil
}

// SelectForTask 按任务选出（必要时绑定/轮换）健康出口。
// 解析顺序：已绑定且健康 → 复用；已绑定但不健康 → 轮换；未绑定 → 选本任务第一条健康出口。
func (p *EgressPool) SelectForTask(taskID string) (EgressEndpoint, error) {
	if p == nil {
		return EgressEndpoint{}, fmt.Errorf("egress pool is nil")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return EgressEndpoint{}, fmt.Errorf("task id 不能为空（出口按任务隔离）")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	boundID := p.bindings[taskID]
	if boundID != "" {
		ep := p.findLocked(boundID)
		if ep != nil && p.usableLocked(ep, taskID) {
			return *ep, nil
		}
		// 绑定失效：轮换到本任务的另一个健康出口，并记录 from→to。
		return p.rotateLocked(taskID, boundID)
	}
	// 未绑定：挑第一条本任务可用出口并绑定。
	for _, ep := range p.endpoints {
		if p.usableLocked(ep, taskID) {
			p.bindings[taskID] = ep.ID
			p.recordLocked(taskID, "bind", ep.ID, "", "按任务自动绑定")
			return *ep, nil
		}
	}
	return EgressEndpoint{}, fmt.Errorf("任务 %s 没有健康出口（池里 %d 个）", taskID, len(p.endpoints))
}

// ReportFailure 上报某任务某出口的失败：标记不健康、记账，并立即轮换到健康出口。
// 错误文本先脱敏再写入事件，绝不泄漏代理口令。
func (p *EgressPool) ReportFailure(taskID, endpointID string, err error) error {
	if p == nil {
		return fmt.Errorf("egress pool is nil")
	}
	taskID = strings.TrimSpace(taskID)
	p.mu.Lock()
	defer p.mu.Unlock()
	ep := p.findLocked(endpointID)
	if ep == nil {
		return fmt.Errorf("出口 %q 不存在", endpointID)
	}
	ep.Healthy = false
	ep.Failures++
	detail := ""
	if err != nil {
		ep.LastError = redactProxyText(err.Error())
		detail = ep.LastError
	}
	p.recordLocked(taskID, "fail", endpointID, "", detail)
	if p.bindings[taskID] == endpointID {
		_, _ = p.rotateLocked(taskID, endpointID)
	}
	return nil
}

// RotateForTask 主动为任务切换出口（P4 限速/挑战触发），不把旧出口标记成坏——
// 被目标限速是目标侧信号，不该冤枉出口；只是换一条线继续。
func (p *EgressPool) RotateForTask(taskID, reason string) error {
	if p == nil {
		return fmt.Errorf("egress pool is nil")
	}
	taskID = strings.TrimSpace(taskID)
	p.mu.Lock()
	defer p.mu.Unlock()
	old := p.bindings[taskID]
	if old == "" {
		return fmt.Errorf("任务 %s 尚未绑定出口", taskID)
	}
	_, err := p.rotateLocked(taskID, old)
	if err != nil {
		return err
	}
	if reason != "" {
		p.recordLocked(taskID, "rotate_reason", p.bindings[taskID], old, reason)
	}
	return nil
}

// Events 返回事件快照（副本，调用方改不动内部状态）。
func (p *EgressPool) Events() []EgressEvent {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]EgressEvent, len(p.events))
	copy(out, p.events)
	return out
}

// BindingFor 返回任务当前绑定（仅 ID，可用于台账展示）。
func (p *EgressPool) BindingFor(taskID string) string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bindings[strings.TrimSpace(taskID)]
}

// ---- 内部 ----

func (p *EgressPool) findLocked(id string) *EgressEndpoint {
	for _, ep := range p.endpoints {
		if ep.ID == id {
			return ep
		}
	}
	return nil
}

// usableLocked 判断出口能否给 taskID 用：归属匹配 + 健康 + 探测通过。
func (p *EgressPool) usableLocked(ep *EgressEndpoint, taskID string) bool {
	if ep == nil || !ep.Healthy {
		return false
	}
	if ep.TaskID != "" && ep.TaskID != taskID {
		return false
	}
	if p.probe != nil {
		if err := p.probe(ep.ProxyURL); err != nil {
			ep.Healthy = false
			ep.Failures++
			ep.LastError = redactProxyText(err.Error())
			p.recordLocked(taskID, "probe_fail", ep.ID, "", ep.LastError)
			return false
		}
	}
	return true
}

func (p *EgressPool) rotateLocked(taskID, fromID string) (EgressEndpoint, error) {
	for _, ep := range p.endpoints {
		if ep.ID == fromID {
			continue
		}
		if p.usableLocked(ep, taskID) {
			p.bindings[taskID] = ep.ID
			p.recordLocked(taskID, "rotate", ep.ID, fromID, "失败/不健康自动轮换")
			return *ep, nil
		}
	}
	return EgressEndpoint{}, fmt.Errorf("任务 %s 没有可用出口可轮换", taskID)
}

func (p *EgressPool) recordLocked(taskID, action, endpointID, fromID, detail string) {
	p.events = append(p.events, EgressEvent{
		TS: time.Now(), TaskID: taskID, Action: action,
		EndpointID: endpointID, FromEndpointID: fromID,
		Detail: redactProxyText(detail),
	})
	if len(p.events) > 2000 {
		p.events = p.events[len(p.events)-2000:]
	}
}

// redactProxyText 把文本里的 user:pass@ 折成 ***:***@，避免凭据进日志/响应。
func redactProxyText(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Fields(s)
	for i, part := range parts {
		if u, err := url.Parse(part); err == nil && u.User != nil {
			if _, ok := u.User.Password(); ok {
				u.User = url.UserPassword("***", "***")
			} else {
				u.User = url.User("***")
			}
			parts[i] = u.String()
			continue
		}
		// 没有 scheme 的 user:pass@host 也兜住。
		if at := strings.LastIndex(part, "@"); at > 0 {
			prefix := part[:at]
			if colon := strings.Index(prefix, ":"); colon > 0 {
				parts[i] = prefix[:colon] + ":***@" + part[at+1:]
			}
		}
	}
	return strings.Join(parts, " ")
}
