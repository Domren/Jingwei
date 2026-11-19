package guard

// RCE 验证阶梯的代码闸门（P9）。
//
// 设计要点：阶梯授权必须由代码裁决，sidecar 提示词里的「逐级执行」自律只是给模型的
// 建议，绝不能替代本文件的闸门。本文件把四级抽象成可独立开关的配置，请求级别由调用方
// （server 的深度工具）写进 deep task 的 params；任何跳级都转成 intercept 的 ask 决策，
// 复用现成的 HandleAsk/Decide 人工审批链路，被拒则落审批记录。
//
// 四级顺序：回连证明 → 无害命令 → 读文件 → 写文件。级别越高，对目标的实际影响越大，
// 因此不允许越过中间级别直接申请高级别，除非人工批准。

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Domren/jingwei/intercept"
)

// RCE 验证阶梯级别。0 表示尚未做任何验证（起点），不是可请求的级别。
const (
	RCELevelNone     = 0
	RCELevelCallback = 1 // 回连证明：唯一 token 的 OOB 回连，证明命令确由目标发起
	RCELevelHarmless = 2 // 无害命令：id / whoami 一类无副作用的回显命令
	RCELevelRead     = 3 // 读文件：读取目标上的一个文件
	RCELevelWrite    = 4 // 写文件：在目标上写入一个文件（影响最大）
)

// RCELevelName 返回级别的中文名，供审批理由与报告使用。
func RCELevelName(level int) string {
	switch level {
	case RCELevelCallback:
		return "回连证明"
	case RCELevelHarmless:
		return "无害命令"
	case RCELevelRead:
		return "读文件"
	case RCELevelWrite:
		return "写文件"
	default:
		return "未知级别"
	}
}

// RCELadderConfig 是四级阶梯的独立开关。false 表示该级永久禁止——连跳级审批也不能放行，
// 这保证操作员能把「写文件」这类高风险级别整个关掉，而不是仅依赖模型自觉。
type RCELadderConfig struct {
	Callback bool // 第 1 级：回连证明
	Harmless bool // 第 2 级：无害命令
	Read     bool // 第 3 级：读文件
	Write    bool // 第 4 级：写文件
}

// DefaultRCELadderConfig 默认四级全开；跳级仍然必须人工审批。
func DefaultRCELadderConfig() RCELadderConfig {
	return RCELadderConfig{Callback: true, Harmless: true, Read: true, Write: true}
}

// LevelEnabled 报告 level 级是否被配置允许。
func (c RCELadderConfig) LevelEnabled(level int) bool {
	switch level {
	case RCELevelCallback:
		return c.Callback
	case RCELevelHarmless:
		return c.Harmless
	case RCELevelRead:
		return c.Read
	case RCELevelWrite:
		return c.Write
	default:
		return false
	}
}

// RCEAction 是代码闸门对一次级别请求的裁决，取值与 intercept.Decision.Action 对齐。
type RCEAction string

const (
	RCEAllow RCEAction = "allow" // 逐级放行（含重复验证已授权级别）
	RCEAsk   RCEAction = "ask"   // 跳级，必须人工审批
	RCEDeny  RCEAction = "deny"  // 级别关闭或非法，直接拒绝
)

// EvaluateRCELevel 是纯函数：给定四级开关、当前已达级别与本次请求级别，返回裁决与理由。
//
// 规则（优先级从高到低）：
//  1. 请求级别非法或已被配置关闭 → deny；
//  2. 请求级别 <= 已达级别 → allow（已授权，重复验证不重新审批）；
//  3. 请求级别 == 已达级别+1 → allow（逐级推进）；
//  4. 请求级别 > 已达级别+1 → ask（跳级，必须人工审批）。
//
// 注意：关闭的中级不会阻断「已达高级别后的下一级请求」——关闭只禁止执行该级本身，
// 跳级仍然由 above 规则处理。
func EvaluateRCELevel(cfg RCELadderConfig, achieved, requested int) (RCEAction, string) {
	if requested < RCELevelCallback || requested > RCELevelWrite {
		return RCEDeny, fmt.Sprintf("RCE 验证级别 %d 非法（有效范围 1-4）", requested)
	}
	if !cfg.LevelEnabled(requested) {
		return RCEDeny, fmt.Sprintf("RCE 验证第 %d 级（%s）已被配置关闭，禁止执行（含跳级审批）",
			requested, RCELevelName(requested))
	}
	if achieved < RCELevelNone {
		achieved = RCELevelNone
	}
	if achieved > RCELevelWrite {
		achieved = RCELevelWrite
	}
	if requested <= achieved {
		return RCEAllow, fmt.Sprintf("第 %d 级（%s）已获授权，重复验证放行", requested, RCELevelName(requested))
	}
	if requested == achieved+1 {
		return RCEAllow, fmt.Sprintf("逐级授权：从第 %d 级推进到第 %d 级（%s）",
			achieved, requested, RCELevelName(requested))
	}
	return RCEAsk, fmt.Sprintf("跳级请求：当前已授权第 %d 级，却直接请求第 %d 级（%s）；必须人工审批",
		achieved, requested, RCELevelName(requested))
}

// intParam 从 deep task 的 params 中读整数。JSON 数字常以 float64 落地，字符串数字也接受。
func intParam(params map[string]any, key string, def int) int {
	v, ok := params[key]
	if !ok || v == nil {
		return def
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return int(i)
		}
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err == nil {
			return i
		}
	}
	return def
}

// boolParam 从 deep task 的 params 中读布尔开关（false 表示关闭该级）。缺省为 def。
func boolParam(params map[string]any, key string, def bool) bool {
	v, ok := params[key]
	if !ok || v == nil {
		return def
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		switch strings.ToLower(strings.TrimSpace(b)) {
		case "false", "0", "off", "no":
			return false
		case "true", "1", "on", "yes":
			return true
		}
	}
	return def
}

// RCELevelFromParams 解析阶梯参数：rce_level 本次请求级别，rce_achieved 当前已达级别，
// rce_callback / rce_harmless / rce_read / rce_write 为四级开关（缺省开启）。
func RCELevelFromParams(params map[string]any) (cfg RCELadderConfig, achieved, requested int) {
	cfg = DefaultRCELadderConfig()
	cfg.Callback = boolParam(params, "rce_callback", true)
	cfg.Harmless = boolParam(params, "rce_harmless", true)
	cfg.Read = boolParam(params, "rce_read", true)
	cfg.Write = boolParam(params, "rce_write", true)
	achieved = intParam(params, "rce_achieved", RCELevelNone)
	requested = intParam(params, "rce_level", RCELevelCallback)
	return
}

// rceApprover 是 intercept.Interceptor 在本闸门中用到的那一小片能力，抽成接口便于纯单测：
// HandleAsk 创建审批记录并等待 Decide；Log 直接落一条已决记录（用于跳级拒绝/级别关闭）。
type rceApprover interface {
	HandleAsk(ctx context.Context, convID int64, dec intercept.Decision, toolName string, input []byte) bool
	Log(ctx context.Context, convID int64, dec intercept.Decision, toolName string, input []byte, status string)
}

// RCEGate 把纯函数裁决接到现成的人工审批链路上。
type RCEGate struct {
	approver rceApprover
}

// NewRCEGate 构造闸门。approver 为 nil 时（例如无拦截器的直连场景）仍会做代码裁决，
// 只是 ask 一律视为未获批——宁可拦住也不放行跳级。
func NewRCEGate(a rceApprover) *RCEGate { return &RCEGate{approver: a} }

// RCEGateResult 是闸门对一次工具调用的最终裁决。Achieved 是放行后应写回的新已达级别。
type RCEGateResult struct {
	Action   RCEAction
	Reason   string
	Achieved int
	Allowed  bool
}

// Evaluate 执行闸门：先纯函数裁决，再把 ask/deny 接到审批记录。
// tool 与 input 原样透传给 intercept，使审批页能看到这次 RCE 请求的完整上下文。
func (g *RCEGate) Evaluate(ctx context.Context, convID int64, tool string, params map[string]any, input []byte) RCEGateResult {
	cfg, achieved, requested := RCELevelFromParams(params)
	action, reason := EvaluateRCELevel(cfg, achieved, requested)
	dec := intercept.Decision{
		RuleName:       "[内置] RCE 验证阶梯跳级审批",
		Action:         string(action),
		Message:        reason,
		TimeoutEnabled: true,
		TimeoutSeconds: 120,
		TimeoutAction:  "deny", // 跳级审批超时按拒绝处理，绝不自动放行
	}
	switch action {
	case RCEAllow:
		next := achieved
		if requested > next {
			next = requested
		}
		return RCEGateResult{Action: RCEAllow, Reason: reason, Achieved: next, Allowed: true}
	case RCEDeny:
		// 级别关闭/非法也留一条已决审批记录，便于事后审计为何被拒。
		if g.approver != nil {
			g.approver.Log(ctx, convID, dec, tool, input, "denied")
		}
		return RCEGateResult{Action: RCEDeny, Reason: reason, Achieved: achieved}
	case RCEAsk:
		approved := false
		if g.approver != nil {
			approved = g.approver.HandleAsk(ctx, convID, dec, tool, input)
		}
		if approved {
			return RCEGateResult{Action: RCEAllow, Reason: reason + "（人工已批准）", Achieved: requested, Allowed: true}
		}
		// 跳级被拒：HandleAsk 已在审批表留下 pending→denied 记录；这里再补一条已决
		// 记录，确保历史页/任务拦截页一定看得到这次被拒的跳级（即使审批流程被取消）。
		if g.approver != nil {
			g.approver.Log(ctx, convID, dec, tool, input, "denied")
		}
		return RCEGateResult{Action: RCEDeny, Reason: reason + "（人工未批准）", Achieved: achieved}
	}
	return RCEGateResult{Action: RCEDeny, Reason: "未知裁决", Achieved: achieved}
}
