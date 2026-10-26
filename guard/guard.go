// Package guard implements the safety boundary layer (docs §11): deterministic
// sensitive-egress and task-scope/asset checks (no LLM required), an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// Deterministic gates run first; destructive/exfil gating beyond them lives in
// the DB intercept rules (seeded as ordinary [内置] rules, so users can disable
// or delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
	egress      *EgressGuard           // optional; process-wide secret fingerprints
	policy      TargetPolicy           // optional; task scope + asset block rules
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

// SetEgress installs the process-wide sensitive-egress fingerprints.
func (g *Guard) SetEgress(e *EgressGuard) {
	g.mu.Lock()
	g.egress = e
	g.mu.Unlock()
}

// SetTargetPolicy installs the deterministic target policy (task scope + asset
// block rules). A nil policy disables target checks.
func (g *Guard) SetTargetPolicy(p TargetPolicy) {
	g.mu.Lock()
	g.policy = p
	g.mu.Unlock()
}

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	// Deterministic gates run before the rule/judge layer and do not depend on an
	// LLM: sensitive-egress first (hard block), then task scope + asset blocks.
	if res, blocked := g.checkEgress(ev, cmd); blocked {
		return res
	}
	res, blocked, recorded := g.checkTargets(ctx, ev, cmd)
	if blocked {
		return res
	}
	if !recorded {
		g.record(ev.ToolName, "allow", "", cmd)
	}
	return g.applyIntercept(ctx, ev)
}

const (
	// maxEgressScanBytes bounds the outbound text scanned per call; oversized
	// inputs are checked head+tail so a secret cannot hide past the cap.
	maxEgressScanBytes = 64 << 10
)

// egressCheckTool reports whether a non-shell tool sends caller-provided
// content to a remote endpoint. Local metadata tools are excluded so a finding
// note or asset record that happens to contain a secret is not mistaken for
// exfiltration.
func egressCheckTool(name string) bool {
	if name == "WebFetch" || strings.HasPrefix(name, "mcp__") {
		return true
	}
	switch name {
	case "web_fetch", "http_request", "http_post",
		"verify_vulnerability", "exploit_vulnerability", "test_waf_bypass", "inject_webshell",
		"intranet_exec", "intranet_batch_exec", "intranet_upload", "intranet_tunnel":
		return true
	}
	return false
}

func egressTexts(toolName string, input json.RawMessage, cmd string) []string {
	text := ""
	if cmd != "" {
		text = cmd
	} else if egressCheckTool(toolName) {
		text = string(input)
	} else {
		return nil
	}
	if len(text) <= maxEgressScanBytes {
		return []string{text}
	}
	half := maxEgressScanBytes / 2
	return []string{text[:half], text[len(text)-half:]}
}

func (g *Guard) checkEgress(ev hook.Event, cmd string) (hook.Result, bool) {
	texts := egressTexts(ev.ToolName, ev.Input, cmd)
	if len(texts) == 0 {
		return hook.Result{}, false
	}
	// References to platform credential files / env names are blocked even when
	// their values are expanded at shell runtime and never appear in the input.
	for _, text := range texts {
		if ref := rePlatformSecretRef.FindString(text); ref != "" {
			log.Printf("[guard][egress] tool=%s 引用平台敏感凭据(%s)，已拦截", ev.ToolName, ref)
			return g.block(ev.ToolName, systemBlockMessage("操作引用了平台敏感凭据（"+ref+"），禁止读取或外发"), ""), true
		}
	}
	g.mu.Lock()
	eg := g.egress
	g.mu.Unlock()
	if eg == nil {
		return hook.Result{}, false
	}
	for _, text := range texts {
		if kind, hit := eg.Check(text); hit {
			// Never log or audit the matched content — only the kind.
			log.Printf("[guard][egress] tool=%s 检出平台敏感信息(%s)，已拦截", ev.ToolName, kind)
			return g.block(ev.ToolName, systemBlockMessage("操作包含平台敏感信息（"+kind+"），禁止外发"), ""), true
		}
	}
	return hook.Result{}, false
}

var rePlatformSecretRef = regexp.MustCompile(`(?i)(jwt\.key|/proc/(?:self|[0-9]+)/environ|\b(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|ARTEX_PG_DSN|JAVA_CHAINS_MCP_TOKEN|JAVA_CHAINS_PASS)\b)`)

// checkTargets enforces the deterministic scope/asset policy. The third return
// value reports that an audit entry was already written (warn mode), so the
// caller skips the plain allow record.
func (g *Guard) checkTargets(ctx context.Context, ev hook.Event, cmd string) (hook.Result, bool, bool) {
	g.mu.Lock()
	pol := g.policy
	g.mu.Unlock()
	if pol == nil {
		return hook.Result{}, false, false
	}
	mode := strings.ToLower(strings.TrimSpace(pol.Mode()))
	if mode == "" {
		mode = "warn"
	}
	if mode == "off" {
		return hook.Result{}, false, false
	}
	urls, hosts := ExtractTargets(ev.ToolName, ev.Input, cmd)
	if len(urls) == 0 && len(hosts) == 0 {
		return hook.Result{}, false, false
	}
	verdict, reason := pol.Check(intercept.TaskIDFromContext(ctx), urls, hosts)
	if verdict != ScopeOut {
		return hook.Result{}, false, false
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "目标不在任务授权范围内"
	}
	if mode != "strict" {
		// warn: keep the current behavior (allow) but make the violation visible.
		g.record(ev.ToolName, "allow", "范围告警(仅记录): "+reason, cmd)
		log.Printf("[guard][target] %s", reason)
		return hook.Result{}, false, true
	}
	return g.block(ev.ToolName, systemBlockMessage(reason+"。请勿改换写法重试，先补齐授权范围或调整禁令"), cmd), true, true
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an ARTEX platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【Jingwei 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
