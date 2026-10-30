package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

const findingIDGuidance = "\n\n**漏洞编号约定**：finding_id 是独立漏洞记录 ID；finding_node_id 是探索节点 ID。list_findings / list_task_findings / node_detail / get_task_node_detail 的 id 保留为探索节点 ID，应从同一返回的 finding_id 读取独立编号。get_finding_traffic / bind_finding_traffic 用独立 finding_id。旧 update_finding_report 的 finding_id 参数仍传 finding_node_id。不要把 report_finding 第一行的数字用于证据工具，也不要遇到编号错误后猜测其他数字。"

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, ""
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\nHTTP 漏洞必须自带报文：用 traffic_refs（或 evidence_hint_id 读取本任务指定 hint 的结构化引用）提交已核实的真实流量，按复现顺序给出，任一无效则本次上报全部失败；确实从未向目标发出过可复现请求（仅读源码/配置得出）才传 no_raw_capture=true 并在 evidence 说明原因。两者都没有时本次上报被退回、漏洞不登记。报告 Agent 仍会在编写报告前核对并补绑遗漏的流量。上报者在 evidence 中保留验证命令、关键输出与流量用途，供报告 Agent 对照执行记录核实。TCP/非 HTTP 用 raw_request/raw_response，不需要这些流量参数。返回 finding_id 与 finding_node_id 分别表示独立记录和探索节点。"
		case "add_hint", "add_task_hint":
			note = "\n交接已确认漏洞时，在对应提示的 traffic_refs 中保留已核实流量的 ID、用途、说明和顺序（单条放顶层，批量放对应 hints 元素），并在 text 中说明它证明的具体漏洞。调用方不能只交接文字而丢弃已有流量引用。未核实的候选不能作为证据传递。"
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**流量证据交接**：自动绑定默认由报告 Agent 在漏洞入库后、编写报告前完成，但报文不是可选项——HTTP 漏洞上报时必须给出已核实的 traffic_refs/evidence_hint_id，或显式声明 no_raw_capture 并在 evidence 说明为何从未发出可复现请求。上报者在 evidence 保留验证命令、关键输出、已有真实流量 ID 及其用途，任务中带 intent_id，便于报告 Agent 追溯；不要为此重复探测。Auto / Planner 代为上报时不要丢弃执行者已有的引用。add_hint / add_task_hint 可用 traffic_refs 交接；显式即时绑定仍兼容 report_finding 的 traffic_refs / evidence_hint_id。TCP 非 HTTP 漏洞用 raw_request/raw_response 正常登记，不能猜测 ID。"
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\n平台对话没有任务上下文时，不直接调用 report_finding；通过 add_task_hint 向已有对应任务交接，由任务 Agent 登记，并用 list_task_findings 核对结果。"
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\n判定目标完成前，先完成本次已有证据的上报/交接。不要在证据交接尚未完成时仅因文字漏洞已登记就结束任务、取消 Worker；无包不要求等待或强行抓包。"
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**报告前自动关联流量（已开启）**：你负责为本次触发的漏洞核对并绑定流量，再撰写报告。先从 report_finding 返回 JSON 或 get_task_node_detail / list_task_findings 取得明确的 finding_id 与 finding_node_id。读取漏洞详情、对应意图的执行记录及已有证据清单，优先使用上报者交接的真实 ID。若本次验证为 HTTP 且流量工具可用，用 traffic_search 筛选候选，再用 traffic_get 逐条核实请求/响应确实支持该漏洞；域名和时间只用于筛选，不证明归属。将确认的证据按复现顺序用 bind_finding_traffic(finding_id, traffic_refs) 关联，选择 baseline / proof / verification / supporting 并说明用途。只能操作本次漏洞，不重复创建漏洞或重新探测目标。绑定成功后重新调用 get_finding_traffic 获取最新 version，读取所需正文，再将实际读取的 version 作为 evidence_version 传给 update_finding_report（其 finding_id 参数仍用 finding_node_id）。已有绑定不必重复追加。TCP、未采集、工具不可用或没有确切匹配时，跳过自动绑定，依据文字/命令证据正常写报告并说明原因，不得为凑齐流量而猜测。绑定失败不宣称成功；保留已有证据并在报告说明未绑定原因。"
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// injectionVerifyWorkflow sends injection conclusions to the specialized
// verifiers. A POC hit, an error string or one hand-built payload only shows a
// response looked interesting; sqlmap/dalfox decide whether the parameter really
// is an injection point and replay the proved packets plus a neutral control into
// the same finding. Applied on the final permitted tool set, so an agent that
// lost the binding is never told to call a tool it does not have.
func injectionVerifyWorkflow(tools []actool.CoreTool) ([]actool.CoreTool, string) {
	has := map[string]bool{}
	for _, tool := range tools {
		has[tool.Name()] = true
	}
	if !has["report_finding"] {
		return tools, ""
	}
	verifiers := ""
	switch {
	case has["verify_sqli"] && has["verify_xss"]:
		verifiers = "SQL 注入用 verify_sqli（sqlmap）、XSS 用 verify_xss（dalfox）"
	case has["verify_sqli"]:
		verifiers = "SQL 注入用 verify_sqli（sqlmap）"
	case has["verify_xss"]:
		verifiers = "XSS 用 verify_xss（dalfox）"
	default:
		return tools, ""
	}
	out := append([]actool.CoreTool(nil), tools...)
	for i, tool := range out {
		if tool.Name() == "report_finding" {
			out[i] = &injectionNudgeTool{
				CoreTool: DecorateTool(tool, tool.Description()+
					"\n登记 SQLi/XSS 后立刻改用"+verifiers+"复测该注入点，并带上 finding_ids=<本次返回的 finding_id>，由工具结论定案、工具报文覆盖证据。",
					tool.InputSchema()),
				sqli: has["verify_sqli"],
				xss:  has["verify_xss"],
			}
		}
	}
	return out, "\n\n**注入类漏洞专项复测**：SQLi/XSS 不得停在 POC 模板命中、报错回显或手工试通一次 payload 就当定论——这些只证明响应有意思，不证明参数是注入点。" +
		verifiers + "复测该点：GET 传含参数的完整 URL，POST 用 points 携带原始请求体，登录站点必须传 cookie，并传该发现的 finding_ids；工具只做检测（sqlmap 不取数、dalfox 不利用），把判定结论连同证明报文与未注入对照请求写回同一条发现。" +
		"时间不够等完验证时传 queue_only=true 先把专项任务排上队，结论跑完自动回写，不要直接跳过复测。" +
		"工具判 not_reproduced 时按结论撤销或降级该漏洞，改记一条 inferred fact 说明为何未复现；判 tool_uncovered（宽字节字符集、盲打/DOM/存储型无回显输出点、基线不可用）或 session_needed（需要有效登录）时保留原判定与状态，在 evidence 写明原因，不要反复重跑同一验证任务。"
}

// injectionNudgeTool appends the verify-next-step reminder to a successful
// report_finding result for injection classes. System-prompt guidance alone was
// not enough: Pikachu round L5 registered nine SQLi findings in the last two
// minutes of its wall clock and never called sqlmap, because deciding to verify
// competes with finishing the batch. Riding the tool result puts the reminder —
// and the concrete finding_id — in front of the model at the moment it picks the
// next call, and queue_only gives it a way to comply without blowing the budget.
type injectionNudgeTool struct {
	actool.CoreTool
	sqli bool
	xss  bool
}

var injectedFindingID = regexp.MustCompile(`"finding_id":\s*"?(\d+)`)

func (v *injectionNudgeTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	res, err := v.CoreTool.Call(ctx, in, tc)
	if err != nil {
		return res, err
	}
	note := v.note(in, res)
	if note == "" {
		return res, nil
	}
	return actool.Result{Content: appendTextBlock(res.Content, note), IsError: res.IsError, Extra: res.Extra}, nil
}

// note picks the verifier from the finding's own class, and only once the record
// actually exists (a rejected report must not advertise a step for a finding that
// was never written).
func (v *injectionNudgeTool) note(in json.RawMessage, res actool.Result) string {
	text := strings.Join(resultText(res), "\n")
	if !strings.HasPrefix(text, "finding recorded:") {
		return ""
	}
	var a struct {
		VulnClass string `json:"vulnclass"`
		Name      string `json:"name"`
	}
	_ = json.Unmarshal(in, &a)
	cls := strings.ToLower(a.VulnClass + " " + a.Name)
	tool, label := "", ""
	switch {
	case v.sqli && strings.Contains(cls, "sql"):
		tool, label = "verify_sqli", "sqlmap"
	case v.xss && (strings.Contains(cls, "xss") || strings.Contains(cls, "跨站")):
		tool, label = "verify_xss", "dalfox"
	default:
		return ""
	}
	id := "<本次 finding_id>"
	if m := injectedFindingID.FindStringSubmatch(text); len(m) == 2 {
		id = m[1]
	}
	return "\n下一步就在本意图内（别攒到批处理最后再复测）：" + tool + " 验证这个注入点，url/points 用刚才证明它的完整请求（POST 带原始 body、登录点带 cookie），finding_ids=[" + id + "]；" +
		"剩余时间不够等 " + label + " 跑完就传 queue_only=true 先排队，结论与原始报文会自动回写该发现。"
}

// resultText flattens a result's text blocks, and appendTextBlock adds a line to
// the first one so the nudge reads as part of the tool output rather than a
// second message.
func resultText(res actool.Result) []string {
	out := make([]string, 0, len(res.Content))
	for _, b := range res.Content {
		if b.Type == llm.BlockText && b.Text != "" {
			out = append(out, b.Text)
		}
	}
	return out
}

func appendTextBlock(blocks []llm.ContentBlock, note string) []llm.ContentBlock {
	for i, b := range blocks {
		if b.Type == llm.BlockText && b.Text != "" {
			blocks[i].Text += note
			return blocks
		}
	}
	return append(blocks, llm.TextBlock(note))
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "可选：已核实且对应本提示中具体漏洞的流量引用，保留顺序；交接后 report_finding 可传 evidence_hint_id 携带这些引用。", "items": obj(map[string]any{"traffic_id": str("真实流量 ID"), "role": str("baseline / proof / verification / supporting"), "note": str("该流量支持什么结论")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d 必须是本任务的提示节点（继承提示不可直接用于绑定）", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
