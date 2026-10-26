package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestFindingWorkflowSharedAssemblyAndSwitch(t *testing.T) {
	oldPolicy, oldResolve, oldAugment := FindingTrafficBindingEnabled, ToolResolve, ToolAugment
	t.Cleanup(func() { FindingTrafficBindingEnabled, ToolResolve, ToolAugment = oldPolicy, oldResolve, oldAugment })
	ToolAugment = nil
	on := false
	FindingTrafficBindingEnabled = func() bool { return on }
	ts := NewToolSet(nil, "fixture")
	ToolResolve = func(_ context.Context, _ string, base []actool.CoreTool) []actool.CoreTool {
		out := make([]actool.CoreTool, len(base))
		for i, tool := range base {
			out[i] = DecorateTool(tool, "CUSTOM DESCRIPTION", tool.InputSchema())
		}
		return out
	}
	for _, role := range []string{"worker", "planner", "mainagent", "auto", "pentest", "custom-agent"} {
		for _, enabled := range []bool{false, true, false} {
			on = enabled
			out, def, cleanup := AugmentTools(t.Context(), role, []actool.CoreTool{ts.addFinding(), ts.addHint()})
			cleanup()
			system, _ := deferredSystem("USER CUSTOM PROMPT", def)
			if !strings.HasPrefix(system[0], "USER CUSTOM PROMPT") {
				t.Fatal("custom prompt replaced")
			}
			if strings.Contains(system[0], "traffic_refs") != on {
				t.Fatalf("%s: guidance ignored switch: %v", role, on)
			}
			if on && (!strings.Contains(system[0], "TCP") || !strings.Contains(system[0], "evidence_hint_id")) {
				t.Fatal("missing optional/handoff contract")
			}
			for _, tool := range out {
				if !strings.HasPrefix(tool.Description(), "CUSTOM DESCRIPTION") {
					t.Fatal("custom description replaced")
				}
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				json.Unmarshal(raw, &schema)
				props := schema["properties"].(map[string]any)
				if (props["traffic_refs"] != nil) != on {
					t.Fatalf("%s: binding schema ignored switch", role)
				}
				if tool.Name() == "add_hint" {
					nested := props["hints"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
					if (nested["traffic_refs"] != nil) != on {
						t.Fatal("nested hint schema ignored switch")
					}
				}
			}
		}
	}
	on = true
	ToolResolve = func(context.Context, string, []actool.CoreTool) []actool.CoreTool { return nil }
	out, def, cleanup := AugmentTools(t.Context(), "planner", []actool.CoreTool{ts.addFinding()})
	defer cleanup()
	if len(out) != 0 || def.FindingGuidance != "" {
		t.Fatal("reintroduced disabled tool or its guidance")
	}
}

// The specialized verifiers are only worth advertising to an agent that can
// actually call them, and only the ones it can call: a worker whose binding lost
// verify_xss must not be told to run a tool that is not in its callable set.
func TestInjectionVerifyWorkflowAdvertisesOnlyBoundVerifiers(t *testing.T) {
	noop := func(context.Context, json.RawMessage) (actool.Result, error) { return actool.Text("ok"), nil }
	finding := func() actool.CoreTool {
		return readTool("report_finding", "记录确认的漏洞", obj(map[string]any{"vulnclass": str("类别")}), noop)
	}
	verifier := func(name string) actool.CoreTool {
		return readTool(name, "专项注入验证", obj(map[string]any{"urls": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}), noop)
	}

	if out, guidance := injectionVerifyWorkflow([]actool.CoreTool{finding(), verifier("exploit_vulnerability")}); guidance != "" || out[0].Description() != "记录确认的漏洞" {
		t.Fatalf("unbound verifier advertised: guidance=%q desc=%q", guidance, out[0].Description())
	}

	for _, tc := range []struct {
		bind    []string
		want    []string
		notWant string
	}{
		{bind: []string{"verify_sqli", "verify_xss"}, want: []string{"verify_sqli", "verify_xss"}},
		{bind: []string{"verify_sqli"}, want: []string{"verify_sqli"}, notWant: "verify_xss"},
		{bind: []string{"verify_xss"}, want: []string{"verify_xss"}, notWant: "verify_sqli"},
	} {
		tools := []actool.CoreTool{finding()}
		for _, name := range tc.bind {
			tools = append(tools, verifier(name))
		}
		out, guidance := injectionVerifyWorkflow(tools)
		for _, name := range tc.want {
			if !strings.Contains(guidance, name) {
				t.Fatalf("%v: guidance omits %s: %q", tc.bind, name, guidance)
			}
		}
		if tc.notWant != "" && strings.Contains(guidance, tc.notWant) {
			t.Fatalf("%v: guidance names unbound %s: %q", tc.bind, tc.notWant, guidance)
		}
		for _, verb := range []string{"not_reproduced", "tool_uncovered", "session_needed", "finding_ids", "cookie"} {
			if !strings.Contains(guidance, verb) {
				t.Fatalf("%v: guidance omits %s", tc.bind, verb)
			}
		}
		for _, tool := range out {
			props, _ := json.Marshal(tool.InputSchema())
			var schema map[string]any
			_ = json.Unmarshal(props, &schema)
			if p, _ := schema["properties"].(map[string]any); len(p) == 0 {
				t.Fatalf("%v: %s lost its schema", tc.bind, tool.Name())
			}
			switch tool.Name() {
			case "report_finding":
				if !strings.HasPrefix(tool.Description(), "记录确认的漏洞") || !strings.Contains(tool.Description(), "finding_ids") {
					t.Fatalf("report_finding note wrong: %q", tool.Description())
				}
			default:
				if tool.Description() != "专项注入验证" {
					t.Fatalf("%s description rewritten", tool.Name())
				}
			}
		}
	}
}

// The guidance must reach the rendered system prompt through the same channel as
// the other finding-workflow notes, and stay out of agents without verifiers.
func TestInjectionVerifyGuidanceReachesSystemPrompt(t *testing.T) {
	oldResolve, oldAugment, oldPolicy := ToolResolve, ToolAugment, FindingTrafficBindingEnabled
	t.Cleanup(func() { ToolResolve, ToolAugment, FindingTrafficBindingEnabled = oldResolve, oldAugment, oldPolicy })
	ToolAugment, FindingTrafficBindingEnabled = nil, func() bool { return true }
	noop := func(context.Context, json.RawMessage) (actool.Result, error) { return actool.Text("ok"), nil }
	bound := func(context.Context, string, []actool.CoreTool) []actool.CoreTool { return nil }

	base := []actool.CoreTool{
		readTool("report_finding", "记录确认的漏洞", obj(map[string]any{"vulnclass": str("类别")}), noop),
		readTool("verify_sqli", "专项注入验证", obj(map[string]any{"urls": map[string]any{"type": "array"}}), noop),
	}
	ToolResolve = func(_ context.Context, _ string, tools []actool.CoreTool) []actool.CoreTool { return tools }
	_, def, cleanup := AugmentTools(t.Context(), "worker", base)
	cleanup()
	if !strings.Contains(def.FindingGuidance, "verify_sqli") {
		t.Fatalf("worker guidance missing: %q", def.FindingGuidance)
	}
	system, _ := deferredSystem("PROMPT", def)
	if !strings.Contains(system[0], "注入类漏洞专项复测") {
		t.Fatal("guidance never reaches the system prompt")
	}

	ToolResolve = bound
	_, def, cleanup = AugmentTools(t.Context(), "worker", base)
	cleanup()
	if def.FindingGuidance != "" {
		t.Fatalf("guidance survived unbinding: %q", def.FindingGuidance)
	}
}

// Rounds that save every injection report for the end of an intent run out of wall
// clock before sqlmap could start (Pikachu L5: nine SQLi findings in 15 seconds, two
// minutes before the deadline, none verified). The reminder therefore rides the
// report_finding result itself, with the concrete finding_id and the queue_only
// escape, and stays off both non-injection classes and refused reports.
func TestInjectionNudgeFollowsEachInjectionReport(t *testing.T) {
	verifier := func(name string) actool.CoreTool {
		return readTool(name, "专项注入验证", obj(map[string]any{"urls": map[string]any{"type": "array"}}),
			func(context.Context, json.RawMessage) (actool.Result, error) { return actool.Text("ok"), nil })
	}
	bind := func(out []actool.CoreTool) actool.CoreTool {
		for _, tool := range out {
			if tool.Name() == "report_finding" {
				return tool
			}
		}
		t.Fatal("report_finding missing")
		return nil
	}
	out, _ := injectionVerifyWorkflow([]actool.CoreTool{
		readTool("report_finding", "记录确认的漏洞", obj(map[string]any{"vulnclass": str("类别")}),
			func(_ context.Context, in json.RawMessage) (actool.Result, error) {
				var a struct {
					VulnClass string `json:"vulnclass"`
				}
				_ = json.Unmarshal(in, &a)
				if a.VulnClass == "REFUSED" {
					return actool.Errorf("HTTP 漏洞必须能让人逐字节重放"), nil
				}
				return actool.Text("finding recorded: 9\n{\"finding_id\":6442,\"finding_node_id\":9}"), nil
			}),
		verifier("verify_sqli"), verifier("verify_xss"),
	})
	tool := bind(out)

	call := func(class string) string {
		res, err := tool.Call(t.Context(), json.RawMessage(`{"vulnclass":"`+class+`"}`), nil)
		if err != nil {
			t.Fatalf("%s: %v", class, err)
		}
		return strings.Join(resultText(res), "\n")
	}

	sqli := call("SQL Injection")
	if !strings.Contains(sqli, "verify_sqli") || !strings.Contains(sqli, "finding_ids=[6442]") || !strings.Contains(sqli, "queue_only") {
		t.Fatalf("sql report nudge wrong: %q", sqli)
	}
	if strings.Contains(sqli, "verify_xss") {
		t.Fatalf("sql report nudged the wrong tool: %q", sqli)
	}
	xss := call("存储型 XSS")
	if !strings.Contains(xss, "verify_xss") || strings.Contains(xss, "verify_sqli") {
		t.Fatalf("xss report nudge wrong: %q", xss)
	}
	if got := call("CSRF"); got != "finding recorded: 9\n{\"finding_id\":6442,\"finding_node_id\":9}" {
		t.Fatalf("non-injection report got a nudge: %q", got)
	}
	if got := call("REFUSED"); strings.Contains(got, "verify_") {
		t.Fatalf("refused report got a nudge: %q", got)
	}
}
