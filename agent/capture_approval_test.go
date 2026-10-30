package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/guard"
	"github.com/Autumn-27/jingwei/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
)

// preserveNewSettings deletes settings keys the database did not hold when the
// test started, so it has to be registered before any cleanup that writes
// settings. The interceptor can store a key but never forget one, so "restore what
// I read" would persist every read default as if an operator had chosen it.
func preserveNewSettings(t *testing.T, d *db.DB) {
	t.Helper()
	list := func() map[string]bool {
		out := map[string]bool{}
		rows, err := d.Query(`SELECT key FROM settings`)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				return out
			}
			out[key] = true
		}
		return out
	}
	before := list()
	t.Cleanup(func() {
		var added []string
		for key := range list() {
			if !before[key] {
				added = append(added, key)
			}
		}
		if len(added) == 0 {
			return
		}
		if _, err := d.Exec(`DELETE FROM settings WHERE key = ANY($1::text[])`, added); err != nil {
			t.Logf("清理测试写入的设置失败: %v", err)
		}
	})
}

// Exercise the actual SDK event -> hook -> execution -> result path. No real
// model or command is used; the probe tool only returns a fixed string.
func TestCaptureApprovalLifecycle(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	preserveNewSettings(t, d)
	ic := intercept.New(d)
	priorTools, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	priorConfig := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetEnabledTools(priorTools); _ = ic.SetJudgeConfig(priorConfig) })
	if err := ic.SetEnabledTools([]string{"ApprovalAuditProbe"}); err != nil {
		t.Fatal(err)
	}
	if err := ic.SetJudgeConfig(intercept.JudgeConfig{Enabled: true, FailAction: "allow", AskTimeoutSeconds: 1, AskTimeoutAction: "allow"}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, action, status, execution string
		manual, approve, toolError      bool
	}{
		{"model_fallback", "invalid", "allowed", "succeeded", false, false, false},
		{"model_allow", "allow", "allowed", "succeeded", false, false, false},
		{"model_deny", "deny", "denied", "not_executed", false, false, false},
		{"human_allow_tool_error", "ask", "allowed", "failed", true, true, true},
		{"human_deny", "ask", "denied", "not_executed", true, false, false},
		{"timeout_allow", "ask", "timeout", "succeeded", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ic.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
				return intercept.Decision{Action: tc.action, Message: "probe review", ProfileID: 7}, nil
			})
			g := guard.NewWithInterceptor(ic)
			taskID := "approval-lifecycle-" + tc.name
			t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, taskID) })
			ctx := intercept.WithTaskContext(t.Context(), taskID, "test-agent", func(a db.Activity) {
				if a.Kind != "intercept_request" || !tc.manual {
					return
				}
				var detail struct {
					ID int64 `json:"pending_id"`
				}
				if err := json.Unmarshal([]byte(a.Detail), &detail); err != nil {
					t.Error(err)
					return
				}
				if err := ic.Decide(detail.ID, tc.approve); err != nil {
					t.Error(err)
				}
			})
			turn, executions := 0, 0
			provider := captureUsageProvider{stream: func(_ context.Context, yield func(llm.StreamEvent, error) bool) {
				turn++
				events := []llm.StreamEvent{{Type: llm.SETextDelta, Text: "done"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
				if turn == 1 {
					events = []llm.StreamEvent{
						{Type: llm.SEToolUseStart, ToolID: "probe-call", ToolName: "ApprovalAuditProbe"},
						{Type: llm.SEToolInputJSON, Text: `{}`}, {Type: llm.SEMessageDelta, StopReason: "tool_use"},
					}
				}
				for _, event := range events {
					if !yield(event, nil) {
						return
					}
				}
			}}
			probe := tool.Build(tool.Spec{Name: "ApprovalAuditProbe", Schema: map[string]any{"type": "object"},
				Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
					executions++
					if tc.toolError {
						return tool.Errorf("probe failed"), nil
					}
					return tool.Text("probe succeeded"), nil
				},
			})
			_, _, err := captureRun(ctx, agentcore.Options{Provider: provider, Tools: []tool.CoreTool{probe}, Hooks: g.Hooks(),
				PermissionMode: permission.ModeBypass, WorkingDir: t.TempDir(), MaxTurns: 2}, "record this review", nil)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := d.ListTaskIntercepts(taskID)
			if err != nil || len(rows) != 1 {
				t.Fatalf("rows=%d err=%v", len(rows), err)
			}
			detail, err := d.GetInterceptDetail(rows[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			a := detail.Audit
			initialAction := tc.action
			if tc.action == "invalid" {
				initialAction = "allow"
			}
			wantUserMessage := "record this review"
			if initialAction == "allow" {
				// Routine automatic allows keep decision/execution metadata but
				// intentionally omit the bulky replay context from the audit row.
				wantUserMessage = ""
			}
			wantSource := "model"
			if tc.manual {
				// 人工裁决行记 manual，规则命中记 rule；只有模型判定的行才是 model。
				wantSource = "manual"
			}
			if detail.Status != tc.status || detail.DecisionSource != wantSource || a == nil || a.ExecutionStatus != tc.execution || a.ToolUseID != "probe-call" || a.UserMessage != wantUserMessage || a.InitialAction != initialAction || a.ModelFallback != (tc.action == "invalid") || a.ProfileID != 7 {
				t.Fatalf("unexpected review: row=%+v audit=%+v", detail.InterceptApprovalRow, a)
			}
			if initialAction == "allow" && (len(a.Context) != 0 || a.UserTruncated || a.ContextTruncated) {
				t.Fatalf("routine allow retained replay context: %+v", a)
			}
			wantCalls := 1
			if tc.execution == "not_executed" {
				wantCalls = 0
			}
			if executions != wantCalls {
				t.Fatalf("tool ran %d times, wanted %d", executions, wantCalls)
			}
		})
	}
}
