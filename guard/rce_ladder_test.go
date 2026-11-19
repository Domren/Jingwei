package guard

// P9 验收：四级各自可独立关闭；逐级放行；跳级必须人工审批且被拒进审批记录。
// 全部用纯函数 + 假审批器跑通，不依赖 Postgres / sidecar。

import (
	"context"
	"testing"

	"github.com/Domren/jingwei/intercept"
)

// fakeRCEApprover 记录 HandleAsk/Log 调用，便于断言跳级是否走审批、被拒是否入审批记录。
type fakeRCEApprover struct {
	askCalls  int
	askAction string
	logs      []logCall
	approve   bool
}
type logCall struct {
	status  string
	tool    string
	message string
}

func (f *fakeRCEApprover) HandleAsk(_ context.Context, _ int64, dec intercept.Decision, tool string, _ []byte) bool {
	f.askCalls++
	f.askAction = dec.Action
	return f.approve
}
func (f *fakeRCEApprover) Log(_ context.Context, _ int64, dec intercept.Decision, tool string, _ []byte, status string) {
	f.logs = append(f.logs, logCall{status: status, tool: tool, message: dec.Message})
}

func TestEvaluateRCELevel_FourLevelSwitches(t *testing.T) {
	// 四个级别各自关闭后应 deny，且理由点名「已关闭」；开启后逐级请求应放行。
	levels := []int{RCELevelCallback, RCELevelHarmless, RCELevelRead, RCELevelWrite}
	cases := []struct {
		name string
		off  func(*RCELadderConfig)
	}{
		{"关闭回连证明", func(c *RCELadderConfig) { c.Callback = false }},
		{"关闭无害命令", func(c *RCELadderConfig) { c.Harmless = false }},
		{"关闭读文件", func(c *RCELadderConfig) { c.Read = false }},
		{"关闭写文件", func(c *RCELadderConfig) { c.Write = false }},
	}
	for _, tc := range cases {
		cfg := DefaultRCELadderConfig()
		tc.off(&cfg)
		for _, level := range levels {
			if cfg.LevelEnabled(level) {
				continue
			}
			action, reason := EvaluateRCELevel(cfg, level-1, level)
			if action != RCEDeny {
				t.Fatalf("%s：第 %d 级应被关闭拒绝，得到 %s", tc.name, level, action)
			}
			if !contains(reason, "关闭") {
				t.Fatalf("%s：拒绝理由应说明关闭，得到 %q", tc.name, reason)
			}
		}
	}
	// 全开时每级逐级请求都放行。
	cfg := DefaultRCELadderConfig()
	for _, level := range levels {
		if a, _ := EvaluateRCELevel(cfg, level-1, level); a != RCEAllow {
			t.Fatalf("全开时第 %d 级逐级请求应放行，得到 %s", level, a)
		}
	}
}

func TestEvaluateRCELevel_StepByStep(t *testing.T) {
	cfg := DefaultRCELadderConfig()
	achieved := 0
	for level := RCELevelCallback; level <= RCELevelWrite; level++ {
		action, _ := EvaluateRCELevel(cfg, achieved, level)
		if action != RCEAllow {
			t.Fatalf("从第 %d 级推进到第 %d 级应逐级放行，得到 %s", achieved, level, action)
		}
		achieved = level
	}
	// 重复验证已授权级别也放行，不再触发审批。
	if a, _ := EvaluateRCELevel(cfg, RCELevelWrite, RCELevelRead); a != RCEAllow {
		t.Fatalf("重复验证已授权级别应放行，得到 %s", a)
	}
}

func TestEvaluateRCELevel_SkipNeedsApproval(t *testing.T) {
	cfg := DefaultRCELadderConfig()
	// 从 0 直接请求 3、从 1 直接请求 4 都是跳级 → ask。
	for _, tc := range []struct{ achieved, requested int }{{0, 3}, {0, 4}, {1, 3}, {1, 4}, {2, 4}} {
		action, reason := EvaluateRCELevel(cfg, tc.achieved, tc.requested)
		if action != RCEAsk {
			t.Fatalf("achieved=%d requested=%d 应跳级审批，得到 %s（%s）", tc.achieved, tc.requested, action, reason)
		}
		if !contains(reason, "人工审批") {
			t.Fatalf("跳级理由应说明需人工审批，得到 %q", reason)
		}
	}
	// 非法级别直接拒绝。
	if a, _ := EvaluateRCELevel(cfg, 0, 5); a != RCEDeny {
		t.Fatalf("级别 5 应非法拒绝，得到 %s", a)
	}
}

func TestRCEGate_SkipDeniedGoesToApprovalRecord(t *testing.T) {
	approver := &fakeRCEApprover{approve: false} // 人工拒绝跳级
	gate := NewRCEGate(approver)
	params := map[string]any{"rce_level": RCELevelRead, "rce_achieved": 0}
	res := gate.Evaluate(context.Background(), 0, "verify_rce", params, []byte(`{}`))

	if res.Allowed {
		t.Fatal("跳级被人工拒绝时不应放行")
	}
	if res.Achieved != 0 {
		t.Fatalf("未批准不得推进已达级别，得到 %d", res.Achieved)
	}
	if approver.askCalls != 1 || approver.askAction != "ask" {
		t.Fatalf("跳级应走一次 ask 审批，askCalls=%d action=%s", approver.askCalls, approver.askAction)
	}
	// 被拒必须进审批记录。
	found := false
	for _, l := range approver.logs {
		if l.status == "denied" && l.tool == "verify_rce" {
			found = true
		}
	}
	if !found {
		t.Fatalf("跳级被拒应落 denied 审批记录，实际 %+v", approver.logs)
	}
}

func TestRCEGate_SkipApprovedAdvancesLevel(t *testing.T) {
	approver := &fakeRCEApprover{approve: true}
	gate := NewRCEGate(approver)
	params := map[string]any{"rce_level": RCELevelWrite, "rce_achieved": 1}
	res := gate.Evaluate(context.Background(), 0, "verify_rce", params, []byte(`{}`))

	if !res.Allowed {
		t.Fatalf("跳级经人工批准应放行：%s", res.Reason)
	}
	if res.Achieved != RCELevelWrite {
		t.Fatalf("批准后已达级别应推进到 %d，得到 %d", RCELevelWrite, res.Achieved)
	}
	if approver.askCalls != 1 {
		t.Fatalf("跳级应只问一次审批，得到 %d", approver.askCalls)
	}
}

func TestRCEGate_DisabledLevelDeniedAndLogged(t *testing.T) {
	approver := &fakeRCEApprover{approve: true}
	gate := NewRCEGate(approver)
	params := map[string]any{
		"rce_level":    RCELevelWrite,
		"rce_achieved": RCELevelRead, // 逐级本应放行
		"rce_write":    false,        // 但第 4 级被独立关闭
	}
	res := gate.Evaluate(context.Background(), 0, "verify_rce", params, []byte(`{}`))
	if res.Allowed {
		t.Fatal("被关闭的级别即使逐级也不应放行")
	}
	if approver.askCalls != 0 {
		t.Fatalf("关闭的级别不应进入跳级审批，askCalls=%d", approver.askCalls)
	}
	if len(approver.logs) == 0 || approver.logs[0].status != "denied" {
		t.Fatalf("关闭级别被拒也应留审批记录，实际 %+v", approver.logs)
	}
}

func TestRCEGate_NoApproverFailsClosed(t *testing.T) {
	// 没有拦截器时跳级一律不放行（宁可拦住，不靠提示词自律）。
	gate := NewRCEGate(nil)
	params := map[string]any{"rce_level": RCELevelRead, "rce_achieved": 0}
	res := gate.Evaluate(context.Background(), 0, "verify_rce", params, []byte(`{}`))
	if res.Allowed {
		t.Fatal("无审批器时跳级应失败关闭")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
