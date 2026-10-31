package server

import (
	"context"
	"strings"
	"testing"
)

// A planner steer must never swallow the write-back call that persists an
// already-confirmed finding/fact. It stays queued and blocks the next ordinary
// tool instead.
func TestSteerHooksPreToolUseExemptsWriteBackTools(t *testing.T) {
	queue := []string{"先别继续扫了，把已确认的漏洞写回"}
	drained := 0
	h := steerHooks{drain: func() (string, bool) {
		if len(queue) == 0 {
			return "", false
		}
		msg := queue[0]
		queue = queue[1:]
		drained++
		return msg, true
	}}

	for _, name := range []string{"report_finding", "record_fact", "record_intelligence", "insert_assets", "bind_finding_traffic"} {
		blocked, _, _ := h.PreToolUse(context.Background(), name, nil)
		if blocked {
			t.Fatalf("write-back tool %s was blocked by a queued steer", name)
		}
	}
	if drained != 0 || len(queue) != 1 {
		t.Fatalf("write-back tools must not drain the steer: drained=%d queued=%d", drained, len(queue))
	}

	want := queue[0]
	blocked, msg, _ := h.PreToolUse(context.Background(), "run_nuclei", nil)
	if !blocked || !strings.Contains(msg, "规划者实时纠偏") || !strings.Contains(msg, want) {
		t.Fatalf("ordinary tool did not consume the steer: blocked=%v msg=%q", blocked, msg)
	}
	if drained != 1 || len(queue) != 0 {
		t.Fatalf("steer state after ordinary tool: drained=%d queued=%d", drained, len(queue))
	}

	if blocked, _, _ := h.PreToolUse(context.Background(), "run_nuclei", nil); blocked {
		t.Fatal("ordinary tool must run once no steer is queued")
	}
}

// Without a queued steer every tool behaves exactly as before.
func TestSteerHooksPreToolUsePassesThroughWithoutSteer(t *testing.T) {
	h := steerHooks{drain: func() (string, bool) { return "", false }}
	for _, name := range []string{"report_finding", "run_nuclei", "http_request"} {
		if blocked, _, _ := h.PreToolUse(context.Background(), name, nil); blocked {
			t.Fatalf("%s blocked without a queued steer", name)
		}
	}
}
