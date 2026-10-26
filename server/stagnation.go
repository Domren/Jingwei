package server

// Deterministic stagnation detection for agent runs. The empty-turn nudge in
// engine.go covers "thought but did nothing"; this covers the other failure
// mode: the model keeps emitting the same action (or the same closing text)
// with no new information, burning the intent's turn budget.
//
// Two layers:
//   - tool level: the same tool+input producing a byte-identical result N times
//     in a row → the next repetition is blocked with a strategy-change message.
//   - stop level: the last two text-only assistant turns are identical → inject
//     a nudge; after the limit, hard-stop the run.
//
// The detector is per-intent (fresh each runIntent), holds no message content,
// and only compares SHA-256 digests.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/llm"
)

const (
	stagnationRepeatThreshold = 3
	stagnationNudgeLimit      = 2
	stagnationMinTextRunes    = 24
)

const stagnationStopNudge = "【停滞提醒】你最近两次结束时的正文几乎完全相同，没有产生新信息。" +
	"请基于已有证据写回 fact/finding 并结束，或明确换一条分析/测试路径；不要重复同一段话。"

type stagnationDetector struct {
	mu         sync.Mutex
	lastSig    string
	lastResult [32]byte
	streak     int
	nudges     int
	stopNudges int
}

func newStagnationDetector() *stagnationDetector { return &stagnationDetector{} }

// stagnantTool excludes tools whose identical repetition is legitimate pacing
// rather than a stalled loop.
func stagnantTool(name string) bool {
	switch name {
	case "Sleep", "TodoWrite":
		return false
	}
	return true
}

func toolCallSignature(name string, input []byte) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0})
	// Normalize JSON so key order / whitespace differences don't defeat the match.
	var v any
	if len(input) > 0 && json.Unmarshal(input, &v) == nil {
		if b, err := json.Marshal(v); err == nil {
			h.Write(b)
			return fmt.Sprintf("%x", h.Sum(nil))
		}
	}
	h.Write(input)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func resultDigest(result []byte, isErr bool) [32]byte {
	h := sha256.New()
	if isErr {
		h.Write([]byte("err:"))
	}
	h.Write(result)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// checkCall blocks the next repetition once the same call has produced the same
// result threshold times in a row. The model receives the reason as the tool
// result and must change tool/input; blocked calls never execute.
func (d *stagnationDetector) checkCall(name string, input []byte) (string, bool) {
	if d == nil || !stagnantTool(name) {
		return "", false
	}
	sig := toolCallSignature(name, input)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.streak < stagnationRepeatThreshold || sig != d.lastSig {
		return "", false
	}
	d.nudges++
	if d.nudges > stagnationNudgeLimit {
		return "【停滞拦截】该调用已多次返回完全相同的结果，继续重复不会带来新信息。本次调用已被阻止；" +
			"请基于已有证据写回 fact/finding 并结束本意图，或改用其他目标/参数/工具。不要原样重试。", true
	}
	return fmt.Sprintf("【停滞提醒】同一工具与参数已连续 %d 次返回完全相同的结果，继续重复不会产生新信息。"+
		"本次调用已被阻止；请立刻改变策略：换目标/换参数/换工具，或基于现有证据写回 fact/finding 并结束本意图。不要原样重试。", d.streak), true
}

func (d *stagnationDetector) observeResult(name string, input, result []byte, isErr bool) {
	if d == nil || !stagnantTool(name) {
		return
	}
	sig := toolCallSignature(name, input)
	digest := resultDigest(result, isErr)
	d.mu.Lock()
	if sig == d.lastSig && digest == d.lastResult {
		d.streak++
	} else {
		d.lastSig, d.lastResult, d.streak = sig, digest, 1
	}
	d.mu.Unlock()
}

// checkStop returns (nudge, prevent) when the closing assistant text repeats.
func (d *stagnationDetector) checkStop(messages []llm.Message) (string, bool) {
	if d == nil || !homogeneousAssistantText(messages) {
		return "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopNudges++
	if d.stopNudges > stagnationNudgeLimit {
		return "【停滞拦截】多次续跑后回复仍与之前完全相同，判定为停滞，结束本次执行。", true
	}
	return stagnationStopNudge, false
}

// homogeneousAssistantText reports whether the last two text-only assistant
// turns are identical and non-trivial. Tool-call turns are handled by checkCall.
func homogeneousAssistantText(messages []llm.Message) bool {
	var texts []string
	for i := len(messages) - 1; i >= 0 && len(texts) < 2; i-- {
		m := messages[i]
		if m.Role != llm.RoleAssistant || len(m.ToolUses()) > 0 {
			continue
		}
		t := strings.TrimSpace(m.Text())
		if len([]rune(t)) < stagnationMinTextRunes {
			continue
		}
		texts = append(texts, t)
	}
	return len(texts) == 2 && texts[0] == texts[1]
}
