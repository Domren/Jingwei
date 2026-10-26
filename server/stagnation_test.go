package server

import (
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestStagnationBlocksRepeatedCall(t *testing.T) {
	d := newStagnationDetector()
	input := []byte(`{"command":"curl -s http://a.test/"}`)
	for i := 0; i < stagnationRepeatThreshold; i++ {
		if msg, blocked := d.checkCall("Bash", input); blocked {
			t.Fatalf("call %d blocked too early: %s", i+1, msg)
		}
		d.observeResult("Bash", input, []byte("same output"), false)
	}
	msg, blocked := d.checkCall("Bash", input)
	if !blocked || msg == "" {
		t.Fatal("expected the repeat after threshold to be blocked")
	}
	if _, blocked := d.checkCall("Bash", []byte(`{"command":"id"}`)); blocked {
		t.Fatal("a different call must not be blocked")
	}
}

func TestStagnationResetsOnChangedResult(t *testing.T) {
	d := newStagnationDetector()
	input := []byte(`{"command":"curl -s http://a.test/"}`)
	d.observeResult("Bash", input, []byte("one"), false)
	d.observeResult("Bash", input, []byte("one"), false)
	d.observeResult("Bash", input, []byte("one"), false)
	if _, blocked := d.checkCall("Bash", input); !blocked {
		t.Fatal("expected block after 3 identical results")
	}
	d.observeResult("Bash", input, []byte("two"), false)
	if _, blocked := d.checkCall("Bash", input); blocked {
		t.Fatal("changed output must reset the streak")
	}
}

func TestStagnationIgnoresPacingTools(t *testing.T) {
	d := newStagnationDetector()
	input := []byte(`{"seconds":1}`)
	for i := 0; i < stagnationRepeatThreshold+1; i++ {
		d.observeResult("Sleep", input, []byte(""), false)
	}
	if _, blocked := d.checkCall("Sleep", input); blocked {
		t.Fatal("Sleep must not be treated as stagnation")
	}
}

func textTurn(s string) llm.Message {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(s)}}
}

func TestHomogeneousAssistantText(t *testing.T) {
	long := "我已经完成了对目标的检查，没有发现新的可利用入口，建议结束本意图。"
	msgs := []llm.Message{
		textTurn("first unrelated turn"),
		llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("continue")}},
		textTurn(long),
		textTurn(long),
	}
	if !homogeneousAssistantText(msgs) {
		t.Fatal("two identical closing texts should be homogeneous")
	}
	if homogeneousAssistantText([]llm.Message{textTurn(long), textTurn(long + "不同")}) {
		t.Fatal("different texts must not match")
	}
	if homogeneousAssistantText([]llm.Message{textTurn("short"), textTurn("short")}) {
		t.Fatal("trivial short texts must not match")
	}
	toolTurn := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		llm.TextBlock(long),
		{Type: llm.BlockToolUse, Name: "Bash", Input: []byte(`{"command":"id"}`)},
	}}
	if homogeneousAssistantText([]llm.Message{toolTurn, toolTurn}) {
		t.Fatal("tool-call turns are handled by the call detector, not the text check")
	}
}

func TestStagnationStopEscalates(t *testing.T) {
	d := newStagnationDetector()
	long := "我已经完成了对目标的检查，没有发现新的可利用入口，建议结束本意图。"
	msgs := []llm.Message{textTurn(long), textTurn(long)}
	for i := 1; i <= stagnationNudgeLimit; i++ {
		msg, hard := d.checkStop(msgs)
		if hard || msg == "" {
			t.Fatalf("nudge %d should not hard-stop", i)
		}
	}
	if msg, hard := d.checkStop(msgs); !hard || msg == "" {
		t.Fatal("expected a hard stop after the nudge limit")
	}
}
