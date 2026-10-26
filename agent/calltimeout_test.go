package agent

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

type hangingProvider struct{}

func (hangingProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		<-ctx.Done()
		yield(llm.StreamEvent{}, ctx.Err())
	}
}

func (hangingProvider) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	<-ctx.Done()
	return llm.Message{}, "", llm.Usage{}, ctx.Err()
}

func TestCallTimeoutProviderStream(t *testing.T) {
	p := &callTimeoutProvider{inner: hangingProvider{}, timeout: 40 * time.Millisecond}
	start := time.Now()
	var got error
	for _, err := range p.Stream(context.Background(), llm.CompletionRequest{}) {
		got = err
	}
	if !errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("hard wall clock did not fire promptly: %s", elapsed)
	}
}

func TestCallTimeoutProviderComplete(t *testing.T) {
	p := &callTimeoutProvider{inner: hangingProvider{}, timeout: 40 * time.Millisecond}
	start := time.Now()
	_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("hard wall clock did not fire promptly: %s", elapsed)
	}
}

func TestLLMCallTimeoutResolution(t *testing.T) {
	t.Setenv("ARTEX_LLM_CALL_TIMEOUT", "90s")
	if got := llmCallTimeout(); got != 90*time.Second {
		t.Fatalf("duration form: got %s", got)
	}
	t.Setenv("ARTEX_LLM_CALL_TIMEOUT", "120")
	if got := llmCallTimeout(); got != 2*time.Minute {
		t.Fatalf("seconds form: got %s", got)
	}
	t.Setenv("ARTEX_LLM_CALL_TIMEOUT", "bogus")
	if got := llmCallTimeout(); got != defaultLLMCallTimeout {
		t.Fatalf("invalid value must fall back: got %s", got)
	}
	t.Setenv("ARTEX_LLM_CALL_TIMEOUT", "0")
	if got := llmCallTimeout(); got != 0 {
		t.Fatalf("zero must disable the cap: got %s", got)
	}
}

func TestUntrustedRulesAppended(t *testing.T) {
	for name, sys := range map[string]string{
		"worker":    workerSystem("", "", "/data", "/data/run"),
		"planner":   plannerSystem("goal", "/data", "/data/run"),
		"chat":      chatSystem("worker", "/data", "/data/run"),
		"mainagent": mainAgentSystem("goal", "/data", "/data/run"),
	} {
		if !strings.Contains(sys, "不可信数据与证据规则") {
			t.Errorf("%s prompt is missing the untrusted-data rules", name)
		}
	}
}
