package agent

// Hard wall clock for a single LLM call. The SDK's retry ladder only guards the
// connection phase; a stream that stalls after headers, or a gateway that never
// finishes, can keep a run hanging forever (MaxDuration is checked at turn
// boundaries). This wrapper bounds the WHOLE call — all SDK retries plus body
// streaming — with one deadline, so the agent loop always makes progress.

import (
	"context"
	"errors"
	"iter"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// defaultLLMCallTimeout is deliberately generous: thinking models can take many
// minutes on one reply. It exists to kill hangs, not to cap normal latency.
const defaultLLMCallTimeout = 15 * time.Minute

// llmCallTimeout resolves ARTEX_LLM_CALL_TIMEOUT. Accepts a Go duration
// ("10m", "900s") or plain seconds; invalid values fall back to the default.
// <= 0 disables the hard cap.
func llmCallTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("ARTEX_LLM_CALL_TIMEOUT"))
	if raw == "" {
		return defaultLLMCallTimeout
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		return time.Duration(secs) * time.Second
	}
	log.Printf("[llm] ARTEX_LLM_CALL_TIMEOUT=%q 无效，使用默认 %s", raw, defaultLLMCallTimeout)
	return defaultLLMCallTimeout
}

type callTimeoutProvider struct {
	inner   llm.Provider
	timeout time.Duration
}

func (p *callTimeoutProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		ctx, cancel := context.WithTimeout(ctx, p.timeout)
		defer cancel()
		for ev, err := range p.inner.Stream(ctx, req) {
			p.logTimeout(ctx, err)
			if !yield(ev, err) {
				return
			}
			if err != nil {
				return
			}
		}
	}
}

func (p *callTimeoutProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	msg, text, usage, err := p.inner.Complete(ctx, req)
	p.logTimeout(ctx, err)
	return msg, text, usage, err
}

func (p *callTimeoutProvider) logTimeout(ctx context.Context, err error) {
	if err != nil && errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		log.Printf("[llm] 单次调用超过硬性墙钟 %s，已中止（含 SDK 重试与流式读取）", p.timeout)
	}
}
