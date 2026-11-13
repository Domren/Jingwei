package llmrec

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/norma/llm"
)

// PerCallProvider 夹具：worker 侧「一次调用 = 一轮」的监督。三个独立面：
// 正常轮的 usage 折算与留痕、错误轮的分类、T1 卡死轮的主动 cancel + stalled。

// fakeProv 是可脚本化的 provider：stream / complete 各自独立编排。
type fakeProv struct {
	events []llm.StreamEvent // Stream 依序吐出的事件
	err    error             // 事件吐完后追加的终态错误（nil = 正常收尾）
	delay  time.Duration     // 吐第一个事件前的延迟（卡死夹具用）
}

func (f *fakeProv) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if f.delay > 0 {
			select {
			case <-time.After(f.delay):
			case <-ctx.Done():
				yield(llm.StreamEvent{}, ctx.Err())
				return
			}
		}
		for _, ev := range f.events {
			if !yield(ev, nil) {
				return
			}
		}
		if f.err != nil {
			yield(llm.StreamEvent{}, f.err)
		}
	}
}

func (f *fakeProv) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	var u llm.Usage
	for _, ev := range f.events {
		if ev.Type == llm.SEMessageStart || ev.Type == llm.SEMessageDelta {
			u.Add(ev.Usage)
		}
	}
	return llm.Message{}, "stop", u, f.err
}

// usage 事件组：message_start 只带输入、message_delta 只带输出（与真实 provider 同形）。
func usageEvents() []llm.StreamEvent {
	return []llm.StreamEvent{
		{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 1500}},
		{Type: llm.SETextDelta, Text: "hi"},
		{Type: llm.SEMessageDelta, StopReason: "stop", Usage: llm.Usage{OutputTokens: 100}},
	}
}

func waitFor(t *testing.T, stub *stubDB, cond func([]db.LLMRound) bool) []db.LLMRound {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var rows []db.LLMRound
	for time.Now().Before(deadline) {
		rows = stub.snapshot()
		if cond(rows) {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
	return rows
}

func TestPerCallProviderRecordsUsageRound(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)
	sup.firstEventTimeout = time.Second

	p := NewPerCallProvider(sup, &fakeProv{events: usageEvents()}, 7, "worker", "7-w42")
	ctx := context.Background()
	for _, err := range p.Stream(ctx, llm.CompletionRequest{}) {
		_ = err
	}

	rows := waitFor(t, stub, func(rows []db.LLMRound) bool {
		return len(rows) == 1 && rows[0].Status == "ok"
	})
	if len(rows) != 1 || rows[0].Status != "ok" {
		t.Fatalf("应落一条 ok 轮，实际 %v", rows)
	}
	if !strings.HasPrefix(rows[0].RoundID, "7-w42-") {
		t.Fatalf("轮号应带 baseID 前缀，实际 %q", rows[0].RoundID)
	}
	if rows[0].InputTokens != 1500 || rows[0].OutputTokens != 100 {
		t.Fatalf("轮级 token 应为 1500/100，实得 %d/%d", rows[0].InputTokens, rows[0].OutputTokens)
	}
	if rows[0].Worker != "worker" || rows[0].TaskID != "7" {
		t.Fatalf("lane/task 应为 worker/7，实际 %q/%q", rows[0].Worker, rows[0].TaskID)
	}
}

func TestPerCallProviderRecordsErrorRound(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)

	p := NewPerCallProvider(sup, &fakeProv{events: usageEvents(),
		err: errors.New(`status 429: rate limit exceeded`)}, 7, "worker", "7-w1")
	for _, err := range p.Stream(context.Background(), llm.CompletionRequest{}) {
		_ = err
	}

	rows := waitFor(t, stub, func(rows []db.LLMRound) bool {
		return len(rows) == 1 && rows[0].Status == "error"
	})
	if len(rows) != 1 {
		t.Fatalf("应落一条错误轮，实际 %v", rows)
	}
	if rows[0].ErrorClass != string(ErrClassRateLimited) {
		t.Fatalf("应判 rate_limited，实际 %q", rows[0].ErrorClass)
	}
	if rows[0].InputTokens != 1500 || rows[0].OutputTokens != 100 {
		t.Fatalf("失败轮也应带上已折算的 token，实得 %d/%d", rows[0].InputTokens, rows[0].OutputTokens)
	}
}

func TestPerCallProviderStallCancels(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)
	sup.firstEventTimeout = 80 * time.Millisecond // 夹具等不了 75s

	// 一直不给首帧：T1 一过监督层应 cancel，调用方看到 stream error，
	// 轮记录落 stalled。
	p := NewPerCallProvider(sup, &fakeProv{delay: 5 * time.Second}, 7, "worker", "7-w9")
	sawErr := false
	for _, err := range p.Stream(context.Background(), llm.CompletionRequest{}) {
		if err != nil {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatalf("T1 卡死应让本次调用以错误收尾")
	}

	rows := waitFor(t, stub, func(rows []db.LLMRound) bool {
		return len(rows) == 1 && rows[0].Status != "running"
	})
	if len(rows) != 1 || rows[0].Status != "stalled" {
		t.Fatalf("应落一条 stalled 轮，实际 %v", rows)
	}
}

func TestPerCallProviderCompleteRecords(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)

	p := NewPerCallProvider(sup, &fakeProv{events: usageEvents()}, 9, "mainagent", "9-m1")
	_, _, u, err := p.Complete(context.Background(), llm.CompletionRequest{})
	if err != nil {
		t.Fatalf("Complete 不应出错：%v", err)
	}
	if u.InputTokens != 1500 || u.OutputTokens != 100 {
		t.Fatalf("usage 应透传，实得 %d/%d", u.InputTokens, u.OutputTokens)
	}

	rows := waitFor(t, stub, func(rows []db.LLMRound) bool { return len(rows) == 1 })
	if len(rows) != 1 || rows[0].Status != "ok" {
		t.Fatalf("非流式调用也应落一条 ok 轮，实际 %v", rows)
	}
	if rows[0].InputTokens != 1500 || rows[0].OutputTokens != 100 {
		t.Fatalf("非流式轮级 token 应为 1500/100，实得 %d/%d", rows[0].InputTokens, rows[0].OutputTokens)
	}
}
