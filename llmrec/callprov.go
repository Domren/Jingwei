package llmrec

import (
	"context"
	"fmt"
	"iter"
	"sync/atomic"

	"github.com/Autumn-27/norma/llm"
)

// PerCallProvider 把「一次 LLM 调用 = 一轮监督」套在 provider 外层，给 worker 这类
// 单次 run 内发多次调用的角色补上 R21 L2 的缺口：此前只有 planner 有轮留痕
// （engine 手工 Begin/End），worker 的几十次调用只在 llm_usage/llm_record 里留了
// token，T1 首帧监督与错误分类全部缺席——端点卡死要等意图墙钟超时才被发现。
//
// 用法：worker 在每个 run 开始时用本层包住实际 provider；每次 Stream/Complete
// 自动 Begin/End 一轮，RoundID = <baseID>-<序号>。planner 仍走手工 Begin/End
// （一次 Plan = 一轮），不经这里。
//
// usage 折算口径与 Recorder 相同：message_start 只带输入侧、message_delta 只带
// 输出侧，两侧相加（Add 折叠），与 llm_usage 行一致。
type PerCallProvider struct {
	sup    *Supervisor
	base   llm.Provider
	taskID int64
	worker string
	baseID string
	seq    atomic.Int64
}

// NewPerCallProvider 构造。baseID 是轮号前缀（建议 taskID+"-w-"+intentID），
// worker 是轮记录的 lane 标签（"worker" / "mainagent"）。
func NewPerCallProvider(sup *Supervisor, base llm.Provider, taskID int64, worker, baseID string) *PerCallProvider {
	return &PerCallProvider{sup: sup, base: base, taskID: taskID, worker: worker, baseID: baseID}
}

func (p *PerCallProvider) begin(ctx context.Context) (*Round, context.Context, llm.Provider) {
	id := fmt.Sprintf("%s-%d", p.baseID, p.seq.Add(1))
	r, rctx := p.sup.Begin(ctx, RoundMeta{
		RoundID: id, TaskID: p.taskID, Worker: p.worker,
	})
	return r, rctx, r.WrapProvider(p.base)
}

// Stream 每次流式调用包一轮。T1 内无首帧时监督层会 cancel rctx，本次调用以
// stalled 终态落库，agentcore 侧看到的是一次 stream error（与端点故障同形）。
func (p *PerCallProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		r, rctx, inner := p.begin(ctx)
		// usage 折算在 WrapProvider（firstEventProvider）里做：message_start 只带
		// 输入侧、message_delta 只带输出侧，Add 折叠，口径与 Recorder 一致。
		// 这里不重复折，否则与监督层的回报双记。
		for ev, err := range inner.Stream(rctx, req) {
			if err != nil {
				r.End(err)
				if !yield(ev, err) {
					return
				}
				return
			}
			if !yield(ev, err) {
				r.End(nil) // 消费方提前停：调用本身没有失败证据，不硬判错误
				return
			}
		}
		r.End(nil)
	}
}

// Complete 每次非流式调用包一轮。WrapProvider.Complete 已做首帧与 usage 回报。
func (p *PerCallProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	r, rctx, inner := p.begin(ctx)
	msg, stop, u, err := inner.Complete(rctx, req)
	r.End(err)
	return msg, stop, u, err
}
