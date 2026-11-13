package llmrec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// R21 十条补丁的夹具（2026-11-12）。
//
// 每个用例对应 §5.1 R21 行里编号的一条缺口，且都做**反向验证**：把判据改回
// 旧行为，用例必须失败——夹具自身不做反向验证，就只是把现状抄了一遍。
//
// 用到的假错误都按真实形态写：中转端 502/504 的 body、Go 的 net.OpError、
// 中转端 model_not_found 的原文（见 §4.4 的实测记录）。

// ── ① 分类器：四类故障必须分开，不能再全落 other ──────────────────────────

func TestClassifyUnreachableIsNotOther(t *testing.T) {
	// 真实形态：本地 DNS 把域名 sinkhole 到回环（§5.3 第 6 条）。
	_, err := net.Dial("tcp", "127.0.1.1:443")
	if err == nil {
		t.Skip("127.0.1.1:443 可达，无法构造 connection refused")
	}
	if got := ClassifyError(fmt.Errorf("dial tcp 127.0.1.1:443: %w", err), nil); got != ErrClassUnreachable {
		t.Fatalf("连接被拒必须归 unreachable（处置是修 DNS/换端点），实得 %q", got)
	}

	// 真实形态：域名解析不到。
	lookupErr := &net.DNSError{Err: "no such host", Name: "llm.invalid", IsNotFound: true}
	if got := ClassifyError(fmt.Errorf("post: %w", lookupErr), nil); got != ErrClassUnreachable {
		t.Fatalf("DNS 解析失败必须归 unreachable，实得 %q", got)
	}
}

func TestClassifyUpstream5xx(t *testing.T) {
	cases := map[string]string{
		"504 网关超时":            `openai: status 504: <html>Gateway Timeout</html>`,
		"502 Upstream failed": `openai: status 502: {"error":"Upstream request failed"}`,
		"503 service unavail": `anthropic: status 503: service unavailable`,
		"裸文案 upstream":        `upstream connect error or disconnect/reset before headers`,
	}
	for name, msg := range cases {
		if got := ClassifyError(errors.New(msg), nil); got != ErrClassUpstream5xx {
			t.Errorf("%s 应归 upstream_5xx（处置是重试/换端点），实得 %q", name, got)
		}
	}
}

func TestClassifyModelNotFound(t *testing.T) {
	// §4.4 13:24:30 的原文。
	msg := `openai: status 404: Model "DeepSeek-V4.1-Flash-1017" is not supported by any configured account in this group`
	if got := ClassifyError(errors.New(msg), nil); got != ErrClassModelNotFound {
		t.Fatalf("模型名不被支持必须归 model_not_found（处置是改模型名），实得 %q", got)
	}
}

func TestClassifyRateLimitedFromUpstream429(t *testing.T) {
	// §4.4 12:23 的原文：中转端把上游 429 包在 200 里回来时，只剩这行 body。
	msg := `openai: status 429: Upstream rate limit exceeded, please try again later`
	if got := ClassifyError(errors.New(msg), nil); got != ErrClassRateLimited {
		t.Fatalf("限流必须归 rate_limited（处置是退避，且不计熔断），实得 %q", got)
	}
}

// 反向验证：旧的裸数字匹配会把端口号当成 401。
func TestClassifyDoesNotMistakePortForStatusCode(t *testing.T) {
	// 这条错误里真正的状态码是 500，端口 40123 不该被当成 401。
	msg := `openai: status 500: dial tcp 10.0.0.5:40123: connection refused`
	if got := ClassifyError(errors.New(msg), nil); got == ErrClassAccountInvalid {
		t.Fatalf("端口号被误判成 401（旧实现在这里会归 account_invalid）: %q", msg)
	}
	// 500 与「连接被拒」同时出现时，net 错误链的证据更具体：连都没连上。
	if got := ClassifyError(errors.New(msg), nil); got != ErrClassUnreachable {
		t.Logf("当前归 %q（500 优先也合理，只要不是 account_invalid）", got)
	}
}

// 五类必须能全部分开——这是「按类处置」的前提。
func TestAllClassesAreReachable(t *testing.T) {
	cases := []struct {
		msg  string
		want ErrorClass
	}{
		{`stream error: stream ID 633; INTERNAL_ERROR; received from peer`, ErrClassTransportReset},
		{`openai: status 429: too many requests`, ErrClassRateLimited},
		{`openai: status 402: insufficient balance`, ErrClassAccountInvalid},
		{`openai: status 404: model_not_found`, ErrClassModelNotFound},
		{`openai: status 504: gateway timeout`, ErrClassUpstream5xx},
		{`dial tcp 127.0.1.1:443: connect: connection refused`, ErrClassUnreachable},
		{`empty response from provider`, ErrClassEmptyResponse},
		{`something nobody classified`, ErrClassOther},
	}
	for _, c := range cases {
		if got := ClassifyError(errors.New(c.msg), nil); got != c.want {
			t.Errorf("ClassifyError(%q) = %q，期望 %q", c.msg, got, c.want)
		}
	}
	if got := ClassifyError(context.DeadlineExceeded, nil); got != ErrClassTimeout {
		t.Errorf("墙钟到点应归 timeout，实得 %q", got)
	}
	// 分类清单与实际实现数量一致，前端与夹具都不会漏。
	if len(AllErrorClasses) != 10 {
		t.Errorf("AllErrorClasses 应有 10 类，实得 %d", len(AllErrorClasses))
	}
}

// ── ⑩ T1 解析：纯数字必须按秒，两侧同一口径 ──────────────────────────────

func TestParseTimeoutValueTreatsBareNumberAsSeconds(t *testing.T) {
	cases := map[string]time.Duration{
		"":      DefaultFirstEventTimeout,
		"90":    90 * time.Second,
		"45":    45 * time.Second,
		"1.5":   1500 * time.Millisecond,
		"2m":    2 * time.Minute,
		"90s":   90 * time.Second,
		"abc":   DefaultFirstEventTimeout, // 非法值回落
		"0":     0,
		"-30":   DefaultFirstEventTimeout, // 负数不接受（纯数字解析只认数字）
		"1h30m": 90 * time.Minute,
	}
	for raw, want := range cases {
		if got := ParseTimeoutValue(raw); got != want {
			t.Errorf("ParseTimeoutValue(%q) = %v，期望 %v", raw, got, want)
		}
	}
}

func TestDefaultFirstEventTimeoutIsRelaxed(t *testing.T) {
	// 缺口⑩：实测恢复期首帧到过 43s，45s 阈值只差 2 秒就误杀。默认必须放宽。
	if DefaultFirstEventTimeout < 60*time.Second {
		t.Fatalf("默认 T1 必须放宽到 60s 以上（实测 43s 压线），实得 %v", DefaultFirstEventTimeout)
	}
}

// ── ⑤ 失败退避：序列必须递增且封顶 ────────────────────────────────────────

func TestBackoffBeforeGrowsAndCaps(t *testing.T) {
	if d := BackoffBefore(0); d != 0 {
		t.Errorf("没有失败时不该退避，实得 %v", d)
	}
	prev := time.Duration(0)
	for i := 1; i <= 6; i++ {
		d := BackoffBefore(i)
		if d <= 0 {
			t.Fatalf("第 %d 次连续失败必须有退避", i)
		}
		if i <= 3 && d <= prev {
			t.Errorf("退避应递增：第 %d 次 %v 不大于上一次 %v", i, d, prev)
		}
		prev = d
	}
	if BackoffBefore(100) > 2*time.Minute {
		t.Errorf("退避必须封顶 2 分钟（否则端点恢复后仍要等很久才被发现），实得 %v", BackoffBefore(100))
	}
}

// ── L3 零进展判据：阈值真的被读、且只在连续时触发 ──────────────────────────

func TestStalledTaskReadsThreshold(t *testing.T) {
	if !StalledTask(5, 5) {
		t.Error("连续 5 轮零进展、阈值 5 应判 stalled")
	}
	if StalledTask(4, 5) {
		t.Error("未达阈值不该判 stalled")
	}
	// 阈值 <=0 时回落默认值 5：3 轮不够，5 轮才够。
	if StalledTask(3, 0) {
		t.Error("阈值为 0 回落默认 5 时，3 轮不该触发")
	}
	if !StalledTask(5, 0) {
		t.Error("阈值为 0 回落默认 5 时，5 轮必须触发")
	}
}

func TestSupervisorStalledRoundsIsReadable(t *testing.T) {
	// 缺口：过去 DefaultStalledRounds 只有常量与 setter，没有任何判据读它。
	sup := NewSupervisor(nil, nil)
	if got := sup.StalledRounds(); got != DefaultStalledRounds {
		t.Fatalf("默认阈值应为 %d，实得 %d", DefaultStalledRounds, got)
	}
	sup.SetStalledRounds(2)
	if got := sup.StalledRounds(); got != 2 {
		t.Fatalf("setter 之后应读到 2，实得 %d", got)
	}
}

// Progress 的「有进展」定义：任一计数增长即算。
func TestProgressConverged(t *testing.T) {
	if (Progress{}).Converged() {
		t.Error("全零必须算零进展")
	}
	for name, p := range map[string]Progress{
		"判出目标": {GoalMet: 1},
		"新意图":  {NewIntent: 1},
		"新资产":  {NewAsset: 1},
	} {
		if !p.Converged() {
			t.Errorf("%s 必须算有进展", name)
		}
	}
}

// ── ⑥⑧⑨ 轮记账：token、去重、逐发错误 ──────────────────────────────────

// ⑥ 轮级 token 必须落到这一轮上；只靠 llm_usage 的累计答不出「这一轮烧了多少」。
func TestRoundRecordsTokenUsage(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)
	sup.SetFirstEventTimeout(0) // 关掉 L1，专注记账

	round, _ := sup.Begin(context.Background(), RoundMeta{
		RoundID: "t-1", TaskID: 7, Worker: "planner", Model: "m-1", ProfileName: "p-1",
	})
	round.OnEvent()
	round.AddUsage(1200, 80)
	round.AddUsage(300, 20) // 重试也要累加
	round.End(nil)

	rows := stub.snapshot()
	if len(rows) != 1 {
		t.Fatalf("一轮只该有一条终态记录，实得 %d 条", len(rows))
	}
	got := rows[0]
	if got.InputTokens != 1500 || got.OutputTokens != 100 {
		t.Fatalf("轮级 token 应为 1500/100，实得 %d/%d", got.InputTokens, got.OutputTokens)
	}
	if got.Status != "ok" {
		t.Fatalf("成功轮 status 应为 ok，实得 %q", got.Status)
	}
	if got.Model != "m-1" || got.ProfileName != "p-1" {
		t.Fatalf("缺口③：model/profile 必须落库，实得 %q/%q", got.Model, got.ProfileName)
	}
}

// ⑧ 同一轮重复记账必须只留一行。旧实现里 stalled 路径先写一行、End 又写一行。
//
// 这里刻意用**最坏情况的库**（Insert 不去重、Update 永远失败）：
// 真实库有唯一约束兜底，但应用层守卫必须独立成立——否则换一次迁移、或者
// 并发窗口里两条路径都以为自己是第一个，就又会写出两行。
func TestRoundRecordsTerminalOnceWithoutDBDedup(t *testing.T) {
	stub := &noDedupWorstDB{}
	sup := NewSupervisor(nil, stub)
	sup.SetFirstEventTimeout(40 * time.Millisecond)

	round, _ := sup.Begin(context.Background(), RoundMeta{RoundID: "t-2", TaskID: 8, Worker: "planner"})
	// 不给首帧，等 L1 触发；随后引擎那侧的 End 也会到。
	time.Sleep(200 * time.Millisecond)
	round.End(context.Canceled)

	finals := stub.finalRows()
	if len(finals) != 1 {
		t.Fatalf("终态应只写一次（缺口⑧，不依赖库的唯一约束），实得 %d 次：%+v", len(finals), finals)
	}
	if finals[0].Status != "stalled" {
		t.Fatalf("应留下 stalled 这一行，实得 %q", finals[0].Status)
	}
	if finals[0].ErrorClass != string(ErrClassStalled) {
		t.Fatalf("stalled 行的分类应为 stalled，实得 %q", finals[0].ErrorClass)
	}
}

// ⑨ 逐发错误：内层的 429 必须在轮记录里留下，不能只剩 context canceled。
func TestRoundKeepsPerAttemptClasses(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)
	sup.SetFirstEventTimeout(0)

	round, _ := sup.Begin(context.Background(), RoundMeta{RoundID: "t-3", TaskID: 9, Worker: "planner"})
	round.OnEvent()
	// 模拟内层一次重试：第 1 发遇到 429，重试（BeginAttempt → 第 2 发）遇到 502，
	// 最后外层包成 canceled。Begin 已代表第 1 发，所以这里只调一次 BeginAttempt。
	round.NoteAttemptError(errors.New("openai: status 429: Upstream rate limit exceeded"))
	round.BeginAttempt()
	round.NoteAttemptError(errors.New("openai: status 502: Upstream request failed"))
	round.End(context.Canceled)

	rows := stub.snapshot()
	if len(rows) != 1 {
		t.Fatalf("应只有一行，实得 %d", len(rows))
	}
	got := rows[0]
	if len(got.AttemptClasses) != 2 {
		t.Fatalf("逐发错误应留 2 条，实得 %v", got.AttemptClasses)
	}
	if got.AttemptClasses[0] != string(ErrClassRateLimited) || got.AttemptClasses[1] != string(ErrClassUpstream5xx) {
		t.Fatalf("逐发形态不符：%v", got.AttemptClasses)
	}
	// 最终分类不能是 other：内层有明确形态时以最后一次有意义者为准。
	if got.ErrorClass == string(ErrClassOther) {
		t.Fatalf("缺口⑨：最终分类仍是 other，内层原因被吞了（逐发=%v）", got.AttemptClasses)
	}
	if got.ErrorClass != string(ErrClassUpstream5xx) {
		t.Fatalf("最终分类应取最后一次有意义的错误(upstream_5xx)，实得 %q", got.ErrorClass)
	}
	if got.Attempts != 2 {
		t.Fatalf("attempts 应记真实发数 2，实得 %d", got.Attempts)
	}
}

// ⑦ 在飞的轮必须可见：Begin 之后就该有一行 status=running。
func TestRunningRoundIsVisible(t *testing.T) {
	stub := &stubDB{}
	sup := NewSupervisor(nil, stub)
	sup.SetFirstEventTimeout(0)

	round, _ := sup.Begin(context.Background(), RoundMeta{RoundID: "t-4", TaskID: 10, Worker: "planner"})
	rows := stub.snapshot()
	if len(rows) != 1 || rows[0].Status != "running" {
		t.Fatalf("缺口⑦：Begin 后应立刻能看到一行 running，实得 %+v", rows)
	}
	round.OnEvent()
	round.End(nil)
	rows = stub.snapshot()
	if len(rows) != 1 || rows[0].Status != "ok" {
		t.Fatalf("结束后应原地更新为 ok（不新增行），实得 %+v", rows)
	}
}

// ── stub ────────────────────────────────────────────────────────────────

// stubDB 按「同一 round_id 一行」的语义实现；与真实库的 ON CONFLICT 对齐。
type r21StubDB struct {
	mu   sync.Mutex
	rows []db.LLMRound
}

func (s *r21StubDB) InsertLLMRound(r *db.LLMRound) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rows {
		if s.rows[i].RoundID == r.RoundID {
			s.rows[i] = *r
			return nil
		}
	}
	s.rows = append(s.rows, *r)
	return nil
}

func (s *r21StubDB) UpdateLLMRound(r *db.LLMRound) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rows {
		if s.rows[i].RoundID == r.RoundID {
			s.rows[i] = *r
			return nil
		}
	}
	return db.ErrLLMRoundNotFound
}

func (s *r21StubDB) snapshot() []db.LLMRound {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.LLMRound, len(s.rows))
	copy(out, s.rows)
	return out
}

// noDedupWorstDB 模拟最坏情况的库：Insert 不去重、Update 永远失败。
// 用它才能验证「应用层守卫独立成立」，而不被唯一约束掩盖。
type noDedupWorstDB struct {
	mu     sync.Mutex
	rows   []db.LLMRound
	finals []db.LLMRound
}

func (s *noDedupWorstDB) InsertLLMRound(r *db.LLMRound) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, *r)
	if r.Status != "running" {
		s.finals = append(s.finals, *r)
	}
	return nil
}

func (s *noDedupWorstDB) UpdateLLMRound(*db.LLMRound) error { return db.ErrLLMRoundNotFound }

func (s *noDedupWorstDB) finalRows() []db.LLMRound {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.LLMRound, len(s.finals))
	copy(out, s.finals)
	return out
}

// 保证环境变量不会把默认值改掉，从而让上面的断言稳稳成立。
func TestMain(m *testing.M) {
	os.Unsetenv("JINGWEI_LLM_FIRST_EVENT_TIMEOUT")
	os.Exit(m.Run())
}
