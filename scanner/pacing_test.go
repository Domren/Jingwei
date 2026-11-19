package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// P4 验收：放行/限速/挑战三形态各给可核对节奏参数；一个目标降速不拖垮别的任务。

func TestAdaptivePacerThreeShapes(t *testing.T) {
	p := NewAdaptivePacer(10*time.Millisecond, 10*time.Second)
	var waits []time.Duration
	p.SetWaitFunc(func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	})

	// 放行：保持基础节奏，突发 4。
	p.Observe("allow.example", DeepResponse{StatusCode: 200, Body: "ok"})
	allow := p.PaceFor("allow.example")
	if allow.Mode != PaceOpen || allow.Interval != 10*time.Millisecond || allow.Burst != 4 {
		t.Fatalf("放行参数: %+v", allow)
	}

	// 限速：429 且无验证码标记 → throttled，间隔翻倍且标记切出口。
	p.Observe("rate.example", DeepResponse{StatusCode: 429, Body: ""})
	rate := p.PaceFor("rate.example")
	if rate.Mode != PaceThrottled || rate.ModeName != "throttled" ||
		rate.Interval != 20*time.Millisecond || rate.Burst != 1 || !rate.RotateEgress {
		t.Fatalf("限速参数: %+v", rate)
	}

	// 挑战页：验证码/人机验证 → challenge，退避更狠（10ms * 2^(1+2)=80ms）。
	p.Observe("challenge.example", DeepResponse{StatusCode: 403, Body: "请输入验证码完成人机验证"})
	ch := p.PaceFor("challenge.example")
	if ch.Mode != PaceChallenge || ch.ModeName != "challenge" || ch.Interval != 80*time.Millisecond {
		t.Fatalf("挑战参数: %+v", ch)
	}
	if !(allow.Interval < rate.Interval && rate.Interval < ch.Interval) {
		t.Fatalf("三形态节奏未递增: %v < %v < %v", allow.Interval, rate.Interval, ch.Interval)
	}

	// 各目标 Wait 用各自的间隔。
	for _, target := range []string{"allow.example", "rate.example", "challenge.example"} {
		if err := p.Wait(context.Background(), target); err != nil {
			t.Fatalf("wait %s: %v", target, err)
		}
	}
	want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 80 * time.Millisecond}
	if len(waits) != 3 {
		t.Fatalf("wait 调用次数=%d: %v", len(waits), waits)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("wait[%d]=%v, want %v", i, waits[i], want[i])
		}
	}
}

func TestAdaptivePacerRecoversGradually(t *testing.T) {
	p := NewAdaptivePacer(10*time.Millisecond, time.Second)
	p.Observe("x", DeepResponse{StatusCode: 429})
	if p.PaceFor("x").Interval != 20*time.Millisecond {
		t.Fatalf("throttle: %+v", p.PaceFor("x"))
	}
	p.Observe("x", DeepResponse{StatusCode: 200, Body: "ok"})
	got := p.PaceFor("x")
	if got.Failures != 0 || got.Mode != PaceOpen || got.RotateEgress || got.Interval != 10*time.Millisecond {
		t.Fatalf("成功响应应恢复基础节奏: %+v", got)
	}
}

func TestAdaptivePacerSlowTargetDoesNotBlockOthers(t *testing.T) {
	p := NewAdaptivePacer(100*time.Millisecond, 2*time.Second)
	for i := 0; i < 3; i++ {
		p.Observe("slow.example", DeepResponse{StatusCode: 429}) // 800ms 退避
	}
	if p.PaceFor("slow.example").Interval <= 100*time.Millisecond {
		t.Fatalf("慢目标未降速: %+v", p.PaceFor("slow.example"))
	}

	gate := make(chan struct{})
	p.SetWaitFunc(func(_ context.Context, d time.Duration) error {
		if d > 100*time.Millisecond {
			<-gate // 模拟慢目标的长等待
		}
		return nil
	})
	slowDone := make(chan error, 1)
	go func() { slowDone <- p.Wait(context.Background(), "slow.example") }()

	// 慢目标还卡在等待里时，快目标的 Wait 必须立刻返回——证明锁没被占住。
	fastDone := make(chan error, 1)
	go func() { fastDone <- p.Wait(context.Background(), "fast.example") }()
	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatalf("fast wait: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		close(gate)
		t.Fatal("快目标被慢目标拖垮")
	}
	close(gate)
	if err := <-slowDone; err != nil {
		t.Fatalf("slow wait: %v", err)
	}
	if got := p.PaceFor("fast.example"); got.Interval != 100*time.Millisecond {
		t.Fatalf("快目标继承了慢目标参数: %+v", got)
	}
}

func TestDeepClientDoAppliesPacerAndRotatesOnThrottle(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			w.WriteHeader(429) // 空 body：纯限速，不带验证码标记
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p := NewEgressPool()
	mustRegister(t, p, EgressEndpoint{ID: "e1", TaskID: "T"})
	mustRegister(t, p, EgressEndpoint{ID: "e2", TaskID: "T"})
	pacer := NewAdaptivePacer(time.Millisecond, time.Second)
	waitCalls := 0
	pacer.SetWaitFunc(func(_ context.Context, _ time.Duration) error {
		waitCalls++
		return nil
	})
	client := NewDeepClient(2*time.Second).WithEgressPool(p, "T").WithPacer(pacer)

	first := client.Do(context.Background(), DeepRequest{Method: "GET", URL: srv.URL})
	if first.StatusCode != 429 {
		t.Fatalf("first = %+v", first)
	}
	if got := pacer.PaceFor(hostOfTarget(srv.URL)); got.Mode != PaceThrottled {
		t.Fatalf("429 未进入限速形态: %+v", got)
	}
	if p.BindingFor("T") != "e2" {
		t.Fatalf("限速未自动切出口: %s", p.BindingFor("T"))
	}
	var rotated bool
	for _, ev := range p.Events() {
		if ev.Action == "rotate_reason" && strings.Contains(ev.Detail, "throttled") {
			rotated = true
		}
	}
	if !rotated {
		t.Fatalf("切出口未留痕: %+v", p.Events())
	}

	second := client.Do(context.Background(), DeepRequest{Method: "GET", URL: srv.URL})
	if second.StatusCode != 200 {
		t.Fatalf("second = %+v", second)
	}
	if pacer.ObserveCount() != 2 || waitCalls != 2 {
		t.Fatalf("pacer 观测=%d wait=%d", pacer.ObserveCount(), waitCalls)
	}
}

func TestAdaptivePacerWaitHonorsContext(t *testing.T) {
	p := NewAdaptivePacer(time.Hour, time.Hour)   // 真实等待一小时，靠 ctx 取消
	p.Observe("x", DeepResponse{StatusCode: 429}) // 2 小时后封顶到 1h
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Wait(ctx, "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait err = %v", err)
	}
}

func hostOfTarget(raw string) string {
	return normalizePaceTarget(raw)
}
