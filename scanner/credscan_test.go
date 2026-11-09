package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// credFakeAdapter 是引擎测试用的协议实现：只记录被调用次数，不碰网络。
// 断言「有没有发起连接」靠的就是这些计数——引擎的止损与不猜测规则，
// 只有从调用次数才看得出来，光看返回值看不出「其实它偷偷试了三次」。
type credFakeAdapter struct {
	mu        sync.Mutex
	protocol  string
	identify  bool
	idErr     error
	outcome   CredOutcome
	tryErr    error
	idCalls   int
	tryCalls  int
	tryDelay  time.Duration
	portCheck int
	// tryFn 按凭据决定结果（nil 时用固定 outcome），用于按账号断言止损行为。
	tryFn func(Credential) CredOutcome
}

func (a *credFakeAdapter) Protocol() string { return a.protocol }

func (a *credFakeAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	a.mu.Lock()
	a.idCalls++
	a.mu.Unlock()
	return a.identify, "FAKE-BANNER", a.idErr
}

func (a *credFakeAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (CredAttempt, error) {
	a.mu.Lock()
	a.tryCalls++
	delay := a.tryDelay
	a.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
		}
	}
	outcome := a.outcome
	if a.tryFn != nil {
		outcome = a.tryFn(cred)
	}
	return CredAttempt{Outcome: outcome, RawResp: []byte("RESP"), RawReq: []byte("REQ")}, a.tryErr
}

func (a *credFakeAdapter) counts() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.idCalls, a.tryCalls
}

// collector 收集引擎结果。busy 是一次「正在 emit 里」的占位：引擎承诺串行调用 emit，
// 两个 goroutine 同时进来就是违约——后面 B7 直接往数据库写，重入会写坏同一行。
type credCollector struct {
	mu         sync.Mutex
	seen       []CredAttempt
	busy       sync.Mutex
	overlapped int
}

func (c *credCollector) emit(a CredAttempt) {
	if !c.busy.TryLock() {
		c.mu.Lock()
		c.overlapped++
		c.mu.Unlock()
	} else {
		defer c.busy.Unlock()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = append(c.seen, a)
}

func (c *credCollector) all() []CredAttempt {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]CredAttempt(nil), c.seen...)
}

func (c *credCollector) reentrant() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.overlapped
}

func (c *credCollector) countBy(o CredOutcome) int {
	n := 0
	for _, a := range c.all() {
		if a.Outcome == o {
			n++
		}
	}
	return n
}

func TestCredPlanThreeTierPortDecision(t *testing.T) {
	t.Run("第一级：输入带端口就只用该端口", func(t *testing.T) {
		plan, err := CredPlan([]Target{{Raw: "10.0.0.1:2222", Kind: KindIP, Host: "10.0.0.1", Port: 2222}},
			nil, []string{"ssh"})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan) != 1 || plan[0].Port != 2222 {
			t.Fatalf("plan = %+v, want 唯一一条 2222", plan)
		}
		if plan[0].ProtocolSource != CredProtocolSourceExplicit || plan[0].ProtocolConfirmed {
			t.Fatalf("没有指纹时不能声称协议已确认: %+v", plan[0])
		}
	})

	t.Run("第一级 + 指纹：端口上是什么就说什么", func(t *testing.T) {
		svc := []CredService{{Host: "10.0.0.1", Port: 2222, Protocol: "http", Banner: "HTTP/1.1"}}
		plan, err := CredPlan([]Target{{Kind: KindIP, Host: "10.0.0.1", Port: 2222}}, svc, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan) != 1 || plan[0].Protocol != "http" || !plan[0].ProtocolConfirmed {
			t.Fatalf("plan = %+v", plan)
		}
	})

	t.Run("硬约束：指纹说是 HTTP 的端口，不因为勾了 SSH 就打 SSH 字典", func(t *testing.T) {
		svc := []CredService{{Host: "10.0.0.1", Port: 2222, Protocol: "http", Banner: "HTTP/1.1"}}
		plan, err := CredPlan([]Target{{Kind: KindIP, Host: "10.0.0.1", Port: 2222}}, svc, []string{"ssh"})
		if err == nil {
			t.Fatalf("该组合没有可测端点，却给出了计划: %+v", plan)
		}
		if !strings.Contains(err.Error(), "没有可测端点") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("第二级：没给端口时用指纹的服务", func(t *testing.T) {
		svc := []CredService{
			{Host: "10.0.0.2", Port: 6379, Protocol: "redis", Banner: "-ERR"},
			{Host: "10.0.0.2", Port: 80, Protocol: "http", Banner: "nginx"},
		}
		plan, err := CredPlan([]Target{{Kind: KindIP, Host: "10.0.0.2"}}, svc, []string{"redis", "http"})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan) != 2 || plan[0].ProtocolSource != CredProtocolSourceFingerprint {
			t.Fatalf("plan = %+v", plan)
		}
		for _, e := range plan {
			if !e.ProtocolConfirmed {
				t.Fatalf("第二级的协议来自指纹，必须算已确认: %+v", e)
			}
		}
	})

	t.Run("第三级：默认端口表只决定测哪个端口", func(t *testing.T) {
		plan, err := CredPlan([]Target{{Kind: KindIP, Host: "10.0.0.3"}}, nil, []string{"redis", "mysql"})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan) != 2 {
			t.Fatalf("plan = %+v", plan)
		}
		for _, e := range plan {
			if e.ProtocolSource != CredProtocolSourceDefaultPort || e.ProtocolConfirmed {
				t.Fatalf("默认端口表得出的端点必须未确认协议: %+v", e)
			}
			if e.Port != CredDefaultPort(e.Protocol) {
				t.Fatalf("端口与协议默认值不符: %+v", e)
			}
		}
	})

	t.Run("去重与稳定顺序", func(t *testing.T) {
		targets := []Target{{Kind: KindIP, Host: "10.0.0.4"}, {Kind: KindIP, Host: "10.0.0.4"}}
		plan, err := CredPlan(targets, nil, []string{"redis"})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan) != 1 {
			t.Fatalf("重复目标应当合并: %+v", plan)
		}
	})

	t.Run("没有服务也没勾协议时不产出计划", func(t *testing.T) {
		// 这时第三级会退化成「所有已注册协议」，测试环境里可能一个都没有；
		// 关键是它绝不凭空造一个协议名。
		plan, err := CredPlan([]Target{{Kind: KindIP, Host: "10.0.0.5"}}, nil, nil)
		if err == nil && len(plan) > 0 {
			for _, e := range plan {
				if !CredProtocolKnown(e.Protocol) {
					t.Fatalf("计划里出现了不认识的协议 %q", e.Protocol)
				}
			}
		}
	})
}

// 引擎在协议没被确认之前不得进入字典循环。
func TestCredRunDoesNotGuessProtocolFromPort(t *testing.T) {
	adapter := &credFakeAdapter{protocol: credTestProto, identify: false}
	RegisterCredAdapter(adapter)
	defer unregisterCredAdapter(credTestProto)

	plan := []CredEndpoint{{Host: "10.0.0.9", Port: 6379, Protocol: credTestProto,
		ProtocolSource: CredProtocolSourceDefaultPort}}
	c := &credCollector{}
	if err := CredRun(context.Background(), plan, []Credential{{Username: "u", Password: "p"}},
		CredOptions{}, c.emit); err != nil {
		t.Fatal(err)
	}
	if id, tries := adapter.counts(); id != 1 || tries != 0 {
		t.Fatalf("未确认协议却进了字典循环: identify=%d try=%d", id, tries)
	}
	got := c.all()
	if len(got) != 1 || got[0].Outcome != CredInconclusive {
		t.Fatalf("results = %+v", got)
	}
}

// 预算耗尽必须留下「不可判定」的记录，而不是静默少一批结果：
// 报告里少了行，读者就会以为测过了。
func TestCredRunBudgetRecordsInconclusive(t *testing.T) {
	adapter := &credFakeAdapter{protocol: credTestProto, identify: true, outcome: CredDeny, tryDelay: 40 * time.Millisecond}
	RegisterCredAdapter(adapter)
	defer unregisterCredAdapter(credTestProto)

	plan := []CredEndpoint{}
	for i := 0; i < 12; i++ {
		plan = append(plan, CredEndpoint{Host: fmt.Sprintf("10.9.%d.%d", i/256, i%256),
			Port: 6379, Protocol: credTestProto, ProtocolConfirmed: true})
	}
	creds := []Credential{{Username: "a", Password: "1"}, {Username: "b", Password: "2"}}
	c := &credCollector{}
	err := CredRun(context.Background(), plan, creds, CredOptions{Budget: 60 * time.Millisecond, Concurrency: 2}, c.emit)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.all()) != len(plan)*len(creds) {
		t.Fatalf("每个端点×凭据都要有一条结果: got %d want %d", len(c.all()), len(plan)*len(creds))
	}
	if c.countBy(CredInconclusive) == 0 {
		t.Fatalf("预算耗尽必须留下不可判定: %+v", c.all())
	}
	if n := c.reentrant(); n != 0 {
		t.Fatalf("emit 被并发调用 %d 次：调用方（将来的落库回调）不该自己猜锁", n)
	}
	for _, a := range c.all() {
		if a.Outcome == CredDeny && a.Reason != "" {
			t.Fatalf("deny 不该带解释: %+v", a)
		}
	}
}

// 连续传输层失败到阈值后停止连接；锁定提示立刻停止该端点。
func TestCredRunStopLossAndLockout(t *testing.T) {
	t.Run("stop-loss", func(t *testing.T) {
		adapter := &credFakeAdapter{protocol: credTestProto, identify: true, outcome: CredUnreachable}
		RegisterCredAdapter(adapter)
		defer unregisterCredAdapter(credTestProto)
		plan := []CredEndpoint{{Host: "10.0.0.30", Port: 6379, Protocol: credTestProto, ProtocolConfirmed: true}}
		creds := make([]Credential, 0, 10)
		for i := 0; i < 10; i++ {
			creds = append(creds, Credential{Username: "u", Password: string(rune('a' + i))})
		}
		c := &credCollector{}
		if err := CredRun(context.Background(), plan, creds, CredOptions{StopLossAfter: 3}, c.emit); err != nil {
			t.Fatal(err)
		}
		if _, tries := adapter.counts(); tries != 3 {
			t.Fatalf("连续 3 次不通就该停手，实际试了 %d 次", tries)
		}
		if len(c.all()) != len(creds) {
			t.Fatalf("放弃的尝试也要留痕: got %d want %d", len(c.all()), len(creds))
		}
		if c.countBy(CredInconclusive) != len(creds)-3 {
			t.Fatalf("余下 7 次应记为不可判定: %+v", c.all())
		}
	})

	t.Run("locked 立刻停手", func(t *testing.T) {
		adapter := &credFakeAdapter{protocol: credTestProtoLock, identify: true, outcome: CredLocked}
		RegisterCredAdapter(adapter)
		defer unregisterCredAdapter(credTestProtoLock)
		plan := []CredEndpoint{{Host: "10.0.0.31", Port: 22, Protocol: credTestProtoLock, ProtocolConfirmed: true}}
		c := &credCollector{}
		if err := CredRun(context.Background(), plan,
			[]Credential{{Username: "root", Password: "a"}, {Username: "root", Password: "b"}},
			CredOptions{}, c.emit); err != nil {
			t.Fatal(err)
		}
		if _, tries := adapter.counts(); tries != 1 {
			t.Fatalf("触发锁定后不得再试第二组: %d", tries)
		}
		if c.countBy(CredLocked) != 1 {
			t.Fatalf("locked 要如实落库: %+v", c.all())
		}
	})
}

// 登记为「暂不支持」的协议：即使有适配器，也一个包都不发，结果写「不支持」。
// 这条保护现在没有生产条目（12 个降级项都实现了），但机制必须留着：以后再加
// 降级项时，靠它保证不会先连上去再报不支持。
func TestCredRunUnsupportedSendsNothing(t *testing.T) {
	const proto = "cred-test-downgraded"
	credUnsupportedProtocols[proto] = "本版不做适配器（测试条目）"
	defer delete(credUnsupportedProtocols, proto)
	adapter := &credFakeAdapter{protocol: proto, identify: true, outcome: CredHit}
	RegisterCredAdapter(adapter)
	defer unregisterCredAdapter(proto)
	plan := []CredEndpoint{{Host: "10.0.0.40", Port: 3389, Protocol: proto, ProtocolConfirmed: true}}
	c := &credCollector{}
	if err := CredRun(context.Background(), plan, []Credential{{Username: "a", Password: "b"}},
		CredOptions{}, c.emit); err != nil {
		t.Fatal(err)
	}
	if id, tries := adapter.counts(); id != 0 || tries != 0 {
		t.Fatalf("不支持的协议不应发起任何连接: identify=%d try=%d", id, tries)
	}
	if c.countBy(CredUnsupported) != 1 {
		t.Fatalf("要落 unsupported 而不是空结果: %+v", c.all())
	}
}

// 没有实现 = 没测过。落 unsupported，绝不落 deny——deny 在报告里等于「已验证这组口令不行」。
func TestCredRunMissingAdapterIsNotDeny(t *testing.T) {
	plan := []CredEndpoint{{Host: "10.0.0.41", Port: 1234, Protocol: "nosuchproto", ProtocolConfirmed: true}}
	c := &credCollector{}
	if err := CredRun(context.Background(), plan, []Credential{{Username: "a", Password: "b"}},
		CredOptions{}, c.emit); err != nil {
		t.Fatal(err)
	}
	if c.countBy(CredUnsupported) != 1 || c.countBy(CredDeny) != 0 {
		t.Fatalf("results = %+v", c.all())
	}
}

// 适配器没给态（或给了空态）不能被当成拒绝。
func TestCredRunEmptyOutcomeBecomesInconclusive(t *testing.T) {
	adapter := &credFakeAdapter{protocol: credTestProto, identify: true, outcome: "", tryErr: errors.New("connection reset")}
	RegisterCredAdapter(adapter)
	defer unregisterCredAdapter(credTestProto)
	plan := []CredEndpoint{{Host: "10.0.0.42", Port: 6379, Protocol: credTestProto, ProtocolConfirmed: true}}
	c := &credCollector{}
	if err := CredRun(context.Background(), plan, []Credential{{Username: "a", Password: "b"}},
		CredOptions{}, c.emit); err != nil {
		t.Fatal(err)
	}
	got := c.all()
	if len(got) != 1 || got[0].Outcome != CredInconclusive || !strings.Contains(got[0].Reason, "connection reset") {
		t.Fatalf("results = %+v", got)
	}
}

func TestCredRunRejectsEmptyInputs(t *testing.T) {
	c := &credCollector{}
	if err := CredRun(context.Background(), nil, []Credential{{Username: "a"}}, CredOptions{}, c.emit); err == nil {
		t.Fatal("空计划必须报错")
	}
	plan := []CredEndpoint{{Host: "10.0.0.1", Port: 6379, Protocol: credTestProto, ProtocolConfirmed: true}}
	if err := CredRun(context.Background(), plan, nil, CredOptions{}, c.emit); err == nil {
		t.Fatal("空字典不能当成「已验证不存在弱口令」")
	}
	if err := CredRun(context.Background(), plan, []Credential{{Username: "a"}}, CredOptions{}, nil); err == nil {
		t.Fatal("没有结果回调就不能跑：结果无处可落")
	}
}

// 限速是「对同一个端点别把认证请求打成一串连发」：触发锁定策略的目标，连发就是锁号。
// 断言的是间隔，不是绝对耗时——计时器在负载下只会更慢，不会更快。
func TestCredRunRateLimitSpacesAttempts(t *testing.T) {
	adapter := &credFakeAdapter{protocol: credTestProto, identify: true, outcome: CredDeny}
	RegisterCredAdapter(adapter)
	defer unregisterCredAdapter(credTestProto)
	plan := []CredEndpoint{{Host: "10.0.0.50", Port: 6379, Protocol: credTestProto, ProtocolConfirmed: true}}
	creds := []Credential{{Username: "a", Password: "1"}, {Username: "b", Password: "2"}, {Username: "c", Password: "3"}}

	c := &credCollector{}
	start := time.Now()
	if err := CredRun(context.Background(), plan, creds, CredOptions{RateLimit: 20}, c.emit); err != nil {
		t.Fatal(err)
	}
	spaced := time.Since(start)
	if _, tries := adapter.counts(); tries != len(creds) {
		t.Fatalf("限速不该少试: tries=%d", tries)
	}

	adapter2 := &credFakeAdapter{protocol: credTestProtoSlow, identify: true, outcome: CredDeny}
	RegisterCredAdapter(adapter2)
	defer unregisterCredAdapter(credTestProtoSlow)
	plan2 := []CredEndpoint{{Host: "10.0.0.51", Port: 3306, Protocol: credTestProtoSlow, ProtocolConfirmed: true}}
	c2 := &credCollector{}
	start = time.Now()
	if err := CredRun(context.Background(), plan2, creds, CredOptions{}, c2.emit); err != nil {
		t.Fatal(err)
	}
	fast := time.Since(start)
	if spaced < fast*3 || spaced < 90*time.Millisecond {
		t.Fatalf("限速没起作用: spaced=%v fast=%v", spaced, fast)
	}
	if len(c2.all()) != len(creds) {
		t.Fatalf("results = %+v", c2.all())
	}
}

// 手工停任务同样不能少行：取消和预算耗尽是两种收尾，读者要能分清是自己停的手还是时间用完了。
func TestCredRunCancelStillRecordsEveryRow(t *testing.T) {
	adapter := &credFakeAdapter{protocol: credTestProto, identify: true, outcome: CredDeny, tryDelay: 25 * time.Millisecond}
	RegisterCredAdapter(adapter)
	defer unregisterCredAdapter(credTestProto)

	plan := []CredEndpoint{}
	for i := 0; i < 8; i++ {
		plan = append(plan, CredEndpoint{Host: fmt.Sprintf("10.9.%d.1", i), Port: 6379,
			Protocol: credTestProto, ProtocolConfirmed: true})
	}
	creds := []Credential{{Username: "a", Password: "1"}, {Username: "b", Password: "2"}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()
	c := &credCollector{}
	err := CredRun(ctx, plan, creds, CredOptions{Concurrency: 2}, c.emit)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消要把 ctx.Err() 交回调用方，任务状态才区分得开: %v", err)
	}
	if len(c.all()) != len(plan)*len(creds) {
		t.Fatalf("取消也要逐行交代: got %d want %d", len(c.all()), len(plan)*len(creds))
	}
	for _, a := range c.all() {
		if a.Outcome == CredHit || a.Outcome == CredDeny {
			continue
		}
		if a.Outcome != CredInconclusive {
			t.Fatalf("取消后的收尾行只能是不可判定: %+v", a)
		}
	}
	if !strings.Contains(fmt.Sprint(c.all()), "已取消") {
		t.Fatalf("收尾行要写明为什么没试: %+v", c.all())
	}
}

// 命中/拒绝都要留下可复现的字节（#81 定的非 HTTP 证据通道），而且发起过请求的尝试
// 不能借用 banner 格式——那个格式自带「扫描器未发送任何应用层请求字节」，是假记录。
func TestCredAttemptEvidenceCarriesRawBytes(t *testing.T) {
	a := CredAttempt{Host: "10.0.0.1", Port: 6379, Protocol: "redis", Outcome: CredHit,
		Cred:   Credential{Username: "default", Password: "pass"},
		RawReq: []byte("AUTH pass\r\n"), RawResp: []byte("+OK\r\n")}
	ev := a.Evidence()
	for _, want := range []string{"REDIS", "6379", "+OK", "AUTH pass", "default / pass"} {
		if !strings.Contains(ev, want) {
			t.Fatalf("evidence lost %q: %s", want, ev)
		}
	}
	if strings.Contains(ev, "未发送任何应用层请求字节") {
		t.Fatalf("发起过请求的尝试不能记成被动采集:\n%s", ev)
	}
	// 只读到 banner（还没发请求）时才是被动通道。
	only := CredAttempt{Host: "10.0.0.1", Port: 6379, Protocol: "redis", RawResp: []byte("+OK\r\n")}
	if !strings.Contains(only.Evidence(), "未发送任何应用层请求字节") {
		t.Fatalf("banner 通道应当说明被动采集:\n%s", only.Evidence())
	}
	// 没有字节时也不能返回空串糊过去：判定说明就是唯一的可解释信息。
	b := CredAttempt{Outcome: CredInconclusive, Reason: "握手未完成"}
	if b.Evidence() != "握手未完成" {
		t.Fatalf("evidence = %q", b.Evidence())
	}
}

func TestCredProtocolSupportTable(t *testing.T) {
	// 三档（rdp / weblogic-console / jboss-console）本版已实现适配器，必须报支持。
	for _, p := range []string{"rdp", "weblogic-console", "jboss-console", "snmp"} {
		if !CredProtocolSupported(p) {
			t.Fatalf("%q 已实现适配器，应当报支持", p)
		}
	}
	for _, p := range []string{"ssh", "redis", "mysql", "ftp"} {
		if !CredProtocolSupported(p) {
			t.Fatalf("%q 应当是支持的协议", p)
		}
	}
}

// 测试桩用的协议名。不能借用 redis/ssh/mysql：真适配器在 init 里就占了这些名字，
// 借用会触发 RegisterCredAdapter 的重复注册保护（那保护本来就是防两份实现互相漂移）。
const (
	credTestProto     = "credtest"
	credTestProtoLock = "credtest-lock"
	credTestProtoSlow = "credtest-slow"
)

func unregisterCredAdapter(protocol string) {
	credAdapterMu.Lock()
	defer credAdapterMu.Unlock()
	delete(credAdapters, strings.ToLower(protocol))
}

// 同一账号连续被拒到达上限后停手：余下的口令组是「没测」，不是「也错了」。
// 停手按账号而不是按端点——root 被拒不该拖累 admin 的覆盖。
func TestCredRunStopsDeniedAccountBeforeLockout(t *testing.T) {
	adapter := &credFakeAdapter{protocol: credTestProto, identify: true,
		tryFn: func(Credential) CredOutcome { return CredDeny }}
	RegisterCredAdapter(adapter)
	defer unregisterCredAdapter(credTestProto)

	plan := []CredEndpoint{{Host: "10.0.0.60", Port: 6379, Protocol: credTestProto, ProtocolConfirmed: true}}
	creds := []Credential{
		{Username: "root", Password: "a"},
		{Username: "root", Password: "b"},
		{Username: "root", Password: "c"},
		{Username: "admin", Password: "a"},
	}
	c := &credCollector{}
	if err := CredRun(context.Background(), plan, creds, CredOptions{StopAfterDenies: 2}, c.emit); err != nil {
		t.Fatal(err)
	}
	rows := c.all()
	if len(rows) != len(creds) {
		t.Fatalf("每个口令组都要留一行: %d", len(rows))
	}
	if rows[0].Outcome != CredDeny || rows[1].Outcome != CredDeny {
		t.Fatalf("前两次应当是明确拒绝: %+v", rows[:2])
	}
	if rows[2].Outcome != CredInconclusive || !strings.Contains(rows[2].Reason, "避免触发账号锁定") {
		t.Fatalf("到达上限后 root 的第三组应当停手并说明原因: %+v", rows[2])
	}
	if rows[3].Outcome != CredDeny {
		t.Fatalf("admin 是另一个账号，不该被 root 的失败拖累: %+v", rows[3])
	}
	if _, tries := adapter.counts(); tries != 3 {
		t.Fatalf("停手之后不能再发起尝试: tries=%d", tries)
	}
}
