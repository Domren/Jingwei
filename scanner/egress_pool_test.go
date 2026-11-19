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

// P2 验收：任务 A/B 出口不互串；坏出口自动轮换并留痕；凭据不进日志与响应。

func TestEgressPoolNoCrossTask(t *testing.T) {
	p := NewEgressPool()
	mustRegister(t, p, EgressEndpoint{ID: "A1", TaskID: "A", ProxyURL: "http://10.0.0.1:8080"})
	mustRegister(t, p, EgressEndpoint{ID: "B1", TaskID: "B", ProxyURL: "http://10.0.0.2:8080"})
	mustRegister(t, p, EgressEndpoint{ID: "SH", TaskID: "", ProxyURL: "http://10.0.0.3:8080"})

	if err := p.Bind("A", "B1"); err == nil {
		t.Fatal("任务 A 不应能绑定任务 B 的出口")
	}
	if err := p.Bind("B", "A1"); err == nil {
		t.Fatal("任务 B 不应能绑定任务 A 的出口")
	}
	epA, err := p.SelectForTask("A")
	if err != nil || epA.ID != "A1" {
		t.Fatalf("task A select = %+v, %v", epA, err)
	}
	epB, err := p.SelectForTask("B")
	if err != nil || epB.ID != "B1" {
		t.Fatalf("task B select = %+v, %v", epB, err)
	}
	if p.BindingFor("A") == p.BindingFor("B") {
		t.Fatalf("A/B 出口串用: %s", p.BindingFor("A"))
	}
	// 共享出口谁都能选，但不改变各自已有绑定。
	shared, err := p.SelectForTask("C")
	if err != nil || shared.ID != "SH" {
		t.Fatalf("shared select = %+v, %v", shared, err)
	}
}

func TestEgressPoolRotateOnFailureAndLeaveTrace(t *testing.T) {
	p := NewEgressPool()
	mustRegister(t, p, EgressEndpoint{ID: "A1", TaskID: "A", ProxyURL: "socks5://admin:s3cr3t@10.0.0.1:1080"})
	mustRegister(t, p, EgressEndpoint{ID: "A2", TaskID: "A", ProxyURL: "http://10.0.0.2:8080"})
	if ep, err := p.SelectForTask("A"); err != nil || ep.ID != "A1" {
		t.Fatalf("first select = %+v, %v", ep, err)
	}
	// 失败错误里带代理口令：绝不能被记账下来。
	if err := p.ReportFailure("A", "A1", errors.New("dial socks5://admin:s3cr3t@10.0.0.1:1080: refused")); err != nil {
		t.Fatalf("report: %v", err)
	}
	if got := p.BindingFor("A"); got != "A2" {
		t.Fatalf("未自动轮换: binding=%s", got)
	}
	ep, err := p.SelectForTask("A")
	if err != nil || ep.ID != "A2" {
		t.Fatalf("after rotate select = %+v, %v", ep, err)
	}
	var sawFail, sawRotate bool
	for _, ev := range p.Events() {
		if ev.Action == "fail" {
			sawFail = true
		}
		if ev.Action == "rotate" && ev.FromEndpointID == "A1" && ev.EndpointID == "A2" {
			sawRotate = true
		}
	}
	if !sawFail || !sawRotate {
		t.Fatalf("缺少失败/轮换留痕: %+v", p.Events())
	}
	for _, ev := range p.Events() {
		if strings.Contains(ev.Detail, "s3cr3t") {
			t.Fatalf("事件泄漏代理口令: %+v", ev)
		}
	}
}

func TestEgressPoolHealthProbeRotatesBeforeUse(t *testing.T) {
	p := NewEgressPool()
	mustRegister(t, p, EgressEndpoint{ID: "bad", TaskID: "A", ProxyURL: "http://bad:8080"})
	mustRegister(t, p, EgressEndpoint{ID: "good", TaskID: "A", ProxyURL: "http://good:8080"})
	p.SetProbe(func(proxyURL string) error {
		if strings.Contains(proxyURL, "bad") {
			return errors.New("proxy http://u:p@bad:8080 unreachable")
		}
		return nil
	})
	ep, err := p.SelectForTask("A")
	if err != nil || ep.ID != "good" {
		t.Fatalf("健康探测未跳过坏出口: %+v, %v", ep, err)
	}
	var probed bool
	for _, ev := range p.Events() {
		if ev.Action == "probe_fail" {
			probed = true
			if strings.Contains(ev.Detail, "u:p@") || strings.Contains(ev.Detail, ":p@") {
				t.Fatalf("探测事件泄漏口令: %+v", ev)
			}
		}
	}
	if !probed {
		t.Fatalf("探测失败未留痕: %+v", p.Events())
	}
}

func TestEgressPoolSelectRequiresTaskID(t *testing.T) {
	p := NewEgressPool()
	mustRegister(t, p, EgressEndpoint{ID: "shared", ProxyURL: "http://10.0.0.1:8080"})
	if _, err := p.SelectForTask(""); err == nil {
		t.Fatal("空 task id 必须拒绝，避免默认池被所有任务共用")
	}
	if ep, err := p.SelectForTask("X"); err != nil || ep.ID != "shared" {
		t.Fatalf("共享出口应可选: %+v, %v", ep, err)
	}
}

func TestDeepClientDoUsesEgressPoolAndRotates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p := NewEgressPool()
	mustRegister(t, p, EgressEndpoint{ID: "e1", TaskID: "T"}) // 空代理=直连，便于本地夹具
	mustRegister(t, p, EgressEndpoint{ID: "e2", TaskID: "T"})
	client := NewDeepClient(2*time.Second).WithEgressPool(p, "T")

	resp := client.Do(context.Background(), DeepRequest{Method: "GET", URL: srv.URL})
	if resp.StatusCode != 200 || !resp.OK() {
		t.Fatalf("first Do = %+v", resp)
	}
	if client.ActiveEgress() == "" || p.BindingFor("T") == "" {
		t.Fatalf("出口未绑定/未留痕: active=%s binding=%s", client.ActiveEgress(), p.BindingFor("T"))
	}
	first := p.BindingFor("T")

	// 模拟出口故障：下一次 Do 必须走轮换后的另一个出口，且不影响第二个任务。
	if err := p.ReportFailure("T", first, errors.New("connection refused")); err != nil {
		t.Fatal(err)
	}
	mustRegister(t, p, EgressEndpoint{ID: "other1", TaskID: "OTHER"})
	resp2 := client.Do(context.Background(), DeepRequest{Method: "GET", URL: srv.URL})
	if resp2.StatusCode != 200 {
		t.Fatalf("after rotate Do = %+v", resp2)
	}
	if p.BindingFor("T") == first {
		t.Fatal("失败后仍用坏出口")
	}
	if p.BindingFor("OTHER") != "" {
		t.Fatalf("任务 T 的失败污染了 OTHER: %s", p.BindingFor("OTHER"))
	}
}

func mustRegister(t *testing.T, p *EgressPool, ep EgressEndpoint) {
	t.Helper()
	if err := p.Register(ep); err != nil {
		t.Fatalf("register %s: %v", ep.ID, err)
	}
}
