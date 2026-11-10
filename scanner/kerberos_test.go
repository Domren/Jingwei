package scanner

import (
	"context"
	"errors"
	"testing"
)

func TestParseSPNRow(t *testing.T) {
	cases := []struct {
		line string
		want SPNRecord
		ok   bool
	}{
		{"svc_acct|HTTP/dc.jingwei.local", SPNRecord{User: "svc_acct", SPN: "HTTP/dc.jingwei.local", Enabled: true}, true},
		{"svc_acct|HTTP/dc.jingwei.local|enabled", SPNRecord{User: "svc_acct", SPN: "HTTP/dc.jingwei.local", Enabled: true}, true},
		{"svc_acct|HTTP/dc.jingwei.local|disabled", SPNRecord{User: "svc_acct", SPN: "HTTP/dc.jingwei.local", Enabled: false}, true},
		{"svc_acct|HTTP/dc.jingwei.local|DisableD", SPNRecord{User: "svc_acct", SPN: "HTTP/dc.jingwei.local", Enabled: false}, true},
		{"svc_acct|HTTP/dc.jingwei.local|false", SPNRecord{User: "svc_acct", SPN: "HTTP/dc.jingwei.local", Enabled: false}, true},
		{"svc_acct|HTTP/dc.jingwei.local|0", SPNRecord{User: "svc_acct", SPN: "HTTP/dc.jingwei.local", Enabled: false}, true},
		{"svc_acct", SPNRecord{}, false},
		// 缺账号或缺 SPN 的脏行没有利用价值，按解析失败处理。
		{"|HTTP/dc.jingwei.local", SPNRecord{}, false},
		{"svc_acct|", SPNRecord{}, false},
		{"  svc | HTTPS/x.y   |  ", SPNRecord{User: "svc", SPN: "HTTPS/x.y", Enabled: true}, true},
	}
	for _, c := range cases {
		got, ok := ParseSPNRow(c.line)
		if ok != c.ok {
			t.Fatalf("ParseSPNRow(%q) ok=%v want %v", c.line, ok, c.ok)
		}
		if !ok {
			continue
		}
		if got != c.want {
			t.Fatalf("ParseSPNRow(%q) = %+v want %+v", c.line, got, c.want)
		}
	}
}

func TestDefaultKerberoasterIsStub(t *testing.T) {
	// 默认 stub 必须在每次调用时返回 ErrKerberosSidecarNotConfigured，
	// 这样调用方不会静默跳过 Kerberoasting 机会，而是明确告知。
	ctx := context.Background()
	_, err := DefaultKerberoaster().GetTGS(ctx, "svc", "hash", "HTTP/x", true)
	if !errors.Is(err, ErrKerberosSidecarNotConfigured) {
		t.Fatalf("stub GetTGS err=%v want ErrKerberosSidecarNotConfigured", err)
	}
	_, err = DefaultKerberoaster().DomainSPNs(ctx, "ldap://dc:389", "u", "p")
	if !errors.Is(err, ErrKerberosSidecarNotConfigured) {
		t.Fatalf("stub DomainSPNs err=%v want ErrKerberosSidecarNotConfigured", err)
	}
}

// mockKerberoaster 是测试用的假实现，用来证明 RegisterKerberoaster 确实能换。
type mockKerberoaster struct{}

func (mockKerberoaster) GetTGS(_ context.Context, _, _, _ string, _ bool) (string, error) {
	return "TGS_HEX", nil
}
func (mockKerberoaster) DomainSPNs(_ context.Context, _, _, _ string) ([]SPNRecord, error) {
	return []SPNRecord{{User: "u", SPN: "HTTP/x", Enabled: true}}, nil
}

func TestRegisterKerberoasterSwapsImplementation(t *testing.T) {
	// 换一次、跑一次、换回去，保证全局状态不脏。
	orig := DefaultKerberoaster()
	defer RegisterKerberoaster(orig)

	RegisterKerberoaster(mockKerberoaster{})
	got, _ := DefaultKerberoaster().GetTGS(context.Background(), "u", "h", "SPN", true)
	if got != "TGS_HEX" {
		t.Fatalf("mock GetTGS=%q want TGS_HEX", got)
	}
	spns, _ := DefaultKerberoaster().DomainSPNs(context.Background(), "a", "b", "c")
	if len(spns) != 1 || spns[0].SPN != "HTTP/x" {
		t.Fatalf("mock DomainSPNs=%+v", spns)
	}
	// nil 注册被拒绝——kerberoaster 不变，仍然是 mock，返回 TGS_HEX。
	RegisterKerberoaster(nil)
	if got, _ := DefaultKerberoaster().GetTGS(context.Background(), "", "", "", false); got != "TGS_HEX" {
		t.Fatalf("nil register 后 kerberoaster 不应变，got GetTGS=%q", got)
	}
}
