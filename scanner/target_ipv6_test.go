package scanner

import (
	"bytes"
	"context"
	"log"
	"net"
	"strings"
	"testing"
)

// C6：IPv6 目标支持。覆盖五种输入形态、混批不丢其它目标、非法 IPv6 明确报错、
// net.JoinHostPort 拨号形态，以及 ParseTargets 跳过非法项时写明原因。

func TestParseTargetIPv6Forms(t *testing.T) {
	cases := []struct {
		raw  string
		kind TargetKind
		host string
		port int
	}{
		{"10.0.0.1", KindIP, "10.0.0.1", 0},               // 裸 IPv4
		{"10.0.0.1:2222", KindIP, "10.0.0.1", 2222},       // ip:port
		{"[2001:db8::1]:443", KindIP, "2001:db8::1", 443}, // [ipv6]:port
		{"2001:db8::1", KindIP, "2001:db8::1", 0},         // 裸 IPv6
		{"10.0.0.0/24", KindCIDR, "10.0.0.0/24", 0},       // IPv4 CIDR
	}
	for _, c := range cases {
		got, err := ParseTarget(c.raw)
		if err != nil {
			t.Fatalf("%q 应当解析成功，却报错: %v", c.raw, err)
		}
		if got.Kind != c.kind || got.Host != c.host || got.Port != c.port || got.Raw != c.raw {
			t.Fatalf("%q 解析成 %+v，想要 kind=%s host=%q port=%d", c.raw, got, c.kind, c.host, c.port)
		}
	}
}

func TestParseTargetIPv6NormalizesHost(t *testing.T) {
	// Host 必须是规范化后的裸地址，绝不带方括号，否则 JoinHostPort 会拼成 [[...]]。
	for raw, want := range map[string]string{
		"2001:0DB8:0000:0000:0000:0000:0000:0001": "2001:db8::1",
		"0:0:0:0:0:0:0:1":                         "::1",
		"[2001:DB8::AB]:8080":                     "2001:db8::ab",
	} {
		got, err := ParseTarget(raw)
		if err != nil {
			t.Fatalf("%q 应当解析成功: %v", raw, err)
		}
		if got.Host != want || strings.ContainsAny(got.Host, "[]") {
			t.Fatalf("%q 的 Host = %q，想要裸地址 %q", raw, got.Host, want)
		}
	}
}

// 混批里混有 IPv6 甚至一条非法 IPv6 时，其余 IP/CIDR/域名必须照常返回，
// 绝不复现「一个 IPv6 让整批端口探测静默不发生」。
func TestParseTargetsIPv6MixedBatchDoesNotDropOthers(t *testing.T) {
	raws := []string{
		"10.0.0.1",
		"[2001:db8::1]:443",
		"2001:db8::2",
		"10.0.0.0/30",
		"example.com",
		"2001:db8::zz", // 非法 IPv6：跳过但写明，不能拖垮整批
	}
	got, err := ParseTargets(raws)
	if err != nil {
		t.Fatalf("混批不应整体失败: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("想要 5 条有效目标，实得 %d: %+v", len(got), got)
	}
	want := map[string]bool{
		"ip|10.0.0.1":        true,
		"ip|2001:db8::1":     true,
		"ip|2001:db8::2":     true,
		"cidr|10.0.0.0/30":   true,
		"domain|example.com": true,
	}
	for _, t2 := range got {
		key := string(t2.Kind) + "|" + t2.Host
		if !want[key] {
			t.Fatalf("多出或错解析的目标: %s (%+v)", key, t2)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("这些目标被整批弄丢了: %v", want)
	}
	// [ipv6]:port 的端口必须跟着保留，不能被去重或改写吃掉。
	for _, t2 := range got {
		if t2.Host == "2001:db8::1" && t2.Port != 443 {
			t.Fatalf("[ipv6]:port 的端口丢了: %+v", t2)
		}
	}
}

func TestParseTargetIPv6InvalidAndCIDRRejected(t *testing.T) {
	bad := []struct{ raw, want string }{
		{"2001:db8::zz", "IPv6"},
		{"[gggg::1]:80", "IPv6"},
		{"[2001:db8::1]", "IPv6"},
		{"fe80::1%eth0", "IPv6"},
		{"2001:db8::/32", "IPv4 CIDR"}, // 不支持 IPv6 CIDR，但必须点名而不是静默跳过
		{"::1/128", "IPv4 CIDR"},
	}
	for _, c := range bad {
		_, err := ParseTarget(c.raw)
		if err == nil {
			t.Fatalf("%q 应当明确报错", c.raw)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%q 的报错要含 %q，实得 %q", c.raw, c.want, err.Error())
		}
	}
}

// 拨号形态：Host 交给 net.JoinHostPort 后，IPv4 不加括号、IPv6 恰好一层 []。
func TestParseTargetIPv6JoinHostPortDialShape(t *testing.T) {
	cases := []struct {
		raw, host, dialPort, want string
	}{
		{"10.0.0.1:8443", "10.0.0.1", "8443", "10.0.0.1:8443"},
		{"[2001:db8::1]:443", "2001:db8::1", "443", "[2001:db8::1]:443"},
		{"2001:db8::1", "2001:db8::1", "80", "[2001:db8::1]:80"},
		{"::1", "::1", "22", "[::1]:22"},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.raw)
		if err != nil {
			t.Fatalf("%q 应当解析成功: %v", c.raw, err)
		}
		if got.Host != c.host || strings.ContainsAny(got.Host, "[]") {
			t.Fatalf("%q 的 Host = %q，想要裸地址 %q", c.raw, got.Host, c.host)
		}
		if addr := net.JoinHostPort(got.Host, c.dialPort); addr != c.want {
			t.Fatalf("%q 拨号形态 = %q，想要 %q", c.raw, addr, c.want)
		}
		// 反解一次，确认括号只包住地址本身（[[]] 之类会在这里露馅）。
		h, p, err := net.SplitHostPort(net.JoinHostPort(got.Host, c.dialPort))
		if err != nil || h != c.host || p != c.dialPort {
			t.Fatalf("%q 无法反解: h=%q p=%q err=%v", c.raw, h, p, err)
		}
	}
}

// Resolve 把 IPv6 目标直接放进 IP 集合，Discover 才会用 JoinHostPort 拨到它。
func TestParseTargetIPv6ResolvesIntoIPSet(t *testing.T) {
	targets, err := ParseTargets([]string{"10.0.0.1", "2001:db8::1", "[2001:db8::2]:443"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Resolve(context.Background(), targets, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.IPs) != 3 {
		t.Fatalf("想要 3 个 IP，实得 %v", res.IPs)
	}
	seen := map[string]bool{}
	for _, ip := range res.IPs {
		seen[ip] = true
	}
	for _, want := range []string{"10.0.0.1", "2001:db8::1", "2001:db8::2"} {
		if !seen[want] {
			t.Fatalf("IPv6 目标 %q 没进 IP 集合: %v", want, res.IPs)
		}
	}
}

// 非法项跳过要写明原因；全部非法时必须返回带原因的错误，不能静默成功。
func TestParseTargetsSkipsInvalidWithLoggedReason(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	got, err := ParseTargets([]string{"10.0.0.1", "2001:db8::zz", "10.0.0.2"})
	if err != nil {
		t.Fatalf("部分非法不应让整批失败: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("想要 2 条有效目标，实得 %+v", got)
	}
	logged := buf.String()
	if !strings.Contains(logged, "2001:db8::zz") || !strings.Contains(logged, "IPv6") {
		t.Fatalf("跳过原因没有写明（目标与原因都要出现）: %q", logged)
	}
	if _, err := ParseTargets([]string{"2001:db8::zz"}); err == nil ||
		!strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("全部无效要返回带原因的错误: %v", err)
	}
}
