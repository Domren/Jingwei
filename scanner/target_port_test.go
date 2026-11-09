package scanner

import (
	"strings"
	"testing"
)

// B1：目标解析支持 host:port。这里的断言重点是「操作员写了端口就只测那个端口」，
// 以及端口写错时必须报端口错、不能退回去当主机名猜。
func TestParseTargetHostPort(t *testing.T) {
	ok := []struct {
		raw  string
		kind TargetKind
		host string
		port int
	}{
		{"10.0.0.1:2222", KindIP, "10.0.0.1", 2222},
		{"127.0.0.1:6379", KindIP, "127.0.0.1", 6379},
		{"intranet.local:3306", KindDomain, "intranet.local", 3306},
		{"IntraNet.LOCAL:8080", KindDomain, "intranet.local", 8080},
		{"10.0.0.1", KindIP, "10.0.0.1", 0},
		{"example.org", KindDomain, "example.org", 0},
		{"10.0.0.0/24", KindCIDR, "10.0.0.0/24", 0},
	}
	for _, c := range ok {
		got, err := ParseTarget(c.raw)
		if err != nil {
			t.Fatalf("%q 应当解析成功，却报错: %v", c.raw, err)
		}
		if got.Kind != c.kind || got.Host != c.host || got.Port != c.port {
			t.Fatalf("%q 解析成 %+v，想要 kind=%s host=%s port=%d", c.raw, got, c.kind, c.host, c.port)
		}
		if got.Raw != c.raw {
			t.Fatalf("%q 的 Raw 被改写成 %q", c.raw, got.Raw)
		}
	}

	// URL 里显式写的端口也要带出来，弱口令检测要靠它。
	u, err := ParseTarget("http://db.internal:8443/admin")
	if err != nil {
		t.Fatal(err)
	}
	if u.Kind != KindURL || u.Host != "db.internal" || u.Port != 8443 {
		t.Fatalf("带端口的 URL 解析错: %+v", u)
	}
	if noPort, err := ParseTarget("https://db.internal/"); err != nil || noPort.Port != 0 {
		t.Fatalf("不带端口的 URL 应当 Port=0，实得 %+v err=%v", noPort, err)
	}

	bad := []struct {
		raw    string
		wanted string
	}{
		{"10.0.0.1:0", "端口无效"},
		{"10.0.0.1:65536", "端口无效"},
		{"10.0.0.1:abc", "端口无效"},
		{"10.0.0.1:", "端口无效"},
		{"example.com:2222/path", "不带路径"},
		{"10.0.0.0/24:80", "网段不带端口"},
		{"300.1.1.1:22", "无效"}, // 主机部分本身非法，不能被端口分支掩盖
		{"bad host:22", "无效"},  // 主机名里有空格
		{"10.0.0.0/24:10.0.0.5", "格式无效"},
	}
	for _, c := range bad {
		if _, err := ParseTarget(c.raw); err == nil {
			t.Fatalf("%q 应当报错，却解析成功", c.raw)
		} else if !strings.Contains(err.Error(), c.wanted) {
			t.Fatalf("%q 的报错要含 %q，实得 %q", c.raw, c.wanted, err.Error())
		}
	}

	// C6：IPv6 与 IPv4 同走 KindIP，Host 存裸地址，交给 net.JoinHostPort 拨号。
	for _, c := range []struct {
		raw  string
		host string
		port int
	}{
		{"::1", "::1", 0},
		{"2001:db8::1", "2001:db8::1", 0},
		{"[2001:db8::1]:22", "2001:db8::1", 22},
	} {
		got, err := ParseTarget(c.raw)
		if err != nil {
			t.Fatalf("%q 应当解析成功，却报错: %v", c.raw, err)
		}
		if got.Kind != KindIP || got.Host != c.host || got.Port != c.port {
			t.Fatalf("%q 解析成 %+v，想要 kind=ip host=%s port=%d", c.raw, got, c.host, c.port)
		}
	}
}

// 同一主机不同端口是两条意图，不能被去重吃掉。
func TestParseTargetsKeepsDistinctPorts(t *testing.T) {
	got, err := ParseTargets([]string{"10.0.0.1", "10.0.0.1:2222", "10.0.0.1:2222", "example.com:3306"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("想要 3 条目标，实得 %d: %+v", len(got), got)
	}
	if got[0].Port != 0 || got[1].Port != 2222 {
		t.Fatalf("端口在去重后被搞混: %+v", got)
	}
}
