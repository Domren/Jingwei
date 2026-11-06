package scanner

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// 真 DNS 服务器上的解析器用例。
//
// 上面的枚举用例全部走假解析器——那是对的（枚举逻辑不该依赖外网此刻怎么答），
// 但也因此没有覆盖到 SystemSubdomainResolver 本身：A/AAAA/CNAME 的真实分类、
// IPv6 会不会被丢掉、NXDOMAIN 与「问不出来」在 net.Resolver 的错误里到底长什么样。
// 这三件事错任何一件，报告都会说出一句没有证据的话。所以这里在 127.0.0.1 上起一个
// 真的 DNS 服务器，让 net.Resolver 从它那里拿答复——不出网、不打任何第三方的名字服务。

const liveDNSTestZone = "jw-live.test"

// startLiveDNS 起一个只监听回环的 DNS 服务器：
//   - A    www.<zone> / <zone>          → 127.0.0.1
//   - AAAA v6.<zone>                    → ::1
//   - CNAME cdn.<zone> → www.<zone>     然后再答 A
//   - 其余名字：开泛解析时统一答 127.0.0.1，否则 NXDOMAIN
//
// mode："" = 没有泛解析；"a" = 只有 A 的泛解析；"aaaa" = A 与 AAAA 都泛解析。
func startLiveDNS(t *testing.T, mode string) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		if len(req.Question) == 0 {
			_ = w.WriteMsg(msg)
			return
		}
		q := req.Question[0]
		name := strings.ToLower(q.Name)
		zone := strings.ToLower(liveDNSTestZone) + "."
		answer := func(rr dns.RR) {
			rr.Header().Name = q.Name
			msg.Answer = append(msg.Answer, rr)
		}
		switch {
		case name == "v6."+zone && q.Qtype == dns.TypeAAAA && mode != "aaaa":
			answer(&dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1}, AAAA: net.ParseIP("::1")})
		case name == "cdn."+zone && q.Qtype == dns.TypeCNAME:
			answer(&dns.CNAME{Hdr: dns.RR_Header{Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1}, Target: "www." + zone})
		case (name == "www."+zone || name == zone) && q.Qtype == dns.TypeA:
			answer(&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("127.0.0.1")})
		case mode != "" && q.Qtype == dns.TypeA:
			// 泛解析：任何名字的 A 都答同一个地址（含随机探测名）。
			answer(&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("127.0.0.1")})
		case mode == "aaaa" && q.Qtype == dns.TypeAAAA:
			answer(&dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1}, AAAA: net.ParseIP("::1")})
		default:
			msg.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(msg)
	})

	server := &dns.Server{PacketConn: nil, Handler: mux}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听回环 UDP：%v", err)
	}
	server.PacketConn = conn
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return conn.LocalAddr().String()
}

func liveResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// 真实答复下的三种记录 + 两种「没有」。
func TestSystemSubdomainResolverAgainstLiveDNS(t *testing.T) {
	addr := startLiveDNS(t, "")
	r := &SystemSubdomainResolver{Resolver: liveResolver(addr), Timeout: 2 * time.Second}

	records, err := r.Resolve(context.Background(), "www."+liveDNSTestZone)
	if err != nil {
		t.Fatalf("A 记录查询失败：%v", err)
	}
	if len(records) != 1 || records[0].Type != SubdomainRecordA || records[0].Values[0] != "127.0.0.1" {
		t.Fatalf("A 答复不对：%+v", records)
	}

	// IPv6 必须留下来：解析器里那句「只要 To4() 不为空」的写法就是这么把 v6 丢掉的。
	records, err = r.Resolve(context.Background(), "v6."+liveDNSTestZone)
	if err != nil {
		t.Fatalf("AAAA 查询失败：%v", err)
	}
	if len(records) != 1 || records[0].Type != SubdomainRecordAAAA || records[0].Values[0] != "::1" {
		t.Fatalf("AAAA 答复不对（IPv6 被丢了？）：%+v", records)
	}

	records, err = r.Resolve(context.Background(), "cdn."+liveDNSTestZone)
	if err != nil {
		t.Fatalf("CNAME 查询失败：%v", err)
	}
	var sawCNAME bool
	for _, rec := range records {
		if rec.Type == SubdomainRecordCNAME {
			sawCNAME = true
			if strings.HasSuffix(rec.Values[0], ".") {
				t.Fatalf("CNAME 值要去掉末尾点：%q", rec.Values[0])
			}
		}
	}
	if !sawCNAME {
		t.Fatalf("没拿到 CNAME：%+v", records)
	}

	// NXDOMAIN：确定的「不存在」——空记录且没有错误。
	records, err = r.Resolve(context.Background(), "definitely-absent."+liveDNSTestZone)
	if err != nil {
		t.Fatalf("NXDOMAIN 不该算错误：%v", err)
	}
	if len(records) != 0 {
		t.Fatalf("不存在的名字不该有记录：%+v", records)
	}

	// 服务器被关掉：这是「问不出来」，必须返回错误，绝不能当成不存在。
	_ = r
	dead := &SystemSubdomainResolver{Resolver: liveResolver("127.0.0.1:1"), Timeout: 500 * time.Millisecond}
	if _, err := dead.Resolve(context.Background(), "www."+liveDNSTestZone); err == nil {
		t.Fatal("连不上解析器时不该返回「没有记录」——那会被写成「这个子域名不存在」")
	}
}

// 整条枚举链路跑在真 DNS 上：泛解析检测、基线对照、IPv6 保留、未判定计数。
func TestEnumerateSubdomainsAgainstLiveDNS(t *testing.T) {
	// 只有 A 的泛解析：v6 那条是真记录（AAAA 与基线不同），必须留下。
	addr := startLiveDNS(t, "a")
	out, err := EnumerateSubdomains(context.Background(), []string{liveDNSTestZone}, SubdomainOptions{
		Words:       []string{"www", "absent", "v6"},
		Resolver:    &SystemSubdomainResolver{Resolver: liveResolver(addr), Timeout: 2 * time.Second},
		MaxQueries:  50,
		Concurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.WildcardRoots) != 1 {
		t.Fatalf("真 DNS 上的泛解析没被检测出来：%+v", out.WildcardRoots)
	}
	if got := namesOfOutcome(out); len(got) != 1 || got[0] != "v6."+liveDNSTestZone {
		t.Fatalf("只应留下与泛解析基线不一致的那条：%v", got)
	}
	if out.WildcardDropped < 2 {
		t.Fatalf("剔除条数要记下来，否则「0 条发现」看着像这个域名没有子域名：%d", out.WildcardDropped)
	}
	if out.Unresolved != 0 {
		t.Fatalf("这条链路上没有未判定：%d %v", out.Unresolved, out.Samples)
	}
	if !strings.Contains(out.SubdomainText(), "泛解析") {
		t.Fatalf("结论要写明泛解析剔除了多少：%s", out.SubdomainText())
	}

	// A 与 AAAA 都泛解析：整批命中都与基线一致，一条发现都不该留。
	addr2 := startLiveDNS(t, "aaaa")
	out2, err := EnumerateSubdomains(context.Background(), []string{liveDNSTestZone}, SubdomainOptions{
		Words:       []string{"www", "v6"},
		Resolver:    &SystemSubdomainResolver{Resolver: liveResolver(addr2), Timeout: 2 * time.Second},
		MaxQueries:  50,
		Concurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out2.Found) != 0 || out2.WildcardDropped == 0 {
		t.Fatalf("全类型泛解析下不该产出发现：found=%v dropped=%d", namesOfOutcome(out2), out2.WildcardDropped)
	}
}

func namesOfOutcome(out SubdomainOutcome) []string {
	names := make([]string, 0, len(out.Found))
	for _, f := range out.Found {
		names = append(names, f.Name)
	}
	return names
}
