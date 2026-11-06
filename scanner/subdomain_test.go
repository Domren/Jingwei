package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeResolver 是可控的解析器：登记表里有的名字按登记答复，没登记的算 NXDOMAIN，
// err 里的名字返回错误（未判定）。枚举的正确性不该依赖外网 DNS 此刻怎么答。
type fakeResolver struct {
	mu      sync.Mutex
	records map[string][]SubdomainRecord
	errs    map[string]error
	queries int
	// anyAnswer 非空时，所有名字都答这一份记录——用来模拟泛解析。
	anyAnswer []SubdomainRecord
	// alwaysErr 非 nil 时所有查询都失败——用来模拟容器里没有 DNS。
	alwaysErr error
	// errsPattern 命中的名字返回错误——用来只让随机探测名失败。
	errsPattern string
	// delay 让每次解析都慢一点：取消用例要靠它把执行拖到取消之后。
	delay time.Duration
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{records: map[string][]SubdomainRecord{}, errs: map[string]error{}}
}

func (f *fakeResolver) Resolve(ctx context.Context, name string) ([]SubdomainRecord, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries++
	if f.alwaysErr != nil {
		return nil, f.alwaysErr
	}
	if f.errsPattern != "" && strings.Contains(name, f.errsPattern) {
		return nil, errors.New("dns: server misbehaving")
	}
	if err, ok := f.errs[name]; ok {
		return nil, err
	}
	if recs, ok := f.records[name]; ok {
		return recs, nil
	}
	return f.anyAnswer, nil
}

func (f *fakeResolver) answer(name, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[name] = []SubdomainRecord{{Type: SubdomainRecordA, Values: []string{ip}}}
}

func (f *fakeResolver) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries
}

func rec(typ string, values ...string) SubdomainRecord {
	return SubdomainRecord{Type: typ, Values: values}
}

func findingByName(out SubdomainOutcome, name string) (SubdomainFinding, bool) {
	for _, f := range out.Found {
		if f.Name == name {
			return f, true
		}
	}
	return SubdomainFinding{}, false
}

// 泛解析是这个功能最容易整体失效的地方：不检测的话字典爆破每一条都「命中」。
func TestSubdomainWildcardSuppressesDictHits(t *testing.T) {
	const root = "example.com"
	res := newFakeResolver()
	// 任何名字都答同一个 IP —— 典型的 *.example.com。
	res.anyAnswer = []SubdomainRecord{rec(SubdomainRecordA, "1.2.3.4")}

	out, err := EnumerateSubdomains(context.Background(), []string{root}, SubdomainOptions{
		Words: []string{"admin", "api", "mail", "dev", "test"}, Resolver: res, MaxQueries: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.WildcardRoots) != 1 || out.WildcardRoots[0] != root {
		t.Fatalf("没认出泛解析：%+v", out.WildcardRoots)
	}
	if len(out.Found) != 0 {
		t.Fatalf("泛解析答复不该算发现，得到 %d 条：%v", len(out.Found), namesOf(out))
	}
	if out.WildcardDropped == 0 {
		t.Fatal("剔除的条数没有记进结论，报告就说不清为什么是空的")
	}
	if !strings.Contains(out.SubdomainText(), "泛解析") {
		t.Fatalf("结论没提泛解析：%s", out.SubdomainText())
	}
	if got := res.count(); got < 3 {
		t.Fatalf("泛解析检测至少要问随机名，只问了 %d 次", got)
	}
}

// 打开 KeepWildcard 时，泛解析命中要带着标记回来，而不是静默消失。
func TestSubdomainKeepWildcardMarksInsteadOfHiding(t *testing.T) {
	res := newFakeResolver()
	res.anyAnswer = []SubdomainRecord{rec(SubdomainRecordA, "1.2.3.4")}
	out, err := EnumerateSubdomains(context.Background(), []string{"example.com"}, SubdomainOptions{
		Words: []string{"admin"}, Resolver: res, KeepWildcard: true, MaxQueries: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findingByName(out, "admin.example.com")
	if !ok || !f.Wildcard {
		t.Fatalf("保留泛解析命中时要打标，得到 %+v ok=%v", f, ok)
	}
}

func TestSubdomainFindsRealNamesAndLabelsSources(t *testing.T) {
	res := newFakeResolver()
	const root = "example.com"
	res.answer("www."+root, "93.184.216.34")
	res.answer("api."+root, "93.184.216.35")
	res.records["mail."+root] = []SubdomainRecord{
		rec(SubdomainRecordA, "93.184.216.36"),
		rec(SubdomainRecordCNAME, "mail.example.net"),
	}
	out, err := EnumerateSubdomains(context.Background(), []string{root}, SubdomainOptions{
		Words: []string{"api", "mail", "nonexistent"}, Resolver: res, MaxQueries: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Found) != 3 {
		t.Fatalf("期望 3 条（root 自身 NXDOMAIN、www/api/mail 命中），得到 %d：%v", len(out.Found), namesOf(out))
	}
	if www, ok := findingByName(out, "www."+root); !ok || www.Source != SubdomainSourceInput {
		t.Fatalf("www 该记成直接给出的名字，得到 %+v", www)
	}
	if api, ok := findingByName(out, "api."+root); !ok || api.Source != SubdomainSourceDict {
		t.Fatalf("api 该记成字典命中，得到 %+v", api)
	}
	mail, _ := findingByName(out, "mail."+root)
	if len(mail.IPs) != 1 || mail.IPs[0] != "93.184.216.36" {
		t.Fatalf("IP 合集不对：%+v", mail.IPs)
	}
	if len(mail.Records) != 2 || mail.Records[1].Type != SubdomainRecordCNAME ||
		mail.Records[1].Values[0] != "mail.example.net" {
		t.Fatalf("CNAME 要单独成条并去掉末尾点：%+v", mail.Records)
	}
	if out.Unresolved != 0 {
		t.Fatalf("NXDOMAIN 不该算未判定：%d", out.Unresolved)
	}
}

// IPv6 不能在这里被丢掉：只有 AAAA 的子域名也是子域名（IPv4-only 的老解析器就是这么漏的）。
func TestSubdomainKeepsIPv6OnlyNames(t *testing.T) {
	res := newFakeResolver()
	res.records["v6.example.com"] = []SubdomainRecord{rec(SubdomainRecordAAAA, "2001:db8::1")}
	out, err := EnumerateSubdomains(context.Background(), []string{"example.com"}, SubdomainOptions{
		Words: []string{"v6"}, Resolver: res, MaxQueries: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findingByName(out, "v6.example.com")
	if !ok || len(f.IPs) != 1 || f.IPs[0] != "2001:db8::1" {
		t.Fatalf("AAAA 记录丢了：%+v ok=%v", f, ok)
	}
}

// 解析失败与「不存在」必须分开：把超时当成 NXDOMAIN，报告就会说「没有别的子域名了」。
func TestSubdomainUnresolvedIsCountedSeparately(t *testing.T) {
	res := newFakeResolver()
	const root = "example.com"
	res.answer("www."+root, "1.1.1.1")
	res.errs["api."+root] = errors.New("dns: timeout")
	res.errs["mail."+root] = errors.New("dns: server misbehaving")
	out, err := EnumerateSubdomains(context.Background(), []string{root}, SubdomainOptions{
		Words: []string{"api", "mail"}, Resolver: res, MaxQueries: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Unresolved != 2 {
		t.Fatalf("两次解析失败都要记为未判定，得到 %d", out.Unresolved)
	}
	if len(out.Samples) == 0 {
		t.Fatal("未判定要留样本名字，否则人无法复查")
	}
	if len(out.Found) != 1 {
		t.Fatalf("未判定不该产出发现：%+v", out.Found)
	}
	text := out.SubdomainText()
	if !strings.Contains(text, "未判定") || !strings.Contains(text, "不等于不存在") {
		t.Fatalf("结论措辞要写明未判定不等于不存在：%s", text)
	}
}

// 解析器整体不可用（容器里没 DNS）时，继续问五万次也只会把「未判定」刷大——停下并说明。
func TestSubdomainStopsWhenResolverAlwaysFails(t *testing.T) {
	res := newFakeResolver()
	res.alwaysErr = errors.New("dns: server misbehaving")
	out, err := EnumerateSubdomains(context.Background(), []string{"example.com"}, SubdomainOptions{
		Words: makeWords(200), Resolver: res, MaxQueries: 5000, Concurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Stopped != "resolver-unavailable" {
		t.Fatalf("解析连续失败要停下并写明原因，得到 stopped=%q", out.Stopped)
	}
	if out.Queried > subDefaultStopAfterFailures+20 {
		t.Fatalf("停得太晚，问了 %d 次", out.Queried)
	}
	if !strings.Contains(out.SubdomainText(), "解析连续失败") {
		t.Fatalf("结论没提停下的原因：%s", out.SubdomainText())
	}
}

func TestSubdomainBudgetTruncatesAndSaysSo(t *testing.T) {
	res := newFakeResolver()
	res.answer("api.example.com", "2.2.2.2")
	out, err := EnumerateSubdomains(context.Background(), []string{"example.com"}, SubdomainOptions{
		Words: makeWords(500), Resolver: res, MaxQueries: 3, Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Stopped != "budget" {
		t.Fatalf("预算用尽要写明，得到 %q", out.Stopped)
	}
	if out.Queried > 3 {
		t.Fatalf("问了 %d 次，超出预算 3", out.Queried)
	}
	if out.Candidates <= out.Queried {
		t.Fatalf("候选总数(%d)要大于实际问出的次数(%d)，否则看不出截断了什么", out.Candidates, out.Queried)
	}
	if !strings.Contains(out.SubdomainText(), "预算") {
		t.Fatalf("结论没提预算：%s", out.SubdomainText())
	}
}

func TestSubdomainMaxNamesCap(t *testing.T) {
	res := newFakeResolver()
	for i := 0; i < 30; i++ {
		res.answer(fmt.Sprintf("h%d.example.com", i), fmt.Sprintf("10.0.0.%d", i+1))
	}
	words := make([]string, 0, 30)
	for i := 0; i < 30; i++ {
		words = append(words, fmt.Sprintf("h%d", i))
	}
	out, err := EnumerateSubdomains(context.Background(), []string{"example.com"}, SubdomainOptions{
		Words: words, Resolver: res, MaxQueries: 1000, MaxNames: 10, Concurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Found) != 10 {
		t.Fatalf("命中上限 10 条，得到 %d", len(out.Found))
	}
	if out.Stopped != "budget" {
		t.Fatalf("截断要写明，得到 %q", out.Stopped)
	}
}

func TestSubdomainCancelReturnsPartialResults(t *testing.T) {
	res := newFakeResolver()
	res.delay = 5 * time.Millisecond
	res.answer("www.example.com", "3.3.3.3")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	out, err := EnumerateSubdomains(ctx, []string{"example.com"}, SubdomainOptions{
		Words: makeWords(2000), Resolver: res, MaxQueries: 100000, Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Stopped != "canceled" {
		t.Fatalf("手动停止要写明，得到 %q", out.Stopped)
	}
	if len(out.Found) == 0 {
		t.Fatal("中途停止时已经拿到的结果要能交付")
	}
	if !strings.Contains(out.SubdomainText(), "手动停止") {
		t.Fatalf("结论没提停止：%s", out.SubdomainText())
	}
}

// 公开接口：crt.sh 的 name_value 常见多行、逗号分隔，还会夹带别人的域。
func TestSubdomainCrtshParsesAndFiltersForeignNames(t *testing.T) {
	body := []crtshEntry{
		{NameValue: "a.example.com\nb.example.com"},
		{Name: "c.example.com", SanEntries: "d.example.com,e.example.org"},
		{NameValue: "victim-inside-elsewhere.net"},
		{NameValue: "*.example.com"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("output") != "json" {
			t.Errorf("请求没带 output=json：%s", r.URL.RawQuery)
		}
		if q := r.URL.Query()["q"]; len(q) != 1 || q[0] != "*.example.com" {
			t.Errorf("查询参数不对：%v", r.URL.Query())
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()
	withCrtsh(t, srv.URL)

	res := newFakeResolver()
	res.answer("a.example.com", "4.4.4.1")
	res.answer("b.example.com", "4.4.4.2")
	res.answer("c.example.com", "4.4.4.3")
	res.answer("d.example.com", "4.4.4.4")
	res.answer("e.example.org", "4.4.4.5")
	res.answer("victim-inside-elsewhere.net", "4.4.4.6")
	res.answer("example.com", "4.4.4.7")

	out, err := EnumerateSubdomains(context.Background(), []string{"example.com"}, SubdomainOptions{
		Words: []string{"zzz-not-a-real-prefix"}, Sources: []string{"crtsh"}, Resolver: res,
		HTTPClient: srv.Client(), MaxQueries: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.PublicOn || out.PublicErrors != 0 {
		t.Fatalf("公开接口状态不对：%+v", out)
	}
	// *.example.com 归一化成 example.com（通配符本身不是资产），elsewhere 的域一律不进队列。
	if got := namesOf(out); strings.Join(got, ",") != "a.example.com,b.example.com,c.example.com,d.example.com,example.com" {
		t.Fatalf("公开接口结果越界或漏了：%v", got)
	}
	for _, f := range out.Found {
		if f.Name == "example.com" {
			continue
		}
		if f.Source != SubdomainSourcePublic {
			t.Fatalf("%s 该记成公开接口来源，得到 %q", f.Name, f.Source)
		}
	}
}

// 第三方挂了不算本轮失败：字典照跑，但结论里必须说清那部分覆盖面缺失。
func TestSubdomainCrtshFailureDoesNotBreakRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()
	withCrtsh(t, srv.URL)

	res := newFakeResolver()
	res.answer("www.example.com", "5.5.5.5")
	out, err := EnumerateSubdomains(context.Background(), []string{"example.com"}, SubdomainOptions{
		Words: []string{"api"}, Sources: []string{"crtsh"}, Resolver: res, HTTPClient: srv.Client(), MaxQueries: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.PublicErrors != 1 {
		t.Fatalf("要记下公开接口失败次数，得到 %d", out.PublicErrors)
	}
	if len(out.Found) != 1 {
		t.Fatalf("公开接口失败不该影响字典：%+v", out.Found)
	}
	if !strings.Contains(out.SubdomainText(), "公开接口失败") {
		t.Fatalf("结论要写明公开接口失败：%s", out.SubdomainText())
	}
}

// 重定向到别的主机就不能跟：这条外发只有一个目的地，否则枚举接口自己变成 SSRF 跳板。
func TestSubdomainCrtshRefusesCrossHostRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]crtshEntry{{NameValue: "leaked.example.com"}})
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	withCrtsh(t, srv.URL)

	res := newFakeResolver()
	out, err := EnumerateSubdomains(context.Background(), []string{"example.com"}, SubdomainOptions{
		Sources: []string{"crtsh"}, Resolver: res, HTTPClient: srv.Client(), MaxQueries: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.PublicErrors != 1 {
		t.Fatalf("跨主机重定向应当中止并记一次失败，得到 %+v", out)
	}
	if _, ok := findingByName(out, "leaked.example.com"); ok {
		t.Fatal("跟了重定向，把查询带到了别处")
	}
}

// 不认识的来源不假装查过。
func TestSubdomainUnknownSourceSkipped(t *testing.T) {
	res := newFakeResolver()
	res.answer("www.example.com", "6.6.6.6")
	out, err := EnumerateSubdomains(context.Background(), []string{"example.com"}, SubdomainOptions{
		Words: []string{"api"}, Sources: []string{"fofa"}, Resolver: res, MaxQueries: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.PublicOn || out.PublicSkipped != 1 {
		t.Fatalf("未知来源不该算开启：%+v", out)
	}
	if !strings.Contains(out.SubdomainText(), "未使用第三方公开接口") {
		t.Fatalf("不开公开接口时结论要写明：%s", out.SubdomainText())
	}
}

func TestSubdomainRootsFromTargets(t *testing.T) {
	roots, err := SubdomainRootsFromTargets([]string{
		"https://www.example.com/path", "http://shop.corp.example.org:8080", "example.net", "EXAMPLE.COM",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(roots, ",")
	// 注册域按标签数粗判：三段以上只去掉最左一段（宁可保守，也不把别人的域名当成目标）。
	if got != "corp.example.org,example.com,example.net" {
		t.Fatalf("根域名集合不对：%s", got)
	}
	if _, err := SubdomainRootsFromTargets([]string{"10.0.0.0/24", "192.168.1.1"}); err == nil ||
		!strings.Contains(err.Error(), "没有可用的根域名") {
		t.Fatalf("IP 与 CIDR 要清楚拒绝，得到 %v", err)
	}
}

func TestValidSubdomainRoot(t *testing.T) {
	for _, ok := range []string{"example.com", "a.b.example.com", "xn--fiqs8s.cn", "test-example.co"} {
		if !ValidSubdomainRoot(ok) {
			t.Fatalf("%q 应当可用", ok)
		}
	}
	for _, bad := range []string{"", "com", "example", "1.2.3.4", "http://example.com", "example.com:80",
		"a b.example.com", "*.example.com/../", "example..com"} {
		if ValidSubdomainRoot(bad) {
			t.Fatalf("%q 不该被当成根域名", bad)
		}
	}
}

// 系统解析器这一路不能是死代码：本机 localhost 至少要能问出来，且 NXDOMAIN 与错误要分得开。
func TestSystemSubdomainResolverAgainstLocalhost(t *testing.T) {
	r := NewSystemSubdomainResolver(2 * time.Second)
	records, err := r.Resolve(context.Background(), "localhost")
	if err != nil {
		t.Skipf("本机解析器不可用（%v），跳过", err)
	}
	if len(records) == 0 {
		t.Fatal("localhost 至少该有一条记录")
	}
	var hasV4 bool
	for _, rec := range records {
		if rec.Type == SubdomainRecordA {
			hasV4 = true
		}
	}
	if !hasV4 {
		t.Fatalf("localhost 应有 A 记录：%+v", records)
	}
	if got, err := r.Resolve(context.Background(), "jw-definitely-not-a-real-host.example"); err != nil {
		t.Fatalf("不存在的名字应返回 NXDOMAIN 而不是错误：%v", err)
	} else if len(got) != 0 {
		t.Fatalf("不存在的名字不该有记录：%+v", got)
	}
}

func TestIsNotFoundErrSeparatesNotFoundFromFailure(t *testing.T) {
	if !isNotFoundErr(&net.DNSError{Err: "no such host", IsNotFound: true}) {
		t.Fatal("NXDOMAIN 要认出来")
	}
	if isNotFoundErr(&net.DNSError{Err: "server misbehaving", IsTimeout: true}) {
		t.Fatal("超时/SERVFAIL 不能算不存在")
	}
	if isNotFoundErr(errors.New("boom")) {
		t.Fatal("普通错误不能算不存在")
	}
}

func TestNormalizeDomainAndFingerprint(t *testing.T) {
	if got := normalizeDomain("*.WWW.Example.COM."); got != "www.example.com" {
		t.Fatalf("归一化不对：%q", got)
	}
	fp := recordFingerprint([]SubdomainRecord{rec(SubdomainRecordCNAME, "x.co"), rec(SubdomainRecordA, "1.1.1.1")})
	if !strings.HasPrefix(fp, "A=1.1.1.1;") {
		t.Fatalf("指纹要按类型排序，便于与泛解析基线比对：%q", fp)
	}
	if recordFingerprint(nil) != "" {
		t.Fatal("空记录不该有指纹")
	}
}

// 泛解析检测本身问不出结果时（解析器报错），宁可当「没有泛解析」：
// 误判成「有」会把真子域名整批丢掉，那是更大的损失。
func TestSubdomainWildcardDetectionFailureKeepsFindings(t *testing.T) {
	res := newFakeResolver()
	res.errsPattern = "jw-" // 随机探测名全部报错，真名字正常答复
	res.answer("www.example.com", "7.7.7.7")
	out, err := EnumerateSubdomains(context.Background(), []string{"example.com"}, SubdomainOptions{
		Words: nil, Resolver: res, MaxQueries: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.WildcardRoots) != 0 {
		t.Fatalf("问不出结果时不该认定泛解析：%v", out.WildcardRoots)
	}
	if len(out.Found) != 1 {
		t.Fatalf("真子域名不该被误判丢掉：%+v", out.Found)
	}
}

func withCrtsh(t *testing.T, url string) {
	t.Helper()
	old := crtshBaseURL
	crtshBaseURL = url
	t.Cleanup(func() { crtshBaseURL = old })
}

func makeWords(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("w%d", i))
	}
	return out
}

func namesOf(out SubdomainOutcome) []string {
	names := make([]string, 0, len(out.Found))
	for _, f := range out.Found {
		names = append(names, f.Name)
	}
	return names
}

// crt.sh 的真实响应形态（2026-11-06 从线上抓的两条 + 三条合成条目，用来覆盖过滤分支）。
// 为什么留一份样本在库里：这个接口的字段名与「name_value 是多行」的写法只有真数据能证明，
// 而它随时可能改；解析器一旦对不上就会静默返回 0 条名字，报告于是说「公开接口没找到别的子域名」。
func TestSubdomainCrtshRealResponseShape(t *testing.T) {
	payload, err := os.ReadFile("testdata/crtsh-sample.json")
	if err != nil {
		t.Fatalf("读取 crt.sh 样本失败：%v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	withCrtsh(t, srv.URL)

	const root = "example.com"
	res := newFakeResolver()
	res.answer(root, "93.184.216.34")
	res.answer("api."+root, "93.184.216.35")
	res.answer("db."+root, "10.0.0.5")
	res.answer("backup."+root, "10.0.0.6")
	out, err := EnumerateSubdomains(context.Background(), []string{root}, SubdomainOptions{
		Words: []string{"zzz-not-a-real-prefix"}, Sources: []string{"crtsh"},
		Resolver: res, HTTPClient: srv.Client(), MaxQueries: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.PublicErrors != 0 {
		t.Fatalf("真实形态的响应应当解析成功：%+v", out)
	}
	got := namesOf(out)
	want := []string{"api.example.com", "backup.example.com", "db.example.com", "example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("公开接口结果不对：got=%v want=%v", got, want)
	}
	for _, f := range out.Found {
		if f.Name != root && f.Source != SubdomainSourcePublic {
			t.Fatalf("%s 该记成公开接口来源（f.Source=%q）", f.Name, f.Source)
		}
	}
	// 别的根（other.tld / shop.other.tld）连问都不该问：那是别人的资产。
	for _, bad := range []string{"other.tld", "shop.other.tld"} {
		if _, ok := res.records[bad]; ok {
			t.Fatalf("%s 不该出现在解析队列里", bad)
		}
	}
}
