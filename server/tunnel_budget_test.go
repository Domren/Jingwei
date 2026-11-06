package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

// 隧道身份必须把「同一个通道的不同写法」认成一个：代理串里带不带端口、带不带凭据，
// 名额都该记在同一条隧道上。凭据尤其不能出现在端点里——它会被写进接口响应与占用表。
func TestProxyEndpointIdentity(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"socks5://10.99.0.20:11080", "10.99.0.20:11080"},
		{"socks5://10.99.0.20", "10.99.0.20:1080"},
		{"socks5h://user:sup3rsecret@10.99.0.20:11080", "10.99.0.20:11080"},
		{"http://127.0.0.1:7890", "127.0.0.1:7890"},
		{"https://proxy.example.com", "proxy.example.com:443"},
		{"socks5://[fd00::1]:1080", "[fd00::1]:1080"},
		{"SOCKS5://HOST.Example.COM:1080", "host.example.com:1080"},
	}
	for _, c := range cases {
		if got := proxyEndpoint(c.in); got != c.want {
			t.Errorf("proxyEndpoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if strings.Contains(proxyEndpoint("socks5://u:p@1.2.3.4:1080"), "p@") {
		t.Error("代理凭据漏进了端点标识里")
	}
}

// 预算关掉时必须一个字节都不改：F6 是「可调」，不是把 1.5.0 的口径强行换掉。
func TestTunnelBudgetClamps(t *testing.T) {
	s, _ := newCredTestServer(t)
	free := s.budget("")
	if free.ok {
		t.Fatal("没填代理不该受隧道预算约束")
	}
	if c, r := free.clampNuclei(25, 50); c != 25 || r != 50 {
		t.Fatalf("不受约束时并发被改了：%d / %d", c, r)
	}
	if p := free.clampProbes(200); p != 200 {
		t.Fatalf("不受约束时探测并发被改了：%d", p)
	}

	setTunnelBudget(t, s, true, 1, 4)
	on := s.budget("socks5://10.99.0.20:11080")
	if !on.ok || on.requests != 4 || on.probes != 16 || on.rateLimit != 40 {
		t.Fatalf("预算口径不对：%+v", on)
	}
	if c, r := on.clampNuclei(25, 50); c != 4 || r != 40 {
		t.Fatalf("nuclei 并发/限速没收敛：%d / %d", c, r)
	}
	if c, r := on.clampNuclei(2, 5); c != 2 || r != 5 {
		t.Fatalf("本来就更保守的设置被放大了：%d / %d", c, r)
	}
	if p := on.clampProbes(200); p != 16 {
		t.Fatalf("探测并发没收敛：%d", p)
	}

	off := s.m.pg.SetSetting(settingTunnelConcurrencyOn, "false")
	if off != nil {
		t.Fatal(off)
	}
	if s.budget("socks5://10.99.0.20:11080").ok {
		t.Fatal("关掉开关后仍在约束隧道任务")
	}
}

// 名额是「同一条隧道」的，不是「同一个任务类型」的：漏扫与它自己派生的深挖任务
// 共用一条通道，两边各数各的等于没有预算。
func TestTunnelBudgetOccupancy(t *testing.T) {
	setting := proxyBudget{ok: true, endpoint: "10.99.0.20:11080", taskLimit: 1}
	other := proxyBudget{ok: true, endpoint: "10.99.0.30:11080", taskLimit: 1}
	tb := newTunnelBudget()
	if !tb.acquire(setting) {
		t.Fatal("空隧道上第一个任务就该拿到名额")
	}
	if tb.acquire(setting) {
		t.Fatal("同一条隧道上第二个任务不该拿到名额")
	}
	if !tb.acquire(other) {
		t.Fatal("另一条隧道不该被邻居占满")
	}
	if got := tb.occupancy("10.99.0.20:11080"); got != 1 {
		t.Fatalf("占用数不对：%d", got)
	}
	tb.release(setting)
	if !tb.acquire(setting) {
		t.Fatal("释放后应当能再排上")
	}
	// 不受约束的任务（直连）不计数、也不会被别处的满隧道挡住。
	for i := 0; i < 3; i++ {
		if !tb.acquire(proxyBudget{}) {
			t.Fatal("直连任务不该被预算拦下")
		}
	}
	if snap := tb.snapshot(); len(snap) != 2 {
		t.Fatalf("占用表应当只有两条隧道：%v", snap)
	}
}

// 认领必须跳过「隧道满了」的任务去跑后面能跑的：一条忙隧道把整条队列堵住，
// 等于用排队换来了一个更糟的「什么都动不了」。
func TestScanClaimSkipsSaturatedTunnel(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM scan_tasks WHERE name LIKE 'f6-%'`) })

	mk := func(name, proxy string) int64 {
		task, err := pg.CreateScanTask(db.ScanTaskInput{
			Name: name, Targets: []string{"http://10.99.0.10/"}, Mode: "auto", Ports: "80", Proxy: proxy,
		})
		if err != nil {
			t.Fatal(err)
		}
		return task.ID
	}
	tunnelA := mk("f6-tunnel-1", "socks5://10.99.0.20:11080")
	direct := mk("f6-direct", "")
	tunnelB := mk("f6-tunnel-2", "socks5://user:pass@10.99.0.20:11080")
	setTunnelBudget(t, s, true, 1, 4)

	mgr := newScanManager(s)
	// 先占住那条隧道的一个名额（模拟已经在跑的扫描）。
	budget := s.budget("socks5://10.99.0.20:11080")
	if !s.tunnels.acquire(budget) {
		t.Fatal("第一次占位就该成功")
	}

	// 队首是隧道任务：不能认领它，也不能因此停手——直连任务必须能开工。
	task, claimedBudget, err := mgr.claimNext()
	if err != nil {
		t.Fatal(err)
	}
	if task == nil || task.ID != direct {
		t.Fatalf("应当认领直连任务，得到 %+v", task)
	}
	if claimedBudget.ok {
		t.Fatal("直连任务不该占用隧道名额")
	}

	// 剩下的两条隧道任务：名额已满，留在队列里并写明原因。
	if got, _, err := mgr.claimNext(); got != nil || err != nil {
		t.Fatalf("隧道满了就不该认领到任务：%+v %v", got, err)
	}
	for _, id := range []int64{tunnelA, tunnelB} {
		got, err := pg.GetScanTask(id)
		if err != nil {
			t.Fatal(err)
		}
		note, _ := got.Progress["queue_note"].(string)
		if got.Status != "queued" {
			t.Fatalf("被预算挡下的任务状态被改了：%s", got.Status)
		}
		if !strings.Contains(note, "10.99.0.20:11080") || !strings.Contains(note, "排队等待") {
			t.Fatalf("排队原因没写清楚（%d）：%q", id, note)
		}
		if strings.Contains(note, "pass") {
			t.Fatalf("排队原因里漏出了代理凭据：%q", note)
		}
	}
	s.tunnels.release(budget)

	// 调高上限之后应当立刻能认领（等待的原因是预算，不是任务坏了）。
	if err := s.SetTunnelConcurrency(nil, intPtr(2), nil, nil); err != nil {
		t.Fatal(err)
	}
	next, nextBudget, err := mgr.claimNext()
	if err != nil {
		t.Fatal(err)
	}
	if next == nil || next.ID != tunnelA {
		t.Fatalf("放宽预算后应按 FIFO 认领隧道任务，得到 %+v", next)
	}
	if !nextBudget.ok || nextBudget.endpoint != "10.99.0.20:11080" {
		t.Fatalf("认领到的任务没有占住隧道名额：%+v", nextBudget)
	}
	s.tunnels.release(nextBudget)
}

// 深挖任务与漏扫共用同一张占用表：自动深挖就是漏扫自己排下去的。
func TestDeepClaimSharesTunnelBudget(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM deep_tasks WHERE name LIKE 'f6-%'`) })
	if _, err := pg.CreateDeepTask(db.DeepTaskInput{
		Name: "f6-deep", Kind: db.DeepTaskExploit, Target: "http://10.99.0.10/",
		Params: map[string]any{"proxy": "socks5://10.99.0.20:11080"},
	}); err != nil {
		t.Fatal(err)
	}
	setTunnelBudget(t, s, true, 1, 4)
	budget := s.budget("socks5://10.99.0.20:11080")
	if !s.tunnels.acquire(budget) {
		t.Fatal("占位失败")
	}
	mgr := newDeepManager(s)
	if task, _, err := mgr.claimNext(); task != nil || err != nil {
		t.Fatalf("隧道被扫描占满时不该认领深挖任务：%+v %v", task, err)
	}
	s.tunnels.release(budget)
	task, claimed, err := mgr.claimNext()
	if err != nil {
		t.Fatal(err)
	}
	if task == nil || !claimed.ok {
		t.Fatalf("释放名额后深挖任务应能开工：%+v %+v", task, claimed)
	}
}

// 预算的持久化：数字越界被钳制而不是被拒（一个手抖的 0 不该把预算变成「不限」），
// 设置接口回显当前口径与占用表。
func TestTunnelBudgetSettingsAPI(t *testing.T) {
	s, _ := newCredTestServer(t)
	setTunnelBudget(t, s, true, 1, 4)

	if err := s.SetTunnelConcurrency(nil, intPtr(999), intPtr(0), nil); err != nil {
		t.Fatal(err)
	}
	on, taskLimit, reqLimit, _ := s.tunnelSettings()
	if !on || taskLimit != maxTunnelTaskLimit || reqLimit != 1 {
		t.Fatalf("钳制不对：on=%v task=%d req=%d", on, taskLimit, reqLimit)
	}

	rec := httptest.NewRecorder()
	s.getSettings(rec, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["tunnel_concurrency_enabled"] != true ||
		payload["tunnel_concurrency_limit"] != float64(maxTunnelTaskLimit) ||
		payload["tunnel_request_concurrency_limit"] != float64(1) {
		t.Fatalf("设置接口没有回显隧道预算：%v", payload["tunnel_concurrency_limit"])
	}
	if _, ok := payload["tunnel_busy"]; !ok {
		t.Fatal("设置接口缺少隧道占用表")
	}

	body, err := json.Marshal(map[string]any{"tunnel_concurrency_enabled": false})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	s.putSettings(rec, httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body))))
	if rec.Code != http.StatusOK {
		t.Fatalf("保存隧道预算失败：%d %s", rec.Code, rec.Body.String())
	}
	if on2, _, _, _ := s.tunnelSettings(); on2 {
		t.Fatal("关掉开关没有生效")
	}
}

// 「平台登记的隧道」只能用在真的登记过的端点上。手写的 socks5://ip:port（哪怕那个 IP
// 不是本机）只是代理端点：把它说成隧道，读日志的人会去找一条并不存在的平台转发，
// 而真正的原因——并发是我自己填的——没人查。
func TestTunnelBudgetLogKind(t *testing.T) {
	s, _ := newCredTestServer(t)
	pg := s.m.pg
	setTunnelBudget(t, s, true, 1, 4)

	plain := s.budget("socks5://172.23.0.1:41080")
	if !plain.ok {
		t.Fatal("未登记的代理端点也应当受预算约束")
	}
	if plain.fromRecord {
		t.Fatal("没有登记记录的代理端点被认成了平台登记的隧道")
	}
	if !strings.Contains(plain.logLine(), "代理端点") {
		t.Fatalf("日志口径不对：%q", plain.logLine())
	}

	tun, err := pg.CreateIntranetTunnel(db.IntranetTunnelInput{
		Name: "f6-budget-label", Kind: db.IntranetTunnelKindSocks5,
		ListenHost: "127.0.0.1", ListenPort: 41081, RemoteHost: "10.99.0.10", RemotePort: 1080,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_tunnels WHERE id=$1`, tun.ID) })
	// 只有部署中/已验证的隧道才真的在听这个端口。
	if _, err := pg.Exec(`UPDATE intranet_tunnels SET status=$1 WHERE id=$2`, db.IntranetTunnelDeployed, tun.ID); err != nil {
		t.Fatal(err)
	}

	registered := s.budget("socks5://127.0.0.1:41081")
	if !registered.fromRecord {
		t.Fatalf("登记在册的隧道没有认出来：%+v", registered)
	}
	if !strings.Contains(registered.logLine(), "平台登记的隧道") {
		t.Fatalf("日志口径不对：%q", registered.logLine())
	}

	// 关掉「未登记代理也按隧道对待」后，手写端点不再受约束，登记的仍然受。
	if err := pg.SetSetting(settingTunnelBudgetAnyProxy, "false"); err != nil {
		t.Fatal(err)
	}
	if s.budget("socks5://172.23.0.1:41080").ok {
		t.Fatal("开关关掉后未登记的代理端点仍被约束")
	}
	if !s.budget("socks5://127.0.0.1:41081").ok {
		t.Fatal("开关关掉后登记的隧道不再被约束")
	}
}

func intPtr(n int) *int { return &n }

// setTunnelBudget 临时设定预算并在用例结束时还原。
func setTunnelBudget(t *testing.T, s *Server, on bool, taskLimit, reqLimit int) {
	t.Helper()
	prevOn, prevTask, prevReq, prevAny := s.tunnelSettings()
	if err := s.SetTunnelConcurrency(&on, &taskLimit, &reqLimit, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = s.SetTunnelConcurrency(&prevOn, &prevTask, &prevReq, &prevAny)
		s.tunnels = newTunnelBudget()
	})
	s.tunnels = newTunnelBudget()
}
