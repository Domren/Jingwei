package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestShellNoIdleWireTraffic 验证 P17 的「空闲零心跳」：构造载荷、通过时间、
// 甚至多次读取载荷，都不产生任何发往 shell 的请求。协议里唯一的自发流量来源
// 会是定时 ping，而 v2 实现没有定时器——wire 只在显式命令/存活检查时构造。
func TestShellNoIdleWireTraffic(t *testing.T) {
	payload := buildTestV2Payload(t, "php")
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// 空闲观察窗口：没有任何显式操作时，一个包都不该到目标。
	time.Sleep(80 * time.Millisecond)
	if n := requests.Load(); n != 0 {
		t.Fatalf("空闲期间不应有自发 wire 流量，got %d requests", n)
	}
	// 多次读取载荷本身也不发请求。
	_ = payload.Content
	_ = payload.SHA256
	_ = payload.v2Request
	if n := requests.Load(); n != 0 {
		t.Fatalf("读取/构造载荷不应发请求，got %d", n)
	}

	// 一次真实操作：恰好一条请求，走的是 E（exec）wire，不是 P（ping）。
	mode := ShellCryptoModeForType(payload.Type)
	req, err := payload.v2Request(srv.URL, shellWireExec("id"))
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	client := NewDeepClient(5 * time.Second)
	resp := client.Do(context.Background(), req)
	if resp.Error != "" {
		t.Fatalf("发包: %v", resp.Error)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("一次操作应恰好一条请求，got %d", n)
	}
	token := ""
	if strings.HasPrefix(payload.Carrier, "X-") {
		token = req.Headers[payload.Carrier]
	} else {
		token = strings.TrimPrefix(req.Body, payload.Carrier+"=")
	}
	pt, err := openShellToken(payload.Key, mode, token, time.Now())
	if err != nil || len(pt) < 2 || pt[0] != 'E' {
		t.Fatalf("wire 应为 E 操作而非自发 ping，pt=%q err=%v", pt, err)
	}
}

// TestShellReplayAndTimestampStillEnforced 钉住 P17 的另一半：改成 piggyback/
// 按需唤醒之后，有操作时时间戳 + nonce 防重放必须仍然成立。
func TestShellReplayAndTimestampStillEnforced(t *testing.T) {
	key := testShellKey(t)
	mode := ShellCryptoGCM
	now := time.Now()

	// 时间戳越界：即便密钥正确也拒绝。
	stale, err := sealShellToken(key, mode, shellWirePing(), now.Add(-10*time.Minute))
	if err != nil {
		t.Fatalf("封过期 token: %v", err)
	}
	if _, err := openShellToken(key, mode, stale, now); err == nil {
		t.Fatal("过期时间戳必须被拒绝")
	}
	if err := checkShellTimestamp(make([]byte, 8), now); err == nil {
		t.Fatal("非法长度时间戳必须被拒绝")
	}

	// nonce 防重放：桩壳拒绝第二次出现的同一 token。
	payload := buildTestV2Payload(t, "php")
	seen := map[string]bool{}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		token := r.PostFormValue(payload.Carrier)
		if token == "" {
			token = r.Header.Get(payload.Carrier)
		}
		mu.Lock()
		replayed := seen[token]
		seen[token] = true
		mu.Unlock()
		if replayed {
			w.WriteHeader(404)
			return
		}
		pt, oerr := openShellToken(payload.Key, mode, token, time.Now())
		if oerr != nil || len(pt) == 0 || pt[0] != 'E' {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(token)) // 占位；这里只验请求侧重放
	}))
	defer srv.Close()

	client := NewDeepClient(5 * time.Second)
	req, err := payload.v2Request(srv.URL, shellWireExec("whoami"))
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	first := client.Do(context.Background(), req)
	if first.StatusCode != 200 {
		t.Fatalf("首次请求应 200，got %d", first.StatusCode)
	}
	second := client.Do(context.Background(), req)
	if second.StatusCode != 404 {
		t.Fatalf("重放同一 token 应 404，got %d", second.StatusCode)
	}

	// wire op 里的随机填充保证同一命令两次构造出不同 token（nonce 层面）。
	ra, _ := payload.v2Request(srv.URL, shellWireExec("id"))
	rb, _ := payload.v2Request(srv.URL, shellWireExec("id"))
	tokenOf := func(r *DeepRequest) string {
		if strings.HasPrefix(payload.Carrier, "X-") {
			return r.Headers[payload.Carrier]
		}
		return strings.TrimPrefix(r.Body, payload.Carrier+"=")
	}
	if tokenOf(&ra) == tokenOf(&rb) {
		t.Fatal("同一命令两次构造应得到不同 token（随机 nonce/padding）")
	}
}
