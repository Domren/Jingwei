package traffic

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestProxyRecordsPlainHTTP covers the end-to-end recording path: a request
// through the running proxy must land in the index. It exists because the proxy
// can happily forward traffic while the sink never fires — a failure mode that
// looks like "抓包偶尔没东西" instead of an error.
func TestProxyRecordsPlainHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>pikachu</body></html>"))
	}))
	defer target.Close()

	dir := t.TempDir()
	// 端口要给具体的：ProxyAddr() 返回的是配置值，传 0 就成了"127.0.0.1:0"，
	// 连接方拿不到真实端口。
	addr := freeAddr(t)
	tr, err := Open(dir, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	// Start() 在监听循环里阻塞（和主程序一样在 goroutine 里跑）。
	go func() { _ = tr.Start() }()
	// 等端口真的可连，避免把"还没起来"当成"没记录"。
	proxyURL, err := url.Parse(tr.ProxyAddr())
	if err != nil {
		t.Fatal(err)
	}
	waitListening(t, proxyURL.Host)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get(target.URL + "/vul/sqli/sqli_str.php?name=1")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	resp.Body.Close()

	// The sink runs on the response addon; give it a moment to commit.
	deadline := time.Now().Add(3 * time.Second)
	for {
		var n int
		if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE url LIKE '%sqli_str.php%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("代理没有把这次请求记录进索引（sink 未触发或写库失败）")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// freeAddr picks a currently-free loopback port.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// waitListening blocks until the proxy port accepts a TCP connection.
func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("代理端口 %s 一直没起来: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
