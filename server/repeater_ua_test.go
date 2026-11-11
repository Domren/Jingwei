package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 欠账 R20 第③条的回归夹具：请求重发不得替原始报文编造头。
//
// 原来的行为：报文里没有 UA 时 net/http 会补一个 "Go-http-client/1.1"，且默认加
// "Accept-Encoding: gzip"。这两件事都让「输出字节」与「输入字节」不一致，
// 等于把「这是我们构造的」签在头上。
//
// 不改变已给定头部的行为：用户给了 UA / Accept-Encoding 就按它发。

func repeaterEchoServer(t *testing.T, got *map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu := map[string]string{}
		for _, k := range []string{"User-Agent", "Accept-Encoding", "X-Test"} {
			if vs, ok := r.Header[k]; ok {
				mu[k] = strings.Join(vs, ",")
			}
		}
		*got = mu
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
}

func sendRepeaterRequest(t *testing.T, s *Server, headers map[string]string) map[string]string {
	t.Helper()
	// httptest 服务器跑在 127.0.0.1，而重发默认拒绝本机/链路本地地址（防 SSRF）。
	// 这个开关本来就是给"确实要打本机服务"的场景用的，夹具正属于此列。
	t.Setenv(repeaterAllowLocalEnv, "1")
	got := map[string]string{}
	srv := repeaterEchoServer(t, &got)
	defer srv.Close()

	body := map[string]any{
		"method":  "GET",
		"url":     srv.URL,
		"headers": headers,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/repeater/send", mustJSONReader(t, body))
	rec := httptest.NewRecorder()
	s.sendRepeater(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	return got
}

// mustJSONReader 把一个值打成 JSON body；失败直接终止当前用例。
func mustJSONReader(t *testing.T, v any) *strings.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	return strings.NewReader(string(b))
}

func TestRepeaterDoesNotInventUserAgent(t *testing.T) {
	s := &Server{}

	// 原始报文没带 UA：出站绝不能出现一个客户端编出来的 UA。
	got := sendRepeaterRequest(t, s, map[string]string{"X-Test": "1"})
	if ua, ok := got["User-Agent"]; ok {
		if ua != "" && strings.Contains(ua, "Go-http-client") {
			t.Fatalf("重发不得补 Go 默认 UA，实际：%q", ua)
		}
	}
	// 原始报文没带 Accept-Encoding：也不能补 'gzip'。
	if ae, ok := got["Accept-Encoding"]; ok {
		if strings.Contains(ae, "gzip") {
			t.Fatalf("重发不得补 Accept-Encoding: gzip，实际：%q", ae)
		}
	}
	// 用户给的头照常发出。
	if got["X-Test"] != "1" {
		t.Fatalf("自定义头应原样发送，实际：%v", got)
	}
}

func TestRepeaterRespectsUserSuppliedUA(t *testing.T) {
	s := &Server{}

	const ua = "TestUA/1.0 (from raw request)"
	got := sendRepeaterRequest(t, s, map[string]string{
		"User-Agent":      ua,
		"Accept-Encoding": "identity",
	})
	if got["User-Agent"] != ua {
		t.Fatalf("人工 UA 应原样使用，实际：%q", got["User-Agent"])
	}
	if got["Accept-Encoding"] != "identity" {
		t.Fatalf("人工 Accept-Encoding 应原样使用，实际：%q", got["Accept-Encoding"])
	}
}
