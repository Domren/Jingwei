package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// E2：目标上那个文件存在、能执行、返回 200，但它不是精卫生成的载荷。
// 这种情况必须说成「这不是协议报文」，而不是「密钥/版本不对」——后者会把操作员
// 支去给一把根本不存在的壳轮换密钥。
func TestCheckShellAliveV2NamesNonPayloadFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 一个普通的 PHP 文件：不管收到什么，都回它自己的输出。
		_, _ = w.Write([]byte("42"))
	}))
	defer srv.Close()

	p := ShellPayload{Protocol: ShellProtocolV2, Key: make([]byte, 32), Carrier: "jwE2Carrier"}
	alive, note := checkShellAliveV2(context.Background(), NewDeepClient(3*time.Second), srv.URL, p)
	if alive {
		t.Fatal("a plain file must never be reported alive")
	}
	for _, want := range []string{"不是加密 v2 协议报文", "webshell_register", "deploy_path"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note must say %q, got: %s", want, note)
		}
	}
	if strings.Contains(note, "密钥") {
		t.Fatalf("note must not blame the key for a file that is not a shell: %s", note)
	}
}

// A real v2 envelope that fails to open (wrong key) is a protocol problem and
// must keep the protocol wording — the two causes cannot share one message.
func TestV2AliveNoteKeepsProtocolWordingForRealEnvelope(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	token, err := sealShellToken(key, ShellCryptoGCM, []byte("pong"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	protoErr := errors.New("令牌认证失败（密钥不匹配）")
	note := v2AliveNote(token, protoErr)
	if strings.Contains(note, "不是加密 v2 协议报文") {
		t.Fatalf("a genuine envelope must not be called a non-payload file: %s", note)
	}
	if note != protoErr.Error() {
		t.Fatalf("note = %q, want the protocol error itself", note)
	}
}

// An HTML error page (soft 404, WAF block page) is also not an envelope, and the
// note must not be fooled by a body that happens to be long.
func TestV2AliveNoteRejectsHtmlBody(t *testing.T) {
	body := "<html><body>" + strings.Repeat("blocked", 20) + "</body></html>"
	note := v2AliveNote(body, errors.New("令牌不是合法的 base64url"))
	if !strings.Contains(note, "不是加密 v2 协议报文") {
		t.Fatalf("an HTML page must be called a non-payload response: %s", note)
	}
}
