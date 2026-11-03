package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
	actool "github.com/Autumn-27/norma/tool"
)

// ---------------------------------------------------------------------------
// 凭据台账的明文只属于 agent。REST 响应必须只带 has_password：口令一旦跟着列表
// 下发，就会留在浏览器状态、前端缓存与反向代理日志里，而内网账号恰恰是最不该
// 外泄的东西。反过来，agent 要用它拼原始报文（Basic 头、POST 体、SSH 交互），
// 这些请求没有 credential_id 可携带，所以工具结果里口令必须在。
// ---------------------------------------------------------------------------

const (
	credMaskHost = "10.253.77.99"
	credMaskPass = "Lab-P@ss-77"
)

func credMaskFixture(t *testing.T) *Server {
	t.Helper()
	pg := prescanTestDB(t)
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM intranet_credentials WHERE host=$1`, credMaskHost) })
	if _, err := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
		Host: credMaskHost, Port: 22, Protocol: "ssh", Username: "labuser", Password: credMaskPass,
		Source: "manual", Evidence: "凭据掩罩测试",
	}); err != nil {
		t.Fatal(err)
	}
	return &Server{m: &Manager{pg: pg}}
}

func TestIntranetCredentialAPINeverReturnsPlaintext(t *testing.T) {
	s := credMaskFixture(t)

	rec := httptest.NewRecorder()
	s.listIntranetCredentials(rec, httptest.NewRequest("GET", "/api/intranet/credentials?host="+credMaskHost, nil))
	if rec.Code != 200 {
		t.Fatalf("list code = %d: %s", rec.Code, rec.Body.String())
	}
	listened := rec.Body.String()
	if strings.Contains(listened, credMaskPass) {
		t.Fatalf("the ledger list leaked the password: %s", listened)
	}
	var list struct {
		Credentials []map[string]any `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(listened), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Credentials) == 0 {
		t.Fatal("the fixture credential is missing from the list")
	}
	for _, c := range list.Credentials {
		if c["has_password"] != true {
			t.Fatalf("has_password must say a secret is stored, got %#v", c)
		}
		if _, ok := c["password"]; ok {
			t.Fatalf("password key must not be serialized at all: %#v", c)
		}
	}

	// 手工登记同样不能把口令回显给调用方——前端表单刚提交，回显只会多留一份副本。
	body := `{"host":"` + credMaskHost + `","port":3306,"protocol":"mysql","username":"root","password":"` +
		credMaskPass + `","source":"manual","evidence":"登记回显测试"}`
	reg := httptest.NewRecorder()
	s.registerIntranetCredential(reg, httptest.NewRequest("POST", "/api/intranet/credentials", strings.NewReader(body)))
	if reg.Code != 200 {
		t.Fatalf("register code = %d: %s", reg.Code, reg.Body.String())
	}
	if strings.Contains(reg.Body.String(), credMaskPass) {
		t.Fatalf("registering echoed the password back: %s", reg.Body.String())
	}
}

func TestIntranetCredentialsToolKeepsPasswordForAgent(t *testing.T) {
	s := credMaskFixture(t)
	var tool actool.CoreTool
	for _, c := range s.intranetTools() {
		if c.Name() == "intranet_credentials" {
			tool = c
		}
	}
	if tool == nil {
		t.Fatal("intranet_credentials is not registered in intranetTools()")
	}
	res, err := tool.Call(context.Background(), json.RawMessage(`{"host":"`+credMaskHost+`"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("querying the ledger failed: %q", res.Content[0].Text)
	}
	var out struct {
		Credentials []struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(res.Content[0].Text), &out); err != nil {
		t.Fatalf("result is not JSON: %q", res.Content[0].Text)
	}
	if len(out.Credentials) == 0 {
		t.Fatal("the fixture credential is missing from the tool result")
	}
	for _, c := range out.Credentials {
		// Equality, not emptiness: sealing happens in the store, so a missing
		// unseal step still yields a non-empty value — the ciphertext. Handing that
		// to a worker is worse than handing it nothing, because the raw request it
		// builds looks plausible and the failure lands on the target as a rejected
		// login.
		if c.Password != credMaskPass {
			t.Fatalf("the agent must be handed the plaintext password to craft raw requests: got %q", c.Password)
		}
	}
}
