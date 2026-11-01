package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// newAuthFlowServer prepares a server backed by the test database. The auth
// settings are restored after the test so handler flows do not leak into other
// tests sharing jingwei_schema_test.
func newAuthFlowServer(t *testing.T, password string) *Server {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	for _, key := range []string{authPassKey, authTokenVer} {
		old, exists, err := m.pg.GetSetting(key)
		if err != nil {
			t.Fatal(err)
		}
		func(key, old string, exists bool) {
			t.Cleanup(func() {
				if exists {
					_ = m.pg.SetSetting(key, old)
				} else {
					_, _ = m.pg.Exec("DELETE FROM settings WHERE key=$1", key)
				}
			})
		}(key, old, exists)
	}
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.pg.SetSetting(authPassKey, string(hash)); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{m: m, jwtKey: []byte("test-only-signing-key-32-characters")}
	if _, err := s.ensureAuthTokenVersion(); err != nil {
		t.Fatal(err)
	}
	return s
}

func authJSONRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func loginPayload(password, captchaID string, captchaX int) string {
	b, _ := json.Marshal(map[string]any{
		"username": authUsername, "password": password,
		"captcha_id": captchaID, "captcha_x": captchaX,
	})
	return string(b)
}

func findAuthCookie(cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if c.Name == authCookieName {
			return c
		}
	}
	return nil
}

func TestAuthLoginRequiresOneShotCaptcha(t *testing.T) {
	s := newAuthFlowServer(t, "correct horse battery")

	// 没有验证码：即使密码正确也不能登录。
	w := httptest.NewRecorder()
	s.authLogin(w, authJSONRequest("POST", "/api/auth/login", loginPayload("correct horse battery", "", 0)))
	if w.Code != 400 || findAuthCookie(w.Result().Cookies()) != nil || strings.Contains(w.Body.String(), "token") {
		t.Fatalf("captcha-less login: status=%d cookie=%v body=%s", w.Code, findAuthCookie(w.Result().Cookies()), w.Body.String())
	}

	// 答错一次会消费掉验证码，重放同一张图必须失败。
	id, answerX := issueTestCaptcha(t, s)
	w = httptest.NewRecorder()
	s.authLogin(w, authJSONRequest("POST", "/api/auth/login", loginPayload("correct horse battery", id, answerX+50)))
	if w.Code != 400 {
		t.Fatalf("wrong captcha: status=%d body=%s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.authLogin(w, authJSONRequest("POST", "/api/auth/login", loginPayload("correct horse battery", id, answerX)))
	if w.Code != 400 || findAuthCookie(w.Result().Cookies()) != nil {
		t.Fatalf("replayed captcha: status=%d body=%s", w.Code, w.Body.String())
	}

	// 正确解答的新验证码可以登录，并签发 HttpOnly 会话 cookie。
	id, answerX = issueTestCaptcha(t, s)
	w = httptest.NewRecorder()
	s.authLogin(w, authJSONRequest("POST", "/api/auth/login", loginPayload("correct horse battery", id, answerX)))
	if w.Code != 200 {
		t.Fatalf("login: status=%d body=%s", w.Code, w.Body.String())
	}
	cookie := findAuthCookie(w.Result().Cookies())
	if cookie == nil || cookie.Value == "" {
		t.Fatal("login did not set a session cookie")
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.MaxAge <= 0 {
		t.Fatalf("unsafe session cookie: %+v", cookie)
	}

	// cookie 本身能通过受保护路由；同样的 token 放进 URL 则不能。
	protected := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest("GET", "/api/tasks", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	protected.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("cookie session rejected: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("GET", "/api/tasks?token="+cookie.Value, nil)
	w = httptest.NewRecorder()
	protected.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("query-string token accepted: %d", w.Code)
	}
}

func TestAuthLoginLocksOutAfterRepeatedFailures(t *testing.T) {
	s := newAuthFlowServer(t, "correct horse battery")

	for i := 1; i <= authMaxFailures; i++ {
		id, answerX := issueTestCaptcha(t, s)
		w := httptest.NewRecorder()
		s.authLogin(w, authJSONRequest("POST", "/api/auth/login", loginPayload("wrong password", id, answerX)))
		if i < authMaxFailures && w.Code != 401 {
			t.Fatalf("failure %d: status=%d body=%s", i, w.Code, w.Body.String())
		}
		if i == authMaxFailures && w.Code != 429 {
			t.Fatalf("failure %d did not lock: status=%d body=%s", i, w.Code, w.Body.String())
		}
		if w.Header().Get("Retry-After") == "" && w.Code == 429 {
			t.Fatal("429 without Retry-After")
		}
	}

	// 锁定期间即使密码和验证码都正确也必须拒绝，且不能下发会话。
	id, answerX := issueTestCaptcha(t, s)
	w := httptest.NewRecorder()
	s.authLogin(w, authJSONRequest("POST", "/api/auth/login", loginPayload("correct horse battery", id, answerX)))
	if w.Code != 429 || findAuthCookie(w.Result().Cookies()) != nil {
		t.Fatalf("locked login accepted: status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("lock response missing Retry-After")
	}
}

func TestAuthChangePasswordRevokesAllSessions(t *testing.T) {
	const oldPassword = "correct horse battery"
	s := newAuthFlowServer(t, oldPassword)

	id, answerX := issueTestCaptcha(t, s)
	w := httptest.NewRecorder()
	s.authLogin(w, authJSONRequest("POST", "/api/auth/login", loginPayload(oldPassword, id, answerX)))
	oldCookie := findAuthCookie(w.Result().Cookies())
	if w.Code != 200 || oldCookie == nil {
		t.Fatalf("login: status=%d body=%s", w.Code, w.Body.String())
	}

	body, _ := json.Marshal(map[string]string{"old_password": oldPassword, "new_password": "new correct horse battery"})
	r := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(string(body)))
	r.AddCookie(oldCookie)
	w = httptest.NewRecorder()
	s.authChangePassword(w, r)
	if w.Code != 200 {
		t.Fatalf("change password: status=%d body=%s", w.Code, w.Body.String())
	}
	newCookie := findAuthCookie(w.Result().Cookies())
	if newCookie == nil || newCookie.Value == oldCookie.Value {
		t.Fatal("change-password did not issue a replacement session")
	}

	check := func(cookie *http.Cookie) int {
		r := httptest.NewRequest("GET", "/api/auth/session", nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		s.authSession(w, r)
		return w.Code
	}
	if code := check(oldCookie); code != 401 {
		t.Fatalf("old session survived password change: %d", code)
	}
	if code := check(newCookie); code != 200 {
		t.Fatalf("replacement session rejected: %d", code)
	}

	// 旧密码不能再登录，新密码可以。
	id, answerX = issueTestCaptcha(t, s)
	w = httptest.NewRecorder()
	s.authLogin(w, authJSONRequest("POST", "/api/auth/login", loginPayload(oldPassword, id, answerX)))
	if w.Code != 401 {
		t.Fatalf("old password still works: status=%d", w.Code)
	}
	s.loginLimiter.success(clientIP(httptest.NewRequest("GET", "/", nil)))
	id, answerX = issueTestCaptcha(t, s)
	w = httptest.NewRecorder()
	s.authLogin(w, authJSONRequest("POST", "/api/auth/login", loginPayload("new correct horse battery", id, answerX)))
	if w.Code != 200 {
		t.Fatalf("new password rejected: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAuthInitRequiresCaptcha(t *testing.T) {
	s := newAuthFlowServer(t, "")

	// 无验证码的初始化请求不能设置密码。
	w := httptest.NewRecorder()
	s.authInit(w, authJSONRequest("POST", "/api/auth/init", `{"password":"initial password"}`))
	if w.Code != 400 {
		t.Fatalf("init without captcha: status=%d body=%s", w.Code, w.Body.String())
	}
	hash, _, err := s.m.pg.GetSetting(authPassKey)
	if err != nil || hash != "" {
		t.Fatalf("password was set without captcha: hash=%q err=%v", hash, err)
	}

	id, answerX := issueTestCaptcha(t, s)
	body, _ := json.Marshal(map[string]any{"password": "initial password", "captcha_id": id, "captcha_x": answerX})
	w = httptest.NewRecorder()
	s.authInit(w, authJSONRequest("POST", "/api/auth/init", string(body)))
	if w.Code != 200 || findAuthCookie(w.Result().Cookies()) == nil {
		t.Fatalf("init with captcha: status=%d cookie=%v body=%s", w.Code, findAuthCookie(w.Result().Cookies()), w.Body.String())
	}
}

func TestAuthLoginRejectsOversizedBody(t *testing.T) {
	s := newAuthFlowServer(t, "correct horse battery")
	oversized := fmt.Sprintf(`{"username":"Jingwei","password":"%s"}`, strings.Repeat("a", authMaxBodyBytes+1))
	w := httptest.NewRecorder()
	s.authLogin(w, authJSONRequest("POST", "/api/auth/login", oversized))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status=%d body=%s", w.Code, w.Body.String())
	}
	if findAuthCookie(w.Result().Cookies()) != nil {
		t.Fatal("oversized request received a session")
	}
}
