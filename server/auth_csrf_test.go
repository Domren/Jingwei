package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The API accepts bearer tokens for automation and an HttpOnly cookie for the
// console. Cookie-authenticated state changes need an explicit same-site gate;
// CORS rules alone do not decide whether the browser sends the cookie.
func TestRequireAuthRejectsCrossSiteCookieMutation(t *testing.T) {
	s := newAuthFlowServer(t, "correct horse battery")
	id, answerX := issueTestCaptcha(t, s)
	login := httptest.NewRecorder()
	s.authLogin(login, authJSONRequest(http.MethodPost, "/api/auth/login", loginPayload("correct horse battery", id, answerX)))
	cookie := findAuthCookie(login.Result().Cookies())
	if cookie == nil {
		t.Fatal("login did not issue a session cookie")
	}

	handler := s.Handler()
	for _, tc := range []struct {
		method    string
		fetchSite string
		origin    string
	}{
		{method: http.MethodPost, fetchSite: "cross-site", origin: "https://evil.example"},
		{method: http.MethodPut, fetchSite: "cross-site", origin: "https://evil.example"},
		{method: http.MethodPatch, fetchSite: "cross-site", origin: "https://evil.example"},
		{method: http.MethodDelete, fetchSite: "cross-site", origin: "https://evil.example"},
		{method: http.MethodPost, origin: "https://evil.example"},
	} {
		req := httptest.NewRequest(tc.method, "http://jingwei.example/api/tasks", nil)
		req.AddCookie(cookie)
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if tc.fetchSite != "" {
			req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s site=%q origin=%q: status=%d, want 403", tc.method, tc.fetchSite, tc.origin, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "http://jingwei.example/api/tasks", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatal("read-only cookie request must not be rejected by the mutation gate")
	}

	req = httptest.NewRequest(http.MethodPost, "http://jingwei.example/api/tasks", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "http://jingwei.example")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatal("same-origin cookie request rejected by the mutation gate")
	}
}

func TestRequireAuthBearerRequestsSkipCookieMutationGate(t *testing.T) {
	s := newAuthFlowServer(t, "correct horse battery")
	id, answerX := issueTestCaptcha(t, s)
	login := httptest.NewRecorder()
	s.authLogin(login, authJSONRequest(http.MethodPost, "/api/auth/login", loginPayload("correct horse battery", id, answerX)))
	cookie := findAuthCookie(login.Result().Cookies())
	if cookie == nil {
		t.Fatal("login did not issue a session cookie")
	}
	handler := s.Handler()
	req := httptest.NewRequest(http.MethodPost, "http://jingwei.example/api/tasks", nil)
	req.Header.Set("Authorization", "Bearer "+cookie.Value)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatal("explicit bearer request rejected by cookie mutation gate")
	}
}
