package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/captcha"
)

func TestGeneratedSliderPuzzleIsSolvable(t *testing.T) {
	for i := 0; i < 40; i++ {
		puzzle, err := newSliderPuzzle("192.0.2.10")
		if err != nil {
			t.Fatal(err)
		}
		bg, err := captcha.DecodeDataURL(puzzle.background)
		if err != nil {
			t.Fatal(err)
		}
		piece, err := captcha.DecodeDataURL(puzzle.piece)
		if err != nil {
			t.Fatal(err)
		}
		res, err := captcha.SolveSlider(bg, piece, captcha.SolveOptions{})
		if err != nil {
			t.Fatalf("puzzle %d: %v", i, err)
		}
		delta := res.Offset - puzzle.challenge.answerX
		if delta < 0 {
			delta = -delta
		}
		if delta > sliderTolerance {
			t.Fatalf("puzzle %d: solver offset=%d want %d (confidence=%.2f)", i, res.Offset, puzzle.challenge.answerX, res.Confidence)
		}
	}
}

// TestRawSliderRenderAmbiguityRate measures how often a single drawing pass is
// ambiguous before newSliderPuzzle redraws it. The retry loop is what keeps
// TestGeneratedSliderPuzzleIsSolvable deterministic, so the raw rate is tracked
// here instead: if drawing ever degrades toward mostly-unreadable, issuance
// would burn all four solver runs per captcha and this test says so.
func TestRawSliderRenderAmbiguityRate(t *testing.T) {
	const rounds = 200
	var missed int
	for i := 0; i < rounds; i++ {
		render, err := renderSliderPuzzle()
		if err != nil {
			t.Fatal(err)
		}
		if !sliderPuzzleSolvable(render) {
			missed++
		}
	}
	t.Logf("单次绘制歧义率 %d/%d", missed, rounds)
	if float64(missed) > float64(rounds)*0.25 {
		t.Fatalf("歧义率过高: %d/%d，签发一次验证码要重绘满 %d 次", missed, rounds, sliderPuzzleAttempts)
	}
}

func TestSliderChallengeIsSingleUseAndIPBound(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := &sliderChallengeStore{now: func() time.Time { return now }}
	base := &sliderChallenge{id: "a", answerX: 100, expires: now.Add(time.Minute), clientIP: "10.0.0.1"}
	if !store.put(base) {
		t.Fatal("challenge was not stored")
	}
	if store.consume("a", "10.0.0.1", 90) {
		t.Fatal("outside tolerance accepted")
	}
	// The failed attempt consumed the challenge.
	if store.consume("a", "10.0.0.1", 100) {
		t.Fatal("challenge replay accepted")
	}

	other := &sliderChallenge{id: "b", answerX: 120, expires: now.Add(time.Minute), clientIP: "10.0.0.1"}
	store.put(other)
	if store.consume("b", "10.0.0.2", 120) {
		t.Fatal("challenge accepted from a different client IP")
	}

	expired := &sliderChallenge{id: "c", answerX: 80, expires: now.Add(-time.Second), clientIP: "10.0.0.1"}
	store.put(expired)
	if store.consume("c", "10.0.0.1", 80) {
		t.Fatal("expired challenge accepted")
	}

	ok := &sliderChallenge{id: "d", answerX: 80, expires: now.Add(time.Minute), clientIP: "10.0.0.1"}
	store.put(ok)
	if !store.consume("d", "10.0.0.1", 80+sliderTolerance) {
		t.Fatal("edge of tolerance rejected")
	}
}

func TestExtractTokenNeverReadsQueryString(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/logs/stream?token=leaked-in-url", nil)
	if got := extractToken(r); got != "" {
		t.Fatalf("query token accepted: %q", got)
	}
	r.AddCookie(&http.Cookie{Name: authCookieName, Value: "cookie-token"})
	if got := extractToken(r); got != "cookie-token" {
		t.Fatalf("cookie token not used: %q", got)
	}
	r.Header.Set("Authorization", "Bearer bearer-token")
	if got := extractToken(r); got != "bearer-token" {
		t.Fatalf("bearer token not preferred: %q", got)
	}
}

func TestSessionTokenIsBoundToVersion(t *testing.T) {
	key := []byte("unit-test-signing-key-32-characters")
	tok, err := signJWT(key, "version-one")
	if err != nil {
		t.Fatal(err)
	}
	if !verifySessionJWT(tok, key, "version-one") {
		t.Fatal("valid token rejected")
	}
	if verifySessionJWT(tok, key, "version-two") {
		t.Fatal("token accepted after version rotation")
	}
	if verifySessionJWT(tok, key, "") {
		t.Fatal("token accepted without a server version")
	}
	legacy, err := signJWT(key, "")
	if err != nil {
		t.Fatal(err)
	}
	if verifySessionJWT(legacy, key, "version-one") {
		t.Fatal("legacy token without version accepted")
	}
}

func TestAuthLoginLimiterLocksAndResets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := &authLoginLimiter{now: func() time.Time { return now }}
	for i := 0; i < authMaxFailures-1; i++ {
		if wait := l.fail("10.0.0.1"); wait != 0 {
			t.Fatalf("locked too early at attempt %d", i+1)
		}
	}
	if wait := l.fail("10.0.0.1"); wait != authLockDuration {
		t.Fatalf("fifth failure did not lock: %v", wait)
	}
	if wait := l.lockedFor("10.0.0.1"); wait <= 0 {
		t.Fatal("lockedFor did not report the lock")
	}
	now = now.Add(authLockDuration + time.Second)
	if wait := l.lockedFor("10.0.0.1"); wait != 0 {
		t.Fatalf("lock did not expire: %v", wait)
	}
	if wait := l.fail("10.0.0.1"); wait != 0 {
		t.Fatal("expired lock still counted old failures")
	}
	l.success("10.0.0.1")
	if wait := l.lockedFor("10.0.0.1"); wait != 0 {
		t.Fatal("success did not clear failures")
	}
}

func TestAuthWindowLimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := &authWindowLimiter{now: func() time.Time { return now }}
	for i := 0; i < 2; i++ {
		if ok, _ := l.allow("k", 2, time.Minute); !ok {
			t.Fatalf("request %d rejected too early", i+1)
		}
	}
	if ok, retry := l.allow("k", 2, time.Minute); ok || retry <= 0 {
		t.Fatalf("limit not enforced: ok=%v retry=%v", ok, retry)
	}
	now = now.Add(time.Minute)
	if ok, _ := l.allow("k", 2, time.Minute); !ok {
		t.Fatal("window did not slide")
	}
}

func TestAuthCookieFlags(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "https://jingwei.example/", nil)
	w := httptest.NewRecorder()
	s.setAuthCookie(w, r, "token")
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%d", len(cookies))
	}
	c := cookies[0]
	if c.Name != authCookieName || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode ||
		c.Path != "/" || c.MaxAge != int(jwtTTL.Seconds()) {
		t.Fatalf("insecure cookie: %+v", c)
	}

	plain := httptest.NewRequest("GET", "http://jingwei.local/", nil)
	w = httptest.NewRecorder()
	s.setAuthCookie(w, plain, "token")
	if c := w.Result().Cookies()[0]; c.Secure {
		t.Fatal("Secure set on plain HTTP (cookie would never be stored)")
	}
	plain.Header.Set("X-Forwarded-Proto", "https")
	w = httptest.NewRecorder()
	s.setAuthCookie(w, plain, "token")
	if c := w.Result().Cookies()[0]; !c.Secure {
		t.Fatal("Secure missing behind an HTTPS reverse proxy")
	}
}

func TestPrepareAuthRequestBodyLimit(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(strings.Repeat("a", authMaxBodyBytes+1)))
	w := httptest.NewRecorder()
	prepareAuthRequest(w, r)
	_, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("oversized body not capped: %v", err)
	}
}
