package server

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	// Login/init/change-password bodies contain only a handful of short JSON
	// fields. 16 KiB leaves room for a long passphrase without letting an
	// unauthenticated caller make the server buffer a megabyte per attempt.
	authMaxBodyBytes  = 16 << 10
	authReadTimeout   = 10 * time.Second
	authMaxFailures   = 5
	authFailureWindow = 15 * time.Minute
	authLockDuration  = 15 * time.Minute
)

// clientIP deliberately relies on RemoteAddr instead of X-Forwarded-For. The
// header is attacker-controlled unless a trusted reverse proxy overwrites it,
// and honoring it here would let anyone reset their own login lockout by
// rotating a spoofed address between attempts.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

// prepareAuthRequest bounds how long the server will wait for the request body
// and how much of it it will accept. SetReadDeadline is unsupported by
// httptest.ResponseRecorder, which is fine for handler tests.
func prepareAuthRequest(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(authReadTimeout))
	r.Body = http.MaxBytesReader(w, r.Body, authMaxBodyBytes)
}

func writeAuthDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, "请求体过大")
		return
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		writeErr(w, http.StatusRequestTimeout, "读取请求超时")
		return
	}
	writeErr(w, http.StatusBadRequest, "请求格式错误")
}

type authFailureState struct {
	failures    []time.Time
	lockedUntil time.Time
	last        time.Time
}

// authLoginLimiter is an in-memory per-client failure counter. Restarting the
// process clears it; that is acceptable because the database password remains
// and every attempt still requires a fresh captcha.
type authLoginLimiter struct {
	mu   sync.Mutex
	byIP map[string]*authFailureState
	now  func() time.Time
}

func (l *authLoginLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *authLoginLimiter) pruneLocked(st *authFailureState, now time.Time) {
	cutoff := now.Add(-authFailureWindow)
	kept := st.failures[:0]
	for _, t := range st.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.failures = kept
}

// lockedFor reports the remaining lockout for ip, starting one when the recent
// failure window has already reached the threshold.
func (l *authLoginLimiter) lockedFor(ip string) time.Duration {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byIP == nil {
		l.byIP = map[string]*authFailureState{}
	}
	st := l.byIP[ip]
	if st == nil {
		return 0
	}
	if !st.lockedUntil.IsZero() {
		if now.Before(st.lockedUntil) {
			return st.lockedUntil.Sub(now)
		}
		delete(l.byIP, ip)
		return 0
	}
	l.pruneLocked(st, now)
	if len(st.failures) >= authMaxFailures {
		st.lockedUntil = now.Add(authLockDuration)
		st.failures = nil
		return authLockDuration
	}
	if len(st.failures) == 0 {
		delete(l.byIP, ip)
	}
	return 0
}

// fail records one rejected credential attempt and returns a non-zero lockout
// when this attempt reaches the threshold.
func (l *authLoginLimiter) fail(ip string) time.Duration {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byIP == nil {
		l.byIP = map[string]*authFailureState{}
	}
	st := l.byIP[ip]
	if st == nil {
		st = &authFailureState{}
		l.byIP[ip] = st
	}
	if !st.lockedUntil.IsZero() && now.Before(st.lockedUntil) {
		return st.lockedUntil.Sub(now)
	}
	st.lockedUntil = time.Time{}
	l.pruneLocked(st, now)
	st.failures = append(st.failures, now)
	st.last = now
	if len(st.failures) >= authMaxFailures {
		st.failures = nil
		st.lockedUntil = now.Add(authLockDuration)
		return authLockDuration
	}
	return 0
}

func (l *authLoginLimiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.byIP, ip)
}

// authWindowLimiter is a small fixed-window counter used for captcha issuance.
// It is not a security boundary on its own; it only keeps image generation from
// becoming an unauthenticated CPU sink.
type authWindowLimiter struct {
	mu      sync.Mutex
	byKey   map[string][]time.Time
	nextGC  time.Time
	now     func() time.Time
	maxKeys int
}

func (l *authWindowLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *authWindowLimiter) allow(key string, limit int, window time.Duration) (bool, time.Duration) {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byKey == nil {
		l.byKey = map[string][]time.Time{}
	}
	if l.maxKeys == 0 {
		l.maxKeys = 4096
	}
	if len(l.byKey) > l.maxKeys || (!l.nextGC.IsZero() && now.After(l.nextGC)) {
		for k, times := range l.byKey {
			if len(times) == 0 || now.Sub(times[len(times)-1]) >= window {
				delete(l.byKey, k)
			}
		}
		l.nextGC = now.Add(time.Minute)
	}
	hit := l.byKey[key]
	kept := hit[:0]
	for _, t := range hit {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		return false, kept[0].Add(window).Sub(now)
	}
	l.byKey[key] = append(kept, now)
	return true, 0
}

func rateLimitSeconds(d time.Duration) int {
	if d < time.Second {
		return 1
	}
	return int((d + time.Second - 1) / time.Second)
}

func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration, message string) {
	w.Header().Set("Retry-After", strconv.Itoa(rateLimitSeconds(retryAfter)))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error":       message,
		"retry_after": rateLimitSeconds(retryAfter),
	})
}
