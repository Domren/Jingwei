package llmpool

import (
	"testing"
	"time"
)

func TestProviderRetryWindowParsesProviderShapes(t *testing.T) {
	cases := []struct {
		err  string
		want time.Duration
	}{
		{`openai: status 429: {"code":"RATE_LIMITED","message":"请求过于频繁","data":{"limit":30,"retryAfterSeconds":28},"traceId":"t1"}`, 28 * time.Second},
		{`HTTP/1.1 429 Too Many Requests\nRetry-After: 45\n\n`, 45 * time.Second},
		{`{"error":{"retry_after":7}}`, 7 * time.Second},
		{`Retry-After: Wed, 21 Oct 2026 07:28:00 GMT`, 0},
		{`openai: status 500: internal error`, 0},
		{`{"retryAfterSeconds":0}`, 0},
		{`retryAfterSeconds=99999`, maxRetryWindow},
	}
	for _, c := range cases {
		if got := providerRetryWindow(c.err); got != c.want {
			t.Errorf("providerRetryWindow(%q)=%v want %v", c.err, got, c.want)
		}
	}
}

// A 5s ladder inside a 28s limiter window re-probes straight into the same 429,
// which is how one rate-limited profile used to burn the whole failover chain.
func TestTripHonoursRetryWindowBelowTripThreshold(t *testing.T) {
	r := NewRegistry(nil, nil)
	r.SetPolicy(3, 5*time.Second)
	if r.Trip(1, `{"retryAfterSeconds":28}`, false) {
		t.Fatal("a single transient failure must not trip at softTrip=3")
	}
	st := r.Get(1)
	if !st.Open() {
		t.Fatal("the declared retry window must still bench the profile")
	}
	if left := time.Until(st.OpenUntil); left < 20*time.Second || left > 28*time.Second {
		t.Fatalf("cooling-off should track the provider window, got %.1fs", left.Seconds())
	}
	if st.Fails != 1 || st.Trips != 0 {
		t.Fatalf("retry window must not consume trip counters: fails=%d trips=%d", st.Fails, st.Trips)
	}
}

func TestTripKeepsLongerLadder(t *testing.T) {
	r := NewRegistry(nil, nil)
	if r.Trip(2, `{"retryAfterSeconds":5}`, true) != true {
		t.Fatal("hard failure must trip")
	}
	if left := time.Until(r.Get(2).OpenUntil); left < 50*time.Second {
		t.Fatalf("the 1-minute ladder rung must win over a 5s hint, got %.1fs", left.Seconds())
	}
}
