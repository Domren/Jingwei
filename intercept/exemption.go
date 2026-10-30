package intercept

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// ExemptionStore holds time-limited approval exemptions. 一键放行：操作员在审批
// 一个工具调用时，可以选择「放行 2/4/8 小时」——同类调用在此期间自动通过，不再
// 逐条弹窗。deny 永远不豁免。
type ExemptionStore struct {
	mu    sync.Mutex
	items map[string]Exemption
}

// Exemption is one time-limited auto-approve rule.
type Exemption struct {
	Tool      string    `json:"tool"`
	Pattern   string    `json:"pattern"` // fingerprint of the input pattern
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
}

// NewExemptionStore creates an empty store.
func NewExemptionStore() *ExemptionStore {
	return &ExemptionStore{items: map[string]Exemption{}}
}

// fingerprint derives a stable key from tool name + input pattern. The pattern
// is normalized (digits replaced) so "curl http://a/1" and "curl http://a/2"
// share the same exemption.
func fingerprint(tool, input string) string {
	h := sha256.Sum256([]byte(tool + "\x00" + normalizePattern(input)))
	return hex.EncodeToString(h[:16])
}

// normalizePattern replaces digits and UUIDs with placeholders so similar
// commands share one exemption.
func normalizePattern(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	out := make([]byte, 0, len(s))
	inDigit := false
	for _, b := range []byte(s) {
		if b >= '0' && b <= '9' {
			if !inDigit {
				out = append(out, 'N')
				inDigit = true
			}
			continue
		}
		inDigit = false
		out = append(out, b)
	}
	return string(out)
}

// Add creates or extends an exemption.
func (s *ExemptionStore) Add(tool, input string, duration time.Duration, reason string) {
	if duration <= 0 {
		duration = 2 * time.Hour
	}
	key := fingerprint(tool, input)
	s.mu.Lock()
	s.items[key] = Exemption{
		Tool:      tool,
		Pattern:   normalizePattern(input),
		ExpiresAt: time.Now().Add(duration),
		Reason:    reason,
	}
	s.mu.Unlock()
}

// Check returns true if a non-expired exemption covers this tool+input.
func (s *ExemptionStore) Check(tool, input string) (Exemption, bool) {
	key := fingerprint(tool, input)
	s.mu.Lock()
	defer s.mu.Unlock()
	ex, ok := s.items[key]
	if !ok {
		return Exemption{}, false
	}
	if time.Now().After(ex.ExpiresAt) {
		delete(s.items, key)
		return Exemption{}, false
	}
	return ex, true
}

// Clean removes expired exemptions (call periodically).
func (s *ExemptionStore) Clean() {
	now := time.Now()
	s.mu.Lock()
	for k, ex := range s.items {
		if now.After(ex.ExpiresAt) {
			delete(s.items, k)
		}
	}
	s.mu.Unlock()
}
