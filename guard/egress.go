package guard

// Sensitive-egress guard: fingerprints of platform secrets (LLM API keys, JWT
// signing key, PG password, web-search keys, java-chains credentials) are kept
// only as SHA-256 digests. Before a tool call runs, its outbound surface is
// scanned; a hit blocks the call so an agent cannot exfiltrate platform
// credentials (e.g. to a honeypot). Plaintext is never stored and never logged.
//
// A Rabin-Karp rolling hash pre-filters windows (O(text) per secret length);
// only hash-equal candidates get a constant-time SHA-256 comparison, so a
// normal KB-sized command costs microseconds. The scan is bounded by the
// caller's surface selection and input cap.

import (
	"crypto/sha256"
	"crypto/subtle"
	"sync"
)

// egressMinSecretLen is the shortest secret that may be registered. Shorter
// strings (weak passwords) occur too often in ordinary commands and would
// produce constant false positives.
const egressMinSecretLen = 8

const egressHashBase uint64 = 0x100000001b3

type egressFingerprint struct {
	kind   string
	sum    [sha256.Size]byte
	roll   uint64
	length int
}

// EgressGuard is a process-wide set of secret fingerprints. Every task guard
// and chat guard references the same instance; refreshing a profile replaces
// its kind and takes effect for all of them immediately.
type EgressGuard struct {
	mu    sync.RWMutex
	fps   []egressFingerprint
	byLen map[int][]int // secret length → indices into fps
	pow   map[int]uint64
}

func NewEgressGuard() *EgressGuard {
	return &EgressGuard{byLen: map[int][]int{}, pow: map[int]uint64{}}
}

// AddFingerprint registers one secret. Empty or too-short values are ignored;
// re-registering the same (kind, secret) is a no-op.
func (e *EgressGuard) AddFingerprint(kind, secret string) {
	if len(secret) < egressMinSecretLen {
		return
	}
	sum := sha256.Sum256([]byte(secret))
	roll := windowHash(secret)
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, fp := range e.fps {
		if fp.kind == kind && fp.length == len(secret) && fp.sum == sum {
			return
		}
	}
	e.fps = append(e.fps, egressFingerprint{kind: kind, sum: sum, roll: roll, length: len(secret)})
	e.byLen[len(secret)] = append(e.byLen[len(secret)], len(e.fps)-1)
	e.pow[len(secret)] = basePow(len(secret) - 1)
}

// RemoveKind drops every fingerprint of one kind (used when a secret source is
// replaced wholesale, e.g. the LLM profile list).
func (e *EgressGuard) RemoveKind(kind string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	kept := e.fps[:0]
	for _, fp := range e.fps {
		if fp.kind != kind {
			kept = append(kept, fp)
		}
	}
	e.fps = kept
	e.byLen = map[int][]int{}
	for i, fp := range e.fps {
		e.byLen[fp.length] = append(e.byLen[fp.length], i)
	}
}

// Check scans text for any registered secret and returns its kind (never the
// secret itself).
func (e *EgressGuard) Check(text string) (kind string, hit bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.fps) == 0 || len(text) < egressMinSecretLen {
		return "", false
	}
	for length, idxs := range e.byLen {
		if length > len(text) {
			continue
		}
		h := windowHash(text[:length])
		pow := e.pow[length]
		for i := 0; ; i++ {
			for _, idx := range idxs {
				fp := &e.fps[idx]
				if h != fp.roll {
					continue
				}
				sum := sha256.Sum256([]byte(text[i : i+length]))
				if subtle.ConstantTimeCompare(sum[:], fp.sum[:]) == 1 {
					return fp.kind, true
				}
			}
			if i+length >= len(text) {
				break
			}
			h = (h-uint64(text[i])*pow)*egressHashBase + uint64(text[i+length])
		}
	}
	return "", false
}

func windowHash(s string) uint64 {
	var h uint64
	for i := 0; i < len(s); i++ {
		h = h*egressHashBase + uint64(s[i])
	}
	return h
}

func basePow(n int) uint64 {
	h := uint64(1)
	for i := 0; i < n; i++ {
		h *= egressHashBase
	}
	return h
}
