package guard

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

// uaPool assigns a stable User-Agent per task. 为什么要按任务固定：同一个任务
// 的所有请求用同一个 UA，看起来像一个人在操作；每个任务用不同 UA，避免跨任务
// 被关联。蜜罐/反爬系统会统计 UA 频率，固定 UA 反而更自然。
type uaPool struct {
	mu     sync.Mutex
	pool   []string
	byTask map[int64]string
}

// commonUAs is a curated list of realistic browser User-Agents.
var commonUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7.2; rv:134.0) Gecko/20100101 Firefox/134.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
}

// NewUAPool creates a pool with the given UA list (or the built-in list if empty).
func NewUAPool(agents []string) *uaPool {
	if len(agents) == 0 {
		agents = commonUAs
	}
	return &uaPool{pool: agents, byTask: map[int64]string{}}
}

// ForTask returns a stable UA for the given task. The assignment is deterministic
// (derived from task ID hash) so restarts produce the same mapping.
func (p *uaPool) ForTask(taskID int64) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ua, ok := p.byTask[taskID]; ok {
		return ua
	}
	// Deterministic: hash task ID → index into pool.
	h := sha256.New()
	h.Write([]byte{byte(taskID >> 56), byte(taskID >> 48), byte(taskID >> 40), byte(taskID >> 32),
		byte(taskID >> 24), byte(taskID >> 16), byte(taskID >> 8), byte(taskID)})
	idx := binary.BigEndian.Uint32(h.Sum(nil)[:4]) % uint32(len(p.pool))
	ua := p.pool[idx]
	p.byTask[taskID] = ua
	return ua
}
