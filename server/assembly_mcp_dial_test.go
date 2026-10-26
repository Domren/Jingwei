package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMCPDialClaimLetsOnlyOneSessionDial(t *testing.T) {
	name := "mcp-claim-test-" + t.Name()
	defer mcpMarkUp(name)

	if !mcpClaimDial(name) {
		t.Fatal("first session must be allowed to dial")
	}
	var allowed int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if mcpClaimDial(name) {
				atomic.AddInt32(&allowed, 1)
			}
		}()
	}
	wg.Wait()
	if allowed != 0 {
		t.Fatalf("concurrent sessions must not dial while one holds the claim, got %d", allowed)
	}

	mcpMarkDown(name)
	if mcpClaimDial(name) {
		t.Fatal("a reported-down server must stay benched for the cooldown")
	}

	mcpDials.Store(name, time.Now().Add(-time.Second))
	if !mcpClaimDial(name) {
		t.Fatal("an expired cooldown must allow a fresh dial")
	}
}
