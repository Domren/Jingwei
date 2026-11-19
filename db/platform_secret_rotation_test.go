package db

import (
	"strings"
	"testing"
	"time"
)

// TestPlatformJWTKeyRotation 验证 P16 的库层不变量：
//   - 轮换把旧根搬到 jwt_key_prev 并盖上 rotated_at；
//   - EnsurePlatformJWTKey 在既有行上走 ON CONFLICT DO NOTHING，不擦掉过渡窗口；
//   - 重复轮换到同一密钥是空操作，不会抹掉仍在生效的旧根。
func TestPlatformJWTKeyRotation(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM platform_secret WHERE id = $1`, platformSecretID)
		d.Close()
	})
	if _, err := d.Exec(`DELETE FROM platform_secret WHERE id = $1`, platformSecretID); err != nil {
		t.Fatalf("clear row: %v", err)
	}

	first := strings.Repeat("a", 32)
	if _, err := d.EnsurePlatformJWTKey(first); err != nil {
		t.Fatalf("ensure first: %v", err)
	}

	second := strings.Repeat("b", 32)
	prev, err := d.RotatePlatformJWTKey(second)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if prev != first {
		t.Fatalf("rotate should return old key %q, got %q", first, prev)
	}

	cur, gotPrev, rotatedAt, found, err := d.PlatformJWTKeys()
	if err != nil || !found {
		t.Fatalf("read keys: found=%v err=%v", found, err)
	}
	if cur != second || gotPrev != first {
		t.Fatalf("keys after rotate: cur=%q prev=%q, want %q/%q", cur, gotPrev, second, first)
	}
	if rotatedAt.IsZero() || time.Since(rotatedAt) > time.Minute {
		t.Fatalf("rotated_at should be ~now, got %v", rotatedAt)
	}
	if !SealTransitionActive(rotatedAt, time.Now()) {
		t.Fatal("freshly rotated key must be inside the transition window")
	}

	// 另一个实例用第三把密钥做首次启动 Ensure：冲突分支必须保留 prev/rotated_at。
	third := strings.Repeat("c", 32)
	if got, err := d.EnsurePlatformJWTKey(third); err != nil || got != second {
		t.Fatalf("ensure under conflict: got=%q err=%v", got, err)
	}
	cur, gotPrev, rotatedAt2, found, err := d.PlatformJWTKeys()
	if err != nil || !found || cur != second || gotPrev != first || !rotatedAt2.Equal(rotatedAt) {
		t.Fatalf("Ensure wiped the window: cur=%q prev=%q at=%v/%v found=%v err=%v",
			cur, gotPrev, rotatedAt, rotatedAt2, found, err)
	}

	// 重复轮换到同一密钥是空操作，prev 不能被清空。
	prev2, err := d.RotatePlatformJWTKey(second)
	if err != nil {
		t.Fatalf("no-op rotate: %v", err)
	}
	if prev2 != "" {
		t.Fatalf("no-op rotate should report no replaced key, got %q", prev2)
	}
	_, gotPrev, _, found, err = d.PlatformJWTKeys()
	if err != nil || !found || gotPrev != first {
		t.Fatalf("no-op rotate wiped prev: prev=%q found=%v err=%v", gotPrev, found, err)
	}

	if _, err := d.RotatePlatformJWTKey("short"); err == nil {
		t.Fatal("a key shorter than 32 bytes must be refused on rotation")
	}
}
