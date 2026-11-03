package db

import (
	"strings"
	"testing"
)

func TestEnsurePlatformJWTKey(t *testing.T) {
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

	if _, found, err := d.PlatformJWTKey(); err != nil || found {
		t.Fatalf("fresh database should hold no key: found=%v err=%v", found, err)
	}

	first := strings.Repeat("a", 32)
	got, err := d.EnsurePlatformJWTKey(first)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if got != first {
		t.Fatalf("stored key = %q, want %q", got, first)
	}

	// The point of the constraint-decides shape: a second instance that minted
	// its own key adopts the one already in the database instead of bricking the
	// shells sealed with the first.
	second, err := d.EnsurePlatformJWTKey(strings.Repeat("b", 32))
	if err != nil {
		t.Fatalf("ensure under conflict: %v", err)
	}
	if second != first {
		t.Fatalf("existing key must survive, got %q", second)
	}
	if stored, found, err := d.PlatformJWTKey(); err != nil || !found || stored != first {
		t.Fatalf("read back = %q found=%v err=%v", stored, found, err)
	}

	// A leak guard, not a style check: the signing root must never end up in the
	// settings table, which is read by name across the app and echoed to the UI.
	var mirrored int
	if err := d.QueryRow(`SELECT count(*) FROM settings WHERE value = $1`, first).Scan(&mirrored); err != nil {
		t.Fatalf("count mirrored settings: %v", err)
	}
	if mirrored != 0 {
		t.Fatalf("signing key also present in %d settings rows", mirrored)
	}

	if _, err := d.EnsurePlatformJWTKey("short"); err == nil {
		t.Fatal("a key shorter than 32 bytes must be refused")
	}
}
