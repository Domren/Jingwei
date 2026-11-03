package server

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSecretStore stands in for the platform_secret row so the precedence rules
// can be tested without a database. conflictWith models an insert that loses the
// race: the read finds no row, and the database hands back somebody else's key.
type fakeSecretStore struct {
	value        string
	found        bool
	readErr      error
	writeErr     error
	written      []string
	conflictWith string
}

func (f *fakeSecretStore) PlatformJWTKey() (string, bool, error) {
	if f.readErr != nil {
		return "", false, f.readErr
	}
	return f.value, f.found, nil
}

func (f *fakeSecretStore) EnsurePlatformJWTKey(candidate string) (string, error) {
	f.written = append(f.written, candidate)
	if f.writeErr != nil {
		return "", f.writeErr
	}
	if f.conflictWith != "" {
		f.value, f.found = f.conflictWith, true
		return f.conflictWith, nil
	}
	if f.found {
		// The primary key decides: an existing row is not overwritten.
		return f.value, nil
	}
	f.value, f.found = candidate, true
	return candidate, nil
}

func writeLegacyKey(t *testing.T, dir, value string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, jwtKeyFilename), []byte(value), 0o600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}
	return filepath.Join(dir, jwtKeyFilename)
}

const (
	testKeyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testKeyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestJWTKeyDatabaseWinsOverLegacyFile(t *testing.T) {
	keyDir := t.TempDir()
	legacy := writeLegacyKey(t, keyDir, testKeyA)
	store := &fakeSecretStore{value: testKeyB, found: true}

	got, err := loadOrCreateJWTKey(store, keyDir, t.TempDir())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != testKeyB {
		t.Fatalf("stored key must win over the file, got %q", got)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("stale key file left behind — it would look authoritative after a restore")
	}
	if len(store.written) != 0 {
		t.Fatalf("no write expected when a row exists, wrote %q", store.written)
	}
}

func TestJWTKeyMigratesLegacyFileIntoDatabase(t *testing.T) {
	keyDir := t.TempDir()
	legacy := writeLegacyKey(t, keyDir, testKeyA)
	store := &fakeSecretStore{}

	got, err := loadOrCreateJWTKey(store, keyDir, t.TempDir())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != testKeyA {
		t.Fatalf("legacy key must be carried over, got %q", got)
	}
	if len(store.written) != 1 || store.written[0] != testKeyA {
		t.Fatalf("want the file's key persisted once, got %q", store.written)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("migrated key file should be removed, still present")
	}

	// A recreate now reads the same key back out of the database — the bug this
	// change exists to remove was a fresh random key on every boot.
	again, err := loadOrCreateJWTKey(store, keyDir, t.TempDir())
	if err != nil || string(again) != testKeyA {
		t.Fatalf("second boot must reuse the stored key: %q err=%v", again, err)
	}
}

func TestJWTKeyWorkspaceLegacyLocationAlsoMigrates(t *testing.T) {
	// Pre-1.3.1 installs kept the key inside the browsable workspace; it is a
	// legacy source now, and migrating it out must not rotate the key.
	dataDir := t.TempDir()
	legacy := writeLegacyKey(t, dataDir, testKeyA)
	store := &fakeSecretStore{}

	got, err := loadOrCreateJWTKey(store, t.TempDir(), dataDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != testKeyA || store.written[0] != testKeyA {
		t.Fatalf("want %q migrated, got %q / %q", testKeyA, got, store.written)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("workspace key file should be gone")
	}
}

func TestJWTKeyGeneratedAndReusedAcrossRestarts(t *testing.T) {
	store := &fakeSecretStore{}
	keyDir := t.TempDir()

	first, err := loadOrCreateJWTKey(store, keyDir, t.TempDir())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(first) != 32 || strings.ContainsAny(string(first), "\n ") {
		t.Fatalf("generated key looks wrong: %q", first)
	}
	second, err := loadOrCreateJWTKey(store, keyDir, t.TempDir())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(second) != string(first) {
		t.Fatalf("restart rotated the signing key: %q -> %q", first, second)
	}
}

func TestJWTKeyKeepsFileWhenItLosesTheInsertRace(t *testing.T) {
	// Two instances boot at once against an empty table. The loser gets the
	// winner's key back from Ensure and must not delete its own file, which is
	// still the only copy of the key that sealed the existing shells.
	keyDir := t.TempDir()
	legacy := writeLegacyKey(t, keyDir, testKeyA)
	store := &fakeSecretStore{conflictWith: testKeyB}

	got, err := loadOrCreateJWTKey(store, keyDir, t.TempDir())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != testKeyB {
		t.Fatalf("winner's key expected, got %q", got)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("disagreeing legacy file must be kept: %v", err)
	}
}

func TestJWTKeyRefusesToBootOnUnpersistedKey(t *testing.T) {
	store := &fakeSecretStore{writeErr: errors.New("db down")}
	if _, err := loadOrCreateJWTKey(store, t.TempDir(), t.TempDir()); err == nil {
		t.Fatal("an ephemeral signing key must fail startup, not silently work until the next recreate")
	}
}
