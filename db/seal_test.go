package db

import (
	"strings"
	"testing"
)

// The seal tests run against their own schema so the startup pass — which by
// design converts every plaintext row it can see — cannot reach fixtures another
// package is using at the same moment.
const sealTestSchema = "jingwei_seal_test"

var sealTestKey = []byte("0123456789abcdef0123456789abcdef-key-a")

func sealTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := OpenTestSchema(testDSN(t), sealTestSchema)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	// The run-once flag lives in this schema's settings table, so each test starts
	// with the migration eligible.
	if _, err := d.Exec(`DELETE FROM settings WHERE key=$1`, settingSecretSealV1); err != nil {
		t.Fatalf("clear seal flag: %v", err)
	}
	return d
}

func rawCredentialPassword(t *testing.T, d *DB, id int64) string {
	t.Helper()
	var stored string
	if err := d.QueryRow(`SELECT password FROM intranet_credentials WHERE id=$1`, id).Scan(&stored); err != nil {
		t.Fatalf("read raw column: %v", err)
	}
	return stored
}

func TestSealCredentialAtRestKeepsDedupe(t *testing.T) {
	d := sealTestDB(t)
	d.UseSealKey(sealTestKey)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intranet_credentials WHERE host LIKE 'seal-test.%'`)
	})

	const plain = "s3cr3t-p@ss"
	in := IntranetCredentialInput{
		Host: "seal-test.a", Port: 22, Protocol: "ssh",
		Username: "admin", Password: plain, Source: "weakpass",
	}
	first, err := d.UpsertIntranetCredential(in)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	stored := rawCredentialPassword(t, d, first.ID)
	if !IsSealed(stored) {
		t.Fatalf("password column holds plaintext: %q", stored)
	}
	if strings.Contains(stored, plain) {
		t.Fatalf("seal leaked the plaintext: %q", stored)
	}
	back, err := d.GetIntranetCredential(first.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if back.Password != plain || back.SealBroken || !back.HasPassword {
		t.Fatalf("read-back = %q broken=%v has=%v", back.Password, back.SealBroken, back.HasPassword)
	}

	// The hazard this test exists for: UNIQUE (host, username, password) is what
	// makes a re-register refresh a row. With a random nonce every re-register would
	// become a new row and the ledger would show the same credential repeatedly.
	again, err := d.UpsertIntranetCredential(in)
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if again.ID != first.ID {
		t.Fatalf("re-register created a second row: #%d vs #%d", first.ID, again.ID)
	}
	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM intranet_credentials WHERE host=$1`, "seal-test.a").Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Fatalf("want 1 credential row, got %d", rows)
	}

	// Re-registering through the server path hands back a row it just read, i.e. a
	// value that is already sealed. Sealing must not wrap it twice.
	third, err := d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: "seal-test.a", Port: 22, Protocol: "ssh",
		Username: "admin", Password: back.Password, Source: "reuse",
	})
	if err != nil {
		t.Fatalf("upsert from a read row: %v", err)
	}
	if third.ID != first.ID {
		t.Fatalf("reusing a read row created a second row: #%d", third.ID)
	}
	if got, err := d.GetIntranetCredential(third.ID); err != nil || got.Password != plain {
		t.Fatalf("double-wrap broke the value: %q err=%v", got.Password, err)
	}
}

func TestSealMigratesPlaintextRows(t *testing.T) {
	d := sealTestDB(t)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intranet_credentials WHERE host LIKE 'seal-mig.%'`)
		_, _ = d.Exec(`DELETE FROM llm_profiles WHERE name LIKE 'seal-mig-%'`)
	})

	// A handle without a key writes exactly what a pre-sealing install wrote.
	legacy, err := d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: "seal-mig.a", Port: 22, Protocol: "ssh",
		Username: "root", Password: "legacy-pass", Source: "manual",
	})
	if err != nil {
		t.Fatalf("legacy upsert: %v", err)
	}
	if IsSealed(rawCredentialPassword(t, d, legacy.ID)) {
		t.Fatal("a keyless handle must not seal")
	}
	profile := &LLMProfile{Name: "seal-mig-1", Format: "openai", Model: "gpt", APIKey: "sk-legacy-1234", RatePerSecond: 1}
	if _, err := d.SaveProfile(profile); err != nil {
		t.Fatalf("legacy save profile: %v", err)
	}

	d.UseSealKey(sealTestKey)

	if stored := rawCredentialPassword(t, d, legacy.ID); !IsSealed(stored) {
		t.Fatalf("credential still plaintext after migration: %q", stored)
	}
	back, err := d.GetIntranetCredential(legacy.ID)
	if err != nil {
		t.Fatalf("get after migration: %v", err)
	}
	if back.Password != "legacy-pass" || back.SealBroken {
		t.Fatalf("migrated credential reads back as %q broken=%v", back.Password, back.SealBroken)
	}
	var storedKey, hint string
	if err := d.QueryRow(`SELECT api_key, api_key_hint FROM llm_profiles WHERE name=$1`, "seal-mig-1").Scan(&storedKey, &hint); err != nil {
		t.Fatalf("read raw api_key: %v", err)
	}
	if !IsSealed(storedKey) {
		t.Fatalf("api_key still plaintext after migration: %q", storedKey)
	}
	if hint != "…1234" {
		t.Fatalf("hint must still describe the plaintext key, got %q", hint)
	}

	// Second start: the run-once flag skips the pass, and clearing it must not
	// double-wrap the rows that are already sealed.
	if _, err := d.Exec(`DELETE FROM settings WHERE key=$1`, settingSecretSealV1); err != nil {
		t.Fatalf("clear flag: %v", err)
	}
	d.UseSealKey(sealTestKey)
	if again, err := d.GetIntranetCredential(legacy.ID); err != nil || again.Password != "legacy-pass" || again.SealBroken {
		t.Fatalf("re-running the migration broke the row: %q broken=%v err=%v", again.Password, again.SealBroken, err)
	}
}

func TestSealWrongKeyMarksCredentialBroken(t *testing.T) {
	d := sealTestDB(t)
	d.UseSealKey(sealTestKey)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intranet_credentials WHERE host LIKE 'seal-other.%'`)
	})
	cred, err := d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: "seal-other.a", Port: 22, Protocol: "ssh",
		Username: "svc", Password: "rotate-me", Source: "manual",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// A different signing root: the row is unreadable. The list must still work
	// (one bad row cannot blank the ledger) and the caller must be able to tell
	// "unreadable" from "no password recorded".
	other := sealTestDB(t)
	other.UseSealKey([]byte("ffffffffffffffffffffffffffffffff-key-b"))
	list, err := other.ListIntranetCredentials(IntranetCredentialFilter{Host: "seal-other.a"})
	if err != nil {
		t.Fatalf("list with the wrong key: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("want the row listed, got %d", len(list))
	}
	got := list[0]
	if !got.SealBroken || got.Password != "" || !got.HasPassword {
		t.Fatalf("broken seal not reported: broken=%v pw=%q has=%v", got.SealBroken, got.Password, got.HasPassword)
	}

	// A keyless handle (an older binary, a test harness) must not be handed
	// ciphertext as if it were the password.
	plain := sealTestDB(t)
	read, err := plain.GetIntranetCredential(cred.ID)
	if err != nil {
		t.Fatalf("keyless read: %v", err)
	}
	if IsSealed(read.Password) {
		t.Fatalf("keyless handle returned ciphertext: %q", read.Password)
	}
}

func TestSealLLMAPIKeyRoundTrip(t *testing.T) {
	d := sealTestDB(t)
	d.UseSealKey(sealTestKey)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM llm_profiles WHERE name LIKE 'seal-llm-%'`)
	})

	const plain = "sk-live-abcdef1234"
	id, err := d.SaveProfile(&LLMProfile{
		Name: "seal-llm-1", Format: "openai", Model: "gpt", APIKey: plain,
		RatePerSecond: 1,
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	// SaveProfile never sets the default; activating is a separate statement, and
	// ActiveProfile is the loader every LLM call actually goes through.
	if err := d.SetActiveProfile(id); err != nil {
		t.Fatalf("activate: %v", err)
	}
	var stored, hint string
	if err := d.QueryRow(`SELECT api_key, api_key_hint FROM llm_profiles WHERE id=$1`, id).Scan(&stored, &hint); err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if !IsSealed(stored) || strings.Contains(stored, plain) {
		t.Fatalf("api_key at rest = %q", stored)
	}
	if hint != "…1234" {
		t.Fatalf("hint must be taken from the plaintext, got %q", hint)
	}

	active, err := d.ActiveProfile()
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active.APIKey != plain {
		t.Fatalf("ActiveProfile must hand back plaintext, got %q", active.APIKey)
	}
	keys, err := d.ProfileAPIKeys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	var fingerprinted bool
	for _, k := range keys {
		if k == plain {
			fingerprinted = true
		}
		if IsSealed(k) {
			t.Fatalf("ProfileAPIKeys returned a seal; the egress guard would fingerprint ciphertext and leak the real key: %q", k)
		}
	}
	if !fingerprinted {
		t.Fatalf("plaintext key missing from the guard fingerprints: %q", keys)
	}

	// "Blank keeps the stored key" is part of the save contract; it must not seal an
	// empty value or drop the existing one.
	same := *active
	same.APIKey = ""
	if _, err := d.SaveProfile(&same); err != nil {
		t.Fatalf("update without a key: %v", err)
	}
	after, err := d.ProfileByID(id)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.APIKey != plain {
		t.Fatalf("blank update lost the key: %q", after.APIKey)
	}

	// Unreadable seal: the profile is reported as having no key rather than being
	// handed a ciphertext to send as an Authorization header.
	wrong := sealTestDB(t)
	wrong.UseSealKey([]byte("gggggggggggggggggggggggggggggggg-key-b"))
	p, err := wrong.ProfileByID(id)
	if err != nil {
		t.Fatalf("read with the wrong key: %v", err)
	}
	if p == nil {
		t.Fatal("the profile row vanished for another handle")
	}
	if p.APIKey != "" {
		t.Fatalf("wrong key must clear the profile key, got %q", p.APIKey)
	}
}

// The startup audit is the only place an operator learns that a stored secret is
// unreadable before wasting a command on it, so it has to count across kinds.
func TestAuditSealedSecretsCountsUnreadable(t *testing.T) {
	d := sealTestDB(t)
	d.UseSealKey(sealTestKey)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intranet_credentials WHERE host LIKE 'seal-audit.%'`)
		_, _ = d.Exec(`DELETE FROM llm_profiles WHERE name LIKE 'seal-audit-%'`)
	})
	cred, err := d.UpsertIntranetCredential(IntranetCredentialInput{
		Host: "seal-audit.a", Port: 22, Protocol: "ssh",
		Username: "root", Password: "rotate-me", Source: "manual",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := d.SaveProfile(&LLMProfile{
		Name: "seal-audit-1", Format: "openai", Model: "gpt", APIKey: "sk-audit-9999", RatePerSecond: 1,
	}); err != nil {
		t.Fatalf("save profile: %v", err)
	}

	if got := d.auditSealedSecrets(); got != 0 {
		t.Fatalf("the key that sealed these rows must read them back, got %d unreadable", got)
	}

	other := sealTestDB(t)
	other.UseSealKey([]byte("hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-key-b"))
	if got := other.auditSealedSecrets(); got == 0 {
		t.Fatal("a rotated signing root must be reported at startup")
	}
	read, err := other.GetIntranetCredential(cred.ID)
	if err != nil {
		t.Fatalf("get with the wrong key: %v", err)
	}
	if !read.SealBroken || read.Password != "" || !read.HasPassword {
		t.Fatalf("the row must be flagged unreadable rather than returned as ciphertext: %+v", read)
	}
}
