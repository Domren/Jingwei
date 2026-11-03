package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestShellPayloadSelfCheck fingerprints every generated payload and, when the
// tools are installed, feeds the sources to YARA and ClamAV. The goal is to
// catch accidental regressions that reintroduce plaintext credentials or a
// signature that generic webshell rules match.
func TestShellPayloadSelfCheck(t *testing.T) {
	dir := t.TempDir()
	files := []string{}
	for _, typ := range []string{"php", "jsp", "aspx"} {
		key, err := GenerateShellKey()
		if err != nil {
			t.Fatal(err)
		}
		carrier, err := GenerateShellCarrier()
		if err != nil {
			t.Fatal(err)
		}
		payload, err := BuildShellPayloadV2(typ, key, carrier)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		sum := sha256.Sum256([]byte(payload.Content))
		if got := hex.EncodeToString(sum[:]); got != payload.SHA256 || len(got) != 64 {
			t.Fatalf("%s fingerprint mismatch: %s != %s", typ, got, payload.SHA256)
		}
		for _, banned := range []string{"{{KEY}}", "{{CARRIER}}", "{{BUILD}}", "pwd=", "enc="} {
			if strings.Contains(payload.Content, banned) {
				t.Fatalf("%s payload still contains %q", typ, banned)
			}
		}
		if payload.Protocol != ShellProtocolV2 {
			t.Fatalf("%s payload protocol = %q", typ, payload.Protocol)
		}
		path := filepath.Join(dir, "check."+typ)
		if err := os.WriteFile(path, []byte(payload.Content), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, path)
	}

	rules := filepath.Join("testdata", "shell_selfcheck.yar")
	if yara, err := exec.LookPath("yara"); err == nil {
		for _, f := range files {
			// Some builds return 0 for both match and no-match, so the match
			// signal is non-empty output (rule name + file).
			out, yerr := exec.Command(yara, "-s", rules, f).CombinedOutput()
			if yerr != nil {
				t.Fatalf("YARA failed on %s: %v\n%s", filepath.Base(f), yerr, out)
			}
			if len(strings.TrimSpace(string(out))) > 0 {
				t.Fatalf("YARA matched %s:\n%s", filepath.Base(f), out)
			}
		}
	} else {
		t.Log("yara not installed; skipped signature self-check")
	}

	if clam, err := exec.LookPath("clamscan"); err == nil {
		for _, f := range files {
			out, cerr := exec.Command(clam, "--no-summary", "--stdout", f).CombinedOutput()
			if cerr != nil {
				t.Fatalf("ClamAV flagged %s: %v\n%s", filepath.Base(f), cerr, out)
			}
		}
	} else {
		t.Log("clamscan not installed; skipped AV self-check")
	}
}
