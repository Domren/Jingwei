package scanner

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func jspE2EEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func jspE2EDocker(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// TestShellV2JSPFileManagerRuntime drives a generated v2 JSP payload deployed
// in a real servlet container: alive check, command execution, the full
// file-manager op set, self-protection and root-deletion refusal. Without
// JINGWEI_JSP_E2E_CONTAINER/JINGWEI_JSP_E2E_URL it skips, so the default suite
// stays hermetic.
func TestShellV2JSPFileManagerRuntime(t *testing.T) {
	container := strings.TrimSpace(os.Getenv("JINGWEI_JSP_E2E_CONTAINER"))
	shellURL := strings.TrimSpace(os.Getenv("JINGWEI_JSP_E2E_URL"))
	if container == "" || shellURL == "" {
		t.Skip("set JINGWEI_JSP_E2E_CONTAINER and JINGWEI_JSP_E2E_URL to run against a real Tomcat")
	}
	if testing.Short() {
		t.Skip("skipping runtime shell test in -short mode")
	}
	remotePath := jspE2EEnv("JINGWEI_JSP_E2E_PATH", "/usr/local/tomcat/webapps/ROOT/jw_shell.jsp")
	workDir := jspE2EEnv("JINGWEI_JSP_E2E_DIR", "/tmp/jw-e2e")

	key, err := GenerateShellKey()
	if err != nil {
		t.Fatal(err)
	}
	// Fixed X- carrier: the 256 KiB chunks must fall back to the form body,
	// because Tomcat rejects header lines beyond its default 8 KiB limit.
	payload, err := BuildShellPayloadV2("jsp", key, "X-JWE2ETest")
	if err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(t.TempDir(), "shell.jsp")
	if err := os.WriteFile(local, []byte(payload.Content), 0o644); err != nil {
		t.Fatal(err)
	}
	jspE2EDocker(t, "exec", "-u", "0", container, "mkdir", "-p", path.Dir(remotePath))
	jspE2EDocker(t, "cp", local, container+":"+remotePath)
	jspE2EDocker(t, "exec", "-u", "0", container, "chmod", "0644", remotePath)

	client := NewDeepClient(60 * time.Second)
	ctx := context.Background()
	// The first request triggers Jasper compilation, so allow a slow start.
	alive, note := false, ""
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if alive, note = CheckShellAlive(ctx, client, shellURL, payload); alive {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !alive {
		t.Fatalf("alive check failed: %s", note)
	}

	out, err := RunShellCommand(ctx, client, shellURL, payload, "id; echo JW_JSP_E2E_OK")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(out, "JW_JSP_E2E_OK") || !strings.Contains(out, "uid=") {
		t.Fatalf("unexpected command output: %q", out)
	}

	// A previous failed run may have left the work tree behind.
	_ = DeleteShellPath(ctx, client, shellURL, payload, workDir, true)
	if err := MkdirShellPath(ctx, client, shellURL, payload, workDir+"/sub"); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	hello := workDir + "/hello.txt"
	if _, err := WriteShellFile(ctx, client, shellURL, payload, hello, 0, true, []byte("hello jingwei")); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	list, err := ListShellFiles(ctx, client, shellURL, payload, workDir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if list.Path != workDir {
		t.Fatalf("list path = %q, want %q", list.Path, workDir)
	}
	byName := map[string]ShellFileEntry{}
	for _, e := range list.Entries {
		byName[e.Name] = e
	}
	for _, name := range []string{"hello.txt", "sub"} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("list missing %s: %+v", name, list.Entries)
		}
	}
	if byName["hello.txt"].Type != "file" || byName["hello.txt"].Size != int64(len("hello jingwei")) {
		t.Fatalf("hello.txt entry = %+v", byName["hello.txt"])
	}
	if byName["sub"].Type != "dir" || byName["hello.txt"].Mode == "" || byName["hello.txt"].Mode == "-" {
		t.Fatalf("unexpected entry metadata: %+v", byName)
	}
	if byName["hello.txt"].Modified <= 0 {
		t.Fatalf("missing mtime: %+v", byName["hello.txt"])
	}

	chunk, err := ReadShellFile(ctx, client, shellURL, payload, hello, 0, 1024)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(chunk.Data) != "hello jingwei" || !chunk.EOF || chunk.Size != int64(len("hello jingwei")) {
		t.Fatalf("read chunk = %+v data=%q", chunk, chunk.Data)
	}

	large := make([]byte, 600<<10)
	for i := range large {
		large[i] = byte(i % 251)
	}
	largePath := workDir + "/large.bin"
	for off := 0; off < len(large); off += ShellFileChunkSize {
		end := off + ShellFileChunkSize
		if end > len(large) {
			end = len(large)
		}
		if _, err := WriteShellFile(ctx, client, shellURL, payload, largePath, int64(off), off == 0, large[off:end]); err != nil {
			t.Fatalf("write large at %d: %v", off, err)
		}
	}
	var rebuilt []byte
	readOff := int64(0)
	for i := 0; ; i++ {
		if i > 8 {
			t.Fatal("large file read did not terminate")
		}
		part, err := ReadShellFile(ctx, client, shellURL, payload, largePath, readOff, ShellFileChunkSize)
		if err != nil {
			t.Fatalf("read large at %d: %v", readOff, err)
		}
		rebuilt = append(rebuilt, part.Data...)
		readOff = part.Offset + int64(len(part.Data))
		if part.EOF {
			break
		}
	}
	if !bytes.Equal(rebuilt, large) {
		t.Fatalf("chunked roundtrip mismatch: %d != %d bytes", len(rebuilt), len(large))
	}

	moved := workDir + "/sub/renamed.txt"
	if err := RenameShellPath(ctx, client, shellURL, payload, hello, moved); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := ReadShellFile(ctx, client, shellURL, payload, hello, 0, 64); err == nil {
		t.Fatal("old path still readable after rename")
	}
	if err := ChmodShellPath(ctx, client, shellURL, payload, moved, "0600"); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	subList, err := ListShellFiles(ctx, client, shellURL, payload, workDir+"/sub")
	if err != nil {
		t.Fatalf("list sub: %v", err)
	}
	renamed := ShellFileEntry{}
	for _, e := range subList.Entries {
		if e.Name == "renamed.txt" {
			renamed = e
		}
	}
	if renamed.Mode != "0600" {
		t.Fatalf("chmod mode = %q, want 0600 (entries %+v)", renamed.Mode, subList.Entries)
	}

	if err := DeleteShellPath(ctx, client, shellURL, payload, workDir, true); err != nil {
		t.Fatalf("recursive delete: %v", err)
	}
	if _, err := ListShellFiles(ctx, client, shellURL, payload, workDir); err == nil {
		t.Fatal("deleted directory is still listable")
	}

	// The deployed shell and the temp key file are protected from the manager.
	if _, err := WriteShellFile(ctx, client, shellURL, payload, remotePath, 0, true, []byte("broken")); err == nil ||
		!strings.Contains(err.Error(), "protected") {
		t.Fatalf("write shell file must be refused, got %v", err)
	}
	if err := DeleteShellPath(ctx, client, shellURL, payload, remotePath, false); err == nil ||
		!strings.Contains(err.Error(), "protected") {
		t.Fatalf("delete shell file must be refused, got %v", err)
	}
	if err := RenameShellPath(ctx, client, shellURL, payload, remotePath, remotePath+".bak"); err == nil ||
		!strings.Contains(err.Error(), "protected") {
		t.Fatalf("rename shell file must be refused, got %v", err)
	}
	if err := ChmodShellPath(ctx, client, shellURL, payload, remotePath, "0777"); err == nil ||
		!strings.Contains(err.Error(), "protected") {
		t.Fatalf("chmod shell file must be refused, got %v", err)
	}
	if err := DeleteShellPath(ctx, client, shellURL, payload, "/", true); err == nil ||
		!strings.Contains(err.Error(), "root") {
		t.Fatalf("deleting / must be refused, got %v", err)
	}
	if alive, note := CheckShellAlive(ctx, client, shellURL, payload); !alive {
		t.Fatalf("shell died after refused operations: %s", note)
	}

	if _, err := ReadShellFile(ctx, client, shellURL, payload, workDir+"/missing.txt", 0, 128); err == nil {
		t.Fatal("reading a missing file must fail")
	}
	if _, err := WriteShellFile(ctx, client, shellURL, payload, "bad\x00path", 0, true, []byte("x")); err == nil {
		t.Fatal("writing a NUL path must fail")
	}
}
