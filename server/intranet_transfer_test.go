package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// localIntranetRunner executes target-side commands with the same wrapper used
// by a POSIX webshell, so transfer helpers can be tested end to end locally.
func localIntranetRunner(t *testing.T) intranetCommandRunner {
	t.Helper()
	return func(command string, timeout time.Duration) intranetExecOutcome {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		raw, err := exec.CommandContext(ctx, "/bin/sh", "-c", intranetScript("/", command)).CombinedOutput()
		out := intranetExecOutcome{ExitCode: -1}
		output, cwd, code, ok := parseIntranetOutput(string(raw))
		out.Output, out.Cwd, out.ExitCode = output, cwd, code
		if !ok {
			out.IsError, out.Output, out.Note = true, string(raw), "未解析到命令结束标记"
			return out
		}
		if err != nil || code != 0 {
			out.IsError = true
		}
		return out
	}
}

func TestGzipIntranetContent(t *testing.T) {
	if _, ok := gzipIntranetContent([]byte("tiny")); ok {
		t.Fatal("tiny payload should skip gzip")
	}
	content := bytes.Repeat([]byte("compressible payload line\n"), 3000)
	gz, ok := gzipIntranetContent(content)
	if !ok || len(gz) >= len(content) {
		t.Fatalf("compressible payload not compressed: %d -> %d ok=%v", len(content), len(gz), ok)
	}
	got, ok := parseGzipChunk(gz)
	if !ok || !bytes.Equal(got, content) {
		t.Fatalf("gzip roundtrip mismatch: ok=%v len=%d", ok, len(got))
	}
	if _, ok := parseGzipChunk([]byte("not gzip")); ok {
		t.Fatal("plain bytes must not decode as gzip")
	}
}

func TestParseIntranetDownloadMeta(t *testing.T) {
	raw := "warning: ignored\n" + intranetSizeMarker + "12345\n" + intranetGzipMarker + "1\n"
	total, gzipOK, ok := parseIntranetDownloadMeta(raw)
	if !ok || total != 12345 || !gzipOK {
		t.Fatalf("meta = %d/%v/%v", total, gzipOK, ok)
	}
	if _, _, ok := parseIntranetDownloadMeta(intranetSizeMarker + "\n" + intranetGzipMarker + "0"); ok {
		t.Fatal("missing size must not parse")
	}
}

func TestParseIntranetChunk(t *testing.T) {
	encoded := "aGVsbG8td29ybGQ="
	raw, ok := parseIntranetChunk("noise\n" + intranetChunkMarker + "\n" + encoded + "\n" + intranetChunkEndMarker + "\ntrailer")
	if !ok || string(raw) != "hello-world" {
		t.Fatalf("chunk = %q ok=%v", raw, ok)
	}
	if _, ok := parseIntranetChunk("no markers"); ok {
		t.Fatal("missing markers must not parse")
	}
	if _, ok := parseIntranetChunk(intranetChunkMarker + "@@@@" + intranetChunkEndMarker); ok {
		t.Fatal("invalid base64 must not parse")
	}
}

func TestIntranetPOSIXUploadDownloadRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix transport test")
	}
	run := localIntranetRunner(t)
	dir := t.TempDir()
	content := bytes.Repeat([]byte("jingwei transfer payload 0123456789\n"), 25000)
	if len(content) < intranetUploadChunk*4 {
		t.Fatalf("test payload too small: %d", len(content))
	}
	path := filepath.Join(dir, "upload.bin")

	out, compressed, existed, err := intranetUploadPOSIX(run, path, content)
	if err != nil {
		t.Fatalf("upload: %v\n%s %s", err, out.Output, out.Note)
	}
	if !compressed || existed {
		t.Fatalf("upload flags compressed=%v existed=%v", compressed, existed)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("uploaded file mismatch: len=%d err=%v", len(got), err)
	}
	if _, _, existed, err = intranetUploadPOSIX(run, path, content); err != nil || !existed {
		t.Fatalf("overwrite upload existed=%v err=%v", existed, err)
	}

	data, total, truncated, compressed, dlOut := intranetDownloadPOSIX(run, path, intranetDownloadLimit)
	if dlOut.IsError {
		t.Fatalf("download: %s %s", dlOut.Output, dlOut.Note)
	}
	if !bytes.Equal(data, content) || total != int64(len(content)) || truncated || !compressed {
		t.Fatalf("download mismatch: len=%d total=%d truncated=%v compressed=%v", len(data), total, truncated, compressed)
	}

	part, total, truncated, _, dlOut := intranetDownloadPOSIX(run, path, 1000)
	if dlOut.IsError || !bytes.Equal(part, content[:1000]) || total != int64(len(content)) || !truncated {
		t.Fatalf("truncated download: len=%d total=%d truncated=%v err=%v", len(part), total, truncated, dlOut.IsError)
	}

	// Force the capability probe to report no gzip and verify the plain
	// chunked path still round-trips.
	plainRun := func(command string, timeout time.Duration) intranetExecOutcome {
		if strings.HasPrefix(command, "command -v gzip") {
			return intranetExecOutcome{Output: intranetGzipMarker + "0", ExitCode: 0}
		}
		out := run(command, timeout)
		if strings.Contains(command, intranetSizeMarker) {
			out.Output = strings.ReplaceAll(out.Output, intranetGzipMarker+"1", intranetGzipMarker+"0")
		}
		return out
	}
	plainPath := filepath.Join(dir, "plain.bin")
	if _, compressed, _, err = intranetUploadPOSIX(plainRun, plainPath, content); err != nil || compressed {
		t.Fatalf("plain upload compressed=%v err=%v", compressed, err)
	}
	if got, err = os.ReadFile(plainPath); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("plain uploaded file mismatch: len=%d err=%v", len(got), err)
	}
	data, total, truncated, compressed, dlOut = intranetDownloadPOSIX(plainRun, plainPath, intranetDownloadLimit)
	if dlOut.IsError || !bytes.Equal(data, content) || total != int64(len(content)) || truncated || compressed {
		t.Fatalf("plain download: len=%d total=%d truncated=%v compressed=%v err=%v", len(data), total, truncated, compressed, dlOut.IsError)
	}

	random := make([]byte, 200*1024)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	randomPath := filepath.Join(dir, "random.bin")
	if _, compressed, _, err = intranetUploadPOSIX(run, randomPath, random); err != nil || compressed {
		t.Fatalf("incompressible upload compressed=%v err=%v", compressed, err)
	}
	if got, err = os.ReadFile(randomPath); err != nil || !bytes.Equal(got, random) {
		t.Fatalf("incompressible file mismatch: len=%d err=%v", len(got), err)
	}
}

func TestIntranetPOSIXDownloadRejectsMissingPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix transport test")
	}
	run := localIntranetRunner(t)
	path := filepath.Join(t.TempDir(), "missing.bin")
	_, _, _, _, out := intranetDownloadPOSIX(run, path, 4096)
	if !out.IsError {
		t.Fatalf("missing file unexpectedly downloaded: %+v", out)
	}
}

func TestIntranetHeartbeatProbe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix heartbeat test")
	}
	run := localIntranetRunner(t)
	alive, latency, out := intranetProbeLiveness(run, intranetOSPosix, 5*time.Second)
	if !alive || out.IsError || latency <= 0 {
		t.Fatalf("heartbeat = %v/%v/%s %s", alive, latency, out.Output, out.Note)
	}
	bad := func(string, time.Duration) intranetExecOutcome {
		return intranetExecOutcome{Output: "not a marker", ExitCode: 0}
	}
	if alive, _, out = intranetProbeLiveness(bad, intranetOSPosix, time.Second); alive || !out.IsError {
		t.Fatalf("bad heartbeat = %v/%+v", alive, out)
	}
	if cmd := intranetHeartbeatCommand(intranetOSWindows); !strings.Contains(cmd, intranetHeartbeatMark) {
		t.Fatalf("windows heartbeat command = %q", cmd)
	}
}

func TestIntranetFailoverCandidates(t *testing.T) {
	current := int64(1)
	sess := &db.IntranetSession{ID: 9, Host: "10.0.0.5", WebshellID: &current}
	shells := []*db.Webshell{
		{ID: 1, URL: "http://10.0.0.5/old.php", Target: "10.0.0.5", Status: "alive"},
		{ID: 2, URL: "http://10.0.0.5/new.php", Target: "10.0.0.5", Status: "unknown"},
		{ID: 3, URL: "http://10.0.0.5/dead.php", Target: "10.0.0.5", Status: "dead"},
		{ID: 4, URL: "http://10.0.0.6/other.php", Target: "10.0.0.6", Status: "alive"},
		{ID: 5, URL: "http://10.0.0.5:8080/url.php", Target: "", Status: "alive"},
	}
	got := intranetFailoverCandidates(sess, shells)
	if len(got) != 2 || got[0].ID != 5 || got[1].ID != 2 {
		t.Fatalf("candidates = %+v", got)
	}
	if cands := intranetFailoverCandidates(&db.IntranetSession{ID: 10}, shells); cands != nil {
		t.Fatalf("hostless session must not auto-pick: %+v", cands)
	}
}
