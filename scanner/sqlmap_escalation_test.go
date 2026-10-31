package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// stubSQLMap puts a fake sqlmap first on PATH and clears the cached lookup so
// the run picks it up. The cleanup clears the cache again, leaving later tests
// to re-resolve the real binary.
func stubSQLMap(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "sqlmap")
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	resetSQLMapLookup()
	t.Cleanup(resetSQLMapLookup)
}

func resetSQLMapLookup() {
	sqlmapLookOnce = sync.Once{}
	sqlmapPath = ""
	sqlmapLookErr = nil
	sqlmapVersionOnce = sync.Once{}
	sqlmapVersionText = ""
}

// sqlmapEscalationRun mimics the tail of a real sqlmap metadata query: the
// detection phase re-runs (the banner block is not printed again), then one
// line per requested flag.
const sqlmapEscalationRun = `[10:00:01] [INFO] resuming back-end DBMS 'mysql'
[10:00:02] [INFO] testing connection to the target URL
sqlmap identified the following injection point(s) with a total of 31 HTTP(s) requests:
---
Parameter: name (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=1' AND 1400=1400-- -
---
[10:00:09] [INFO] fetching banner
banner: '5.7.26'
[10:00:10] [INFO] fetching current user
current user: 'root@localhost'
[10:00:11] [INFO] fetching current database
current database: 'dvwa'
[10:00:12] [INFO] fetching hostname
hostname: 'db01'
[10:00:13] [INFO] testing if current user is DBA
current user is DBA: True
`

func TestParseSQLMapEscalation(t *testing.T) {
	banner, user, dbName, host, dbaText, isDBA := ParseSQLMapEscalation(sqlmapEscalationRun)
	if banner != "5.7.26" {
		t.Errorf("banner = %q", banner)
	}
	if user != "root@localhost" {
		t.Errorf("current user = %q", user)
	}
	if dbName != "dvwa" {
		t.Errorf("current db = %q", dbName)
	}
	if host != "db01" {
		t.Errorf("hostname = %q", host)
	}
	if dbaText != "True" || !isDBA {
		t.Errorf("dba = %q / %v", dbaText, isDBA)
	}
}

func TestParseSQLMapEscalationNonDBA(t *testing.T) {
	_, _, _, _, dbaText, isDBA := ParseSQLMapEscalation("current user is DBA: False\n")
	if dbaText != "False" || isDBA {
		t.Fatalf("dba = %q / %v, want False / false", dbaText, isDBA)
	}
}

func TestParseSQLMapEscalationEmpty(t *testing.T) {
	banner, user, dbName, host, dbaText, isDBA := ParseSQLMapEscalation("[INFO] no metadata here")
	if banner != "" || user != "" || dbName != "" || host != "" || dbaText != "" || isDBA {
		t.Fatalf("noise parsed as metadata: %q %q %q %q %q %v", banner, user, dbName, host, dbaText, isDBA)
	}
}

func TestSQLMapEscalationHasFindingsAndSummary(t *testing.T) {
	empty := SQLMapEscalation{}
	if empty.HasFindings() {
		t.Error("empty escalation reports findings")
	}
	esc := SQLMapEscalation{
		Banner: "5.7.26", CurrentUser: "root@localhost", CurrentDB: "dvwa",
		Hostname: "db01", DBAText: "True", IsDBA: true,
	}
	if !esc.HasFindings() {
		t.Error("populated escalation reports no findings")
	}
	summary := esc.Summary()
	for _, want := range []string{"root@localhost", "dvwa", "db01", "5.7.26", "DBA=True"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q missing %q", summary, want)
		}
	}
	// A non-DBA answer alone is not an impact worth reporting.
	onlyFalse := SQLMapEscalation{DBAText: "False"}
	if onlyFalse.HasFindings() {
		t.Error("DBA=False alone counts as a finding")
	}
}

func TestSQLMapTargetArgsSharedByBothRuns(t *testing.T) {
	dir := t.TempDir()
	opts := SQLMapOptions{
		RawRequest: "POST /x?a=1 HTTP/1.1\r\nHost: t\r\n\r\nb=2",
		Techniques: "be",
		Params:     []string{"a", "b"},
		Cookie:     "sid=1",
		Headers:    []string{"X-Test: 1", "bad\nheader"},
		Proxy:      "http://127.0.0.1:8080",
	}
	args, err := sqlmapTargetArgs("http://t/x", opts, dir)
	if err != nil {
		t.Fatalf("target args: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"-r ", "--technique BE", "-p a,b", "--cookie sid=1", "-H X-Test: 1", "--proxy http://127.0.0.1:8080"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "bad") {
		t.Errorf("multi-line header leaked into args: %q", joined)
	}
	if strings.Contains(joined, "--url") {
		t.Errorf("raw request should replace --url: %q", joined)
	}

	plain, err := sqlmapTargetArgs("http://t/x?a=1", SQLMapOptions{}, dir)
	if err != nil {
		t.Fatalf("plain target args: %v", err)
	}
	if strings.Join(plain, " ") != "--url http://t/x?a=1" {
		t.Fatalf("plain args = %q", strings.Join(plain, " "))
	}
}

func TestRunSQLMapEscalationAgainstStub(t *testing.T) {
	stubSQLMap(t, `#!/bin/sh
if [ "$1" = "--version" ]; then echo "1.10.10#stub"; exit 0; fi
echo "[INFO] fetching banner"
echo "banner: '5.7.26'"
echo "current user: 'root@localhost'"
echo "current database: 'dvwa'"
echo "hostname: 'db01'"
echo "current user is DBA: True"
exit 0
`)
	esc := RunSQLMapEscalation(context.Background(), "http://127.0.0.1/x?a=1", SQLMapOptions{Params: []string{"a"}, WallSeconds: 10})
	if esc.Missing {
		t.Fatal("stub reported missing")
	}
	if esc.Err != nil {
		t.Fatalf("escalation error: %v", esc.Err)
	}
	if !esc.IsDBA || esc.CurrentUser != "root@localhost" || esc.CurrentDB != "dvwa" || esc.Hostname != "db01" || esc.Banner != "5.7.26" {
		t.Fatalf("escalation = %+v", esc)
	}
}

func TestRunSQLMapEscalationReportsFailure(t *testing.T) {
	stubSQLMap(t, `#!/bin/sh
if [ "$1" = "--version" ]; then echo "1.10.10#stub"; exit 0; fi
echo "[CRITICAL] connection timed out"
exit 1
`)
	esc := RunSQLMapEscalation(context.Background(), "http://127.0.0.1/x", SQLMapOptions{WallSeconds: 10})
	if esc.HasFindings() {
		t.Fatalf("failed run parsed metadata: %+v", esc)
	}
	if esc.Err == nil {
		t.Fatal("failed run reported no error")
	}
}
