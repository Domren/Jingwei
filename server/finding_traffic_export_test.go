package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func writeEvidenceBlob(t *testing.T, dir, body string) (string, int64) {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	hash := hex.EncodeToString(sum[:])
	path := filepath.Join(dir, "blobs", hash[:2], hash+".bin")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return hash, int64(len(body))
}

func TestEvidencePacketScorePrefersSuccessfulLogin(t *testing.T) {
	failed := db.FindingEvidencePacket{Role: "proof", HTTPResponse: "HTTP/1.1 200 OK\r\n\r\nUsername and/or password incorrect."}
	success := db.FindingEvidencePacket{Role: "proof", HTTPResponse: "HTTP/1.1 200 OK\r\n\r\nWelcome to the password protected area admin"}
	if evidencePacketScore(success, "Broken Authentication / Brute Force", "") <= evidencePacketScore(failed, "Broken Authentication / Brute Force", "") {
		t.Fatal("successful login packet must outrank a failed attempt")
	}
}

func TestEvidencePacketScorePrefersSessionCookie(t *testing.T) {
	withCookie := db.FindingEvidencePacket{Role: "proof", HTTPResponse: "HTTP/1.1 200 OK\r\nSet-Cookie: dvwaSession=3\r\n\r\n"}
	plain := db.FindingEvidencePacket{Role: "proof", HTTPResponse: "HTTP/1.1 200 OK\r\n\r\n"}
	if evidencePacketScore(withCookie, "Weak Session ID", "") <= evidencePacketScore(plain, "Weak Session ID", "") {
		t.Fatal("session packet that sets the weak cookie must outrank one that does not")
	}
}

func TestEvidencePacketScorePrefersSQLHashDump(t *testing.T) {
	boolean := db.FindingEvidencePacket{Role: "proof", HTTPResponse: "HTTP/1.1 200 OK\r\n\r\n<pre>First name: admin<br />Surname: admin</pre>"}
	union := db.FindingEvidencePacket{Role: "proof", HTTPResponse: "HTTP/1.1 200 OK\r\n\r\n<pre>First name: admin<br />Surname: 5f4dcc3b5aa765d61d8327deb882cf99</pre>"}
	if evidencePacketScore(union, "SQL Injection", "") <= evidencePacketScore(boolean, "SQL Injection", "") {
		t.Fatal("UNION hash dump must outrank the boolean probe")
	}
}

func TestEvidencePacketScorePrefersPasswordChanged(t *testing.T) {
	changed := db.FindingEvidencePacket{Role: "proof", HTTPResponse: "HTTP/1.1 200 OK\r\n\r\n<pre>Password Changed.</pre>"}
	form := db.FindingEvidencePacket{Role: "proof", HTTPResponse: "HTTP/1.1 200 OK\r\n\r\n<form>Change your password</form>"}
	if evidencePacketScore(changed, "CSRF", "") <= evidencePacketScore(form, "CSRF", "") {
		t.Fatal("CSRF success marker must outrank the form page")
	}
}

func TestEvidencePacketScoreCSRFKeepsReflectedDictionaryOut(t *testing.T) {
	page := "HTTP/1.1 200 OK\r\n\r\n<form><input name=\"password_new\">New password</form><pre>Password Changed.</pre>"
	attack := db.FindingEvidencePacket{Role: "proof",
		HTTPRequest:  "GET /vulnerabilities/csrf/?password_new=jw-csrf-test&password_conf=jw-csrf-test&Change=Change HTTP/1.1\r\nHost: lab",
		HTTPResponse: page}
	restore := db.FindingEvidencePacket{Role: "supporting",
		HTTPRequest:  "GET /vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change HTTP/1.1\r\nHost: lab",
		HTTPResponse: page}
	class, name := "Cross-Site Request Forgery (CWE-352)", "DVWA CSRF：攻击者可构造跨站请求改密"
	if evidencePacketScore(attack, class, name) <= evidencePacketScore(restore, class, name) {
		t.Fatal("CSRF cleanup request must not earn the XSS reflection bonus from 跨站 in the finding name")
	}
}

func TestHydrateFindingRawHTTPPrefersSuccessfulLogin(t *testing.T) {
	stage := t.TempDir()
	failHash, failLen := writeEvidenceBlob(t, stage, "Username and/or password incorrect.")
	okHash, okLen := writeEvidenceBlob(t, stage, "Welcome to the password protected area admin")
	bindings := []db.FindingTrafficBinding{
		{ID: 21, Role: "proof", Snapshot: db.TrafficEvidenceSnapshot{ID: "failed", ReqHead: "GET /vulnerabilities/brute/?username=admin&password=wrong2 HTTP/1.1\nHost: lab", RespHead: "HTTP/1.1 200 OK\nContent-Type: text/html", RespHash: failHash, RespLen: failLen}},
		{ID: 22, Role: "proof", Snapshot: db.TrafficEvidenceSnapshot{ID: "success", ReqHead: "GET /vulnerabilities/brute/?username=admin&password=password HTTP/1.1\nHost: lab", RespHead: "HTTP/1.1 200 OK\nContent-Type: text/html", RespHash: okHash, RespLen: okLen}},
	}
	fs := []*db.DBFinding{{
		Name:            "DVWA Brute Force",
		VulnClass:       "Broken Authentication / Brute Force",
		TrafficBindings: bindings,
	}}
	hydrateFindingRawHTTP(fs, stage)
	if !strings.Contains(fs[0].HTTPResponse, "Welcome to the password protected area") {
		t.Fatalf("successful exchange must become the primary packet, got %q", fs[0].HTTPResponse)
	}
	if len(fs[0].EvidencePackets) != 2 {
		t.Fatalf("all exchanges must stay in the report, got %d", len(fs[0].EvidencePackets))
	}
	for _, packet := range fs[0].EvidencePackets {
		if packet.Primary != (packet.BindingID == 22) {
			t.Fatalf("unexpected primary flag on binding #%d", packet.BindingID)
		}
	}
}

func TestHydrateFindingRawHTTPMergesRepeatedRoundCaptures(t *testing.T) {
	stage := t.TempDir()
	step := func(id int64, snapID, head, respHash string) db.FindingTrafficBinding {
		return db.FindingTrafficBinding{ID: id, Role: "proof", Snapshot: db.TrafficEvidenceSnapshot{
			ID: snapID, Method: "GET", URL: "http://lab/vul/xss/xss_reflected_get.php", Status: 200,
			ReqHead: head, RespHead: "HTTP/1.1 200 OK", RespHash: respHash, ReqLen: 70, RespLen: 200,
		}}
	}
	bindings := []db.FindingTrafficBinding{
		step(31, "round1", "GET /vul/xss/xss_reflected_get.php?name=%3Cscript%3E1%3C%2Fscript%3E HTTP/1.1\nCookie: PHPSESSIONID=aaaaaaa", "hash-a"),
		step(32, "round2", "GET /vul/xss/xss_reflected_get.php?name=%3Cscript%3E1%3C%2Fscript%3E HTTP/1.1\nCookie: PHPSESSIONID=bbbbbbb", "hash-a"),
		db.FindingTrafficBinding{ID: 33, Role: "supporting", Snapshot: db.TrafficEvidenceSnapshot{
			ID: "round2-cleanup", Method: "GET", URL: "http://lab/vul/xss/xss_reflected_get.php?name=zz", Status: 200,
			ReqHead: "GET /vul/xss/xss_reflected_get.php?name=zz HTTP/1.1", RespHead: "HTTP/1.1 200 OK", RespHash: "hash-b", ReqLen: 40, RespLen: 180,
		}},
	}
	fs := []*db.DBFinding{{Name: "反射型XSS", VulnClass: "XSS", TrafficBindings: bindings}}
	hydrateFindingRawHTTP(fs, stage)

	packets := fs[0].EvidencePackets
	if len(packets) != 2 {
		t.Fatalf("same step replayed in a later round must merge into one entry, got %d", len(packets))
	}
	if fs[0].EvidencePacketOmitted != 0 {
		t.Fatalf("merged repeats are shown, not omitted: %d", fs[0].EvidencePacketOmitted)
	}
	merged := packets[0]
	if merged.BindingID != 32 || merged.Repeated != 1 {
		t.Fatalf("expected newest capture with 1 repeat folded in, got #%d repeated=%d", merged.BindingID, merged.Repeated)
	}
	if !strings.Contains(merged.HTTPRequest, "PHPSESSIONID=bbbbbbb") {
		t.Fatalf("merged entry must show the latest capture, got %q", merged.HTTPRequest)
	}
	if !packets[0].Primary {
		t.Fatalf("the proof step must outrank the cleanup request")
	}
}

func TestHydrateFindingRawHTTPCapsReproductionSequence(t *testing.T) {
	bindings := make([]db.FindingTrafficBinding, 0, 12)
	for i := 0; i < 12; i++ {
		head := fmt.Sprintf("GET /vul/sql/sqli_1.php?id=%d HTTP/1.1", i)
		resp := "HTTP/1.1 200 OK"
		if i == 9 {
			resp = "HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash"
		}
		bindings = append(bindings, db.FindingTrafficBinding{
			ID: int64(100 + i), Role: "supporting", Snapshot: db.TrafficEvidenceSnapshot{
				ID: fmt.Sprintf("snap-%02d", i), Method: "GET", URL: fmt.Sprintf("http://lab/vul/sql/sqli_1.php?id=%d", i),
				Status: 200, ReqHead: head, RespHead: resp, RespHash: fmt.Sprintf("hash-%02d", i), ReqLen: int64(30 + i), RespLen: int64(400 + i),
			}})
	}
	fs := []*db.DBFinding{{Name: "SQL注入", VulnClass: "SQL Injection", TrafficBindings: bindings}}
	hydrateFindingRawHTTP(fs, t.TempDir())

	packets := fs[0].EvidencePackets
	if len(packets) != maxEvidencePacketsPerFinding {
		t.Fatalf("sequence must be bounded at %d, got %d", maxEvidencePacketsPerFinding, len(packets))
	}
	if fs[0].EvidencePacketOmitted != 12-maxEvidencePacketsPerFinding {
		t.Fatalf("omitted must count the unshown steps, got %d", fs[0].EvidencePacketOmitted)
	}
	primary := -1
	for i, packet := range packets {
		if packet.Primary {
			primary = i
		}
	}
	if primary < 0 {
		t.Fatal("primary packet must survive the cap")
	}
	if !strings.Contains(packets[primary].HTTPResponse, "root:x:0:0:") {
		t.Fatalf("the decisive packet must be kept and primary, got %q", packets[primary].HTTPResponse)
	}
	for i := 1; i < len(packets); i++ {
		if packets[i].Snapshot.ID < packets[i-1].Snapshot.ID {
			t.Fatalf("kept packets must stay in wire order: %s after %s", packets[i].Snapshot.ID, packets[i-1].Snapshot.ID)
		}
	}
}

func TestHydrateFindingRawHTTPPrefersProofAndKeepsExisting(t *testing.T) {
	bindings := []db.FindingTrafficBinding{
		{ID: 11, Role: "baseline", Snapshot: db.TrafficEvidenceSnapshot{ID: "base", ReqHead: "GET /baseline HTTP/1.1\nHost: lab"}},
		{ID: 12, Role: "proof", Snapshot: db.TrafficEvidenceSnapshot{ID: "proof", ReqHead: "GET /proof HTTP/1.1\nHost: lab", RespHead: "HTTP/1.1 200 OK"}},
	}
	fs := []*db.DBFinding{
		{TrafficBindings: bindings},
		{HTTPRequest: "GET /kept HTTP/1.1", HTTPResponse: "HTTP/1.1 204 No Content", TrafficBindings: bindings},
	}
	hydrateFindingRawHTTP(fs, t.TempDir())
	if !strings.Contains(fs[0].HTTPRequest, "GET /proof") {
		t.Fatalf("expected proof request, got %q", fs[0].HTTPRequest)
	}
	if !strings.HasPrefix(fs[0].HTTPResponse, "HTTP/1.1 200 OK") {
		t.Fatalf("expected proof response, got %q", fs[0].HTTPResponse)
	}
	if fs[1].HTTPRequest != "GET /kept HTTP/1.1" || fs[1].HTTPResponse != "HTTP/1.1 204 No Content" {
		t.Fatalf("existing packets must be preserved, got %q / %q", fs[1].HTTPRequest, fs[1].HTTPResponse)
	}
	if len(fs[0].EvidencePackets) != 2 {
		t.Fatalf("expected both bindings hydrated, got %d", len(fs[0].EvidencePackets))
	}
	primary, extras := 0, 0
	for _, packet := range fs[0].EvidencePackets {
		if packet.Primary {
			primary++
			if packet.BindingID != 12 {
				t.Fatalf("proof binding must be primary, got #%d", packet.BindingID)
			}
		} else {
			extras++
			if packet.BindingID != 11 {
				t.Fatalf("baseline must be listed as an extra packet, got #%d", packet.BindingID)
			}
		}
	}
	if primary != 1 || extras != 1 {
		t.Fatalf("unexpected primary/extra split: %d/%d", primary, extras)
	}
}
