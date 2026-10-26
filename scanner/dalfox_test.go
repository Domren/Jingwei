package scanner

import "testing"

// dalfoxRealReport is trimmed from an actual dalfox 3.2.4 `-f json` run against
// the Pikachu lab (xss_reflected_get.php?message=): key names and the
// request/response split (request line + Host only, body-only response) are the
// reason the deep task replays the proving request itself.
const dalfoxRealReport = `{
  "findings": [
    {
      "confidence": "high",
      "confidence_reason": "payload reached an executable position in the parsed response",
      "cwe": "CWE-79",
      "data": "http://192.0.2.4/vul/xss/xss_reflected_get.php?message=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx4dead6fa%3E&submit=submit",
      "detection_method": "reflection",
      "evidence": "DOM verification successful for param message (DOM marker)",
      "inject_type": "inHTML",
      "location": "Query",
      "message_id": 606,
      "message_str": "Triggered XSS Payload (DOM marker): message=<svg onload=alert(1) class=dlx4dead6fa>",
      "method": "GET",
      "param": "message",
      "payload": "<svg onload=alert(1) class=dlx4dead6fa>",
      "request": "GET /vul/xss/xss_reflected_get.php?message=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx4dead6fa%3E&submit=submit HTTP/1.1\r\nHost: 192.0.2.4\r\n",
      "response": "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<title>Get the pikachu</title>\n<body>",
      "severity": "High",
      "type": "V",
      "type_description": "Vulnerable - dalfox asserts this input is exploitable; act on it"
    }
  ],
  "meta": {
    "dalfox_version": "3.2.4",
    "dedup_mode": "exact",
    "failed_requests": 0,
    "findings_count": 1,
    "incomplete": false,
    "scan_duration_ms": 41,
    "total_requests": 46
  }
}`

func TestDalfoxParseRealReport(t *testing.T) {
	var run DalfoxRun
	run.ParseReport([]byte(dalfoxRealReport))
	if len(run.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(run.Findings))
	}
	f := run.Findings[0]
	if f.Param != "message" || f.Location != "Query" || f.Method != "GET" {
		t.Errorf("point = %q/%q/%q", f.Param, f.Location, f.Method)
	}
	if f.URL == "" || f.Payload == "" || f.Request == "" {
		t.Errorf("missing payload material: %+v", f)
	}
	if f.Verdict() != "verified" {
		t.Errorf("verdict = %q, want verified", f.Verdict())
	}
	if run.Version != "3.2.4" || run.FailedRequests != 0 || run.Incomplete {
		t.Errorf("meta = %q %d %v", run.Version, run.FailedRequests, run.Incomplete)
	}
	if run.Err != nil {
		t.Errorf("unexpected error: %v", run.Err)
	}
	if run.Vulnerable() != 1 {
		t.Errorf("vulnerable = %d", run.Vulnerable())
	}
}

func TestDalfoxVerdictMapping(t *testing.T) {
	cases := []struct {
		typ, confidence, want string
	}{
		{"V", "high", "verified"},
		{"R", "medium", "reflected"},
		{"A", "low", "dom_candidate"},
		{"I", "low", "informational"},
		{"", "high", "verified"},
		{"", "low", "reflected"},
	}
	for _, tc := range cases {
		f := DalfoxFinding{Type: tc.typ, Confidence: tc.confidence}
		if got := f.Verdict(); got != tc.want {
			t.Errorf("type=%q confidence=%q → %q, want %q", tc.typ, tc.confidence, got, tc.want)
		}
	}
}

func TestDalfoxParseBrokenReport(t *testing.T) {
	var run DalfoxRun
	run.ParseReport([]byte("dalfox: command not found"))
	if len(run.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(run.Findings))
	}
	if run.Log == "" {
		t.Error("unparsable output should be kept in Log for the task record")
	}
}

func TestDalfoxRunVulnerableCountsOnlyVerified(t *testing.T) {
	run := DalfoxRun{Findings: []DalfoxFinding{{Type: "V"}, {Type: "R"}, {Type: "A"}}}
	if got := run.Vulnerable(); got != 1 {
		t.Fatalf("vulnerable = %d, want 1", got)
	}
}

// dalfox exits non-zero when the session it was handed does not authenticate, and
// explains itself per target in the report. Reading that as a crash would hide the
// one thing the operator can act on and would look like a verdict about the
// parameter itself.
func TestDalfoxReportKeepsSessionBlocker(t *testing.T) {
	var run DalfoxRun
	run.ParseReport([]byte(`{"findings":[],"meta":{"dalfox_version":"3.2.4","failed_requests":0,"incomplete":true,` +
		`"target_summary":[{"target":"http://lab/vul/xss/xssblind/admin.php","error_code":"SESSION_LOST",` +
		`"error_message":"preflight response already looks unauthenticated (HTTP 302)","status":"incomplete"}]}}`))
	if !run.Incomplete {
		t.Error("incomplete flag lost")
	}
	blocker, ok := run.Blocked("http://lab/vul/xss/xssblind/admin.php")
	if !ok || !blocker.NeedsSession() {
		t.Fatalf("session blocker lost: %#v", run.Blockers)
	}
	multi := DalfoxRun{Blockers: []DalfoxBlocker{
		{Target: "http://lab/a", ErrorCode: "SESSION_LOST"},
		{Target: "http://lab/b", ErrorCode: "DNS_ERROR", ErrorMessage: "no such host"},
	}}
	if _, ok := multi.Blocked("http://lab/c"); ok {
		t.Error("blocker attributed to a target dalfox never reported")
	}
	if b, _ := multi.Blocked("http://lab/b"); b.NeedsSession() {
		t.Error("a network failure read as a missing login")
	}
	var crash DalfoxRun
	crash.ParseReport([]byte(`{"findings":[],"meta":{"incomplete":false}}`))
	if _, ok := crash.Blocked("http://lab/a"); ok {
		t.Error("crash reported as a blocker")
	}
}
