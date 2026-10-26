package verdict

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		id   string
		name string
		tags []string
		want Class
	}{
		{"CVE-2021-44228", "Apache Log4j RCE", []string{"rce", "log4j"}, ClassDeserialization},
		{"tech-detect", "Spring Boot actuator", []string{"exposure"}, ClassInfoLeak},
		{"CVE-2022-0001", "SQL injection", nil, ClassSQLi},
		{"CVE-2020-0002", "Reflected XSS", []string{"xss"}, ClassXSS},
		{"CVE-2019-0003", "SSRF", nil, ClassSSRF},
		{"CVE-2018-0004", "OS command injection", nil, ClassCommandInject},
		{"file-upload-check", "Arbitrary file upload", nil, ClassFileUpload},
		{"auth-bypass", "Admin panel access control", nil, ClassAuthBypass},
		{"unknown", "Something", []string{"misc"}, ClassGeneric},
	}
	for _, tc := range cases {
		if got := Classify(tc.id, tc.name, tc.tags); got != tc.want {
			t.Errorf("Classify(%q,%q,%v) = %q, want %q", tc.id, tc.name, tc.tags, got, tc.want)
		}
	}
}

func TestParseMatcherProfile(t *testing.T) {
	statusOnly := `
id: weak-check
type: http
requests:
  - matchers:
      - type: status
        status:
          - 200
`
	p := ParseMatcherProfile(statusOnly)
	if p == nil || !p.StatusOnly {
		t.Fatalf("expected status-only profile, got %+v", p)
	}

	mixed := `
id: strong-check
type: http
requests:
  - matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["root:x:0:0"]
`
	p = ParseMatcherProfile(mixed)
	if p == nil || p.StatusOnly || !p.HasWord || !p.HasStatus {
		t.Fatalf("expected mixed profile, got %+v", p)
	}

	if p := ParseMatcherProfile("just some text"); p != nil {
		t.Fatalf("expected nil profile, got %+v", p)
	}
}

func TestAssessConfirmed(t *testing.T) {
	d := Assess(Observation{
		TemplateID: "CVE-2024-0001",
		Name:       "SQL injection",
		Type:       "http",
		StatusCode: 200,
		Response:   "admin password hash leaked",
		Extracted:  []string{"admin"},
		Matcher:    &MatcherProfile{HasStatus: true, HasWord: true},
	})
	if d.Verdict != Confirmed {
		t.Fatalf("verdict = %q, reasons=%v", d.Verdict, d.Reasons)
	}
	if d.Class != ClassSQLi {
		t.Fatalf("class = %q", d.Class)
	}
	if len(d.Checks) == 0 {
		t.Fatal("checks empty")
	}
}

func TestAssessWeakEvidence(t *testing.T) {
	cases := []struct {
		name string
		obs  Observation
		want Class
	}{
		{
			name: "status only matcher",
			obs: Observation{
				TemplateID: "tech-check", Name: "Generic check", Type: "http",
				StatusCode: 200, Response: "ok",
				Matcher: &MatcherProfile{HasStatus: true, StatusOnly: true},
			},
			want: ClassGeneric,
		},
		{
			name: "server error",
			obs: Observation{
				TemplateID: "CVE-2024-0001", Name: "SQL injection", Type: "http",
				StatusCode: 500, Response: "error", Extracted: []string{"x"},
			},
			want: ClassSQLi,
		},
		{
			name: "missing response",
			obs: Observation{
				TemplateID: "xss-check", Name: "Reflected XSS", Type: "http",
				StatusCode: 200, Extracted: []string{"alert(1)"},
			},
			want: ClassXSS,
		},
		{
			name: "xss without reflection evidence",
			obs: Observation{
				TemplateID: "xss-check", Name: "Reflected XSS", Type: "http",
				StatusCode: 200, Response: "<html>ok</html>",
				Matcher: &MatcherProfile{HasDSL: true},
			},
			want: ClassXSS,
		},
		{
			name: "short info leak",
			obs: Observation{
				TemplateID: "exposure-check", Name: "Sensitive file exposure", Type: "http",
				StatusCode: 200, Response: "ok",
				Matcher: &MatcherProfile{HasWord: true},
			},
			want: ClassInfoLeak,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Assess(tc.obs)
			if d.Verdict != NeedsReview {
				t.Fatalf("verdict = %q, want needs_review", d.Verdict)
			}
			if d.Class != tc.want {
				t.Fatalf("class = %q, want %q", d.Class, tc.want)
			}
			if len(d.Reasons) == 0 {
				t.Fatal("reasons empty")
			}
		})
	}
}

func TestChecklistCopiesDefaults(t *testing.T) {
	a := Checklist(ClassSQLi)
	if len(a) == 0 {
		t.Fatal("empty checklist")
	}
	a[0] = "mutated"
	b := Checklist(ClassSQLi)
	if strings.EqualFold(b[0], "mutated") {
		t.Fatal("checklist shares backing array with defaults")
	}
}
