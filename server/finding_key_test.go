package server

import (
	"testing"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

func TestFindingDedupeKey(t *testing.T) {
	cases := []struct {
		name     string
		template string
		url      string
		want     string
	}{
		{
			name:     "normalizes host port and query",
			template: "CVE-2024-0001",
			url:      "HTTPS://App.Example.com:443/api/Query?name=x#frag",
			want:     "v1|CVE-2024-0001|https://app.example.com/api/Query",
		},
		{
			name:     "keeps non-default port and root path",
			template: "CVE-2024-0002",
			url:      "http://app.example.com:8080?q=1",
			want:     "v1|CVE-2024-0002|http://app.example.com:8080/",
		},
		{
			name:     "non-web target falls back to raw",
			template: "redis-unauth",
			url:      "10.0.0.1:6379",
			want:     "v1|redis-unauth|10.0.0.1:6379",
		},
		{
			name:     "empty template never dedupes",
			template: " ",
			url:      "https://a.example.com/",
			want:     "",
		},
		{
			name:     "empty target never dedupes",
			template: "x",
			url:      "",
			want:     "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := findingDedupeKey(tc.template, tc.url); got != tc.want {
				t.Fatalf("findingDedupeKey = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFindingDedupeKeyMergesSameEndpoint(t *testing.T) {
	a := findingDedupeKey("CVE-2024-0001", "https://a.example.com/api/query?name=x")
	b := findingDedupeKey("CVE-2024-0001", "https://a.example.com/api/query?name=y")
	if a != b {
		t.Fatalf("same endpoint should dedupe: %q vs %q", a, b)
	}
	c := findingDedupeKey("CVE-2024-0002", "https://a.example.com/api/query?name=x")
	if a == c {
		t.Fatal("different templates must not dedupe")
	}
}

func TestAssessNucleiHitWeakMatcher(t *testing.T) {
	tpl := db.POCTemplate{
		TemplateID: "weak-check",
		Name:       "Generic endpoint check",
		Content: `
id: weak-check
type: http
requests:
  - matchers:
      - type: status
        status: [200]
`,
	}
	res := scanner.NucleiResult{
		TemplateID: "weak-check",
		Type:       "http",
		MatchedAt:  "https://a.example.com/",
		Raw:        map[string]any{"response-code": float64(200), "response": "ok"},
	}
	d := assessNucleiHit(res, tpl)
	if d.Verdict != "needs_review" {
		t.Fatalf("verdict = %q, reasons=%v", d.Verdict, d.Reasons)
	}
}

func TestAssessNucleiHitConfirmedTemplate(t *testing.T) {
	tpl := db.POCTemplate{
		TemplateID: "CVE-2024-0001",
		Name:       "SQL injection",
		Tags:       []string{"sqli"},
		Content: `
id: CVE-2024-0001
type: http
requests:
  - matchers:
      - type: word
        words: ["root:x:0:0"]
`,
	}
	res := scanner.NucleiResult{
		TemplateID: "CVE-2024-0001",
		Type:       "http",
		MatchedAt:  "https://a.example.com/item?id=1",
		Extracted:  []string{"root"},
		Raw:        map[string]any{"response-code": float64(200), "response": "root:x:0:0"},
	}
	d := assessNucleiHit(res, tpl)
	if d.Verdict != "confirmed" {
		t.Fatalf("verdict = %q, reasons=%v", d.Verdict, d.Reasons)
	}
	if d.Class != "sqli" {
		t.Fatalf("class = %q", d.Class)
	}
}

func TestTemplateFindingIDs(t *testing.T) {
	params := map[string]any{
		"finding_ids_by_template": map[string]any{
			"CVE-1": []any{float64(11), float64(12)},
			"CVE-2": []int64{21},
		},
	}
	if got := templateFindingIDs(params, "CVE-1"); len(got) != 2 || got[0] != 11 || got[1] != 12 {
		t.Fatalf("CVE-1 = %v", got)
	}
	if got := templateFindingIDs(params, "CVE-2"); len(got) != 1 || got[0] != 21 {
		t.Fatalf("CVE-2 = %v", got)
	}
	if got := templateFindingIDs(params, "missing"); len(got) != 0 {
		t.Fatalf("missing = %v", got)
	}
	flat := map[string]any{"finding_ids": []any{float64(7), "8"}}
	if got := templateFindingIDs(flat, "any"); len(got) != 2 || got[0] != 7 || got[1] != 8 {
		t.Fatalf("flat = %v", got)
	}
}
