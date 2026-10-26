package scanner

import (
	"strings"
	"testing"
)

// nuclei prints info.tags as an array. Reading it as a string returned no tags at
// all, which left injection routing to the template name alone, so a CSRF check
// living on a page called sqli_edit.php was handed to sqlmap.
func TestParseNucleiJSONLReadsTagArray(t *testing.T) {
	raw := `{"template-id":"pikachu-sqli-iu-edit","matched-at":"http://lab/vul/sqli/sqli_iu/sqli_edit.php","type":"http","info":{"name":"Pikachu - Profile Update Without Anti-CSRF Token (sqli_edit)","severity":"medium","tags":["pikachu","csrf","test"]}}` + "\n" +
		`{"template-id":"pikachu-sqli-id","matched-at":"http://lab/vul/sqli/sqli_id.php","type":"http","info":{"name":"Pikachu - SQL Injection in Numeric POST Parameter (sqli_id)","severity":"high","tags":["pikachu","sqli","test"]}}` + "\n" +
		`{"template-id":"legacy","matched-at":"http://lab/x","type":"http","info":{"name":"Legacy","severity":"info","tags":"xss,test"}}`

	results := ParseNucleiJSONL(raw)
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	if got := results[0].Tags; len(got) != 3 || got[0] != "pikachu" || got[1] != "csrf" {
		t.Fatalf("array tags = %v", got)
	}
	if got := results[2].Tags; len(got) != 2 || got[0] != "xss" {
		t.Fatalf("string tags = %v", got)
	}
	// The routing decision the tags exist for.
	if class := ClassifyInjection(results[0].Name, strings.Join(results[0].Tags, ",")); class != "" {
		t.Errorf("csrf template routed to %q; sqlmap must not judge it", class)
	}
	if class := ClassifyInjection(results[1].Name, strings.Join(results[1].Tags, ",")); class != InjectionSQLi {
		t.Errorf("sqli template routed to %q", class)
	}
}
