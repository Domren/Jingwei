package scanner

import (
	"strings"
	"testing"
)

// TestShellV2FileOpTemplates checks every v2 runtime ships the big-shell file
// manager: the F dispatch plus the guards that keep the channel alive. Template
// identifiers get polymorphized, so only protocol literals are asserted.
func TestShellV2FileOpTemplates(t *testing.T) {
	key, err := GenerateShellKey()
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := GenerateShellCarrier()
	if err != nil {
		t.Fatal(err)
	}
	dispatch := map[string]string{
		"php":  "=== 'F'",
		"jsp":  `"F".equals(op)`,
		"aspx": `op == "F"`,
	}
	// Identifiers are polymorphized, so the token-fallback assertions use only
	// framework literals: header first, then the form/query field.
	tokenRead := map[string][]string{
		"php":  {"$_SERVER[", "isset($_POST[", "isset($_GET["},
		"jsp":  {"request.getHeader(", "request.getParameter("},
		"aspx": {"Request.Headers[", "Request.Form[", "Request.QueryString["},
	}
	for shellType, marker := range dispatch {
		payload, err := BuildShellPayloadV2(shellType, key, carrier)
		if err != nil {
			t.Fatalf("%s: %v", shellType, err)
		}
		wants := append([]string{
			marker,
			"not a directory",
			"refuse to delete root",
			"shell file is protected",
			"mkdir",
			"rename",
			"chmod",
		}, tokenRead[shellType]...)
		for _, want := range wants {
			if !strings.Contains(payload.Content, want) {
				t.Fatalf("%s payload is missing file-manager piece %q", shellType, want)
			}
		}
		if strings.Contains(payload.Content, "{{") {
			t.Fatalf("%s payload left an unresolved template placeholder", shellType)
		}
	}
	prepend, err := BuildPHPSemiPersistPayloadV2(key, carrier)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"=== 'F'", "shell file is protected", "chmod", "isset($_GET["} {
		if !strings.Contains(prepend.Content, want) {
			t.Fatalf("php_prepend payload is missing file-manager piece %q", want)
		}
	}
}
