package scanner

import (
	"regexp"
	"strings"
)

// Injection classes handled by a dedicated verifier instead of a POC template.
const (
	InjectionSQLi = "sqli"
	InjectionXSS  = "xss"
)

// sqliMarkers are substrings that identify a template as a SQL-injection check.
// Bare "sql" is deliberately absent: fingerprint templates such as mysql-user
// or mssql-info carry it without testing an injection point.
var sqliMarkers = []string{
	"sqli", "sql-inject", "sql_inject", "sql injection", "sqlinject",
	"blind-sql", "blind sql", "error-based", "union-select", "union select",
	"order-by-inject", "time-based-sql", "sqli-error", "sql-time-based",
}

// xssMarkers identify a template as a cross-site-scripting check.
var xssMarkers = []string{
	"xss", "cross-site-scripting", "cross site scripting", "reflected-xss",
	"stored-xss", "dom-xss", "blind-xss", "html-injection",
}

// nonInjectionTags name a weakness that sqlmap and dalfox cannot judge. When one
// of them appears in a template's tags the template is describing that weakness,
// so routing it to an injection tool would waste the budget and, worse, let a
// tool's negative verdict demote a true finding. Pikachu's login pages are the
// concrete case: they live under /vul/sqli/ and are named "(sqli_iu_login)", so
// the marker scan below would read the endpoint slug as a SQL-injection claim
// even though the template only proves weak credentials.
// "authenticated" and "intrusive" are deliberately absent: they describe how a
// request is made, not what the template proves.
var nonInjectionTags = map[string]bool{
	"auth":           true,
	"default-login":  true,
	"csrf":           true,
	"burteforce":     true, // lab templates keep nuclei's spelling
	"brute-force":    true,
	"overpermission": true,
}

// ClassifyInjection reports which specialized verifier should re-check a POC
// template, or "" when the template tests something else. A template that names
// both classes is treated as SQL injection: sqlmap produces the stronger,
// replayable proof for it.
func ClassifyInjection(parts ...string) string {
	hay := strings.ToLower(strings.Join(parts, " "))
	for _, tag := range parts {
		for _, want := range strings.Split(strings.ToLower(tag), ",") {
			switch strings.TrimSpace(want) {
			case "sqli", "mysql", "mssql", "oracle", "postgres", "sqlite", "nosql":
				return InjectionSQLi
			case "xss":
				return InjectionXSS
			}
		}
	}
	for _, tag := range parts {
		for _, want := range strings.Split(strings.ToLower(tag), ",") {
			if nonInjectionTags[strings.TrimSpace(want)] {
				return ""
			}
		}
	}
	for _, m := range sqliMarkers {
		if strings.Contains(hay, m) {
			return InjectionSQLi
		}
	}
	for _, m := range xssMarkers {
		if strings.Contains(hay, m) {
			return InjectionXSS
		}
	}
	return ""
}

// ToolForInjection returns the command line verifier for one class.
func ToolForInjection(class string) string {
	switch class {
	case InjectionSQLi:
		return "sqlmap"
	case InjectionXSS:
		return "dalfox"
	default:
		return ""
	}
}

// trailingSlug drops the "(sqli_id)" style endpoint hint Jingwei's own templates
// put at the end of a name. It is a template identifier, not a statement about
// what the finding claims.
var trailingSlug = regexp.MustCompile(`\([^()]*[a-z0-9][a-z0-9_-]*\)`)

// ClaimsInjection says whether a finding's own wording asserts an injection
// vulnerability of the class a specialized tool just tested. A template routed to
// sqlmap can still create a finding about weak credentials or a missing CSRF
// token (Pikachu's sqli_* pages do), and the tool's negative result says nothing
// about those, so such a finding must keep its status.
func ClaimsInjection(class string, parts ...string) bool {
	hay := strings.ToLower(strings.Join(parts, " "))
	if i := trailingSlug.FindAllStringIndex(hay, -1); len(i) > 0 {
		last := i[len(i)-1]
		hay = hay[:last[0]] + hay[last[1]:]
	}
	switch class {
	case InjectionSQLi:
		return (strings.Contains(hay, "injection") || strings.Contains(hay, "注入")) &&
			strings.Contains(hay, "sql")
	case InjectionXSS:
		return strings.Contains(hay, "xss") || strings.Contains(hay, "cross-site scripting") ||
			strings.Contains(hay, "cross site scripting") || strings.Contains(hay, "跨站")
	default:
		return false
	}
}
