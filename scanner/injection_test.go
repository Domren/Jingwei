package scanner

import "testing"

func TestClassifyInjection(t *testing.T) {
	cases := []struct {
		name  string
		parts []string
		want  string
	}{
		{"template id", []string{"pikachu-sqli-str"}, InjectionSQLi},
		{"name", []string{"some-id", "Blind SQL Injection - MySQL"}, InjectionSQLi},
		{"tag list", []string{"xss-reflected-get", "php, xss, reflected"}, InjectionXSS},
		{"sqli tag", []string{"cve-2019-0001", "cms, sqli, mysql"}, InjectionSQLi},
		{"blind sql name", []string{"t", "vBulletin blind-sql-time-based"}, InjectionSQLi},
		{"dom xss marker", []string{"t", "Dom XSS"}, InjectionXSS},
		// Fingerprint templates name a database without testing an injection.
		{"mysql fingerprint", []string{"mysql-fingerprint", "MySQL Detected"}, ""},
		{"unrelated", []string{"apache-status", "Apache Status"}, ""},
		{"both classes", []string{"t", "sqli and xss"}, InjectionSQLi},
		// A weakness tag outranks the endpoint slug living in the name.
		{
			"auth tag on a sqli page",
			[]string{"Pikachu - Weak Credentials Accepted (sqli_iu_login)", "pikachu,auth,test"},
			"",
		},
		{
			"csrf tag on a sqli page",
			[]string{"Pikachu - Profile Update Without Anti-CSRF Token (sqli_edit)", "pikachu,csrf,test"},
			"",
		},
		{
			"bruteforce tag on an xss page",
			[]string{"Pikachu - Login Without Server-side Throttling (xss_blind)", "pikachu,burteforce,test"},
			"",
		},
		// An injection tag still wins when the same template also declares how it
		// has to be requested.
		{
			"sqli tag with session tags",
			[]string{"Pikachu - SQL Injection in Cookie", "sqli,authenticated,intrusive"},
			InjectionSQLi,
		},
		{
			"sqli tag over auth tag",
			[]string{"Pikachu - SQL Injection in Numeric POST Parameter (sqli_id)", "pikachu,sqli,auth,test"},
			InjectionSQLi,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyInjection(tc.parts...); got != tc.want {
				t.Fatalf("ClassifyInjection(%q) = %q, want %q", tc.parts, got, tc.want)
			}
		})
	}
}

func TestToolForInjection(t *testing.T) {
	if got := ToolForInjection(InjectionSQLi); got != "sqlmap" {
		t.Errorf("sqli tool = %q", got)
	}
	if got := ToolForInjection(InjectionXSS); got != "dalfox" {
		t.Errorf("xss tool = %q", got)
	}
	if got := ToolForInjection(""); got != "" {
		t.Errorf("empty class tool = %q", got)
	}
}

func TestClaimsInjection(t *testing.T) {
	cases := []struct {
		class string
		text  string
		want  bool
	}{
		{InjectionSQLi, "Pikachu - SQL Injection in Numeric POST Parameter (sqli_id)", true},
		{InjectionSQLi, "Pikachu - Character-based Error SQL Injection (sqli_str)", true},
		{InjectionSQLi, "数字型 SQL 注入（sqli_id）", true},
		{InjectionSQLi, "Pikachu - Weak Credentials Accepted (sqli_iu_login)", false},
		{InjectionSQLi, "Pikachu - Profile Update Without Anti-CSRF Token (sqli_edit)", false},
		{InjectionSQLi, "Pikachu - Reflected XSS Filtering Bypass (xss_01)", false},
		{InjectionXSS, "Pikachu - XSS Inside Attribute Context (xss_02)", true},
		{InjectionXSS, "反射型跨站脚本（xss_01）", true},
		{InjectionXSS, "Pikachu - DOM XSS From PHP-reflected JS (xss_04)", true},
		{InjectionXSS, "Pikachu - SQL Injection in LIKE Clause (sqli_search)", false},
		{InjectionXSS, "Pikachu - Arbitrary File Download via Parameter (download_file)", false},
		{"", "Pikachu - SQL Injection (sqli_x)", false},
	}
	for _, c := range cases {
		if got := ClaimsInjection(c.class, c.text); got != c.want {
			t.Errorf("ClaimsInjection(%q, %q) = %v, want %v", c.class, c.text, got, c.want)
		}
	}
}
