package scanner

import (
	"strings"
	"testing"
)

// sqlmapRealRun is the tail of an actual sqlmap 1.10.10 detection run against
// the Pikachu lab (sqli_str.php?name=). It is kept verbatim because the parser
// matches on sqlmap's exact layout: one "Parameter:" line followed by several
// Type/Title/Payload groups.
const sqlmapRealRun = `[11:33:52] [INFO] testing connection to the target URL
[11:33:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
sqlmap identified the following injection point(s) with a total of 73 HTTP(s) requests:
---
Parameter: name (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: name=1' AND 1400=(SELECT (CASE WHEN (1400=1400) THEN 1400 ELSE (SELECT 5476 UNION SELECT 7512) END))-- -&submit=\xe6\x9f\xa5\xe8\xaf\xa2

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: name=1' AND GTID_SUBSET(CONCAT(0x71766b7871,(SELECT (ELT(2899=2899,1))),0x71626a7a71),2899)-- Lkqv&submit=\xe6\x9f\xa5\xe8\xaf\xa2

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: name=1' UNION ALL SELECT NULL,CONVERT(CONCAT(0x71766b7871,0x4c4d7467735a6974677869775a484f784672565a704350465651517a534d6a4355477459556f7a61,0x71626a7a71) USING utf8mb4) COLLATE utf8mb4_bin-- -&submit=\xe6\x9f\xa5\xe8\xaf\xa2
---
[03:34:05] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.10 or 19.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.6
`

func TestParseSQLMapOutputRealRun(t *testing.T) {
	injections, dbms, tech, osName := ParseSQLMapOutput(sqlmapRealRun)
	if len(injections) != 3 {
		t.Fatalf("injections = %d, want 3: %+v", len(injections), injections)
	}
	first := injections[0]
	if first.Param != "name" || first.Where != "GET" {
		t.Errorf("first point = %q (%q)", first.Param, first.Where)
	}
	if first.Type != "boolean-based blind" {
		t.Errorf("first type = %q", first.Type)
	}
	if !strings.HasPrefix(first.Payload, "name=1' AND 1400=") {
		t.Errorf("first payload = %q", first.Payload)
	}
	// sqlmap prints the Chinese submit value as \xNN; the replay needs %XX.
	if !strings.HasSuffix(first.Payload, "&submit=%E6%9F%A5%E8%AF%A2") {
		t.Errorf("first payload not re-encoded: %q", first.Payload)
	}
	if strings.Contains(first.Payload, `\x`) {
		t.Errorf("escape sequence left in payload: %q", first.Payload)
	}
	if injections[1].Type != "error-based" || injections[2].Type != "UNION query" {
		t.Errorf("types = %q / %q", injections[1].Type, injections[2].Type)
	}
	if injections[1].Param != "name" || injections[2].Where != "GET" {
		t.Errorf("later points lost their parameter: %+v", injections[1:])
	}
	if dbms != "MySQL >= 5.6" {
		t.Errorf("dbms = %q", dbms)
	}
	if tech != "Apache 2.4.41" {
		t.Errorf("tech = %q", tech)
	}
	if !strings.HasPrefix(osName, "Linux Ubuntu") {
		t.Errorf("os = %q", osName)
	}
}

func TestParseSQLMapOutputNegativeAndEmpty(t *testing.T) {
	negative := `[INFO] the back-end DBMS is MySQL
[WARNING] parameter 'id' does not seem to be injectable
`
	if got, _, _, _ := ParseSQLMapOutput(negative); got != nil {
		t.Errorf("negative run parsed injections: %+v", got)
	}
	if got, _, _, _ := ParseSQLMapOutput("banner only, no section"); got != nil {
		t.Errorf("unrelated output parsed injections: %+v", got)
	}
}

func TestParseSQLMapOutputRequiresPayload(t *testing.T) {
	// A proved point without a printed payload cannot be replayed, so it is
	// dropped instead of producing an empty packet pair.
	text := sqlmapBanner + `
---
Parameter: id (GET)
    Type: stacked queries
    Title: MySQL > 5.0.11 stacked queries (comment)
---
`
	if got, _, _, _ := ParseSQLMapOutput(text); len(got) != 0 {
		t.Errorf("payload-less point parsed: %+v", got)
	}
}

func TestDecodeSQLMapEscapes(t *testing.T) {
	got := decodeSQLMapEscapes(`a=\xe6\x9f\xa5%27\xf`)
	if got != `a=%E6%9F%A5%27\xf` {
		t.Fatalf("decoded = %q", got)
	}
}

func TestNormalizeRawRequestForTool(t *testing.T) {
	got := normalizeRawRequestForTool("GET /a?id=1 HTTP/1.1\nHost: x\n\n")
	if got != "GET /a?id=1 HTTP/1.1\r\nHost: x\r\n\r\n" {
		t.Fatalf("normalized = %q", got)
	}
	if !strings.HasSuffix(normalizeRawRequestForTool("POST /a HTTP/1.1\r\nHost: x\r\n"), "\r\n\r\n") {
		t.Fatal("missing body separator")
	}
}

func TestSanitizeToolArgs(t *testing.T) {
	if got := sanitizeTechniques("beu'SQT; rm"); got != "BEUSQT" {
		t.Errorf("techniques = %q", got)
	}
	if got := sanitizeParamList([]string{"id", "na me", "", "x'", "a", "b", "c", "d", "e", "f", "g", "h"}); got != "id,name,x,a,b,c,d,e,f,g" {
		t.Errorf("params = %q", got)
	}
	if got := sanitizeWord("mysql'--"); got != "mysql--" {
		t.Errorf("word = %q", got)
	}
}

func TestClampToolOptions(t *testing.T) {
	if got := clampRange(0, 1, 5, 3); got != 3 {
		t.Errorf("zero should fall back to default, got %d", got)
	}
	if got := clampRange(-2, 1, 5, 3); got != 3 {
		t.Errorf("negative should fall back to default, got %d", got)
	}
	if got := clampRange(99, 1, 5, 3); got != 5 {
		t.Errorf("above max, got %d", got)
	}
	if got := clampOptional(0, 0, 3); got != 0 {
		t.Errorf("zero is a valid --retries value, got %d", got)
	}
	if got := clampOptional(-5, 0, 3); got != 0 {
		t.Errorf("below min, got %d", got)
	}
}
