package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scanner"
	"github.com/Autumn-27/artex/verdict"
)

func TestEncodeProbeQuery(t *testing.T) {
	cases := []struct{ in, want string }{
		{"id=1 AND 2=2", "id=1%20AND%202=2"},
		// Quotes stay literal (the server must see exactly what sqlmap sent);
		// only characters a query string cannot carry literally are escaped.
		{"name=1' UNION SELECT NULL-- -", "name=1'%20UNION%20SELECT%20NULL--%20-"},
		// Escapes sqlmap already produced must survive untouched.
		{"submit=%E6%9F%A5%E8%AF%A2", "submit=%E6%9F%A5%E8%AF%A2"},
		{"a=100%or 1=1", "a=100%25or%201=1"},
		{"x=<svg onload=alert(1)>", "x=%3Csvg%20onload=alert(1)%3E"},
		{"path=/a`b#c", "path=/a%60b%23c"},
	}
	for _, tc := range cases {
		if got := encodeProbeQuery(tc.in); got != tc.want {
			t.Errorf("encodeProbeQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWithProbeQueryReplacesQueryString(t *testing.T) {
	got := withProbeQuery("http://127.0.0.1:18080/vul/sqli/sqli_str.php?name=1&submit=x#frag",
		"name=1' AND 1400=(SELECT 1)-- -&submit=%E6%9F%A5%E8%AF%A2")
	want := "http://127.0.0.1:18080/vul/sqli/sqli_str.php?name=1'%20AND%201400=(SELECT%201)--%20-&submit=%E6%9F%A5%E8%AF%A2"
	if got != want {
		t.Fatalf("withProbeQuery = %q\nwant            %q", got, want)
	}
	if got := withProbeQuery("http://h/p", "id=1"); got != "http://h/p?id=1" {
		t.Fatalf("query-less url = %q", got)
	}
}

func TestMergeProbeCookie(t *testing.T) {
	got := mergeProbeCookie("PHPSESSID=abc", "id=1'")
	if len(got) != 1 || got[0] != "PHPSESSID=abc; id=1'" {
		t.Fatalf("merged = %v", got)
	}
	if got := mergeProbeCookie("", "session=1"); len(got) != 1 || got[0] != "session=1" {
		t.Fatalf("empty existing = %v", got)
	}
	if got := mergeProbeCookie("a=1", ""); len(got) != 1 || got[0] != "a=1" {
		t.Fatalf("empty payload = %v", got)
	}
}

func TestIsProbeHeaderName(t *testing.T) {
	for _, name := range []string{"User-Agent", "X-Forwarded-For", "Referer"} {
		if !isProbeHeaderName(name) {
			t.Errorf("%q should be a header", name)
		}
	}
	// sqlmap prints these as the injection location, but they are not headers.
	for _, name := range []string{"", "GET", "POST", "Cookie", "Host", "uri", "X Y", "A:B"} {
		if isProbeHeaderName(name) {
			t.Errorf("%q should not be a header", name)
		}
	}
}

// The packet written into the finding has to be the request that goes on the
// wire, so an already-encoded query must not be re-encoded by url parsing.
func TestProbeRequestTextIsWireFaithful(t *testing.T) {
	req := scanner.DeepRequest{
		Method:  "GET",
		URL:     "http://127.0.0.1:18080/vul/sqli/sqli_str.php?name=1'%20AND%201=1--%20-&submit=%E6%9F%A5%E8%AF%A2",
		Headers: map[string]string{"Referer": "http://127.0.0.1:18080/vul/sqli/"},
		Cookies: []string{"PHPSESSID=abc"},
	}
	got := probeRequestText(req)
	if !strings.HasPrefix(got, "GET /vul/sqli/sqli_str.php?name=1'%20AND%201=1--%20-&submit=%E6%9F%A5%E8%AF%A2 HTTP/1.1\r\n") {
		t.Fatalf("request line changed: %q", got)
	}
	if !strings.Contains(got, "Host: 127.0.0.1:18080\r\n") {
		t.Errorf("missing Host line: %q", got)
	}
	if !strings.Contains(got, "Cookie: PHPSESSID=abc\r\n") {
		t.Errorf("missing cookie: %q", got)
	}
	if !strings.Contains(got, "Referer: http://127.0.0.1:18080/vul/sqli/\r\n") {
		t.Errorf("missing header: %q", got)
	}
	if strings.Contains(got, "\r\n\r\n\r\n") {
		t.Errorf("extra blank line before body: %q", got)
	}
}

// A form-shaped body must travel with the Content-Type a browser would send, so
// the saved packet replays on servers that gate body parsing on that header.
func TestProbeBodyType(t *testing.T) {
	cases := []struct{ body, want string }{
		{"id=1&submit=1", "form"},
		{"id=1' AND 7390=7390-- -&submit=%E6%9F%A5%E8%AF%A2", "form"},
		{"user[name]=admin", "form"},
		{`{"id":"1"}`, "raw"},
		{"<a x=1/>", "raw"},
		{"eyJhbGciOi.eyJzdWIi.sig", "raw"},
		{"--boundary\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n1", "raw"},
		{"", "raw"},
	}
	for _, tc := range cases {
		if got := probeBodyType(tc.body); got != tc.want {
			t.Errorf("probeBodyType(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func TestProbeRequestTextPostBody(t *testing.T) {
	req := scanner.DeepRequest{Method: "post", URL: "http://h/p", Body: "id=1'", BodyType: "form"}
	got := probeRequestText(req)
	if !strings.HasPrefix(got, "POST /p HTTP/1.1\r\n") {
		t.Fatalf("request line = %q", got)
	}
	if !strings.Contains(got, "Content-Length: 5\r\n") || !strings.Contains(got, "Content-Type: application/x-www-form-urlencoded\r\n") {
		t.Errorf("missing body framing: %q", got)
	}
	if !strings.HasSuffix(got, "\r\n\r\nid=1'") {
		t.Errorf("body not appended: %q", got)
	}

	// A Content-Type the task supplied outranks the derived one, and it must not
	// be printed twice.
	req.Headers = map[string]string{"Content-Type": "application/json"}
	got = probeRequestText(req)
	if n := strings.Count(got, "Content-Type:"); n != 1 {
		t.Fatalf("Content-Type printed %d times: %q", n, got)
	}
	if !strings.Contains(got, "Content-Type: application/json\r\n") {
		t.Errorf("explicit Content-Type lost: %q", got)
	}
}

func TestProbePointsJSONRoundTrip(t *testing.T) {
	// The auto pipeline stores points as JSON; collectProbePoints must be able to
	// read that shape back, including the finding ids as JSON numbers.
	in := autoProbeParams([]probePoint{{
		URL: "http://h/p?id=1", Method: "POST", Body: "id=1'",
		TemplateID: "tpl", Source: "scan", FindingIDs: []int64{7, 8},
	}})
	raw, err := json.Marshal(map[string]any{"points": in})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	pts := mapSliceParam(back, "points")
	if len(pts) != 1 {
		t.Fatalf("points = %v", pts)
	}
	if got := stringFromMap(pts[0], "data"); got != "id=1'" {
		t.Errorf("data = %q", got)
	}
	if ids := idsFromAny(pts[0]["finding_ids"]); len(ids) != 2 || ids[0] != 7 || ids[1] != 8 {
		t.Errorf("finding ids = %v", ids)
	}
}

func TestProbeProofMarkers(t *testing.T) {
	sqlmap := `sqlmap/1.10.10#pip (https://sqlmap.org)'||(SELECT 0x7a687458 WHERE 2415=2415 AND GTID_SUBSET(CONCAT(0x7176787671,(SELECT (ELT(7712=7712,1))),0x7176627871),7712))||'`
	got := probeProofMarkers(sqlmap)
	want := map[string]bool{"zhtX": false, "qvxvq": false, "qvbxq": false}
	for _, m := range got {
		if _, ok := want[m]; !ok {
			t.Fatalf("unexpected marker %q in %v", m, got)
		}
		want[m] = true
	}
	for m, seen := range want {
		if !seen {
			t.Fatalf("marker %q missing from %v", m, got)
		}
	}
	dalfox := `<a class=dlx1a2b3 href=javascript:alert(1)>`
	if m := probeProofMarkers(dalfox); len(m) != 1 || m[0] != "dlx1a2b3" {
		t.Fatalf("dalfox markers = %v", m)
	}
	if m := probeProofMarkers("' AND SLEEP(5) AND '"); len(m) != 0 {
		t.Fatalf("time-based payload should carry no marker, got %v", m)
	}
	if m := probeProofMarkers("0x7f7f"); len(m) != 0 {
		t.Fatalf("non-printable hex decoded to %q", m)
	}
}

func TestProbeReplayProof(t *testing.T) {
	payload := `1' AND GTID_SUBSET(CONCAT(0x7176787671,(SELECT (ELT(7712=7712,1))),0x7176627871),7712)#`
	if proved, note := probeReplayProof(payload, "HTTP/1.1 200 OK\r\n\r\nerror near 'qvxvq1qvbxq'", 200); !proved || note != "" {
		t.Fatalf("proved = %v note = %q, want the marker hit to prove the replay", proved, note)
	}
	proved, note := probeReplayProof(payload, "HTTP/1.1 302 Found\r\nLocation: login.php\r\n\r\nGet the pikachu", 302)
	if proved {
		t.Fatal("a login redirect without the marker cannot count as proof")
	}
	if !strings.Contains(note, "qvxvq") || !strings.Contains(note, "cookie") {
		t.Fatalf("note = %q, want the missing marker and the session hint", note)
	}
	if proved, note := probeReplayProof("' AND SLEEP(5)#", "HTTP/1.1 200 OK\r\n\r\n", 200); !proved || note != "" {
		t.Fatalf("blind timing payloads have nothing to match: %v %q", proved, note)
	}
}

func TestSanitizeProbeTarget(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		body     string
		wantURL  string
		wantBody string
	}{
		{
			name:    "tainted blind payload reset to text",
			url:     "http://lab/vul/sqli/sqli_blind_b.php?name=kobe%27%20and%20if(substr(database(),1,7)%3D%27zzzzzzz%27,1,0)%23&submit=1",
			wantURL: "http://lab/vul/sqli/sqli_blind_b.php?name=test&submit=1",
		},
		{
			name:    "clean value kept",
			url:     "http://lab/vul/sqli/sqli_str.php?name=kobe&submit=1",
			wantURL: "http://lab/vul/sqli/sqli_str.php?name=kobe&submit=1",
		},
		{
			name:    "xss payload reset to text",
			url:     "http://lab/xss/xss_reflected_get.php?message=%3Cscript%3Ealert(1)%3C/script%3E&submit=1",
			wantURL: "http://lab/xss/xss_reflected_get.php?message=test&submit=1",
		},
		{
			name:     "post body sanitized",
			url:      "http://lab/vul/sqli/sqli_id.php",
			body:     "id=1%27%20union%20select%201&submit=1",
			wantURL:  "http://lab/vul/sqli/sqli_id.php",
			wantBody: "id=1&submit=1",
		},
		{
			name:     "json body untouched",
			url:      "http://lab/api/search",
			body:     `{"q":"<script>alert(1)</script>"}`,
			wantURL:  "http://lab/api/search",
			wantBody: `{"q":"<script>alert(1)</script>"}`,
		},
		{
			name:    "fragment stripped",
			url:     "http://lab/p.php?id=1#frag",
			wantURL: "http://lab/p.php?id=1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotURL, gotBody := sanitizeProbeTarget(tc.url, tc.body)
			if gotURL != tc.wantURL {
				t.Fatalf("url = %q, want %q", gotURL, tc.wantURL)
			}
			if tc.wantBody != "" && gotBody != tc.wantBody {
				t.Fatalf("body = %q, want %q", gotBody, tc.wantBody)
			}
		})
	}
}

func TestDedupeProbePointsMergesLinkedFindings(t *testing.T) {
	pts := []probePoint{
		{URL: "http://lab/vul/xss/xssblind/admin.php", Method: "GET", TemplateID: "pikachu-xss-blind", FindingIDs: []int64{11}},
		{URL: "http://lab/vul/xss/xssblind/admin.php", Method: "GET", TemplateID: "pikachu-xss-blind-admin", FindingIDs: []int64{12, 11}},
		{URL: "http://lab/vul/xss/xssblind/admin.php", Method: "POST", Body: "id=1", TemplateID: "pikachu-xss-post", FindingIDs: []int64{13}},
		{URL: "http://LAB/vul/xss/xss_01.php", Method: "get", TemplateID: "pikachu-xss-01"},
	}
	got := dedupeProbePoints(pts)
	if len(got) != 3 {
		t.Fatalf("deduped points = %d, want 3 (%+v)", len(got), got)
	}
	if got[0].TemplateID != "pikachu-xss-blind" {
		t.Fatalf("first point template = %q", got[0].TemplateID)
	}
	if !reflect.DeepEqual(got[0].FindingIDs, []int64{11, 12}) {
		t.Fatalf("merged finding ids = %v, want [11 12]", got[0].FindingIDs)
	}
	if got[1].Method != "POST" || len(got[1].FindingIDs) != 1 {
		t.Fatalf("POST point must stay separate: %+v", got[1])
	}
	if got[2].URL != "http://LAB/vul/xss/xss_01.php" {
		t.Fatalf("unrelated point dropped: %+v", got[2])
	}
}

// The demotion note has to say what the tool replayed, so a reviewer can rerun
// the exact request instead of taking the tool's word for it.
func TestProbeExchangesKeepsPacketForUnreproducedPoint(t *testing.T) {
	res := probeResult{
		Tool:    "sqlmap",
		Verdict: "not_reproduced",
		Baseline: baselineExchange{
			request:  "GET /vul/sqli/sqli_id.php?id=1 HTTP/1.1\r\nHost: lab\r\n\r\n",
			response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nnope",
			status:   200,
		},
	}
	got := probeExchanges(res)
	if len(got) != 1 {
		t.Fatalf("exchanges = %d, want 1 (%+v)", len(got), got)
	}
	if got[0].Role != "supporting" {
		t.Errorf("role = %q, want supporting", got[0].Role)
	}
	if !strings.Contains(got[0].Request, "sqli_id.php") || !strings.Contains(got[0].Response, "200 OK") {
		t.Errorf("baseline packet lost: %q / %q", got[0].Request, got[0].Response)
	}
	if !strings.Contains(got[0].Note, "sqlmap") || !strings.Contains(got[0].Note, "未复现") {
		t.Errorf("note missing the negative verdict: %q", got[0].Note)
	}
}

// A proved injection already carries its own control request, so the run-level
// baseline must not duplicate it.
func TestProbeExchangesPrefersInjectionPackets(t *testing.T) {
	res := probeResult{
		Tool: "dalfox",
		Injections: []probeInjection{{
			Param: "msg", Request: "GET /xss/xss_01.php?msg=dlx777 HTTP/1.1\r\n\r\n",
			Response: "HTTP/1.1 200 OK\r\n\r\ndlx777", BaselineReq: "GET /xss/xss_01.php?msg=test HTTP/1.1\r\n\r\n",
			Baseline: "HTTP/1.1 200 OK\r\n\r\ntest",
		}},
		Baseline: baselineExchange{request: "unused", response: "unused"},
	}
	got := probeExchanges(res)
	if len(got) != 2 {
		t.Fatalf("exchanges = %d, want 2 (%+v)", len(got), got)
	}
	for _, e := range got {
		if strings.Contains(e.Request, "unused") {
			t.Fatalf("run baseline duplicated: %+v", e)
		}
	}
	if got[0].Role != "proof" || got[1].Role != "supporting" {
		t.Fatalf("roles = %q, %q", got[0].Role, got[1].Role)
	}
}

// A login redirect is not evidence that the POC was wrong, so the tool negative
// must not withdraw the finding's confirmed status.
func TestProbePointReachableGatesDemotion(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{status: 200, want: true},
		{status: 302, want: false},
		{status: 401, want: false},
		{status: 500, want: false},
		{status: 0, want: false},
	}
	for _, c := range cases {
		if got := probePointReachable(probeResult{Baseline: baselineExchange{status: c.status}}); got != c.want {
			t.Errorf("status %d reachable = %v, want %v", c.status, got, c.want)
		}
	}
}

// sqlmap has to receive the point's method and body, otherwise a POST injection
// point is tested as a GET and reported not injectable.
func TestSQLMapProbeOptionsCarriesPostRequest(t *testing.T) {
	r := &deepRun{task: &db.DeepTask{Params: map[string]any{"wall_seconds": float64(120), "level": float64(2)}}}
	creds := probeCreds{Cookie: "PHPSESSID=abc", Headers: []string{"Referer: http://lab/"}}

	post := r.sqlmapProbeOptions(probePoint{
		URL: "http://lab/vul/sqli/sqli_id.php", Method: "POST", Body: "id=1&submit=1",
	}, creds)
	if !strings.HasPrefix(post.RawRequest, "POST /vul/sqli/sqli_id.php HTTP/1.1") {
		t.Fatalf("raw request start = %q", firstLine(post.RawRequest, 120))
	}
	if !strings.Contains(post.RawRequest, "id=1&submit=1") {
		t.Errorf("body lost from raw request: %q", post.RawRequest)
	}
	if !strings.Contains(post.RawRequest, "Content-Type: application/x-www-form-urlencoded") {
		t.Errorf("form body sent without its Content-Type: %q", post.RawRequest)
	}
	if !strings.Contains(post.RawRequest, "Cookie: PHPSESSID=abc") || !strings.Contains(post.RawRequest, "Referer: http://lab/") {
		t.Errorf("session material lost from raw request: %q", post.RawRequest)
	}
	if post.Cookie != "" || post.Headers != nil {
		t.Errorf("cookie/headers must not be passed twice: %q / %v", post.Cookie, post.Headers)
	}
	if post.WallSeconds != 120 || post.Level != 2 {
		t.Errorf("task params ignored: wall=%d level=%d", post.WallSeconds, post.Level)
	}

	get := r.sqlmapProbeOptions(probePoint{URL: "http://lab/vul/sqli/sqli_str.php?name=test", Method: "GET"}, creds)
	if get.RawRequest != "" {
		t.Errorf("GET point should use --url, got raw request %q", get.RawRequest)
	}
	if get.Cookie != "PHPSESSID=abc" || len(get.Headers) != 1 {
		t.Errorf("GET point lost creds: %q / %v", get.Cookie, get.Headers)
	}
}

// The POC's own session has to reach the tool, otherwise a point behind a login
// answers with a redirect and sqlmap proves nothing about the real weakness.
func TestCredsForPointUsesPointSession(t *testing.T) {
	r := &deepRun{task: &db.DeepTask{Params: map[string]any{}}}
	base := probeCreds{}
	got := r.credsForPoint(base, probePoint{Cookie: " PHPSESSID=abc "})
	if got.Cookie != "PHPSESSID=abc" {
		t.Fatalf("cookie = %q", got.Cookie)
	}
	// Task-level credentials are the operator's choice and win.
	if got := r.credsForPoint(probeCreds{Cookie: "PHPSESSID=task"}, probePoint{Cookie: "PHPSESSID=poc"}); got.Cookie != "PHPSESSID=task" {
		t.Fatalf("task cookie overridden: %q", got.Cookie)
	}
	if got := r.credsForPoint(base, probePoint{}); got.Cookie != "" {
		t.Fatalf("empty point cookie invented: %q", got.Cookie)
	}
}

// sqlmap carries no multi-byte charset payloads, so a GBK wide-byte point is a
// blind spot rather than a refutation. The payload has to be recognised from the
// point's own request.
func TestWideByteQuoteBypassDetectsCharsetTrick(t *testing.T) {
	for _, payload := range []string{
		"name=%df%27%20or%201=1%23&submit=1",
		"/vul/sqli/sqli_widebyte.php?id=%bf%22",
		"id=%a1%27",
		"id=%25df%2527",
	} {
		if !wideByteQuoteBypass(payload) {
			t.Errorf("%q should read as a wide-byte bypass", payload)
		}
	}
	for _, plain := range []string{
		"name=test%27%20or%201=1--%20-&submit=1",
		"id=1%2520union%2520select",
		"id=%e6%9f%a5%e8%af%a2",
		"message=<svg%20onload=alert(1)>",
	} {
		if wideByteQuoteBypass(plain) {
			t.Errorf("%q is not a wide-byte bypass", plain)
		}
	}
}

func TestNeutralProbePointReplacesEveryValue(t *testing.T) {
	p := probePoint{
		URL:    "http://lab.example.com/vul/sqli/sqli_str.php?name=%df%27%20or%201=1%23&submit=1",
		Method: "GET",
	}
	got, ok := neutralProbePoint(p, "CTL")
	if !ok {
		t.Fatal("query values were not substituted")
	}
	if strings.Contains(got.URL, "%27") || strings.Contains(got.URL, "or") {
		t.Fatalf("payload survived neutralisation: %s", got.URL)
	}
	if !strings.Contains(got.URL, "name=CTL") || !strings.Contains(got.URL, "submit=CTL") {
		t.Fatalf("substitution = %s", got.URL)
	}

	bodyPoint := probePoint{
		URL:    "http://lab.example.com/vul/sqli/sqli_widebyte.php",
		Method: "POST",
		Body:   "name=%df%27%20or%201=1%23&submit=1",
	}
	got, ok = neutralProbePoint(bodyPoint, "CTL")
	if !ok || got.Body != "name=CTL&submit=CTL" || got.URL != bodyPoint.URL {
		t.Fatalf("body neutralisation = %+v ok=%v", got, ok)
	}

	if _, ok := neutralProbePoint(probePoint{URL: "http://lab.example.com/vul/sqli/x.php"}, "CTL"); ok {
		t.Fatal("a point without parameters cannot produce a control request")
	}
}

// A page that differs only in its per-request token is the same page; the rows a
// working payload returns are not.
func TestProbeBodyDiffersWeighsPayloadEffect(t *testing.T) {
	page := func(rows int, token string) string {
		var b strings.Builder
		b.WriteString("<html><head><title>Pikachu</title></head><body>CSRF:")
		b.WriteString(token)
		b.WriteString("<table>")
		for i := 0; i < rows; i++ {
			b.WriteString("<tr><td>user</td><td>mail@example.com</td></tr>")
		}
		b.WriteString("</table></body></html>")
		return b.String()
	}
	if probeBodyDiffers(page(1, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"), page(1, "0f1e2d3c4b5a69788796a5b4c3d2e1f0"), "CTL") {
		t.Fatal("a rotating CSRF token is not a payload effect")
	}
	if !probeBodyDiffers(page(200, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"), page(1, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"), "CTL") {
		t.Fatal("extra rows returned by the payload are a payload effect")
	}
	if probeBodyDiffers("same body", "same body", "") {
		t.Fatal("identical bodies do not differ")
	}
}

func TestProbePayloadParamFindsWideBytePayload(t *testing.T) {
	name, where, value := probePayloadParam(probePoint{
		URL:    "http://lab.example.com/vul/sqli/sqli_widebyte.php",
		Method: "POST",
		Body:   "submit=1&name=%df%27%20or%201=1%23",
	})
	if name != "name" || where != "POST" || !strings.Contains(value, "%df%27") {
		t.Fatalf("param = %q %q %q", name, where, value)
	}
	name, where, _ = probePayloadParam(probePoint{URL: "http://lab/x.php?id=1&submit=1", Method: "GET"})
	if name != "id" || where != "GET" {
		t.Fatalf("fallback param = %q %q", name, where)
	}
}

func TestRejudgeProbeNegativeWideByteSQLi(t *testing.T) {
	newRun := func(h http.Handler) (*deepRun, *httptest.Server) {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		r := &deepRun{task: &db.DeepTask{Params: map[string]any{}, Target: srv.URL}, ctx: context.Background()}
		return r, srv
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		if strings.Contains(req.FormValue("name"), "' or 1=1") {
			w.Write([]byte(strings.Repeat("mail@example.com Bill Gates ", 200)))
			return
		}
		w.Write([]byte("<p>no rows</p>"))
	})

	p := probePoint{
		URL:    "http://lab.example.com/vul/sqli/sqli_widebyte.php",
		Method: http.MethodPost,
		Body:   "name=%df%27%20or%201%3D1%23&submit=1",
	}
	r, srv := newRun(handler)
	p.URL = srv.URL
	res := probeResult{Tool: "sqlmap", Verdict: "not_reproduced", Baseline: baselineExchange{status: 200}}
	got := r.rejudgeProbeNegative(scanner.InjectionSQLi, p, res, probeCreds{})
	if got.Verdict != verdict.Confirmed {
		t.Fatalf("verdict = %q, want confirmed: %s", got.Verdict, got.Detail)
	}
	if len(got.Injections) != 1 || !got.Injections[0].Proved {
		t.Fatalf("injections = %+v", got.Injections)
	}
	inj := got.Injections[0]
	if !strings.Contains(inj.Request, "POST ") || !strings.Contains(inj.BaselineReq, "name=jwctl") {
		t.Fatalf("packets:\n%s\n---\n%s", inj.Request, inj.BaselineReq)
	}
	if !strings.Contains(inj.Payload, "%df%27") {
		t.Fatalf("payload lost its wire form: %q", inj.Payload)
	}
	if !strings.Contains(inj.Response, "Bill Gates") || !strings.Contains(inj.Baseline, "no rows") {
		t.Fatalf("responses lost the difference: %q / %q", inj.Response, inj.Baseline)
	}

	// A payload that no longer moves the page leaves the tool negative standing.
	dead := probePoint{URL: srv.URL, Method: http.MethodPost, Body: "name=%df%27%20sleep(0)%23&submit=1"}
	got = r.rejudgeProbeNegative(scanner.InjectionSQLi, dead, res, probeCreds{})
	if got.Verdict != "not_reproduced" {
		t.Fatalf("dead payload verdict = %q, want not_reproduced", got.Verdict)
	}
}

func TestRejudgeProbeNegativeXSSWithoutEcho(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(`<form><input id="text"></form><script>document.getElementById("dom").innerHTML="<a href='"+str+"'>";</script>`))
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	r := &deepRun{task: &db.DeepTask{Params: map[string]any{}, Target: srv.URL}, ctx: context.Background()}
	p := probePoint{URL: srv.URL + "/vul/xss/xss_dom.php?text=test", Method: http.MethodGet}
	res := probeResult{Tool: "dalfox", Verdict: "not_reproduced", Detail: "dalfox 未发现漏洞", Baseline: baselineExchange{status: 200}}

	got := r.rejudgeProbeNegative(scanner.InjectionXSS, p, res, probeCreds{})
	if got.Verdict != probeVerdictUncovered {
		t.Fatalf("verdict = %q, want %q", got.Verdict, probeVerdictUncovered)
	}
	if !strings.Contains(got.Detail, "dalfox 只能判定") {
		t.Fatalf("detail = %q", got.Detail)
	}

	// A reflected value gives dalfox something to grade, so its negative holds.
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, "<p>"+req.URL.Query().Get("message")+"</p>")
	}))
	defer echo.Close()
	r.task.Target = echo.URL
	reflected := probePoint{URL: echo.URL + "/vul/xss/xss_01.php?message=test", Method: http.MethodGet}
	if got := r.rejudgeProbeNegative(scanner.InjectionXSS, reflected, res, probeCreds{}); got.Verdict != "not_reproduced" {
		t.Fatalf("reflected point verdict = %q, want not_reproduced: %s", got.Verdict, got.Detail)
	}
}

func TestSessionBlockedNegativeKeepsFindingVerdict(t *testing.T) {
	negative := func(status int) probeResult {
		return probeResult{Tool: "dalfox", Verdict: "not_reproduced",
			Detail:   "dalfox 未发现反射点或可执行 XSS。",
			Baseline: baselineExchange{status: status}}
	}

	// A redirect means the tool tested the login page, not the vulnerable one.
	got := sessionBlockedNegative(negative(http.StatusFound))
	if got.Verdict != "session_needed" {
		t.Fatalf("302 baseline verdict = %q, want session_needed", got.Verdict)
	}
	if !strings.Contains(got.Detail, "HTTP 302") || !strings.Contains(got.Detail, "dalfox 未发现") {
		t.Fatalf("detail = %q", got.Detail)
	}

	// A baseline that never answered gives the tool nothing to grade either, and the
	// reason has to name the wedge a previous time-based payload leaves behind —
	// otherwise the model re-runs the same point and piles more sleeps on.
	dead := sessionBlockedNegative(negative(0))
	if dead.Verdict != probeVerdictUncovered {
		t.Fatalf("dead baseline verdict = %q, want %q", dead.Verdict, probeVerdictUncovered)
	}
	if !strings.Contains(dead.Detail, "连不上或超时") || !strings.Contains(dead.Detail, "不要立刻重跑同一个点") {
		t.Fatalf("dead baseline detail = %q", dead.Detail)
	}

	// A reachable point is the tool's to judge, so the negative stands.
	if got := sessionBlockedNegative(negative(http.StatusOK)); got.Verdict != "not_reproduced" {
		t.Fatalf("reachable baseline verdict = %q, want not_reproduced", got.Verdict)
	}
}
