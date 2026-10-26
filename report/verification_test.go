package report

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func verificationRowValue(rows []verificationRow, label string) string {
	for _, row := range rows {
		if row.Label == label {
			return row.Value
		}
	}
	return ""
}

func TestVerificationExcerptUsesSQLiEvidenceNotPreamble(t *testing.T) {
	in := FindingReportInput{
		VulnClass:   "SQL Injection",
		Name:        "DVWA SQLi",
		HTTPRequest: "GET /vulnerabilities/sqli/?id=1%27+UNION+SELECT+user%2Cpassword+FROM+users--+-&Submit=Submit HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\n",
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html;charset=utf-8\r\n\r\n" +
			"<!DOCTYPE html><html><head><title>DVWA</title></head><body><pre>ID: 1' UNION SELECT user,password FROM users-- -<br />First name: admin<br />Surname: 5f4dcc3b5aa765d61d8327deb882cf99<br /></pre></body></html>",
	}
	steps, rows := verificationSteps(in)
	excerpt := verificationRowValue(rows, "响应摘要")
	if !strings.Contains(excerpt, "Surname: 5f4dcc3b5aa765d61d8327deb882cf99") {
		t.Fatalf("excerpt should quote the injected row, got %q", excerpt)
	}
	if strings.Contains(excerpt, "DOCTYPE") {
		t.Fatalf("excerpt must not quote the document preamble: %q", excerpt)
	}
	if !strings.Contains(strings.Join(steps, " "), "Surname") {
		t.Fatalf("verification steps should cite the extracted row")
	}
}

func TestVerificationExcerptFindsReflectedXSS(t *testing.T) {
	in := FindingReportInput{
		VulnClass:   "反射型XSS（Reflected XSS）",
		HTTPRequest: "GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\n",
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<!DOCTYPE html><html><head><title>x</title></head><body><pre>Hello <script>alert(1)</script></pre></body></html>",
	}
	_, rows := verificationSteps(in)
	excerpt := verificationRowValue(rows, "响应摘要")
	if !strings.Contains(excerpt, "<script>alert(1)</script>") {
		t.Fatalf("excerpt should contain the reflected payload, got %q", excerpt)
	}
}

func TestVerificationExcerptFindsCommandOutput(t *testing.T) {
	in := FindingReportInput{
		VulnClass:   "命令注入 Command Injection",
		HTTPRequest: "POST /vulnerabilities/exec/ HTTP/1.1\r\nHost: 192.0.2.4\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nip=127.0.0.1%3Bid&Submit=Submit",
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<!DOCTYPE html><html><body><pre>PING 127.0.0.1<br />uid=33(www-data) gid=33(www-data) groups=33(www-data)</pre></body></html>",
	}
	_, rows := verificationSteps(in)
	if excerpt := verificationRowValue(rows, "响应摘要"); !strings.Contains(excerpt, "uid=33(www-data)") {
		t.Fatalf("excerpt should contain command output, got %q", excerpt)
	}
}

func TestVerificationExcerptUsesRedirectForWeakCredentials(t *testing.T) {
	in := FindingReportInput{
		VulnClass:    "弱口令/默认凭据",
		HTTPRequest:  "POST /login.php HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\nusername=admin&password=password",
		HTTPResponse: "HTTP/1.1 302 Found\r\nLocation: index.php\r\nContent-Length: 0\r\n\r\n",
	}
	_, rows := verificationSteps(in)
	if excerpt := verificationRowValue(rows, "响应摘要"); !strings.Contains(excerpt, "Location: index.php") {
		t.Fatalf("excerpt should cite the login redirect, got %q", excerpt)
	}
	if location := verificationRowValue(rows, "跳转地址"); location != "index.php" {
		t.Fatalf("redirect row mismatch: %q", location)
	}
}

func TestVerificationBodyLengthsKeepWireBytes(t *testing.T) {
	body := "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nvalue\r\n--b--\r\n"
	in := FindingReportInput{
		VulnClass:    "Unrestricted File Upload",
		HTTPRequest:  "POST /upload HTTP/1.1\r\nHost: 192.0.2.4\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body,
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello\r\nworld",
	}
	_, rows := verificationSteps(in)
	if got := verificationRowValue(rows, "请求体大小"); got != strconv.Itoa(len(body))+" 字节" {
		t.Fatalf("request body size should use wire bytes, got %q want %d", got, len(body))
	}
	if got := verificationRowValue(rows, "响应体大小"); got != "12 字节" {
		t.Fatalf("response body size should use wire bytes, got %q", got)
	}
}

func TestVerificationExcerptFindsStoredXSSPayload(t *testing.T) {
	payload := "<script>alert('jingwei-l2')</script>"
	in := FindingReportInput{
		VulnClass:   "Stored XSS",
		Name:        "DVWA 存储型 XSS",
		HTTPRequest: "POST /vulnerabilities/xss_s/ HTTP/1.1\r\nHost: 192.0.2.4\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ntxtName=jingwei-l2&mtxMessage=" + url.QueryEscape(payload),
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<!DOCTYPE html><html><head><script type=\"text/javascript\" src=\"../../dvwa/js/dvwaPage.js\"></script></head>" +
			"<body><pre>jingwei-l2<br />" + payload + "</pre></body></html>",
	}
	steps, rows := verificationSteps(in)
	excerpt := verificationRowValue(rows, "响应摘要")
	if !strings.Contains(excerpt, payload) {
		t.Fatalf("excerpt should quote the stored payload, got %q", excerpt)
	}
	if strings.Contains(excerpt, "DOCTYPE") {
		t.Fatalf("excerpt must not quote the document preamble: %q", excerpt)
	}
	joined := strings.Join(steps, " ")
	if !strings.Contains(joined, "http://192.0.2.4/vulnerabilities/xss_s/") {
		t.Fatalf("step 1 should use the full URL, got %q", joined)
	}
}

func TestVerificationExcerptFindsBlindSQLiVerdict(t *testing.T) {
	in := FindingReportInput{
		VulnClass:   "SQL Injection (Blind)",
		HTTPRequest: "GET /vulnerabilities/sqli_blind/?id=1%27+AND+%271%27%3D%271 HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\n",
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<html><body><form><p>User ID: <input type=\"text\" name=\"id\"></p></form><pre>User ID exists in the database.</pre></body></html>",
	}
	_, rows := verificationSteps(in)
	if excerpt := verificationRowValue(rows, "响应摘要"); !strings.Contains(excerpt, "User ID exists in the database.") {
		t.Fatalf("excerpt should quote the blind verdict, got %q", excerpt)
	}
}

func TestVerificationExcerptFindsUploadSuccess(t *testing.T) {
	in := FindingReportInput{
		VulnClass:   "Unrestricted File Upload / RCE",
		HTTPRequest: "POST /vulnerabilities/upload/ HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\n--b--",
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<html><body><div id=\"main_menu\"><ul><li><a href=\"../../.\">Home</a></li><li><a href=\"../../instructions.php\">Instructions</a></li><li><a href=\"../../setup.php\">Setup / Reset DB</a></li><li><a href=\"../../vulnerabilities/brute/\">Brute Force</a></li><li><a href=\"../../vulnerabilities/exec/\">Command Injection</a></li></ul></div>" +
			"<pre>../../hackable/uploads/jingwei_l2.php succesfully uploaded!</pre></body></html>",
	}
	_, rows := verificationSteps(in)
	excerpt := verificationRowValue(rows, "响应摘要")
	if !strings.Contains(excerpt, "succesfully uploaded!") {
		t.Fatalf("excerpt should quote the upload success marker, got %q", excerpt)
	}
	if strings.Contains(excerpt, "Home") {
		t.Fatalf("excerpt must not quote the navigation preamble: %q", excerpt)
	}
}

func TestVerificationCitesWeakSessionCookie(t *testing.T) {
	in := FindingReportInput{
		VulnClass:    "Weak Session ID",
		Name:         "DVWA Weak Session ID — dvwaSession 顺序递增",
		HTTPRequest:  "POST /vulnerabilities/weak_id/ HTTP/1.1\r\nHost: 192.0.2.4\r\nCookie: dvwaSession=2\r\n\r\n",
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: dvwaSession=3\r\n\r\n<html><body><nav>Home</nav><p>Generate</p></body></html>",
	}
	steps, rows := verificationSteps(in)
	if got := verificationRowValue(rows, "Set-Cookie"); got != "dvwaSession=3" {
		t.Fatalf("Set-Cookie row should cite the recorded cookie, got %q", got)
	}
	excerpt := verificationRowValue(rows, "响应摘要")
	if !strings.Contains(excerpt, "Set-Cookie: dvwaSession=3") {
		t.Fatalf("excerpt should use the cookie proof, got %q", excerpt)
	}
	if strings.Contains(excerpt, "Generate") {
		t.Fatalf("excerpt must not fall back to the page body: %q", excerpt)
	}
	if !strings.Contains(strings.Join(steps, " "), "Set-Cookie: `dvwaSession=3`") {
		t.Fatalf("response step should cite the Set-Cookie header")
	}
}

func TestVerificationExcerptFindsCSRFPasswordChanged(t *testing.T) {
	in := FindingReportInput{
		VulnClass:   "CSRF",
		Name:        "DVWA CSRF — 改密无 CSRF Token 防护",
		HTTPRequest: "GET /vulnerabilities/csrf/?password_new=TempPass123&password_conf=TempPass123&Change=Change HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\n",
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<html><body><form><input name=\"password_new\"><input name=\"password_conf\"></form><pre>Password Changed.</pre></body></html>",
	}
	_, rows := verificationSteps(in)
	excerpt := verificationRowValue(rows, "响应摘要")
	if !strings.Contains(excerpt, "Password Changed.") {
		t.Fatalf("excerpt should quote the password-change proof, got %q", excerpt)
	}
	if strings.Contains(excerpt, "<form>") {
		t.Fatalf("excerpt must not quote the form: %q", excerpt)
	}
}

func TestVerificationExcerptIgnoresSQLFormLabel(t *testing.T) {
	in := FindingReportInput{
		VulnClass:   "SQL Injection",
		Name:        "DVWA Medium SQL 注入（数字型 POST + UNION 注入）",
		HTTPRequest: "POST /vulnerabilities/sqli/ HTTP/1.1\r\nHost: 192.0.2.4\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=1 UNION SELECT user,password FROM users-- -&Submit=Submit",
		HTTPResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<html><body><form action=\"#\" method=\"POST\"><p>User ID: <select name=\"id\"><option value=\"1\">1</option></select></p></form>" +
			"<pre>ID: 1 UNION SELECT user,password FROM users-- -<br />First name: admin<br />Surname: 5f4dcc3b5aa765d61d8327deb882cf99</pre></body></html>",
	}
	_, rows := verificationSteps(in)
	excerpt := verificationRowValue(rows, "响应摘要")
	if !strings.Contains(excerpt, "First name: admin") {
		t.Fatalf("excerpt should quote the injected row, got %q", excerpt)
	}
	if !strings.Contains(excerpt, "Surname: 5f4dcc3b5aa765d61d8327deb882cf99") {
		t.Fatalf("excerpt should quote the extracted hash, got %q", excerpt)
	}
	if strings.Contains(excerpt, "select name") {
		t.Fatalf("excerpt must not center on the form label: %q", excerpt)
	}
}

func TestVerificationHostInjectionUsesAssetAddressNotInjectedHost(t *testing.T) {
	in := FindingReportInput{
		VulnClass: "Host Header Injection",
		Name:      "密码重置链接 Host 头注入",
		MatchedAt: "/WebGoat/PasswordReset/ForgotPassword/create-password-reset-link",
		HTTPRequest: "POST /WebGoat/PasswordReset/ForgotPassword/create-password-reset-link HTTP/1.1\r\n" +
			"Host: evil.example\r\nContent-Length: 23\r\n\r\nemail=jingwei@lab.local",
		HTTPResponse: "HTTP/1.1 200 \r\nContent-Type: application/json\r\n\r\n{\"lessonCompleted\":true}",
	}
	steps, _ := verificationSteps(in)
	all := strings.Join(steps, " ")
	if strings.Contains(all, "http://evil.example") {
		t.Fatalf("injected Host must not become the connection URL: %s", all)
	}
	if !strings.Contains(all, "注入值 `evil.example`") {
		t.Fatalf("step should label the Host as an injected value: %s", all)
	}

	normal := FindingReportInput{
		VulnClass:   "SQL Injection",
		Name:        "DVWA SQLi",
		MatchedAt:   "/vulnerabilities/sqli/",
		HTTPRequest: "GET /vulnerabilities/sqli/?id=1 HTTP/1.1\r\nHost: 192.0.2.4\r\n\r\n",
	}
	steps, _ = verificationSteps(normal)
	if !strings.Contains(strings.Join(steps, " "), "http://192.0.2.4/vulnerabilities/sqli/") {
		t.Fatalf("ordinary findings should still get a concrete URL: %v", steps)
	}
}

func TestVerificationRawProtocolDoesNotPretendHTTP(t *testing.T) {
	in := FindingReportInput{
		VulnClass:    "Redis Server - Unauthenticated Access",
		Name:         "Redis Server - Unauthenticated Access",
		Type:         "tcp",
		Host:         "192.0.2.1:6379",
		MatchedAt:    "192.0.2.1:6379",
		HTTPRequest:  "info\r\nquit\r\n",
		HTTPResponse: "$2714\r\n# Server\r\nredis_version:4.0.14\r\n\r\n",
	}
	steps, rows := verificationSteps(in)
	all := strings.Join(steps, " ")
	if strings.Contains(all, "http://") || strings.Contains(all, "Host:") {
		t.Fatalf("raw protocol steps must not contain HTTP constructs: %s", all)
	}
	if !strings.Contains(all, "TCP") {
		t.Fatalf("steps should name the protocol: %s", all)
	}
	if got := verificationRowValue(rows, "协议"); got != "TCP" {
		t.Fatalf("protocol row = %q", got)
	}
	if got := verificationRowValue(rows, "状态行"); got != "" {
		t.Fatalf("raw protocol must not report an HTTP status line, got %q", got)
	}
}

func TestPacketLabelsDoNotClaimHTTPWithoutPackets(t *testing.T) {
	cases := []struct {
		kind       string
		hasPackets bool
		want       string
	}{
		{"", true, "原始 HTTP 报文"},
		{"", false, "原始报文"},
		{"tcp", false, "原始协议报文"},
		{"tcp", true, "原始协议报文"},
	}
	for _, c := range cases {
		got, _, _, _ := packetLabels(FindingReportInput{Type: c.kind}, c.hasPackets)
		if got != c.want {
			t.Fatalf("type %q hasPackets=%v: heading = %q, want %q", c.kind, c.hasPackets, got, c.want)
		}
	}
}
