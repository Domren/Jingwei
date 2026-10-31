package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

func TestLoginCookieFromResponse(t *testing.T) {
	raw := "HTTP/1.1 302 Found\r\n" +
		"Location: /admin/\r\n" +
		"Set-Cookie: PHPSESSID=abc123; path=/; HttpOnly\r\n" +
		"Set-Cookie: remember=1\r\n" +
		"\r\n" +
		"Set-Cookie: fake=body-cookie\r\n"
	got := loginCookieFromResponse(raw)
	if got != "PHPSESSID=abc123; remember=1" {
		t.Fatalf("cookie = %q", got)
	}
}

func TestLoginCookieFromResponseJoinedHeader(t *testing.T) {
	// requests joins repeated Set-Cookie headers with ", "; the second cookie
	// definition begins after that comma, while attributes stay attributes.
	raw := "HTTP/1.1 200 OK\n" +
		"Set-Cookie: session=abc; Path=/, csrftoken=xyz; Path=/; SameSite=Lax\n" +
		"\n"
	got := loginCookieFromResponse(raw)
	if got != "session=abc; csrftoken=xyz" {
		t.Fatalf("cookie = %q", got)
	}
}

func TestLoginCookieFromResponseLastValueWins(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nSet-Cookie: sid=old\r\nSet-Cookie: sid=new\r\n\r\n"
	if got := loginCookieFromResponse(raw); got != "sid=new" {
		t.Fatalf("cookie = %q", got)
	}
}

func TestLoginCookieFromResponseExpiresAndEmpty(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/\r\n\r\n"
	if got := loginCookieFromResponse(raw); got != "sid=abc" {
		t.Fatalf("cookie = %q", got)
	}
	if got := loginCookieFromResponse("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"); got != "" {
		t.Fatalf("no-cookie response yielded %q", got)
	}
}

func TestWebshellTaskParams(t *testing.T) {
	r := &scanRun{task: &db.ScanTask{WebshellParams: map[string]any{
		"upload_path": "/upload.php",
		"land_path":   "/shell.php",
		"password":    "pass",
	}}}
	params, errMsg := r.webshellTaskParams("http://10.0.0.5:8080/app", map[string]string{"Cookie": "sid=1"}, "weakpass")
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	if params["upload_url"] != "http://10.0.0.5:8080/upload.php" {
		t.Errorf("upload_url = %v", params["upload_url"])
	}
	if params["land_url"] != "http://10.0.0.5:8080/shell.php" {
		t.Errorf("land_url = %v", params["land_url"])
	}
	if params["shell_type"] != "php" || params["field_name"] != "file" {
		t.Errorf("defaults not applied: %v / %v", params["shell_type"], params["field_name"])
	}
	if params["source"] != "weakpass" || params["login_url"] != nil {
		t.Errorf("source/login_url = %v / %v", params["source"], params["login_url"])
	}
	headers, ok := params["headers"].(map[string]string)
	if !ok || headers["Cookie"] != "sid=1" {
		t.Errorf("headers = %#v", params["headers"])
	}

	// A configured shell type and field name win over the defaults.
	r.task.WebshellParams["shell_type"] = "jsp"
	r.task.WebshellParams["field_name"] = "upload"
	params, _ = r.webshellTaskParams("http://h", nil, "scan")
	if params["shell_type"] != "jsp" || params["field_name"] != "upload" {
		t.Errorf("explicit values lost: %v / %v", params["shell_type"], params["field_name"])
	}
	if _, ok := params["headers"]; ok {
		t.Errorf("empty headers should not be stored: %v", params["headers"])
	}

	// Without an upload path there is nothing to chain to.
	empty := &scanRun{task: &db.ScanTask{WebshellParams: map[string]any{}}}
	if _, msg := empty.webshellTaskParams("http://h", nil, "scan"); !strings.Contains(msg, "上传路径") {
		t.Errorf("missing-path message = %q", msg)
	}
	// A non-URL target cannot be joined into an upload address.
	bad := &scanRun{task: &db.ScanTask{WebshellParams: map[string]any{"upload_path": "/u.php"}}}
	if _, msg := bad.webshellTaskParams("not a url", nil, "scan"); msg == "" {
		t.Error("invalid target should fail")
	}
}

func TestShellQueuedDedupe(t *testing.T) {
	r := &scanRun{shellHosts: map[string]bool{"http://10.0.0.5": true}}
	if !r.shellQueued("http://10.0.0.5/app/login.php?next=/") {
		t.Error("queued origin not detected")
	}
	if r.shellQueued("http://10.0.0.6/app") {
		t.Error("other origin reported as queued")
	}
	if r.shellQueued("not a url") {
		t.Error("invalid target reported as queued")
	}

	empty := &scanRun{}
	empty.markShellQueued("http://h:8080/x")
	if !empty.shellHosts["http://h:8080"] {
		t.Errorf("markShellQueued stored %v", empty.shellHosts)
	}

	// The chain is off unless the scan asked for webshell injection.
	off := &scanRun{task: &db.ScanTask{WebshellInject: false}}
	if id, ok := off.queueWeakPassWebshell("http://h/login", "sid=1"); ok || id != 0 {
		t.Errorf("disabled chain queued task %d", id)
	}
}
