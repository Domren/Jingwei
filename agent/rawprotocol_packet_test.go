package agent

import "testing"

func TestUnescapeRawPacketRestoresWireCRLF(t *testing.T) {
	cases := []struct{ in, want string }{
		{`*1\r\n$4\r\nPING\r\n`, "*1\r\n$4\r\nPING\r\n"},
		{"*1\r\n$4\r\nPING\r\n", "*1\r\n$4\r\nPING\r\n"},
		{"SET k v", "SET k v"},
		{`列名\rcol`, "列名\rcol"},
	}
	for _, tc := range cases {
		if got := unescapeRawPacket(tc.in); got != tc.want {
			t.Errorf("unescapeRawPacket(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestDetectRawProtocolFromEvidenceText(t *testing.T) {
	cases := []struct {
		text, want string
	}{
		{"判定依据：RESP 返回 redis_version:4.0.14", "redis"},
		{"*1\r\n$4\r\nPING\r\n +PONG\r\n", "redis"},
		{"server handshake: caching_sha2_password", "mysql"},
		{"banner SSH-2.0-OpenSSH_8.0", "ssh"},
		{"GET /vul/sqli/sqli_str.php?id=1 HTTP/1.1\r\nHost: t\r\n\r\n 提到 redis_version 也不算", ""},
		{"反射型 XSS，payload <script>alert(1)</script>", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := detectRawProtocol(tc.text); got != tc.want {
			t.Errorf("detectRawProtocol(%q)=%q want %q", tc.text, got, tc.want)
		}
	}
}

func TestRawProtocolPacketKeepsHTTPFindingsAsHTTP(t *testing.T) {
	cases := []struct {
		proto, req, resp, want string
	}{
		{"", "GET /a HTTP/1.1\r\nHost: t\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nbody", ""},
		{"HTTP", "GET /a HTTP/1.1\r\n\r\n", "", ""},
		{"https", "", "HTTP/1.1 401 Unauthorized\r\n\r\n", ""},
		{"", "info\r\nquit\r\n", "+PONG\r\n", "tcp"},
		{"Redis", "PING\r\n", "+PONG\r\n", "redis"},
		{"mysql", "\x01\x02", "\x03", "mysql"},
		{"redis", "", "", "redis"},
		{"", "", "", ""},
	}
	for _, tc := range cases {
		got, gotReq, gotResp := rawProtocolPacket(tc.proto, tc.req, tc.resp)
		if got != tc.want {
			t.Errorf("rawProtocolPacket(%q,%q,%q) protocol=%q want %q", tc.proto, tc.req, tc.resp, got, tc.want)
		}
		if gotReq != tc.req || gotResp != tc.resp {
			t.Errorf("rawProtocolPacket must not alter bytes: %q/%q vs %q/%q", gotReq, gotResp, tc.req, tc.resp)
		}
	}
}
