package scanner

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPacketTextKeepsUndecodableBytesAsHex(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ascii", "GET / HTTP/1.1\r\n", "GET / HTTP/1.1\r\n"},
		{"utf8", "姓名: kobe", "姓名: kobe"},
		{"gbk", "\xc4\xe3\xba\xc3", `\xc4\xe3\xba\xc3`},
		{"nul", "a\x00b", "ab"},
		{"mixed", "err: \xdf' or 1=1", `err: \xdf' or 1=1`},
	}
	for _, c := range cases {
		got := PacketText(c.in)
		if got != c.want {
			t.Errorf("%s: PacketText(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: result is not valid UTF-8: %q", c.name, got)
		}
	}
}

func TestPacketTextIdempotent(t *testing.T) {
	once := PacketText("\xc4\xe3")
	if twice := PacketText(once); twice != once {
		t.Fatalf("second pass changed the text: %q != %q", twice, once)
	}
}

func TestSanitizeResultTextsCoversEveryField(t *testing.T) {
	results := []NucleiResult{{
		Name:      "\xc4\xe3 hit",
		MatchedAt: "http://x/\xc4",
		Curl:      "curl 'http://x/\xc4'",
		Request:   "GET /\xc4 HTTP/1.1\r\n",
		Response:  "HTTP/1.1 200 OK\r\n\r\n\xdf'",
		Extracted: []string{"\xc4\xe3"},
		Exchanges: []RawExchange{{Request: "GET /\xc4", Response: "\xdf"}},
		Raw:       map[string]any{"matcher-name": "\xc4", "matched-at": 1},
	}}
	sanitizeResultTexts(results)
	r := results[0]
	for name, v := range map[string]string{
		"name": r.Name, "matched_at": r.MatchedAt, "curl": r.Curl,
		"request": r.Request, "response": r.Response, "extracted": r.Extracted[0],
		"exchange.request": r.Exchanges[0].Request, "exchange.response": r.Exchanges[0].Response,
		"raw.matcher": r.Raw["matcher-name"].(string),
	} {
		if !utf8.ValidString(v) {
			t.Errorf("%s still holds invalid UTF-8: %q", name, v)
		}
	}
	if !strings.Contains(r.Response, `\xdf'`) {
		t.Errorf("response lost the raw byte marker: %q", r.Response)
	}
}
