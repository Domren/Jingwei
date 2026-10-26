package db

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A packet with undecodable bytes must survive the write instead of making
// Postgres reject the whole finding row.
func TestSafePacketTextAcceptsBinaryPayloads(t *testing.T) {
	for _, in := range []string{"\xdf' or 1=1", "\xc4\xe3\xba\xc3", "a\x00b", strings.Repeat("\xff", 40)} {
		got := safePacketText(in, 0)
		if !utf8.ValidString(got) {
			t.Errorf("safePacketText(%q) = %q, still invalid UTF-8", in, got)
		}
		if strings.ContainsRune(got, 0) {
			t.Errorf("safePacketText(%q) kept a NUL byte", in)
		}
	}
	if got := safePacketText("姓名: kobe", 0); got != "姓名: kobe" {
		t.Errorf("valid text was altered: %q", got)
	}
}
