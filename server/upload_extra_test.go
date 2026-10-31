package server

import (
	"strings"
	"testing"
)

func TestCleanExtraFields(t *testing.T) {
	in := map[string]string{
		"submit":   "Submit",
		" csrf ":   "tok",
		"":         "drop",
		"bad\r\n":  "drop",
		"big":      strings.Repeat("x", 9<<10),
		"with\x00": "a\x00b",
	}
	out := cleanExtraFields(in)
	if out["submit"] != "Submit" || out["csrf"] != "tok" {
		t.Fatalf("clean fields = %v", out)
	}
	if _, ok := out[""]; ok {
		t.Fatalf("empty name kept: %v", out)
	}
	if _, ok := out["bad\r\n"]; ok {
		t.Fatalf("control-char name kept: %v", out)
	}
	if len(out["big"]) != 8<<10 {
		t.Fatalf("big value len = %d, want capped 8192", len(out["big"]))
	}
}

func TestHeaderLinesToMap(t *testing.T) {
	got := headerLinesToMap([]string{"Cookie: a=1; b=2", "X-Test:  spaced ", "no-colon", ": empty"})
	if got["Cookie"] != "a=1; b=2" {
		t.Fatalf("cookie = %q", got["Cookie"])
	}
	if got["X-Test"] != "spaced" {
		t.Fatalf("x-test = %q", got["X-Test"])
	}
	if len(got) != 2 {
		t.Fatalf("headers = %v, want only two valid", got)
	}
}
