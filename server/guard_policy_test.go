package server

import (
	"reflect"
	"testing"
)

func TestDSNSecrets(t *testing.T) {
	cases := []struct {
		dsn  string
		want []string
	}{
		{"postgres://jingwei:s3cret%40pw@127.0.0.1:5432/jingwei?sslmode=disable", []string{"s3cret@pw"}},
		{"host=127.0.0.1 port=5432 user=jingwei password=plainpw dbname=jingwei", []string{"plainpw"}},
		{`host=127.0.0.1 password='quoted pw'`, []string{"quoted pw"}},
		{"postgres://jingwei@127.0.0.1/jingwei", nil},
		{"", nil},
	}
	for _, c := range cases {
		if got := dsnSecrets(c.dsn); !reflect.DeepEqual(got, c.want) {
			t.Errorf("dsnSecrets(%q) = %v, want %v", c.dsn, got, c.want)
		}
	}
}

func TestNormalizeGuardMode(t *testing.T) {
	for _, c := range []struct{ in, fallback, want string }{
		{"strict", "warn", "strict"},
		{" WARN ", "strict", "warn"},
		{"off", "strict", "off"},
		{"nonsense", "warn", "warn"},
		{"", "strict", "strict"},
	} {
		if got := normalizeGuardMode(c.in, c.fallback); got != c.want {
			t.Errorf("normalizeGuardMode(%q,%q) = %q, want %q", c.in, c.fallback, got, c.want)
		}
	}
}
