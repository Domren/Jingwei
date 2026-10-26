package guard

import "testing"

func TestScopeMatcher(t *testing.T) {
	m := NewScopeMatcher([]ScopeRule{
		{Kind: "domain", Value: "example.com"},
		{Kind: "cidr", Value: "10.0.0.0/8"},
		{Kind: "ip", Value: "192.168.1.5"},
		{Kind: "keyword", Value: "ignored"},
	})
	if !m.HasRules() {
		t.Fatal("rule set should be enforceable")
	}
	cases := []struct {
		host string
		want ScopeVerdict
	}{
		{"example.com", ScopeIn},
		{"a.b.example.com:8443", ScopeIn},
		{"EXAMPLE.COM.", ScopeIn},
		{"10.1.2.3", ScopeIn},
		{"[::1]:80", ScopeIn},
		{"192.168.1.5", ScopeIn},
		{"192.168.1.6", ScopeOut},
		{"other.test", ScopeOut},
		{"example.com.evil.test", ScopeOut},
		{"localhost", ScopeIn},
		{"127.0.0.1", ScopeIn},
		{"", ScopeUnknown},
	}
	for _, c := range cases {
		if got := m.Check(c.host); got != c.want {
			t.Errorf("Check(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestScopeMatcherNoEnforceableRules(t *testing.T) {
	for _, rules := range [][]ScopeRule{
		nil,
		{{Kind: "keyword", Value: "foo"}},
		{{Kind: "icp", Value: "京ICP备12345678号"}},
		{{Kind: "domain", Value: "not a domain"}},
	} {
		m := NewScopeMatcher(rules)
		if m.HasRules() {
			t.Errorf("rules %v should not be enforceable", rules)
		}
		if got := m.Check("anything.test"); got != ScopeUnknown {
			t.Errorf("Check with no rules = %v, want unknown", got)
		}
	}
}

func TestScopeMatcherAllowLocalCanBeDisabled(t *testing.T) {
	m := NewScopeMatcher([]ScopeRule{{Kind: "domain", Value: "example.com"}})
	m.AllowLocal = false
	if got := m.Check("127.0.0.1"); got != ScopeOut {
		t.Fatalf("local host with AllowLocal=false = %v, want out", got)
	}
}
