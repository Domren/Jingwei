package server

import (
	"testing"

	"github.com/Autumn-27/jingwei/db"
)

// F4：授权清单的匹配语义。记错任何一个（例如 .corp.com 当成也匹配 corp.com）
// 都会让「排除项」在真实客户环境里失效。
func TestAuthorizationRuleMatches(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"10.0.0.0/8", "10.2.3.4", true},
		{"10.0.0.0/8", "11.2.3.4", false},
		{"192.0.2.10", "192.0.2.10", true},
		{"192.0.2.10", "192.0.2.11", false},
		{"corp.com", "corp.com", true},
		{"corp.com", "app.corp.com", true},
		{"corp.com", "corp.com.evil.net", false},
		{".corp.com", "app.corp.com", true},
		{".corp.com", "corp.com", false},
	}
	for _, c := range cases {
		if got := authorizationRuleMatches(c.pattern, c.host); got != c.want {
			t.Errorf("%s ~ %s = %v want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestAuthorizationAllowsWithExclusions(t *testing.T) {
	auths := []*db.Authorization{
		{Name: "客户A", Targets: []string{"10.0.0.0/8", "corp.com"}, Exclusions: []string{"10.9.9.9"}},
	}
	cases := map[string]bool{
		"10.1.2.3":     true,
		"10.9.9.9":     false, // 排除项优先
		"app.corp.com": true,
		"evil.com":     false,
	}
	for host, want := range cases {
		if got := authorizationAllows(auths, host); got != want {
			t.Errorf("allows(%s) = %v want %v", host, got, want)
		}
	}
	// 没有任何授权时不强制（历史行为）；由 Check 决定是否启用。
	if !authorizationAllows(nil, "anything") == false {
		t.Fatal("空授权清单不应放行任何目标")
	}
}
