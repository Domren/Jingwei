package guard

import (
	"net"
	"strings"
)

// ScopeRule is one task-scope rule. Kind is domain|ip|cidr. The server assembles
// these from db task_scope rows; root_domain/subdomain become domain, ip/cidr
// become cidr, and company scope is expanded to its assets.
type ScopeRule struct {
	Kind  string
	Value string
}

// ScopeVerdict is the three-state result of a scope check.
type ScopeVerdict int

const (
	// ScopeUnknown means no enforceable scope exists for the task — unregistered
	// scope passes (preserves the historical behavior).
	ScopeUnknown ScopeVerdict = iota
	// ScopeIn means the host matches at least one scope rule.
	ScopeIn
	// ScopeOut means scope rules exist but none match the host.
	ScopeOut
)

func (v ScopeVerdict) String() string {
	switch v {
	case ScopeIn:
		return "in"
	case ScopeOut:
		return "out"
	default:
		return "unknown"
	}
}

// TargetPolicy is implemented by the server layer (which can read PostgreSQL);
// guard itself never imports db. Mode returns off|warn|strict, Check reports
// whether the extracted targets are acceptable for the task and, when they are
// not, a self-contained explanation the model can act on.
type TargetPolicy interface {
	Mode() string
	Check(taskID int64, urls, hosts []string) (ScopeVerdict, string)
}

// ScopeMatcher matches hosts against a task's registered scope rules. Pure and
// stateless; safe for concurrent use.
type ScopeMatcher struct {
	domains  []string
	ips      []net.IP
	cidrs    []*net.IPNet
	hasRules bool
	// AllowLocal treats worker-local targets (loopback / link-local / localhost)
	// as in-scope: local operations are not an external target. RFC1918 addresses
	// are NOT allowed — intranet targets must be registered in task_scope.
	AllowLocal bool
}

// NewScopeMatcher compiles rules into a matcher. Rules with unparsable values
// are skipped. An empty (or all-skipped) rule set yields ScopeUnknown verdicts.
func NewScopeMatcher(rules []ScopeRule) *ScopeMatcher {
	m := &ScopeMatcher{AllowLocal: true}
	for _, r := range rules {
		v := strings.TrimSpace(r.Value)
		if v == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(r.Kind)) {
		case "domain":
			d := normalizeHost(v)
			if d != "" && net.ParseIP(d) == nil && (reHostName.MatchString(d) || reHostLabel.MatchString(d)) {
				m.domains = append(m.domains, d)
				m.hasRules = true
			}
		case "ip":
			if ip := net.ParseIP(normalizeHost(v)); ip != nil {
				m.ips = append(m.ips, ip)
				m.hasRules = true
			}
		case "cidr":
			if _, n, err := net.ParseCIDR(v); err == nil {
				m.cidrs = append(m.cidrs, n)
				m.hasRules = true
			}
		}
	}
	return m
}

// HasRules reports whether at least one enforceable rule was compiled. ICP and
// keyword-style scopes carry no host constraint, so they do not count.
func (m *ScopeMatcher) HasRules() bool { return m.hasRules }

// Check reports whether host is in scope. host may carry a :port (stripped)
// and is matched case-insensitively with trailing dots removed.
func (m *ScopeMatcher) Check(host string) ScopeVerdict {
	if !m.hasRules {
		return ScopeUnknown
	}
	h := normalizeHost(host)
	if h == "" {
		return ScopeUnknown
	}
	if m.AllowLocal && isLocalHost(h) {
		return ScopeIn
	}
	if ip := net.ParseIP(h); ip != nil {
		for _, rip := range m.ips {
			if rip.Equal(ip) {
				return ScopeIn
			}
		}
		for _, n := range m.cidrs {
			if n.Contains(ip) {
				return ScopeIn
			}
		}
		return ScopeOut
	}
	for _, d := range m.domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return ScopeIn
		}
	}
	return ScopeOut
}

// InScope is the boolean convenience form of Check (true only for ScopeIn).
func (m *ScopeMatcher) InScope(host string) bool { return m.Check(host) == ScopeIn }

// normalizeHost lowercases, trims a trailing dot and an optional :port, and
// strips IPv6 brackets.
func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i >= 0 {
			return strings.ToLower(strings.TrimSuffix(h[1:i], "."))
		}
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// isLocalHost reports whether h is a worker-local target: loopback, link-local,
// unspecified addresses, and the "localhost" name.
func isLocalHost(h string) bool {
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	return false
}
