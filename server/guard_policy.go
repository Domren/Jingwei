package server

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

// settingGuardEnforcement is the runtime override for the deterministic agent
// guard: off | warn | strict. It is read at most every few seconds; the env
// JINGWEI_GUARD_ENFORCEMENT sets the fallback (default strict).
const settingGuardEnforcement = "guard_enforcement"

const (
	guardModeCacheTTL   = 5 * time.Second
	companyScopeTTL     = 60 * time.Second
	companyScopeMaxRows = 20000
	scopeReasonMaxRules = 8
)

// guardTargetPolicy implements guard.TargetPolicy on top of PostgreSQL:
// platform + task asset block rules first, then the task's registered scope.
// Fail-open on read errors (logged): a transient DB hiccup must not brick all
// agent tool calls.
type guardTargetPolicy struct {
	pg      *pgdb.DB
	envMode string

	modeMu sync.Mutex
	mode   string
	modeAt time.Time

	companyMu sync.Mutex
	companies map[int64]companyScopeEntry
}

type companyScopeEntry struct {
	rules     []guard.ScopeRule
	fetchedAt time.Time
}

func newGuardTargetPolicy(pg *pgdb.DB) *guardTargetPolicy {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("JINGWEI_GUARD_ENFORCEMENT")))
	return &guardTargetPolicy{
		pg:        pg,
		envMode:   normalizeGuardMode(env, "strict"),
		companies: map[int64]companyScopeEntry{},
	}
}

func normalizeGuardMode(v, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "off":
		return "off"
	case "warn":
		return "warn"
	case "strict":
		return "strict"
	}
	return fallback
}

// Mode returns the effective enforcement mode. A persisted setting
// (guard_enforcement) wins over the env fallback; both are normalized.
func (p *guardTargetPolicy) Mode() string {
	p.modeMu.Lock()
	if !p.modeAt.IsZero() && time.Since(p.modeAt) < guardModeCacheTTL {
		v := p.mode
		p.modeMu.Unlock()
		return v
	}
	p.modeMu.Unlock()

	mode := p.envMode
	if p.pg != nil {
		if v, ok, err := p.pg.GetSetting(settingGuardEnforcement); err == nil && ok && strings.TrimSpace(v) != "" {
			mode = normalizeGuardMode(v, mode)
		}
	}
	p.modeMu.Lock()
	p.mode, p.modeAt = mode, time.Now()
	p.modeMu.Unlock()
	return mode
}

// Check enforces, in order:
//  1. global + task asset block rules (URL/domain/IP/CIDR; block always wins),
//  2. the task's registered scope (only when it has host-matchable rules).
//
// Check runs for chat too (taskID 0): asset blocks are platform-wide, while the
// scope comparison needs a task.
func (p *guardTargetPolicy) Check(taskID int64, urls, hosts []string) (guard.ScopeVerdict, string) {
	if len(urls) == 0 && len(hosts) == 0 {
		return guard.ScopeUnknown, ""
	}
	domains, ips := splitTargetHosts(hosts)

	blocks, err := p.pg.ListAssetInterceptRules()
	if err != nil {
		log.Printf("[guard][target] 读取全局资产拦截规则失败(放行): %v", err)
		blocks = nil
	}
	if taskID > 0 {
		if tb, _, err := p.pg.Assets().TaskInterceptRulesSplit(taskID); err != nil {
			log.Printf("[guard][target] 读取任务 %d 拦截规则失败(放行): %v", taskID, err)
		} else {
			blocks = append(blocks, tb...)
		}
	}
	if len(blocks) > 0 {
		if rule, matched, ok := pgdb.MatchAssetInterceptRules(blocks, domains, ips, urls); ok {
			return guard.ScopeOut, fmt.Sprintf("目标 %s %s，该资产被平台禁止测试", matched, rule.Reason())
		}
	}

	if taskID <= 0 {
		return guard.ScopeUnknown, ""
	}
	rules := p.scopeRules(taskID)
	m := guard.NewScopeMatcher(rules)
	if !m.HasRules() {
		return guard.ScopeUnknown, ""
	}
	var out []string
	for _, h := range hosts {
		if m.Check(h) == guard.ScopeOut {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return guard.ScopeIn, ""
	}
	return guard.ScopeOut, fmt.Sprintf("目标 %s 不在本任务已登记范围内（登记范围: %s）",
		strings.Join(dedupeStrings(out), ", "), scopeRuleSummary(rules))
}

// scopeRules converts task_scope rows into host-matchable rules. ICP/keyword
// rows carry no host constraint and are deliberately skipped; company rows are
// expanded to the company's assets (cached).
func (p *guardTargetPolicy) scopeRules(taskID int64) []guard.ScopeRule {
	rows, err := p.pg.Assets().ListTaskScope(taskID)
	if err != nil {
		log.Printf("[guard][target] 读取任务 %d 测试范围失败(放行): %v", taskID, err)
		return nil
	}
	var rules []guard.ScopeRule
	for _, ts := range rows {
		switch strings.ToLower(strings.TrimSpace(ts.Kind)) {
		case "root_domain", "subdomain":
			if d := strings.TrimSpace(ts.Domain); d != "" {
				rules = append(rules, guard.ScopeRule{Kind: "domain", Value: d})
			}
		case "ip", "cidr":
			if n := strings.TrimSpace(ts.Net); n != "" {
				rules = append(rules, guard.ScopeRule{Kind: "cidr", Value: n})
			} else if v := strings.TrimSpace(ts.Value); v != "" {
				rules = append(rules, guard.ScopeRule{Kind: "cidr", Value: v})
			}
		case "company":
			if ts.CompanyID != nil && *ts.CompanyID > 0 {
				rules = append(rules, p.companyRules(*ts.CompanyID)...)
			}
		}
	}
	return rules
}

func (p *guardTargetPolicy) companyRules(companyID int64) []guard.ScopeRule {
	p.companyMu.Lock()
	if e, ok := p.companies[companyID]; ok && time.Since(e.fetchedAt) < companyScopeTTL {
		rules := e.rules
		p.companyMu.Unlock()
		return rules
	}
	p.companyMu.Unlock()

	domains, ips, truncated, err := p.pg.Assets().CompanyScopeHosts(companyID, companyScopeMaxRows)
	if err != nil {
		log.Printf("[guard][target] 展开公司 %d 范围失败(放行): %v", companyID, err)
		return nil
	}
	if truncated {
		log.Printf("[guard][target] 公司 %d 资产超过 %d 条，范围匹配仅覆盖已加载部分", companyID, companyScopeMaxRows)
	}
	rules := make([]guard.ScopeRule, 0, len(domains)+len(ips))
	for _, d := range domains {
		rules = append(rules, guard.ScopeRule{Kind: "domain", Value: d})
	}
	for _, ip := range ips {
		rules = append(rules, guard.ScopeRule{Kind: "ip", Value: ip})
	}
	p.companyMu.Lock()
	p.companies[companyID] = companyScopeEntry{rules: rules, fetchedAt: time.Now()}
	p.companyMu.Unlock()
	return rules
}

func splitTargetHosts(hosts []string) (domains, ips []string) {
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if net.ParseIP(h) != nil {
			ips = append(ips, h)
		} else {
			domains = append(domains, h)
		}
	}
	return domains, ips
}

func scopeRuleSummary(rules []guard.ScopeRule) string {
	if len(rules) == 0 {
		return "无"
	}
	parts := make([]string, 0, scopeReasonMaxRules)
	for i, r := range rules {
		if i >= scopeReasonMaxRules {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, r.Kind+"="+r.Value)
	}
	return strings.Join(parts, ", ")
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// dsnSecrets extracts the password from a URL or key-value DSN so the egress
// guard can fingerprint it. The full DSN is registered separately by the caller.
func dsnSecrets(dsn string) []string {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil
	}
	var out []string
	if strings.Contains(dsn, "://") {
		if u, err := url.Parse(dsn); err == nil && u.User != nil {
			if pw, ok := u.User.Password(); ok && pw != "" {
				out = append(out, pw)
			}
		}
		return out
	}
	for _, m := range reDSNPassword.FindAllStringSubmatch(dsn, -1) {
		v := m[1]
		if v == "" {
			v = m[2]
		}
		if v == "" {
			v = m[3]
		}
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

var reDSNPassword = regexp.MustCompile(`(?i)(?:password|pass)\s*=\s*(?:'([^']*)'|"([^"]*)"|([^\s]+))`)
