package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	pgdb "github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/guard"
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
// Target checks fail closed when the policy data source is unavailable. A
// temporary database error must not turn strict scope or asset blocks off.
type guardTargetPolicy struct {
	pg      *pgdb.DB
	envMode string

	modeMu sync.Mutex
	mode   string
	modeAt time.Time

	companyMu sync.Mutex
	companies map[int64]companyScopeEntry

	authzMu sync.Mutex
	authz   []*pgdb.Authorization
	authzAt time.Time
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

// deny records one refusal and returns it. Metering is best-effort: the decision
// is already made, and a statistics write must not become a second failure path
// inside the security gate itself.
func (p *guardTargetPolicy) deny(taskID int64, category, reason string) (guard.ScopeVerdict, string) {
	if p.pg != nil {
		_ = p.pg.InsertGuardDenial(taskID, category, p.Mode(), reason)
	}
	return guard.ScopeOut, reason
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
	if p.pg == nil {
		return p.deny(taskID, pgdb.GuardDenialSourceUnavailable, "目标策略数据源不可用，请稍后重试")
	}
	domains, ips := splitTargetHosts(hosts)

	blocks, err := p.pg.ListAssetInterceptRules()
	if err != nil {
		log.Printf("[guard][target] 读取全局资产拦截规则失败(拒绝): %v", err)
		return p.deny(taskID, pgdb.GuardDenialBlockReadFailed,
			fmt.Sprintf("无法读取平台资产禁令，请稍后重试（%v）", err))
	}
	if taskID > 0 {
		tb, _, err := p.pg.Assets().TaskInterceptRulesSplit(taskID)
		if err != nil {
			log.Printf("[guard][target] 读取任务 %d 拦截规则失败(拒绝): %v", taskID, err)
			return p.deny(taskID, pgdb.GuardDenialBlockReadFailed,
				fmt.Sprintf("无法读取任务 %d 资产禁令，请稍后重试（%v）", taskID, err))
		}
		blocks = append(blocks, tb...)
	}
	if len(blocks) > 0 {
		if rule, matched, ok := pgdb.MatchAssetInterceptRules(blocks, domains, ips, urls); ok {
			return p.deny(taskID, pgdb.GuardDenialAssetBlock,
				fmt.Sprintf("目标 %s %s，该资产被平台禁止测试", matched, rule.Reason()))
		}
	}

	// 客户授权清单（F4）：只要平台里存在任何一条**有效**授权，目标就必须落在
	// 某条授权内且不命中其排除项；没有有效授权时保持历史行为（不强制）。
	// 读取失败按拒绝处理——授权清单读不到时放行，等于把「有授权才能打」变成
	// 「数据库挂了就能打」。
	auths, aerr := p.activeAuthorizations()
	if aerr != nil {
		log.Printf("[guard][target] 读取客户授权清单失败(拒绝): %v", aerr)
		return p.deny(taskID, pgdb.GuardDenialScopeReadFailed,
			fmt.Sprintf("无法读取客户授权清单，请稍后重试（%v）", aerr))
	}
	if len(auths) > 0 {
		var out []string
		for _, h := range hosts {
			probe := h
			if hostname, _, herr := net.SplitHostPort(h); herr == nil {
				probe = hostname
			}
			if !authorizationAllows(auths, probe) {
				out = append(out, h)
			}
		}
		if len(out) > 0 {
			return p.deny(taskID, pgdb.GuardDenialOutOfAuthorization,
				fmt.Sprintf("目标 %s 不在任何有效的客户授权清单内（有效授权: %s）",
					strings.Join(dedupeStrings(out), ", "), authorizationSummary(auths)))
		}
	}

	if taskID <= 0 {
		return guard.ScopeUnknown, ""
	}
	rules, err := p.scopeRules(taskID)
	if err != nil {
		// scopeRules 已在失败点记过类别（任务范围读不到 / 公司资产展不开），
		// 这里只把裁决交回去，不重复计数。
		return guard.ScopeOut, "无法读取任务授权范围，请稍后重试"
	}
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
	return p.deny(taskID, pgdb.GuardDenialOutOfScope, fmt.Sprintf("目标 %s 不在本任务已登记范围内（登记范围: %s）",
		strings.Join(dedupeStrings(out), ", "), scopeRuleSummary(rules)))
}

// activeAuthorizations 读取有效授权清单，缓存 30 秒（授权改动很少，而每个
// 目标检查都查库不值得）。读取失败不缓存，下一次会重试。
func (p *guardTargetPolicy) activeAuthorizations() ([]*pgdb.Authorization, error) {
	p.authzMu.Lock()
	if !p.authzAt.IsZero() && time.Since(p.authzAt) < 30*time.Second {
		v := p.authz
		p.authzMu.Unlock()
		return v, nil
	}
	p.authzMu.Unlock()
	list, err := p.pg.ListActiveAuthorizations()
	if err != nil {
		return nil, err
	}
	p.authzMu.Lock()
	p.authz, p.authzAt = list, time.Now()
	p.authzMu.Unlock()
	return list, nil
}

// invalidateAuthorizations 丢掉这份缓存，下一次检查重读库。
//
// 缓存连「一条授权都没有」这个结果一起缓存，而平台刚起来时那正是常态：操作员补完第一条
// 授权，进程级策略还要拿着空的清单最多 30 秒——这段时间里对着范围外主机的认证包照发不误，
// 发出去的包收不回。写入只发生在授权的建/删两处，所以改完就作废，比让读侧猜缓存新旧靠谱。
func (p *guardTargetPolicy) invalidateAuthorizations() {
	p.authzMu.Lock()
	p.authz, p.authzAt = nil, time.Time{}
	p.authzMu.Unlock()
}

// scopeRules converts task_scope rows into host-matchable rules. ICP/keyword
// rows carry no host constraint and are deliberately skipped; company rows are
// expanded to the company's assets (cached).
func (p *guardTargetPolicy) scopeRules(taskID int64) ([]guard.ScopeRule, error) {
	rows, err := p.pg.Assets().ListTaskScope(taskID)
	if err != nil {
		log.Printf("[guard][target] 读取任务 %d 测试范围失败(拒绝): %v", taskID, err)
		_, _ = p.deny(taskID, pgdb.GuardDenialScopeReadFailed,
			fmt.Sprintf("无法读取任务 %d 的授权范围，请稍后重试（%v）", taskID, err))
		return nil, err
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
				companyRules, err := p.companyRules(*ts.CompanyID)
				if err != nil {
					// 类别按「哪一处读不到」分：任务范围本身读到了，是它登记的
					// 公司资产展不开——操作员要去的是资产侧，不是范围页。
					_, _ = p.deny(taskID, pgdb.GuardDenialCompanyExpandFailed,
						fmt.Sprintf("展开公司 %d 的资产范围失败，请稍后重试（%v）", *ts.CompanyID, err))
					return nil, err
				}
				rules = append(rules, companyRules...)
			}
		}
	}
	return rules, nil
}

func (p *guardTargetPolicy) companyRules(companyID int64) ([]guard.ScopeRule, error) {
	p.companyMu.Lock()
	if e, ok := p.companies[companyID]; ok && time.Since(e.fetchedAt) < companyScopeTTL {
		rules := e.rules
		p.companyMu.Unlock()
		return rules, nil
	}
	p.companyMu.Unlock()

	domains, ips, truncated, err := p.pg.Assets().CompanyScopeHosts(companyID, companyScopeMaxRows)
	if err != nil {
		log.Printf("[guard][target] 展开公司 %d 范围失败(拒绝): %v", companyID, err)
		return nil, err
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
	return rules, nil
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

// guardDenialStats serves the fail-closed refusal ledger: per task and category,
// how many tool calls the target policy turned away in the window, and the last
// reason it gave. Since 1.4.1 an unreadable scope or block list denies the call
// instead of allowing it, so a database wobble looks exactly like a scope
// misconfiguration from the operator's side — this is what tells them apart.
func (s *Server) guardDenialStats(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeJSON(w, 200, map[string]any{"window_hours": 0, "denials": []pgdb.GuardDenialStat{}})
		return
	}
	hours := atoiDefault(r.URL.Query().Get("hours"), 168)
	if hours <= 0 || hours > 720 {
		hours = 168
	}
	stats, err := pg.GuardDenialStats(time.Duration(hours)*time.Hour, 200)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if stats == nil {
		stats = []pgdb.GuardDenialStat{}
	}
	// 按成因的分布与 per-task 明细一起返回：判断「要不要加短暂重试」看的是前者，
	// 定位「哪个任务被拒」看的是后者。两者同一次请求给出，避免界面拼两次数。
	breakdown, berr := pg.GuardDenialBreakdown(time.Duration(hours) * time.Hour)
	if berr != nil {
		writeErr(w, 500, berr.Error())
		return
	}
	if breakdown == nil {
		breakdown = []pgdb.GuardDenialCause{}
	}
	writeJSON(w, 200, map[string]any{
		"window_hours": hours, "mode": s.guardEnforcement(),
		"denials": stats, "causes": breakdown,
	})
}
