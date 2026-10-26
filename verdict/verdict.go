// Package verdict turns a scanner hit into a reviewable conclusion. It is
// deliberately deterministic: it never claims a vulnerability is real, it only
// flags hits that lack enough evidence to stand on their own. The same
// checklist is surfaced to LLM agents so manual review and the no-LLM pipeline
// share one standard.
package verdict

import (
	"regexp"
	"strings"
)

// Verdict values stored on exploit records.
const (
	Confirmed   = "confirmed"
	NeedsReview = "needs_review"
)

// Class is the vulnerability family used to pick the review checklist.
type Class string

const (
	ClassSQLi            Class = "sqli"
	ClassXSS             Class = "xss"
	ClassSSRF            Class = "ssrf"
	ClassCommandInject   Class = "cmdi"
	ClassFileUpload      Class = "file_upload"
	ClassAuthBypass      Class = "auth_bypass"
	ClassInfoLeak        Class = "info_leak"
	ClassDeserialization Class = "deserialization"
	ClassGeneric         Class = "generic"
)

// MatcherProfile is the matcher shape extracted from a nuclei template. A
// template that only checks the HTTP status is much weaker evidence than one
// that asserts a body word, regex or DSL expression.
type MatcherProfile struct {
	StatusOnly bool
	HasStatus  bool
	HasWord    bool
	HasRegex   bool
	HasDSL     bool
	HasOther   bool
}

// Observation is everything known about one hit at decision time.
type Observation struct {
	TemplateID string
	Name       string
	Tags       []string
	Type       string // nuclei result type; only http carries a response body
	StatusCode int
	Response   string
	Extracted  []string
	MatchedAt  string
	Matcher    *MatcherProfile
}

// Decision is the anti-false-positive conclusion for one hit.
type Decision struct {
	Class   Class    `json:"class"`
	Verdict string   `json:"verdict"`
	Reasons []string `json:"reasons,omitempty"`
	Checks  []string `json:"checks"`
}

// NeedsManualReview reports whether the hit is too weak to auto-confirm.
func (d Decision) NeedsManualReview() bool { return d.Verdict == NeedsReview }

var classHints = []struct {
	class Class
	words []string
}{
	{ClassDeserialization, []string{"deserialization", "deserialize", "java-chains", "fastjson", "log4j", "shiro", "jndi", "snakeyaml", "xstream"}},
	{ClassSQLi, []string{"sqli", "sql-injection", "sql_injection", "sql injection", "sql"}},
	{ClassXSS, []string{"xss", "cross-site-scripting", "cross site scripting"}},
	{ClassSSRF, []string{"ssrf", "server-side-request-forgery"}},
	{ClassCommandInject, []string{"cmdi", "command-injection", "command injection", "command_injection", "os-command", "os command", "rce"}},
	{ClassFileUpload, []string{"file-upload", "file_upload", "arbitrary-file-upload", "upload"}},
	{ClassAuthBypass, []string{"auth-bypass", "auth_bypass", "authorization", "access-control", "idor", "privilege-escalation"}},
	{ClassInfoLeak, []string{"info-leak", "info_leak", "exposure", "disclosure", "sensitive", "leak", "backup-file", "directory-listing"}},
}

// Classify maps a template's id, name and tags onto a vulnerability class.
func Classify(templateID, name string, tags []string) Class {
	haystack := strings.ToLower(strings.Join([]string{templateID, name, strings.Join(tags, " ")}, " "))
	for _, hint := range classHints {
		for _, word := range hint.words {
			if strings.Contains(haystack, word) {
				return hint.class
			}
		}
	}
	return ClassGeneric
}

var matcherTypeLine = regexp.MustCompile(`(?m)^\s*-\s*type:\s*(status|word|regex|dsl|xpath|binary|size)\b`)

// ParseMatcherProfile inspects template YAML for its matcher types. A nil
// profile means the shape could not be determined and should not be penalized.
func ParseMatcherProfile(content string) *MatcherProfile {
	matches := matcherTypeLine.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil
	}
	p := &MatcherProfile{}
	for _, m := range matches {
		switch m[1] {
		case "status":
			p.HasStatus = true
		case "word":
			p.HasWord = true
		case "regex":
			p.HasRegex = true
		case "dsl":
			p.HasDSL = true
		default:
			p.HasOther = true
		}
	}
	p.StatusOnly = p.HasStatus && !p.HasWord && !p.HasRegex && !p.HasDSL && !p.HasOther
	return p
}

// Assess decides whether a hit is confirmed by its own evidence or needs a
// manual/differential check. It never downgrades a hit to false positive:
// absence of proof is not proof of absence.
func Assess(obs Observation) Decision {
	class := Classify(obs.TemplateID, obs.Name, obs.Tags)
	d := Decision{Class: class, Verdict: Confirmed, Checks: Checklist(class)}

	if obs.StatusCode >= 500 {
		d.Verdict = NeedsReview
		d.Reasons = append(d.Reasons, "目标返回服务端错误（HTTP 5xx），无法区分漏洞与异常")
	}
	if isHTTP(obs.Type) {
		if strings.TrimSpace(obs.Response) == "" {
			d.Verdict = NeedsReview
			d.Reasons = append(d.Reasons, "未保留响应正文，无法人工复核匹配依据")
		}
	}
	if obs.Matcher != nil && obs.Matcher.StatusOnly && len(obs.Extracted) == 0 {
		d.Verdict = NeedsReview
		d.Reasons = append(d.Reasons, "模板仅以 HTTP 状态码匹配，且没有提取到任何证据")
	}
	if class == ClassXSS && len(obs.Extracted) == 0 {
		d.Verdict = NeedsReview
		d.Reasons = append(d.Reasons, "XSS 命中未提供反射/执行位置，需确认载荷未被编码且处于可执行上下文")
	}
	if class == ClassInfoLeak && isHTTP(obs.Type) && len(strings.TrimSpace(obs.Response)) < 16 {
		d.Verdict = NeedsReview
		d.Reasons = append(d.Reasons, "信息泄露命中响应过短，需确认泄露内容真实且敏感")
	}
	return d
}

func isHTTP(resultType string) bool {
	t := strings.ToLower(strings.TrimSpace(resultType))
	return t == "" || t == "http"
}

var generalChecks = []string{
	"重复执行至少两次，确认结果稳定（排除偶发 200、缓存和负载均衡差异）",
	"发送无效/随机对照载荷，确认响应差异确实由漏洞条件引起",
	"检查状态码与正文长度，排除 5xx、默认页、登录页和 WAF 拦截页",
	"保留原始请求、关键响应片段和可复现 curl 作为证据",
}

var classChecks = map[Class][]string{
	ClassSQLi: {
		"用布尔差异或时间延迟对照证明注入可控，不把单引号触发 500 当作注入",
		"至少给出报错、UNION 回显或时间盲注之一的可复现证据",
	},
	ClassXSS: {
		"确认载荷在响应中未被编码，且处于可执行上下文（HTML/属性/脚本）",
		"存储型需重新拉取页面确认持久化；有条件时用无头浏览器验证执行",
	},
	ClassSSRF: {
		"用唯一 token 的 OOB 回连或内网资源读取证明请求由目标发起",
		"区分仅 DNS 解析与完整 HTTP 请求，优先保留回连记录",
	},
	ClassCommandInject: {
		"用对照请求排除网络抖动后，以时间延迟、命令输出或 OOB 回连证明执行",
		"避免把通用报错页或模板语法错误当作命令执行",
	},
	ClassFileUpload: {
		"确认上传文件可访问，且内容/类型可控（不是仅返回 200 的假上传）",
		"确认落地路径可预测或可枚举，并检查是否可执行",
	},
	ClassAuthBypass: {
		"用未授权对照请求证明差异，确认返回的是受保护数据而不是登录页",
		"确认绕过可稳定复现，并记录受影响角色与接口",
	},
	ClassInfoLeak: {
		"确认泄露内容真实、敏感且非公开占位数据",
		"保留泄露字段的最小片段，避免把大文件整体写入报告",
	},
	ClassDeserialization: {
		"以 java-chains 回连或命令输出证明反序列化执行，而不是仅匹配报错栈",
		"记录利用链、回调地址与执行结果，用完及时关闭回调端口",
	},
	ClassGeneric: {
		"优先寻找模板特征之外的独立证据（唯一 marker、版本页、文件内容）",
		"若只能依赖状态码或通用关键词，标记为待人工复核",
	},
}

// Checklist returns the review checklist for a class. The returned slice is a
// copy so callers can append without mutating the package defaults.
func Checklist(class Class) []string {
	out := make([]string, 0, len(generalChecks)+4)
	out = append(out, generalChecks...)
	out = append(out, classChecks[class]...)
	return out
}
