package report

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// FindingReportInput is everything the deterministic vulnerability report needs.
// When HTTPRequest/HTTPResponse are present the PoC section embeds the raw
// messages; without them the report still renders a complete text report from
// the remaining evidence (TCP/non-HTTP findings, older records).
type FindingReportInput struct {
	FindingID       int64
	Name            string
	VulnClass       string
	Severity        string
	Status          string
	Summary         string
	Evidence        string
	TaskDescription string
	Source          string
	TemplateID      string
	Host            string
	MatchedAt       string
	Type            string
	Curl            string
	Extracted       []string
	HTTPRequest     string
	HTTPResponse    string
	GeneratedAt     time.Time
}

type requestParam struct {
	Name     string
	Location string
	Value    string
	Source   string
}

type vulnGuidance struct {
	Impact      string
	RootCause   string
	Remediation string
}

// BuildFindingReport renders the LLM-free report template. The marker in the
// first line lets storage distinguish this report from an LLM/human-authored
// one, so rescans may refresh it without overwriting manual work.
func BuildFindingReport(in FindingReportInput) string {
	at := in.GeneratedAt
	if at.IsZero() {
		at = time.Now()
	}
	name := nz(in.Name, nz(in.VulnClass, "未命名漏洞"))
	target := findingTarget(in)
	guidance := guidanceFor(in.VulnClass + " " + in.Name)

	var b strings.Builder
	b.WriteString(db.AutoReportMarker)
	b.WriteString("\n")
	b.WriteString(autoReportTemplateMarker)
	b.WriteString("\n")
	fmt.Fprintf(&b, "# [%s] %s", severityLabel(in.Severity), name)
	if target != "" {
		fmt.Fprintf(&b, " — %s", target)
	}
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "> 本报告由系统根据现有扫描/利用证据自动生成（无 LLM 模式）。")
	if in.HTTPRequest != "" || in.HTTPResponse != "" {
		if isRawProtocol(in) {
			b.WriteString(" 原始请求与响应数据已完整放入 PoC 章节。")
		} else {
			b.WriteString(" 原始 HTTP 请求与响应报文已完整放入 PoC 章节。")
		}
	}
	b.WriteString("配置并启用报告 Agent 后可在此基础上生成更深入的分析。\n\n")

	b.WriteString("| 字段 | 内容 |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| 漏洞编号 | #%d |\n", in.FindingID)
	fmt.Fprintf(&b, "| 严重等级 | %s |\n", severityLabel(in.Severity))
	fmt.Fprintf(&b, "| 漏洞类型 | %s |\n", markdownCell(nz(in.VulnClass, "未分类")))
	fmt.Fprintf(&b, "| 处理状态 | %s |\n", nz(in.Status, db.FindingPending))
	if in.MatchedAt != "" {
		fmt.Fprintf(&b, "| 命中位置 | %s |\n", markdownCell(in.MatchedAt))
	}
	if in.Host != "" && in.Host != in.MatchedAt {
		fmt.Fprintf(&b, "| 主机 | %s |\n", markdownCell(in.Host))
	}
	if in.Type != "" {
		fmt.Fprintf(&b, "| 记录类型 | %s |\n", markdownCell(in.Type))
	}
	if in.TaskDescription != "" {
		fmt.Fprintf(&b, "| 所属任务 | %s |\n", markdownCell(in.TaskDescription))
	}
	fmt.Fprintf(&b, "| 数据来源 | %s |\n", markdownCell(nz(in.Source, "平台记录")))
	fmt.Fprintf(&b, "| 报告生成时间 | %s（系统模板） |\n\n", at.Format("2006-01-02 15:04:05"))

	b.WriteString("## 概述\n\n")
	overview := strings.TrimSpace(in.Summary)
	if overview == "" {
		overview = fmt.Sprintf("在 %s 上发现 %s。", nz(target, "目标资产"), name)
	}
	b.WriteString(overview)
	if in.TemplateID != "" && in.TemplateID != in.VulnClass {
		fmt.Fprintf(&b, "\n\n检测模板/POC：`%s`。", in.TemplateID)
	}
	b.WriteString("\n\n")

	b.WriteString("## 影响与危害\n\n")
	b.WriteString(guidance.Impact)
	fmt.Fprintf(&b, "\n\n当前评级为 **%s**，建议结合业务数据敏感度与暴露面复核。\n\n", severityLabel(in.Severity))

	b.WriteString("## 受影响范围\n\n")
	if target != "" {
		fmt.Fprintf(&b, "- 受影响目标：`%s`\n", target)
	}
	if in.Host != "" {
		fmt.Fprintf(&b, "- 主机：`%s`\n", in.Host)
	}
	if in.MatchedAt != "" {
		fmt.Fprintf(&b, "- 命中地址：`%s`\n", in.MatchedAt)
	}
	if in.TemplateID != "" {
		fmt.Fprintf(&b, "- 检测模板：`%s`\n", in.TemplateID)
	}
	if in.Type != "" {
		fmt.Fprintf(&b, "- 请求类型：`%s`\n", in.Type)
	}
	fmt.Fprintf(&b, "- 漏洞类别：`%s`\n\n", nz(in.VulnClass, "未分类"))

	b.WriteString("## 复现与验证步骤\n\n")
	vin := in
	vin.Evidence = sanitizeEvidence(in.Evidence)
	steps, verificationData := verificationSteps(vin)
	for i, step := range steps {
		fmt.Fprintf(&b, "%d. %s\n", i+1, step)
	}
	b.WriteString("\n")
	if len(verificationData) > 0 {
		b.WriteString("## 验证数据\n\n")
		b.WriteString("| 项目 | 值 |\n| --- | --- |\n")
		for _, row := range verificationData {
			fmt.Fprintf(&b, "| %s | `%s` |\n", markdownCell(row.Label), markdownCell(truncateValue(row.Value, 300)))
		}
		b.WriteString("\n以上数据全部来自本次记录的原始报文或证据字段，未做推测补全。\n\n")
	}

	b.WriteString("## 证据\n\n")
	evidence := sanitizeEvidence(in.Evidence)
	if evidence == "" {
		evidence = "（未提供额外文字证据）"
	}
	b.WriteString(fenced("text", evidence))
	b.WriteString("\n\n")
	if len(in.Extracted) > 0 {
		b.WriteString("关键提取结果：\n\n")
		for _, item := range in.Extracted {
			fmt.Fprintf(&b, "- `%s`\n", strings.TrimSpace(item))
		}
		b.WriteString("\n")
	}

	b.WriteString("## PoC\n\n")
	rawProto := isRawProtocol(in)
	if in.HTTPRequest == "" && in.HTTPResponse == "" {
		if rawProto {
			b.WriteString("未采集到原始协议请求/响应数据（可能为服务发现，或扫描器/执行器未返回数据）。以下为现有可验证证据：\n\n")
		} else {
			b.WriteString("未采集到原始 HTTP 请求/响应报文（可能为 TCP、非 HTTP 协议漏洞，或扫描器/执行器未返回报文）。以下为现有可验证证据：\n\n")
		}
		b.WriteString(fenced("text", nz(evidence, "（无）")))
		b.WriteString("\n\n")
		if in.Curl != "" {
			b.WriteString("### 复现命令\n\n")
			b.WriteString(fenced("bash", in.Curl))
			b.WriteString("\n\n")
		}
	} else {
		reqTitle, respTitle, lang := "HTTP 请求报文", "HTTP 响应报文", "http"
		if rawProto {
			reqTitle, respTitle, lang = "原始请求数据", "原始响应数据", "text"
			b.WriteString("以下数据按原始字节记录，可直接用 nc 或任意 socket 客户端复现，无需改写。\n\n")
		} else {
			b.WriteString("以下报文按原始字节记录，可直接粘进 Burp/Repeater、nc 或任意 socket 客户端复现，无需改写。\n\n")
		}
		fmt.Fprintf(&b, "### %s\n\n", reqTitle)
		b.WriteString(fenced(lang, nz(in.HTTPRequest, "（未采集到请求数据）")))
		fmt.Fprintf(&b, "\n\n### %s\n\n", respTitle)
		b.WriteString(fenced(lang, nz(in.HTTPResponse, "（未采集到响应数据）")))
		b.WriteString("\n\n")
	}

	b.WriteString("## 参数与数据来源\n\n")
	if rawProto {
		b.WriteString(fmt.Sprintf("该发现来自非 HTTP 协议（%s），不适用 HTTP 参数解析；请直接使用 PoC 章节的原始请求数据复测。\n\n", nz(in.Type, "raw")))
	} else {
		params, method, requestTarget := parseRequestParams(in.HTTPRequest, nz(in.Source, "请求报文"), in.Extracted)
		if in.HTTPRequest == "" {
			b.WriteString("未采集到 HTTP 请求报文，无法从报文中解析传参。若该漏洞依赖注入参数，请结合「证据」与任务执行记录确认参数位置和来源。\n\n")
		} else if len(params) == 0 {
			fmt.Fprintf(&b, "请求 `%s %s` 中未解析到查询、正文、Cookie 或认证类参数；该漏洞可能是路径级、主机级或仅由请求头触发的类型。\n\n", method, requestTarget)
		} else {
			b.WriteString("| 参数 | 位置 | 值 | 数据来源 |\n| --- | --- | --- | --- |\n")
			for _, p := range params {
				fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s |\n",
					markdownCell(p.Name), p.Location, markdownCell(truncateValue(p.Value, 200)), markdownCell(p.Source))
			}
			b.WriteString("\n")
			if method != "" || requestTarget != "" {
				fmt.Fprintf(&b, "请求方法：`%s`；请求目标：`%s`。以上参数均来自该 HTTP 请求原文，未做猜测或补全。\n\n", method, requestTarget)
			}
		}
	}

	b.WriteString("## 根因分析\n\n")
	b.WriteString(guidance.RootCause)
	b.WriteString("\n\n")

	b.WriteString("## 修复建议\n\n")
	b.WriteString(guidance.Remediation)
	b.WriteString("\n\n")

	b.WriteString("## 附录：原始记录\n\n")
	fmt.Fprintf(&b, "- 数据来源：%s\n", nz(in.Source, "平台记录"))
	if in.TaskDescription != "" {
		fmt.Fprintf(&b, "- 所属任务：%s\n", in.TaskDescription)
	}
	if in.TemplateID != "" {
		fmt.Fprintf(&b, "- 模板 ID：`%s`\n", in.TemplateID)
	}
	if in.Type != "" {
		fmt.Fprintf(&b, "- 类型：`%s`\n", in.Type)
	}
	fmt.Fprintf(&b, "- 报告更新时间：%s\n", at.Format("2006-01-02 15:04:05"))
	return b.String()
}

// BuildFindingReportFromDB builds the deterministic report for a stored finding,
// parsing scan evidence for target/template details when dedicated columns are
// unavailable (older records created before those columns existed).
func BuildFindingReportFromDB(f *db.DBFinding) string {
	if f == nil {
		return ""
	}
	ev := parseEvidenceDetail(f.Evidence)
	in := FindingReportInput{
		FindingID:       f.ID,
		Name:            f.Name,
		VulnClass:       f.VulnClass,
		Severity:        f.Severity,
		Status:          f.Status,
		Summary:         f.Summary,
		Evidence:        f.Evidence,
		TaskDescription: f.TaskDescription,
		Source:          findingSource(f.Worker),
		TemplateID:      ev.templateID,
		Host:            ev.host,
		MatchedAt:       ev.matchedAt,
		Type:            ev.kind,
		Curl:            ev.curl,
		Extracted:       ev.extracted,
		HTTPRequest:     f.HTTPRequest,
		HTTPResponse:    f.HTTPResponse,
		GeneratedAt:     f.CreatedAt,
	}
	if in.TemplateID == "" {
		in.TemplateID = f.VulnClass
	}
	if in.MatchedAt == "" {
		_, _, requestTarget := parseRequestParams(f.HTTPRequest, "", nil)
		in.MatchedAt = requestTarget
	}
	if at := f.CreatedAt; !at.IsZero() {
		in.GeneratedAt = at
	}
	return BuildFindingReport(in)
}

// CompleteFindingReport returns the report to display/export. It generates the
// deterministic report when none exists (or when a previously auto-generated
// report is stale), and appends raw HTTP messages to an LLM/human report that
// omitted them. It never mutates the stored report.
func CompleteFindingReport(f *db.DBFinding) string {
	if f == nil {
		return ""
	}
	report := strings.TrimSpace(f.Report)
	if report == "" || needsAutoRebuild(report, f) {
		return BuildFindingReportFromDB(f)
	}
	return appendHTTPAppendix(report, f.HTTPRequest, f.HTTPResponse, isRawProtocol(FindingReportInputFromDB(f)))
}

// autoReportTemplateMarker records the revision of the deterministic template
// that produced a report. Bump it whenever the report layout changes so stored
// auto-reports are rewritten on next read; reports without the marker (LLM or
// human authored) are never replaced.
const autoReportTemplateMarker = "<!-- jingwei:auto-report-template:6 -->"

func isCurrentAutoReport(report string) bool {
	return strings.Contains(report, autoReportTemplateMarker)
}

func needsAutoRebuild(report string, f *db.DBFinding) bool {
	if !db.IsAutoReport(report) {
		return false
	}
	return !isCurrentAutoReport(report) || f.EvidenceVersion != f.ReportEvidenceVersion
}

func appendHTTPAppendix(report, request, response string, rawProtocol bool) string {
	request = strings.TrimSpace(request)
	response = strings.TrimSpace(response)
	if request == "" && response == "" {
		return report
	}
	hasRequest := request == "" || strings.Contains(report, request)
	hasResponse := response == "" || strings.Contains(report, response)
	if hasRequest && hasResponse {
		return report
	}
	var b strings.Builder
	b.WriteString(report)
	title, reqTitle, respTitle, lang := "## 附：原始 HTTP 报文（系统补充）", "### HTTP 请求报文", "### HTTP 响应报文", "http"
	if rawProtocol {
		title, reqTitle, respTitle, lang = "## 附：原始协议报文（系统补充）", "### 原始请求数据", "### 原始响应数据", "text"
	}
	b.WriteString("\n\n" + title + "\n\n")
	if !hasRequest {
		b.WriteString(reqTitle + "\n\n")
		b.WriteString(fenced(lang, request))
		b.WriteString("\n\n")
	}
	if !hasResponse {
		b.WriteString(respTitle + "\n\n")
		b.WriteString(fenced(lang, response))
		b.WriteString("\n\n")
	}
	return b.String()
}

// curlOmittedNote replaces curl examples in narrative sections so exports only
// present replayable raw HTTP packets.
const curlOmittedNote = "（curl 命令示例已省略，复现请使用本章「原始 HTTP 报文／原始协议报文」中的真实数据。）"

var (
	curlLineStartRE = regexp.MustCompile(`(?i)^\s*(?:\$\s+)?curl(?:\s|$)`)
	codeFenceRE     = regexp.MustCompile("^\\s*```")
)

// stripCurlArtifacts removes curl command examples from narrative text. Fenced
// blocks that start with a curl command are replaced by placeholder when it is
// non-empty; standalone curl lines and their backslash continuations are
// dropped. Fenced blocks holding raw HTTP packets are kept verbatim even when a
// payload line mentions curl.
func stripCurlArtifacts(text, placeholder string) string {
	if text == "" || !strings.Contains(strings.ToLower(text), "curl") {
		return text
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	removed := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if codeFenceRE.MatchString(line) {
			j := i + 1
			for j < len(lines) && !codeFenceRE.MatchString(lines[j]) {
				j++
			}
			if j < len(lines) {
				blockStartsWithCurl := false
				for k := i + 1; k < j; k++ {
					if strings.TrimSpace(lines[k]) == "" {
						continue
					}
					blockStartsWithCurl = curlLineStartRE.MatchString(lines[k])
					break
				}
				if blockStartsWithCurl {
					removed = true
					if placeholder != "" {
						out = append(out, placeholder)
					}
					i = j
					continue
				}
				out = append(out, lines[i:j+1]...)
				i = j
				continue
			}
		}
		if curlLineStartRE.MatchString(line) {
			removed = true
			for i+1 < len(lines) && strings.HasSuffix(strings.TrimSpace(lines[i]), "\\") {
				i++
			}
			continue
		}
		out = append(out, line)
	}
	if !removed {
		return text
	}
	return strings.Join(out, "\n")
}

// sanitizeEvidence drops curl invocations from stored evidence text. The PoC
// section already carries the raw request/response, and a curl line repeated
// next to them is noise that cannot be replayed byte-for-byte.
func sanitizeEvidence(evidence string) string {
	evidence = stripCurlArtifacts(evidence, "")
	lines := strings.Split(strings.ReplaceAll(evidence, "\r\n", "\n"), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			kept = append(kept, "")
			continue
		}
		if strings.HasPrefix(t, "curl") || strings.HasPrefix(t, "复现命令") {
			continue
		}
		kept = append(kept, line)
	}
	var out []string
	blank := false
	for _, line := range kept {
		if line == "" {
			if !blank && len(out) > 0 {
				out = append(out, "")
			}
			blank = true
			continue
		}
		blank = false
		out = append(out, line)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func findingSource(worker string) string {
	switch {
	case strings.HasPrefix(worker, "scan:"):
		return "自动化漏扫（nuclei）"
	case strings.HasPrefix(worker, "deep:"):
		return "深度利用"
	case strings.TrimSpace(worker) != "":
		return "Agent 上报（" + strings.TrimSpace(worker) + "）"
	default:
		return "平台记录"
	}
}

func findingTarget(in FindingReportInput) string {
	if strings.TrimSpace(in.MatchedAt) != "" {
		return strings.TrimSpace(in.MatchedAt)
	}
	if strings.TrimSpace(in.Host) != "" {
		return strings.TrimSpace(in.Host)
	}
	_, _, target := parseRequestParams(in.HTTPRequest, "", nil)
	return target
}

func severityLabel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case db.SeverityCritical:
		return "严重"
	case db.SeverityHigh:
		return "高危"
	case db.SeverityMedium:
		return "中危"
	case db.SeverityLow:
		return "低危"
	default:
		return nz(severity, "未知")
	}
}

func guidanceFor(text string) vulnGuidance {
	lower := strings.ToLower(text)
	// Template IDs are hyphenated (weak-password, default-password), so match
	// both the raw text and a space-normalised copy.
	lower = lower + " " + strings.NewReplacer("-", " ", "_", " ").Replace(lower)
	switch {
	case containsAny(lower, "sql", "sqli", "sql注入"):
		return vulnGuidance{
			Impact:      "攻击者可构造恶意 SQL 改变查询语义，读取、篡改或删除业务数据；在数据库账号权限过高时还可能通过文件读写或扩展执行进一步影响主机。",
			RootCause:   "应用把外部输入直接拼接进 SQL 语句，或使用了不安全的动态 SQL 拼接方式，未使用参数化查询，也没有对输入类型做严格约束。",
			Remediation: "统一使用参数化查询/预编译语句；禁止字符串拼接 SQL；数据库账号遵循最小权限；对输入做类型与长度校验；保留 WAF 作为纵深防御而非唯一修复手段。",
		}
	case containsAny(lower, "rce", "命令执行", "命令注入", "code execution", "远程代码", "代码执行"):
		return vulnGuidance{
			Impact:      "攻击者可在目标服务器上执行任意命令或代码，导致服务器被完全接管、敏感数据泄露，并可据此向内网横向移动。",
			RootCause:   "外部输入未经严格过滤即进入系统命令、模板引擎或代码执行函数，或危险组件/接口暴露在可被外部触达的位置。",
			Remediation: "避免将用户输入拼入命令或动态执行；使用参数化 API 与命令白名单；以最小权限运行服务；及时修复/移除危险组件；对高风险接口增加鉴权与审计。",
		}
	case containsAny(lower, "反序列化", "deserial"):
		return vulnGuidance{
			Impact:      "攻击者可构造恶意序列化数据触发危险对象链，通常可直接造成远程代码执行或服务器接管。",
			RootCause:   "应用反序列化不可信数据，且 classpath 中存在可被利用的 gadget 链，或对序列化数据来源缺乏完整性校验。",
			Remediation: "禁止反序列化不可信输入；使用安全的序列化格式（JSON 等）并做 schema 校验；升级/移除存在 gadget 的依赖；必要时启用反序列化白名单与运行时防护。",
		}
	case containsAny(lower, "xss", "跨站脚本"):
		return vulnGuidance{
			Impact:      "攻击者可在受害者浏览器中执行脚本，窃取会话、冒充用户操作或实施钓鱼；存储型 XSS 可影响大量用户。",
			RootCause:   "应用将不可信输入直接输出到 HTML/属性/脚本上下文，未按上下文做输出编码，也缺少安全的模板与 CSP 防护。",
			Remediation: "按 HTML、属性、URL、JavaScript 等上下文进行输出编码；使用自动转义的模板引擎；启用 CSP；对富文本做白名单清洗；对 Cookie 设置 HttpOnly/Secure。",
		}
	case containsAny(lower, "ssrf", "服务端请求伪造"):
		return vulnGuidance{
			Impact:      "攻击者可借服务端发起内网/本机请求，探测或访问云元数据、内部管理接口与未授权服务，形成边界突破。",
			RootCause:   "服务端直接请求用户可控 URL，未限制协议、目标地址与端口，也未隔离出网流量。",
			Remediation: "对目标域名/IP 实施严格白名单；禁止访问回环、内网与链路本地地址；限制协议与端口；隔离服务出网权限；关闭不必要的云元数据接口。",
		}
	case containsAny(lower, "xxe", "实体注入"):
		return vulnGuidance{
			Impact:      "攻击者可读取服务器本地文件、发起 SSRF 或造成拒绝服务，具体取决于 XML 解析器配置。",
			RootCause:   "XML 解析器允许外部实体或外部 DTD，并且直接解析不可信 XML。",
			Remediation: "禁用外部实体与外部 DTD；使用安全配置的解析器；对 XML 输入做大小与结构限制；优先使用 JSON 等更简单的数据格式。",
		}
	case containsAny(lower, "upload", "上传", "webshell", "任意文件写"):
		return vulnGuidance{
			Impact:      "攻击者可上传可执行脚本或覆盖敏感文件，进而获取服务器控制权；即使仅上传静态文件也可能造成存储型 XSS 或恶意内容托管。",
			RootCause:   "上传接口仅依赖客户端校验或后缀黑名单，未校验真实文件类型/内容，且上传目录可被 Web 直接解析执行。",
			Remediation: "按扩展名、MIME、魔数和内容多重校验；上传文件重命名并存储在 Web 根目录之外；禁止上传目录执行脚本；使用对象存储并做病毒扫描；限制文件大小与数量。",
		}
	case containsAny(lower, "lfi", "traversal", "文件包含", "目录遍历", "任意文件读", "path traversal"):
		return vulnGuidance{
			Impact:      "攻击者可读取服务器敏感文件或源码，为后续提权/横向提供凭据与配置信息；文件包含场景还可能升级为代码执行。",
			RootCause:   "应用直接使用用户可控路径拼接文件路径，未做规范化与白名单校验，允许 ../ 或绝对路径穿越。",
			Remediation: "对路径做规范化并校验最终路径位于允许目录；使用文件 ID/白名单映射替代用户可控路径；禁止包含上传目录中的文件；以最小权限运行服务。",
		}
	case containsAny(lower, "idor", "越权", "unauthorized", "auth bypass", "认证绕过", "未授权访问", "权限绕过"):
		return vulnGuidance{
			Impact:      "攻击者可访问或操作不属于自己的数据与功能，造成数据泄露、业务篡改，严重时可接管管理员能力。",
			RootCause:   "服务端仅依赖前端隐藏或客户端传入的身份标识做授权判断，缺少对当前主体与目标资源归属关系的服务端校验。",
			Remediation: "在服务端对每个敏感接口执行主体认证与对象级授权；以会话身份推导资源归属，不信任客户端传入的用户/资源 ID；补充越权测试与审计日志。",
		}
	case containsAny(lower, "弱口令", "weak password", "默认口令", "default credential", "default password"):
		return vulnGuidance{
			Impact:      "攻击者可凭弱口令直接登录系统，获得对应账号权限；若为管理员账号则可能导致系统完全失守。",
			RootCause:   "系统允许简单口令、使用出厂默认凭据或缺少登录失败限制，使口令可被猜测或撞库。",
			Remediation: "强制口令复杂度与长度要求；禁用默认账号/默认口令；启用 MFA；限制登录失败次数并监控异常登录；定期巡检弱口令。",
		}
	case containsAny(lower, "cors", "跨域"):
		return vulnGuidance{
			Impact:      "恶意站点可能读取受害者已认证的接口响应，造成敏感数据泄露；若同时允许凭据则风险更高。",
			RootCause:   "CORS 配置反射任意 Origin 或使用通配符，并允许携带凭据，未维护可信来源白名单。",
			Remediation: "仅对可信 Origin 返回 CORS 头；禁止 Origin 反射与通配符搭配凭据；按接口收敛允许的方法与头；对敏感接口增加额外校验。",
		}
	case containsAny(lower, "csrf", "跨站请求伪造"):
		return vulnGuidance{
			Impact:      "攻击者可诱导已登录用户在不知情的情况下执行敏感操作，如改密、转账或添加管理员。",
			RootCause:   "敏感操作仅依赖 Cookie 会话认证，缺少 CSRF Token、SameSite 或来源校验。",
			Remediation: "为状态变更操作加入不可预测的 CSRF Token 并在服务端校验；Cookie 设置 SameSite=Lax/Strict；校验 Origin/Referer；敏感操作要求二次确认。",
		}
	case containsAny(lower, "open redirect", "redirect", "跳转"):
		return vulnGuidance{
			Impact:      "攻击者可构造看似可信的跳转链接用于钓鱼或凭据窃取，并可能绕过部分基于域名白名单的安全控制。",
			RootCause:   "跳转目标直接取自用户输入，未限制为站内路径或可信域名。",
			Remediation: "跳转目标使用固定映射或严格域名白名单；仅允许相对路径；对跳转参数做编码与校验；对外链跳转增加提示页。",
		}
	case containsAny(lower, "泄露", "leak", "disclosure", "敏感信息", "debug", "备份", "information"):
		return vulnGuidance{
			Impact:      "暴露的配置、源码、凭据或调试信息可被攻击者用于进一步渗透，显著降低攻击成本。",
			RootCause:   "调试模式、备份文件、版本信息或错误详情在生产环境暴露，缺少访问控制与最小化输出。",
			Remediation: "关闭生产环境调试与详细报错；移除备份、源码与配置文件；统一错误页；对敏感目录增加鉴权；建立敏感信息巡检。",
		}
	default:
		return vulnGuidance{
			Impact:      "该漏洞可能被用于绕过正常业务约束、获取未授权信息或干扰服务。具体危害取决于受影响接口的业务重要性与可触达范围，建议结合资产等级复核。",
			RootCause:   "应用对来自外部的输入或请求缺少必要的校验、鉴权或安全配置，使攻击者可以触发非预期行为。",
			Remediation: "对输入做白名单校验与输出编码；在服务端实施鉴权与最小权限；及时更新受影响组件；为相关接口增加日志、告警与回归测试。",
		}
	}
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

type evidenceDetail struct {
	matchedAt  string
	host       string
	templateID string
	kind       string
	curl       string
	extracted  []string
}

func parseEvidenceDetail(evidence string) evidenceDetail {
	var d evidenceDetail
	for _, line := range strings.Split(evidence, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "匹配地址:"):
			d.matchedAt = strings.TrimSpace(strings.TrimPrefix(line, "匹配地址:"))
		case strings.HasPrefix(line, "主机:"):
			d.host = strings.TrimSpace(strings.TrimPrefix(line, "主机:"))
		case strings.HasPrefix(line, "模板:"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "模板:"))
			if i := strings.LastIndex(rest, " ("); i > 0 && strings.HasSuffix(rest, ")") {
				d.templateID = strings.TrimSpace(rest[i+2 : len(rest)-1])
			}
		case strings.HasPrefix(line, "类型:"):
			d.kind = strings.TrimSpace(strings.TrimPrefix(line, "类型:"))
		case strings.HasPrefix(line, "提取结果:"):
			for _, item := range strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "提取结果:")), ",") {
				if item = strings.TrimSpace(item); item != "" {
					d.extracted = append(d.extracted, item)
				}
			}
		case strings.HasPrefix(line, "curl:") || strings.HasPrefix(line, "复现命令:"):
			d.curl = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "复现命令:"), "curl:"))
		}
	}
	return d
}

func parseRequestParams(raw, source string, extracted []string) ([]requestParam, string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "", ""
	}
	head, body := splitHTTPMessage(raw)
	lines := strings.Split(head, "\n")
	method, target := "", ""
	if fields := strings.Fields(strings.TrimSpace(lines[0])); len(fields) > 0 {
		method = fields[0]
		if len(fields) > 1 {
			target = fields[1]
		}
	}
	headers := map[string]string{}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		if prev, exists := headers[key]; exists {
			headers[key] = prev + "; " + strings.TrimSpace(value)
		} else {
			headers[key] = strings.TrimSpace(value)
		}
	}

	baseSource := nz(source, "HTTP 请求报文")
	var params []requestParam
	add := func(name, location, value string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		params = append(params, requestParam{
			Name:     name,
			Location: location,
			Value:    value,
			Source:   parameterSource(location, name, value, baseSource, extracted),
		})
	}

	path, query := splitTarget(target)
	for _, pair := range formPairs(query) {
		add(pair[0], "URL 查询参数", pair[1])
	}
	for _, segment := range pathSegments(path) {
		if looksLikePathParameter(segment) {
			add("path["+segment+"]", "URL 路径", segment)
		}
	}
	if cookie := headers["cookie"]; cookie != "" {
		for _, pair := range strings.Split(cookie, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if ok && strings.TrimSpace(name) != "" {
				add(strings.TrimSpace(name), "Cookie", value)
			}
		}
	}
	for key, value := range headers {
		switch key {
		case "authorization", "x-api-key", "x-auth-token", "token", "api-key", "x-access-token":
			add(key, "请求头", value)
		}
	}

	contentType := strings.ToLower(headers["content-type"])
	switch {
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		for _, pair := range formPairs(body) {
			add(pair[0], "表单正文", pair[1])
		}
	case strings.Contains(contentType, "application/json"):
		var data any
		if json.Unmarshal([]byte(body), &data) == nil {
			flattenJSONParams("", data, &params, func(name, value string) {
				add(name, "JSON 正文", value)
			})
		}
	case strings.Contains(contentType, "multipart/form-data"):
		for _, p := range parseMultipartParams(body, headers["content-type"]) {
			add(p.Name, "multipart 表单", p.Value)
		}
	case strings.TrimSpace(body) != "" && len(body) <= 4<<10:
		add("(raw body)", "请求体", body)
	}
	return params, method, target
}

// formPairs splits an urlencoded query string or request body. url.ParseQuery is
// deliberately not used: exploit payloads routinely contain `;` (statement
// separators, command chaining) and ParseQuery rejects those outright, which
// would silently drop every parameter from the report.
func formPairs(raw string) [][2]string {
	var out [][2]string
	for _, part := range strings.Split(strings.TrimSpace(raw), "&") {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(unescapeForm(name))
		if name == "" {
			continue
		}
		out = append(out, [2]string{name, unescapeForm(value)})
	}
	return out
}

func unescapeForm(s string) string {
	if decoded, err := url.QueryUnescape(s); err == nil {
		return decoded
	}
	return s
}

func splitHTTPMessage(raw string) (string, string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	return raw, ""
}

func splitTarget(target string) (string, string) {
	if target == "" {
		return "", ""
	}
	u, err := url.Parse(target)
	if err != nil {
		return target, ""
	}
	return u.Path, u.RawQuery
}

func pathSegments(path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func looksLikePathParameter(segment string) bool {
	if len(segment) < 2 {
		return false
	}
	digits, letters := 0, 0
	for _, r := range segment {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			letters++
		}
	}
	return digits > 0 && (digits == len(segment) || (letters > 0 && len(segment) >= 8))
}

func parameterSource(location, name, value, base string, extracted []string) string {
	source := base
	switch location {
	case "URL 查询参数":
		source += "；URL 查询参数，随请求发送到目标"
	case "表单正文":
		source += "；表单正文，随请求发送到目标"
	case "JSON 正文":
		source += "；JSON 正文，随请求发送到目标"
	case "multipart 表单":
		source += "；multipart 表单字段，随请求发送到目标"
	case "Cookie":
		source += "；Cookie 会话值，由客户端携带"
	case "请求头":
		source += "；认证/凭据类请求头，由客户端携带"
	case "URL 路径":
		source += "；URL 路径段"
	case "请求体":
		source += "；原始请求体"
	}
	lower := strings.ToLower(name)
	if location == "请求头" && containsAny(lower, "auth", "token", "key") {
		source += "（认证凭据）"
	}
	for _, item := range extracted {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if value == item || (len(value) >= 4 && strings.Contains(item, value)) || (len(item) >= 4 && strings.Contains(value, item)) {
			source += "；与服务端回显/提取结果一致"
			break
		}
	}
	return source
}

func flattenJSONParams(prefix string, value any, params *[]requestParam, add func(name, value string)) {
	if len(*params) >= 80 {
		return
	}
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			flattenJSONParams(name, v[key], params, add)
		}
	case []any:
		for i, item := range v {
			flattenJSONParams(fmt.Sprintf("%s[%d]", prefix, i), item, params, add)
		}
	case string:
		add(prefix, v)
	case nil:
		add(prefix, "null")
	default:
		add(prefix, fmt.Sprint(v))
	}
}

func parseMultipartParams(body, contentType string) []requestParam {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return nil
	}
	reader := multipart.NewReader(strings.NewReader(body), params["boundary"])
	var out []requestParam
	for len(out) < 40 {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		name := part.FormName()
		if name == "" {
			_ = part.Close()
			continue
		}
		if filename := part.FileName(); filename != "" {
			out = append(out, requestParam{Name: name, Location: "multipart 表单", Value: "[文件] " + filename})
			_ = part.Close()
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(part, 2<<10))
		out = append(out, requestParam{Name: name, Location: "multipart 表单", Value: string(data)})
		_ = part.Close()
	}
	return out
}

func fenced(language, content string) string {
	content = strings.TrimRight(content, "\r\n")
	content = strings.ReplaceAll(content, "\x00", "")
	fence := "```"
	for strings.Contains(content, fence) {
		fence += "`"
	}
	if content == "" {
		return "_（空）_"
	}
	return fence + language + "\n" + content + "\n" + fence
}

func markdownCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", "<br>")
	return s
}

func truncateValue(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit]) + "…"
}
