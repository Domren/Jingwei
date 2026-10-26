package report

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// verificationRow is one labeled fact shown in the report's 验证数据 table.
type verificationRow struct {
	Label string
	Value string
}

// verificationFacts is parsed from the raw HTTP request/response captured for a
// finding. Every value comes from the recorded bytes or the stored record; the
// report never invents a step or a datum.
type verificationFacts struct {
	method      string
	proto       string
	target      string
	host        string
	scheme      string
	protocol    string // raw protocol (tcp/udp/...) when the finding is not HTTP
	reqBodyLen  int
	statusLine  string
	statusCode  int
	contentType string
	server      string
	location    string
	setCookie   string
	respBodyLen int
	respExcerpt string
	extracted   []string
}

// isRawProtocol reports whether the finding's capture is not HTTP(S), e.g. a
// nuclei network template result for Redis or MySQL. Those bytes must not be
// presented as an HTTP request (no http:// replay URL, Host header or status
// line).
func isRawProtocol(in FindingReportInput) bool {
	return IsRawProtocolType(in.Type)
}

// packetLabels names the raw-capture section of a finding. A finding that
// carried no protocol type and no captured bytes must not be labelled HTTP.
func packetLabels(in FindingReportInput, hasPackets bool) (heading, reqTitle, respTitle, missing string) {
	switch {
	case isRawProtocol(in):
		return "原始协议报文", "原始请求数据", "原始响应数据",
			"未采集到原始协议请求/响应数据（可能为端口/服务发现、测试时未开启流量捕获，或执行器未返回数据）。本报告不会用虚构数据替代，请依据「证据」与「验证数据」复验。"
	case !hasPackets:
		return "原始报文", "请求报文", "响应报文",
			"未采集到原始报文或协议数据（可能是非 HTTP 协议发现、端口/服务发现、测试时未开启流量捕获、执行器未返回报文，" +
				"或本次导出早于流量证据落库——任务仍在运行时重新导出即可获得报文）。本报告不会用虚构内容替代，请依据「证据」与「验证数据」复验。"
	default:
		return "原始 HTTP 报文", "HTTP 请求报文", "HTTP 响应报文",
			"未采集到原始 HTTP 请求/响应报文（可能为非 HTTP 协议发现、测试时未开启流量捕获，或执行器未返回报文）。本报告不会用虚构报文替代，请依据「证据」与「验证数据」复验。"
	}
}

// IsRawProtocolType reports whether a finding came from a non-HTTP protocol, so
// callers label its capture as raw request/response data instead of HTTP packets.
func IsRawProtocolType(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "http", "https", "http(s)", "web", "http/1.1", "http/2":
		return false
	}
	return true
}

func rawFirstLine(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		// Rendered protocol packets lead with "# ..." metadata and section
		// markers; the excerpt must be real captured bytes, not the header.
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line != "" {
			return truncateRunes(strings.Join(strings.Fields(line), " "), 120)
		}
	}
	return ""
}

func parseMessageHead(raw string) (startLine string, headers map[string]string, body string, hasBody bool) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	if raw == "" {
		return "", nil, "", false
	}
	head, body := splitHTTPMessage(raw)
	lines := strings.Split(head, "\n")
	startLine = strings.TrimSpace(lines[0])
	headers = map[string]string{}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(name))
		if key != "" {
			headers[key] = strings.TrimSpace(value)
		}
	}
	return startLine, headers, body, body != ""
}

// messageBodyLen counts body bytes before CRLF normalisation so the reported
// sizes match the captured wire bytes (and Content-Length) instead of the
// normalised copy used for parsing.
func messageBodyLen(raw string) int {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return len(raw) - i - 4
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return len(raw) - i - 2
	}
	return 0
}

func verificationFor(in FindingReportInput) verificationFacts {
	f := verificationFacts{extracted: append([]string(nil), in.Extracted...)}
	if isRawProtocol(in) {
		f.protocol = strings.ToUpper(strings.TrimSpace(in.Type))
		f.host = strings.TrimSpace(in.Host)
		f.reqBodyLen = len(in.HTTPRequest)
		f.respBodyLen = len(in.HTTPResponse)
		f.respExcerpt = rawFirstLine(in.HTTPResponse)
		return f
	}
	reqStart, reqHeaders, reqBody, hasReqBody := parseMessageHead(in.HTTPRequest)
	if fields := strings.Fields(reqStart); len(fields) > 0 {
		f.method = fields[0]
		if len(fields) > 1 {
			f.target = fields[1]
		}
		if len(fields) > 2 {
			f.proto = fields[2]
		}
	}
	if f.target != "" {
		if u, err := url.Parse(f.target); err == nil {
			if u.Host != "" {
				f.host = u.Host
				f.scheme = u.Scheme
			}
		}
	}
	if h := reqHeaders["host"]; h != "" {
		f.host = h
	}
	if f.scheme == "" {
		port := ""
		if parsed, err := url.Parse("//" + f.host); err == nil {
			port = parsed.Port()
		}
		if port == "443" || port == "8443" || port == "4443" || port == "9443" {
			f.scheme = "https"
		} else if f.host != "" {
			f.scheme = "http"
		}
	}
	if hasReqBody || reqBody != "" {
		f.reqBodyLen = messageBodyLen(in.HTTPRequest)
	}

	respStart, respHeaders, respBody, _ := parseMessageHead(in.HTTPResponse)
	if respStart != "" {
		f.statusLine = respStart
		if fields := strings.Fields(respStart); len(fields) > 1 {
			f.statusCode, _ = strconv.Atoi(fields[1])
		}
	}
	f.contentType = respHeaders["content-type"]
	f.server = respHeaders["server"]
	f.location = respHeaders["location"]
	f.setCookie = respHeaders["set-cookie"]
	f.respBodyLen = messageBodyLen(in.HTTPResponse)
	if f.respBodyLen > 0 {
		f.respExcerpt = evidenceExcerpt(in.VulnClass, in.Name, f.target, reqBody, respBody)
	}
	if f.respExcerpt == "" && f.location != "" {
		f.respExcerpt = fmt.Sprintf("%s，Location: %s", nz(f.statusLine, "响应"), f.location)
	}
	// Weak session findings are proven by the cookie the server hands out, not by
	// the page body, so cite the recorded Set-Cookie header directly.
	if f.setCookie != "" && isSessionFinding(in.VulnClass, in.Name) {
		f.respExcerpt = fmt.Sprintf("%s，Set-Cookie: %s", nz(f.statusLine, "响应"), f.setCookie)
	}
	if f.host == "" {
		target := findingTarget(in)
		if target != "" {
			if u, err := url.Parse(target); err == nil && u.Host != "" {
				f.host = u.Host
			} else {
				f.host = target
			}
		}
	}
	return f
}

var (
	blindSQLEvidenceRE = regexp.MustCompile(`(?i)User ID (?:exists in the database|is MISSING from the database)[^<\r\n]{0,40}`)
	sqlHashEvidenceRE  = regexp.MustCompile(`(?i)Surname\s*:\s*[0-9a-f]{32}`)
	sqlEvidenceRE      = regexp.MustCompile(`(?i)(?:First name|Surname|User ID)\s*:\s*[^<\s][^<\r\n]{0,99}|You have an error in your SQL syntax[^<\r\n]{0,120}|SQLSTATE\[[A-Z0-9]+\][^<\r\n]{0,120}`)
	xssEvidenceRE      = regexp.MustCompile(`(?is)<script[^>]{0,200}>[^<]{0,300}(?:alert|prompt|confirm|document\.cookie)[^<]{0,300}</script>|<svg[^>]{0,200}onload[^>]{0,200}>|<img[^>]{0,200}onerror[^>]{0,200}>`)
	cmdEvidenceRE      = regexp.MustCompile(`(?i)uid=\d+\([^)]*\)\s*gid=\d+\([^)]*\)[^\r\n<]{0,80}|nt authority\\system`)
	fileEvidenceRE     = regexp.MustCompile(`(?is)root:x:0:0:[^\r\n<]{0,120}|\[boot loader\][^\r\n<]{0,80}|\[extensions\][^\r\n<]{0,80}`)
	uploadEvidenceRE   = regexp.MustCompile(`(?i)[^<>]{0,60}(?:succesfully|successfully) uploaded[^<]{0,60}`)
	authEvidenceRE     = regexp.MustCompile(`(?i)(?:you have logged in as|welcome to the password protected area|logged in)[^<]{0,80}`)
	csrfEvidenceRE     = regexp.MustCompile(`(?i)Password Changed\.?|Passwords do not match\.?`)
	genericTagRE       = regexp.MustCompile(`(?s)<[^>]*>`)
)

// isSessionFinding reports whether the response cookie itself is the proof.
func isSessionFinding(vulnClass, name string) bool {
	class := strings.ToLower(vulnClass + " " + name)
	return containsAny(class, "session", "会话", "cookie")
}

// evidenceExcerpt picks the response bytes that actually demonstrate the
// vulnerability instead of quoting the document preamble. Scan findings carry an
// extractor value; agent findings do not, so the excerpt is located from the
// recorded response using class-appropriate markers and reflected input.
func evidenceExcerpt(vulnClass, name, reqTarget, reqBody, respBody string) string {
	body := toValidText(respBody)
	if strings.TrimSpace(body) == "" {
		return ""
	}
	class := strings.ToLower(vulnClass + " " + name)
	var markers []*regexp.Regexp
	reflectFirst := false
	// Specific classes come before the broad command/RCE bucket: an upload
	// finding titled "Unrestricted File Upload / RCE" must quote its upload
	// success marker, not fall into command-output matching.
	switch {
	case containsAny(class, "upload", "上传"):
		markers = []*regexp.Regexp{uploadEvidenceRE}
	case containsAny(class, "lfi", "file inclusion", "文件包含", "path traversal", "目录遍历", "任意文件", "文件读取"):
		markers = []*regexp.Regexp{fileEvidenceRE}
	case containsAny(class, "sql", "注入"):
		markers = []*regexp.Regexp{blindSQLEvidenceRE, sqlHashEvidenceRE, sqlEvidenceRE}
	case containsAny(class, "csrf", "跨站请求伪造", "请求伪造"):
		// CSRF names often contain 跨站, so this must precede the XSS branch.
		markers = []*regexp.Regexp{csrfEvidenceRE}
	case containsAny(class, "xss", "跨站脚本", "cross-site scripting"):
		markers = []*regexp.Regexp{xssEvidenceRE}
		reflectFirst = true
	case containsAny(class, "credential", "password", "弱口令", "默认口令", "brute", "登录"):
		markers = []*regexp.Regexp{authEvidenceRE}
	case containsAny(class, "command", "命令", "rce", "代码执行", "exec"):
		markers = []*regexp.Regexp{cmdEvidenceRE}
	}
	var fallback []*regexp.Regexp
	if len(markers) == 0 {
		fallback = []*regexp.Regexp{blindSQLEvidenceRE, sqlHashEvidenceRE, sqlEvidenceRE, xssEvidenceRE, cmdEvidenceRE, fileEvidenceRE, uploadEvidenceRE, authEvidenceRE, csrfEvidenceRE}
	}
	if reflectFirst {
		if idx, payload := reflectedInput(reqTarget, reqBody, body); idx >= 0 {
			return snippetAt(body, idx, idx+len(payload), 160)
		}
	}
	for _, re := range markers {
		if loc := re.FindStringIndex(body); loc != nil {
			return snippetAt(body, loc[0], loc[1], 160)
		}
	}
	if !reflectFirst {
		if idx, payload := reflectedInput(reqTarget, reqBody, body); idx >= 0 {
			return snippetAt(body, idx, idx+len(payload), 160)
		}
	}
	for _, re := range fallback {
		if loc := re.FindStringIndex(body); loc != nil {
			return snippetAt(body, loc[0], loc[1], 160)
		}
	}
	return visibleExcerpt(body, 160)
}

// reflectedInput finds the longest request parameter value echoed verbatim in
// the response body — the decisive proof for XSS and similar reflection bugs.
func reflectedInput(target, reqBody, body string) (int, string) {
	values := []string{}
	if u, err := url.Parse(target); err == nil {
		for _, vs := range u.Query() {
			values = append(values, vs...)
		}
	}
	for _, pair := range strings.Split(reqBody, "&") {
		if _, v, ok := strings.Cut(pair, "="); ok {
			if dec, err := url.QueryUnescape(v); err == nil {
				values = append(values, dec)
			}
		}
	}
	best, bestVal := -1, ""
	for _, v := range values {
		v = strings.TrimSpace(v)
		if len(v) < 4 || strings.ContainsAny(v, "\r\n") {
			continue
		}
		if idx := strings.Index(body, v); idx >= 0 && len(v) > len(bestVal) {
			best, bestVal = idx, v
		}
	}
	return best, bestVal
}

func snippetAt(body string, start, end, max int) string {
	if start < 0 || start >= len(body) {
		return ""
	}
	if end <= start {
		end = start
	}
	if end > len(body) {
		end = len(body)
	}
	margin := (max - (end - start)) / 2
	if margin < 0 {
		margin = 0
	}
	from, to := start-margin, end+margin
	if from < 0 {
		from = 0
	}
	if to > len(body) {
		to = len(body)
	}
	for from > 0 && !utf8.RuneStart(body[from]) {
		from--
	}
	for to < len(body) && !utf8.RuneStart(body[to]) {
		to++
	}
	out := strings.Join(strings.Fields(body[from:to]), " ")
	if from > 0 {
		out = "…" + out
	}
	if to < len(body) {
		out += "…"
	}
	return truncateRunes(out, max+2)
}

func visibleExcerpt(body string, max int) string {
	b := body
	lower := strings.ToLower(b)
	if i := strings.Index(lower, "</head>"); i >= 0 {
		b = b[i+len("</head>"):]
	}
	lower = strings.ToLower(b)
	if i := strings.Index(lower, "<body"); i >= 0 {
		if j := strings.Index(b[i:], ">"); j >= 0 {
			b = b[i+j+1:]
		}
	}
	b = genericTagRE.ReplaceAllString(b, " ")
	return truncateRunes(strings.Join(strings.Fields(b), " "), max)
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// isHostHeaderInjection reports whether the Host header is itself the attack
// payload (password-reset poisoning, cache poisoning). Replay instructions must
// not turn that injected value into the connection address.
func isHostHeaderInjection(in FindingReportInput) bool {
	lower := strings.ToLower(in.VulnClass + " " + in.Name)
	if !strings.Contains(lower, "host") {
		return false
	}
	return strings.Contains(lower, "inject") || strings.Contains(lower, "注入") ||
		strings.Contains(lower, "poison") || strings.Contains(lower, "投毒") ||
		strings.Contains(lower, "篡改") || strings.Contains(lower, "伪造")
}

// verificationSteps returns the concrete replay/verification steps for a finding.
// With raw packets the steps cite the exact request line, host, sizes and status;
// without packets they explicitly fall back to the evidence text.
func verificationSteps(in FindingReportInput) ([]string, []verificationRow) {
	f := verificationFor(in)
	target := findingTarget(in)
	steps := []string{}
	if isRawProtocol(in) {
		proto := nz(f.protocol, "TCP")
		host := nz(target, nz(in.Host, "目标地址"))
		steps = append(steps, fmt.Sprintf("确认目标 %s 的 %s 服务可访问（仅在授权测试环境执行）。", host, proto))
		if strings.TrimSpace(in.HTTPRequest) != "" {
			line := fmt.Sprintf("发送原始 %s 请求数据：`%s`", proto, rawFirstLine(in.HTTPRequest))
			if f.reqBodyLen > 0 {
				line += fmt.Sprintf("，共 %d 字节", f.reqBodyLen)
			}
			steps = append(steps, line+"。数据按原始字节发送，不做 HTTP 封装。")
		} else {
			steps = append(steps, fmt.Sprintf("该发现未采集到原始 %s 请求数据；按「证据」章节记录的操作复现。", proto))
		}
		if strings.TrimSpace(in.HTTPResponse) != "" {
			line := fmt.Sprintf("读取原始响应：`%s`", rawFirstLine(in.HTTPResponse))
			if f.respBodyLen > 0 {
				line += fmt.Sprintf("，共 %d 字节", f.respBodyLen)
			}
			steps = append(steps, line+"。")
		}
		if len(f.extracted) > 0 {
			steps = append(steps, fmt.Sprintf("在响应中核对验证特征：%s；这些值同时出现在提取结果中。", strings.Join(f.extracted, "、")))
		} else if f.respExcerpt != "" {
			steps = append(steps, fmt.Sprintf("核对响应中的命中特征：`%s`。", f.respExcerpt))
		}
		steps = append(steps, "如需复测，直接重放本报告「原始协议报文」章节中的请求与响应数据，不要改写内容。")

		rows := make([]verificationRow, 0, 6)
		add := func(label, value string) {
			if strings.TrimSpace(value) != "" {
				rows = append(rows, verificationRow{Label: label, Value: value})
			}
		}
		add("目标", host)
		add("协议", proto)
		if f.reqBodyLen > 0 {
			add("请求数据大小", fmt.Sprintf("%d 字节", f.reqBodyLen))
		}
		if f.respBodyLen > 0 {
			add("响应数据大小", fmt.Sprintf("%d 字节", f.respBodyLen))
		}
		add("响应摘要", f.respExcerpt)
		add("验证特征", strings.Join(f.extracted, "、"))
		return steps, rows
	}
	if f.method != "" || f.target != "" {
		access := nz(target, nz(f.host, "目标地址"))
		scheme := nz(f.scheme, "http")
		if strings.HasPrefix(access, "/") && f.host != "" {
			if isHostHeaderInjection(in) {
				// The Host header is the attacker-controlled payload, not the
				// address that was connected to. Building a URL from it would
				// point the replay at the injected domain.
				steps = append(steps, fmt.Sprintf("确认任务登记的真实资产地址可访问（仅在授权测试环境执行）；本次原始请求的 Host 头为注入值 `%s`，它只作为请求头使用，不是连接地址。", f.host))
			} else {
				access = scheme + "://" + f.host + access
				steps = append(steps, fmt.Sprintf("确认目标可访问：以 %s 访问 %s（仅在授权测试环境执行）。", scheme, access))
			}
		} else {
			steps = append(steps, fmt.Sprintf("确认目标可访问：以 %s 访问 %s（仅在授权测试环境执行）。", scheme, access))
		}
		line := fmt.Sprintf("发送原始请求：`%s %s", f.method, f.target)
		if f.proto != "" {
			line += " " + f.proto
		}
		line += "`"
		if f.host != "" {
			line += fmt.Sprintf("，Host: `%s`", f.host)
		}
		if f.reqBodyLen > 0 {
			line += fmt.Sprintf("，请求体 %d 字节", f.reqBodyLen)
		}
		steps = append(steps, line+"。报文须保持方法、路径、请求头与正文不变。")
		if f.statusLine != "" {
			line := fmt.Sprintf("读取响应：`%s`", f.statusLine)
			if f.contentType != "" {
				line += fmt.Sprintf("，Content-Type: `%s`", f.contentType)
			}
			if f.respBodyLen > 0 {
				line += fmt.Sprintf("，响应体 %d 字节", f.respBodyLen)
			}
			if f.setCookie != "" && isSessionFinding(in.VulnClass, in.Name) {
				line += fmt.Sprintf("，Set-Cookie: `%s`", f.setCookie)
			}
			steps = append(steps, line+"。")
		} else {
			steps = append(steps, "读取响应，记录状态行、关键响应头与响应正文。")
		}
		evidence := nz(f.respExcerpt, "")
		if len(f.extracted) > 0 {
			steps = append(steps, fmt.Sprintf("在响应中核对验证特征：%s；这些值同时出现在提取结果中。", strings.Join(f.extracted, "、")))
		} else if evidence != "" {
			steps = append(steps, fmt.Sprintf("核对响应中的命中特征：`%s`。", evidence))
		} else {
			steps = append(steps, "对照该漏洞的判定条件核对响应状态码与正文回显，确认漏洞可复现。")
		}
		steps = append(steps, "如需复测，直接重放本报告「原始 HTTP 报文」章节中的请求与响应，不要改写报文内容。")
	} else {
		steps = append(steps, fmt.Sprintf("确认目标 %s 可访问（仅在授权测试环境执行）。", nz(target, "资产")))
		steps = append(steps, "该发现未采集到原始报文或协议数据；按「证据」章节记录的操作、命令输出或响应片段复现。")
		if e := firstEvidenceLine(in.Evidence); e != "" {
			steps = append(steps, fmt.Sprintf("核对证据中的关键回显：`%s`。", e))
		} else {
			steps = append(steps, "对照证据中的命令输出、状态码或响应回显确认漏洞存在。")
		}
	}

	rows := make([]verificationRow, 0, 12)
	add := func(label, value string) {
		if strings.TrimSpace(value) != "" {
			rows = append(rows, verificationRow{Label: label, Value: value})
		}
	}
	add("请求方法", f.method)
	add("请求目标", f.target)
	add("主机", f.host)
	add("协议", f.scheme)
	add("状态行", f.statusLine)
	add("Content-Type", f.contentType)
	add("Server", f.server)
	add("跳转地址", f.location)
	add("Set-Cookie", f.setCookie)
	if f.reqBodyLen > 0 {
		add("请求体大小", fmt.Sprintf("%d 字节", f.reqBodyLen))
	}
	if f.respBodyLen > 0 {
		add("响应体大小", fmt.Sprintf("%d 字节", f.respBodyLen))
	}
	add("响应摘要", f.respExcerpt)
	add("验证特征", strings.Join(f.extracted, "、"))
	add("匹配地址", in.MatchedAt)
	add("检测模板", in.TemplateID)
	add("数据来源", nz(in.Source, "平台记录"))
	return steps, rows
}

func firstEvidenceLine(evidence string) string {
	for _, line := range strings.Split(evidence, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "匹配地址:") || strings.HasPrefix(line, "主机:") ||
			strings.HasPrefix(line, "模板:") || strings.HasPrefix(line, "类型:") || strings.HasPrefix(line, "提取结果:") {
			continue
		}
		line = strings.TrimPrefix(line, "命中特征:")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 160 {
			line = line[:160] + "…"
		}
		return line
	}
	return ""
}

// toValidText keeps report text printable: invalid UTF-8 becomes U+FFFD and NUL
// bytes are dropped so an HTML or Markdown export cannot be corrupted by a binary
// protocol payload.
func toValidText(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.ToValidUTF8(s, "\uFFFD")
}
