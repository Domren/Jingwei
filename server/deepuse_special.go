package server

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/artex/scanner"
	"github.com/Autumn-27/artex/verdict"
)

// Specialized injection verification. A POC template only proves that a request
// produced an interesting response; SQL injection and XSS need a tool that
// proves the parameter is really an injection point. sqlmap and dalfox do that,
// and their verdicts replace the template's verdict on the linked finding.

// probePoint is one parameter location handed to a specialized verifier.
type probePoint struct {
	URL        string
	Method     string
	Body       string
	Params     []string
	TemplateID string
	Source     string
	FindingIDs []int64
	// Cookie is the session the POC itself established. A point behind a login is
	// untestable without it, and a tool negative on a page that only answered with
	// a redirect says nothing about what the POC claimed.
	Cookie string
}

// probeInjection is one injection point a tool proved, with the packet pair
// Jingwei replayed to capture reproducible evidence.
type probeInjection struct {
	Param       string
	Where       string
	Kind        string
	Title       string
	Payload     string
	Request     string
	Response    string
	Baseline    string
	BaselineReq string
	StatusCode  int
	ReplayNote  string
	// Proved says the replayed response really shows the payload's effect, so a
	// reader can reproduce the verdict from the packets alone.
	Proved bool
}

// probeResult is the outcome of verifying one point.
type probeResult struct {
	Tool       string
	Verdict    string
	Name       string
	Detail     string
	Injections []probeInjection
	// Baseline holds the untouched request/response of a point the tool could not
	// reproduce, so the negative verdict is reproducible from packets as well.
	Baseline baselineExchange
	Elapsed  time.Duration
	Err      error
}

type probeCreds struct {
	Cookie  string
	Headers []string
}

// mapSliceParam reads an array of JSON objects from task params.
func mapSliceParam(params map[string]any, key string) []map[string]any {
	out := []map[string]any{}
	if params == nil {
		return out
	}
	list, ok := params[key].([]any)
	if !ok {
		return out
	}
	for _, v := range list {
		if m, ok := v.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func stringFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// collectProbePoints returns the injection points to verify, bounded by the
// max_points parameter.
func (r *deepRun) collectProbePoints(class string) []probePoint {
	pts := []probePoint{}
	seen := map[string]bool{}
	add := func(p probePoint) {
		p.URL = strings.TrimSpace(p.URL)
		if p.URL == "" {
			return
		}
		p.URL, p.Body = sanitizeProbeTarget(p.URL, p.Body)
		key := p.TemplateID + "|" + strings.ToLower(p.URL)
		if seen[key] {
			return
		}
		seen[key] = true
		if p.Method == "" {
			p.Method = "GET"
		}
		p.Method = strings.ToUpper(p.Method)
		if len(p.FindingIDs) == 0 {
			p.FindingIDs = templateFindingIDs(r.task.Params, p.TemplateID)
		}
		pts = append(pts, p)
	}
	for _, raw := range mapSliceParam(r.task.Params, "points") {
		p := probePoint{
			URL:        stringFromMap(raw, "url"),
			Method:     stringFromMap(raw, "method"),
			Body:       stringFromMap(raw, "data"),
			Cookie:     usableSession(stringFromMap(raw, "cookie")),
			TemplateID: stringFromMap(raw, "template_id"),
			Source:     stringFromMap(raw, "source"),
			FindingIDs: idsFromAny(raw["finding_ids"]),
		}
		if params, ok := raw["params"].([]any); ok {
			for _, v := range params {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					p.Params = append(p.Params, strings.TrimSpace(s))
				}
			}
		}
		add(p)
	}
	for _, u := range stringSliceParam(r.task.Params, "urls") {
		add(probePoint{URL: u, TemplateID: stringParam(r.task.Params, "template_id"), Source: "参数指定"})
	}
	if len(pts) == 0 {
		add(probePoint{URL: r.task.Target, Source: "任务目标"})
	}
	before := len(pts)
	pts = dedupeProbePoints(pts)
	if len(pts) < before {
		r.logf("probe", "注入点去重：%d 个命中点合并为 %d 个参数位置", before, len(pts))
	}
	limit := intParam(r.task.Params, "max_points", 8)
	if limit < 1 {
		limit = 1
	}
	if limit > 50 {
		limit = 50
	}
	if class == scanner.InjectionXSS && limit > 20 {
		limit = 20
	}
	if len(pts) > limit {
		r.logf("probe", "注入点共 %d 个，仅验证前 %d 个（可用 max_points 调整）", len(pts), limit)
		pts = pts[:limit]
	}
	return pts
}

// dedupeProbePoints collapses points a tool would test twice: one parameter
// location can answer to several template hits, and every linked finding has to
// survive the merge so a single run can confirm them all.
func dedupeProbePoints(pts []probePoint) []probePoint {
	out := make([]probePoint, 0, len(pts))
	index := map[string]int{}
	for _, p := range pts {
		key := p.Method + "|" + strings.ToLower(p.URL) + "|" + p.Body
		if i, ok := index[key]; ok {
			out[i].FindingIDs = mergeProbeIDs(out[i].FindingIDs, p.FindingIDs)
			continue
		}
		index[key] = len(out)
		out = append(out, p)
	}
	return out
}

func mergeProbeIDs(primary, extra []int64) []int64 {
	seen := make(map[int64]bool, len(primary)+len(extra))
	for _, id := range primary {
		seen[id] = true
	}
	for _, id := range extra {
		if id > 0 && !seen[id] {
			primary = append(primary, id)
			seen[id] = true
		}
	}
	return primary
}

// probeCredentials reads the session material the injection point needs.
func (r *deepRun) probeCredentials() probeCreds {
	c := probeCreds{Cookie: stringParam(r.task.Params, "cookie")}
	if i := strings.Index(strings.ToLower(c.Cookie), "cookie:"); i == 0 {
		c.Cookie = strings.TrimSpace(c.Cookie[len("Cookie:"):])
	}
	for _, h := range stringSliceParam(r.task.Params, "headers") {
		if strings.Contains(h, "\n") {
			continue
		}
		c.Headers = append(c.Headers, h)
	}
	if ua := stringParam(r.task.Params, "user_agent"); ua != "" && !strings.Contains(ua, "\n") {
		c.Headers = append(c.Headers, "User-Agent: "+ua)
	}
	return c
}

// probeHostAllowed keeps an external binary on the host the task was given.
// The blocklist is checked for every URL in targets() before the task starts;
// this adds the positive check that no probe wanders to another host.
func (r *deepRun) probeHostAllowed(rawURL string) bool {
	want, err := url.Parse(strings.TrimSpace(r.task.Target))
	if err != nil || want.Hostname() == "" {
		return false
	}
	got, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || got.Hostname() == "" {
		return false
	}
	return strings.EqualFold(got.Hostname(), want.Hostname())
}

func (r *deepRun) runSQLiProbe(summary map[string]any) (string, string, string, map[string]any) {
	return r.runInjectionProbe(scanner.InjectionSQLi, summary)
}

func (r *deepRun) runXSSProbe(summary map[string]any) (string, string, string, map[string]any) {
	return r.runInjectionProbe(scanner.InjectionXSS, summary)
}

// runInjectionProbe verifies every collected point with the tool that owns the
// class and writes one exploit record plus replayed packets per proved point.
func (r *deepRun) runInjectionProbe(class string, summary map[string]any) (string, string, string, map[string]any) {
	tool := scanner.ToolForInjection(class)
	stage := tool
	summary["tool"] = tool
	summary["class"] = class
	points := r.collectProbePoints(class)
	summary["points"] = len(points)
	if len(points) == 0 {
		return "failed", stage, "没有可验证的注入点", summary
	}
	available := scanner.SQLMapAvailable()
	if class == scanner.InjectionXSS {
		available = scanner.DalfoxAvailable()
	}
	if !available {
		msg := tool + " 未安装，无法执行专项验证（镜像需内置 " + tool + "）"
		r.logf(stage, "%s", msg)
		return "failed", stage, msg, summary
	}
	creds := r.probeCredentials()
	r.logf(stage, "开始 %s 专项验证：%d 个注入点（版本 %s）", tool, len(points), displayOr(r.probeToolVersion(class), "未知"))

	confirmed, review, notReproduced, skipped, kept := 0, 0, 0, 0, 0
	uncovered := 0
	reopened := 0
	timedOut := false
	unreachable := 0
	wedged := false
	processed := 0
	for i, p := range points {
		if r.ctx.Err() != nil {
			timedOut = true
			break
		}
		if !r.probeHostAllowed(p.URL) {
			skipped++
			r.logf(stage, "注入点 %s 不属于任务目标 %s，已跳过", p.URL, r.task.Target)
			continue
		}
		processed++
		r.setProgress(stage, map[string]any{"point": i + 1, "points": len(points), "confirmed": confirmed})
		r.logf(stage, "验证注入点 %d/%d：%s", i+1, len(points), p.URL)
		res := r.verifyProbePoint(class, p, r.credsForPoint(creds, p))
		res = sessionBlockedNegative(res)
		if res.Verdict == "not_reproduced" && probePointReachable(res) {
			res = r.rejudgeProbeNegative(class, p, res, r.credsForPoint(creds, p))
		}
		rec := r.recordProbeResult(class, p, res)
		switch res.Verdict {
		case verdict.Confirmed:
			confirmed++
			r.applyProbeConfirmation(class, p, res, rec)
		case verdict.NeedsReview:
			review++
		case "not_reproduced":
			notReproduced++
			reopened += r.demotePOCVerdicts(class, res, p)
		case "session_needed":
			kept++
			r.logf(stage, "%s 无法判定 %s：%s（对照响应 %d），保留原判定，可在专项任务参数中补有效登录后复测",
				res.Tool, p.URL, displayOr(res.Detail, "该点需要登录会话"), res.Baseline.status)
		case probeVerdictUncovered:
			uncovered++
			r.logf(stage, "%s 未复现 %s，但该变体不在其检测能力内，不撤销原判定：%s",
				res.Tool, p.URL, displayOr(res.Detail, "专项工具无法覆盖该注入变体"))
		}
		if res.Err != nil {
			r.logf(stage, "%s 验证 %s 失败: %v", tool, p.URL, res.Err)
		}
		// Two points in a row that the target never answered means the host is out
		// of reach for the whole run; the remaining points would each burn a tool
		// timeout plus a baseline timeout for a verdict that cannot be a judgement.
		if res.Verdict == probeVerdictUncovered && res.Baseline.status == 0 {
			unreachable++
			if unreachable >= 2 {
				wedged = true
				r.logf(stage, "连续 %d 个注入点的对照请求都得不到 HTTP 响应，%s", unreachable, targetWedgedHint)
				break
			}
		} else {
			unreachable = 0
		}
	}
	summary["confirmed"] = confirmed
	summary["needs_review"] = review
	summary["not_reproduced"] = notReproduced
	summary["skipped"] = skipped
	summary["session_needed"] = kept
	summary["tool_uncovered"] = uncovered
	if wedged {
		left := len(points) - processed
		summary["target_unreachable"] = left
		msg := fmt.Sprintf("目标连续拒绝响应，%s 专项验证提前结束（已探测 %d/%d 个注入点，确认 %d 个）", tool, processed, len(points), confirmed)
		if left > 0 {
			msg += fmt.Sprintf("，剩余 %d 个点未发送探测", left)
		}
		return "failed", stage, msg + "。" + targetWedgedHint, summary
	}
	summary["findings_reopened"] = reopened
	summary["findings_confirmed"] = r.confirmedFindingCount()
	r.setProgress(stage, map[string]any{"confirmed": confirmed, "needs_review": review, "not_reproduced": notReproduced})
	if timedOut {
		return "timeout", stage, fmt.Sprintf("%s 专项验证超时：已确认 %d 个注入点，其余未完成", tool, confirmed), summary
	}
	if confirmed+review+notReproduced == 0 && skipped > 0 {
		return "failed", stage, "所有注入点都不在本任务范围内，未发送任何请求", summary
	}
	r.logf(stage, "专项验证完成：%d 个注入点确认，%d 个待复核，%d 个未复现，%d 个跳过", confirmed, review, notReproduced, skipped)
	if uncovered > 0 {
		r.logf(stage, "%d 个注入点不在专项工具的判定能力内（宽字节字符集、盲打/DOM/存储型输出点、基线不可用），原判定保持不变", uncovered)
	}
	if reopened > 0 {
		r.logf(stage, "%s 未能复现的 %d 个发现已退回待处理，其 POC 判定不再计入确认漏洞", tool, reopened)
	}
	if kept > 0 {
		r.logf(stage, "%d 个注入点因缺少登录会话无法判定，原判定保持不变（提供 cookie 后可复测）", kept)
	}
	return "done", stage, "", summary
}

// probePointReachable says whether the untouched point answered like a page the
// tool could actually test. A redirect or a 401/403 means the target wants a
// session, and then a tool negative says nothing about what the POC claimed, so
// the finding keeps its status instead of being reopened.
func probePointReachable(res probeResult) bool {
	return res.Baseline.status >= 200 && res.Baseline.status < 300
}

// sessionBlockedNegative relabels a tool negative that was never measured on the
// vulnerable page: when the untouched point answers with a redirect or an auth
// wall, sqlmap and dalfox tested a login form, so their "not reproducible" is a
// statement about the missing session. Recording it as not_reproduced would tell
// the reviewer the finding was refuted and simultaneously leave the finding alone,
// so the verdict says what actually happened and the finding keeps its status.
// A baseline that is neither a success nor an auth wall (connection failure, 5xx)
// tested nothing at all either, and lands on the same "the tool could not judge"
// verdict instead of a withdrawal.
func sessionBlockedNegative(res probeResult) probeResult {
	if res.Verdict != "not_reproduced" || probePointReachable(res) {
		return res
	}
	code := res.Baseline.status
	why := fmt.Sprintf("对照请求返回 HTTP %d，", code)
	switch {
	case code >= 300 && code < 400:
		res.Verdict = "session_needed"
		res.Detail = why + "页面跳转走了，工具没能测到漏洞页面本身。" + res.Detail
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		res.Verdict = "session_needed"
		res.Detail = why + "该点要求登录或拒绝访问，工具没有可判定的响应体。" + res.Detail
	default:
		res.Verdict = probeVerdictUncovered
		if code == 0 {
			res.Detail = "对照请求连不上或超时（目标没返回任何 HTTP 响应）。" + targetWedgedHint + "工具拿不到可判定的基线响应。" + res.Detail
		} else {
			res.Detail = why + "工具拿不到可判定的基线响应。" + res.Detail
		}
	}
	return res
}

// targetWedgedHint names the failure mode a time-based payload leaves behind: the
// client gives up at its own timeout while the DBMS keeps sleeping, and on a
// table-locked engine every later request queues behind it, so the endpoint stops
// answering altogether. Without this the LLM reads "tool could not judge" as a
// harmless gap and immediately re-runs the same point, piling more sleeps on.
const targetWedgedHint = "若此前对本端点跑过时间盲注（sleep/benchmark），该语句很可能仍在目标数据库执行并把后续请求堵在队列里——" +
	"这不是注入点不存在的证据，原判定保持不变；先让目标恢复响应（或改用低 level/去掉时间盲注技术）再复测，不要立刻重跑同一个点。"

// probeVerdictUncovered is the outcome of a point whose payload variant the
// specialized tool cannot generate: nothing is asserted and nothing is
// withdrawn, so the finding keeps the status the scan gave it.
const probeVerdictUncovered = "tool_uncovered"

// rejudgeProbeNegative asks whether a tool negative on a reachable point says
// anything about the POC claim at all. sqlmap carries no multi-byte charset
// payloads, so a GBK wide-byte point answers "not injectable" to everything it
// knows; dalfox grades only output contexts the response reflects, so a value the
// page never echoes is invisible to it. Those variants get decided on Jingwei's
// own packets instead of on a blind spot: the SQLi point is replayed against a
// neutral control and stays confirmed while the payload still moves the page, and
// an XSS point with no reflection is left alone because no request Jingwei can
// send proves a browser-side sink.
func (r *deepRun) rejudgeProbeNegative(class string, p probePoint, res probeResult, creds probeCreds) probeResult {
	switch class {
	case scanner.InjectionSQLi:
		payload, proved := r.pocPayloadPacket(p, creds)
		if !proved {
			if !wideByteQuoteBypass(p.URL + "&" + p.Body) {
				return res
			}
			payload = r.probeRequest(p.URL, p.Method, p.Body, creds)
		}
		return r.rejudgeWideByteSQLi(payload, res, creds)
	case scanner.InjectionXSS:
		echoed, marker, status := r.probeParamEcho(p, creds)
		if echoed {
			return res
		}
		res.Verdict = probeVerdictUncovered
		res.Detail = fmt.Sprintf("POC 参数值未出现在响应中（回显标记 %s，HTTP %d）：dalfox 只能判定响应里可见的反射上下文，盲打、存储型与需要浏览器交互的 DOM 输出点它测不到，阴性结论不构成反证。%s",
			marker, status, res.Detail)
		return res
	}
	return res
}

// pocPayloadPacket reads back the packet the POC itself proved with. Points are
// benign-graded before a tool runs (sanitizeProbeTarget), so the payload survives
// only in the linked finding's recorded request — and that packet, not a
// reconstructed one, is what a reviewer has to be able to replay.
func (r *deepRun) pocPayloadPacket(p probePoint, creds probeCreds) (scanner.DeepRequest, bool) {
	for _, id := range r.probeLinkedFindings(p) {
		f, err := r.pg.GetFinding(id)
		if err != nil || f == nil {
			continue
		}
		raw := strings.TrimSpace(f.HTTPRequest)
		if raw == "" || !wideByteQuoteBypass(raw) {
			continue
		}
		req, err := parseRawRequest(raw, p.URL)
		if err != nil || strings.TrimSpace(req.URL) == "" {
			continue
		}
		if len(req.Cookies) == 0 && creds.Cookie != "" {
			req.Cookies = append(req.Cookies, creds.Cookie)
		}
		return req, true
	}
	return scanner.DeepRequest{}, false
}

// rejudgeWideByteSQLi replays the wide-byte payload beside a neutral control of
// the same request. The escape-swallowing trick either still changes the page —
// then the injection is real and the packets prove it — or it does not, and the
// tool's negative stands.
func (r *deepRun) rejudgeWideByteSQLi(payload scanner.DeepRequest, res probeResult, creds probeCreds) probeResult {
	token := probeControlToken()
	ctlURL, ctlBody, ok := neutralProbeValues(payload.URL, payload.Body, token)
	if !ok {
		res.Verdict = probeVerdictUncovered
		res.Detail = "宽字节注入点无法构造中性对照请求（参数不可解析），sqlmap 的阴性结论不作为反证。" + res.Detail
		return res
	}
	client := scanner.NewDeepClient(r.probeTimeout())
	payload.Timeout = r.probeTimeout()
	control := probeControlVariant(payload, ctlURL, ctlBody)
	ctl := client.Do(r.ctx, control)
	if ctl.Error != "" {
		res.Verdict = probeVerdictUncovered
		res.Detail = fmt.Sprintf("宽字节对照请求发送失败（%s），sqlmap 的阴性结论不作为反证。%s", ctl.Error, res.Detail)
		return res
	}
	pl := client.Do(r.ctx, payload)
	if pl.Error != "" {
		res.Verdict = probeVerdictUncovered
		res.Detail = fmt.Sprintf("宽字节 payload 复放失败（%s），sqlmap 的阴性结论不作为反证。%s", pl.Error, res.Detail)
		return res
	}
	if pl.StatusCode == ctl.StatusCode && !probeBodyDiffers(pl.Body, ctl.Body, token) {
		res.Detail = fmt.Sprintf("宽字节 payload 与对照请求返回同一页面（HTTP %d，%d 字节），POC 判定同样不成立。%s",
			pl.StatusCode, pl.Length, res.Detail)
		return res
	}
	name, where, value := probePayloadParam(probePoint{URL: payload.URL, Method: payload.Method, Body: payload.Body})
	reqText := probeRequestText(payload)
	res.Verdict = verdict.Confirmed
	res.Name = fmt.Sprintf("宽字节 SQL 注入复放确认：%s 参数 %s（sqlmap 无该字符集的 payload，由 Jingwei 对照复放判定）",
		where, displayOr(name, "-"))
	res.Detail = fmt.Sprintf("对照请求 HTTP %d / %d 字节，注入请求 HTTP %d / %d 字节：宽字节 payload 仍改变响应内容，注入成立。\n%s",
		ctl.StatusCode, ctl.Length, pl.StatusCode, pl.Length, res.Detail)
	res.Injections = append(res.Injections, probeInjection{
		Param:       name,
		Where:       where,
		Kind:        "宽字节（多字节字符集）绕过",
		Title:       "POC 载荷对照复放：注入响应与未注入响应内容不同",
		Payload:     value,
		Request:     reqText,
		Response:    cleanHTTPText(rawHTTPResponse(pl), maxStoredHTTPResponse),
		Baseline:    cleanHTTPText(rawHTTPResponse(ctl), maxStoredHTTPResponse),
		BaselineReq: probeRequestText(control),
		StatusCode:  pl.StatusCode,
		Proved:      true,
	})
	return res
}

// probeControlVariant reuses the payload request with a different target and
// body, so headers and the session that reached the handler stay the same on
// both sides of the comparison.
func probeControlVariant(payload scanner.DeepRequest, ctlURL, ctlBody string) scanner.DeepRequest {
	control := payload
	control.URL, control.Body = ctlURL, ctlBody
	control.Headers = nil
	for name, value := range payload.Headers {
		if control.Headers == nil {
			control.Headers = map[string]string{}
		}
		control.Headers[name] = value
	}
	return control
}

// wideByteQuoteBypass finds a percent-encoded multi-byte lead byte welded to an
// encoded quote. With a GBK/Shift_JIS connection the escape byte the server
// inserts pairs up with the lead byte, the backslash is swallowed as part of a
// character and the quote arrives free — an injection sqlmap never tests.
func wideByteQuoteBypass(text string) bool {
	return scanWideByteQuote(text) || scanWideByteQuote(strings.ReplaceAll(text, "%25", "%"))
}

func scanWideByteQuote(text string) bool {
	for i := 0; i+6 <= len(text); i++ {
		if text[i] != '%' || !isHex(text[i+1]) || !isHex(text[i+2]) {
			continue
		}
		raw, err := hex.DecodeString(text[i+1 : i+3])
		if err != nil || raw[0] < 0x81 || raw[0] > 0xfe {
			continue
		}
		if text[i+3] != '%' || !isHex(text[i+4]) || !isHex(text[i+5]) {
			continue
		}
		quote, err := hex.DecodeString(text[i+4 : i+6])
		if err == nil && (quote[0] == '\'' || quote[0] == '"') {
			return true
		}
	}
	return false
}

// neutralProbePoint rewrites the point with every parameter value replaced by a
// benign token, so the handler runs the same code path on something that cannot
// be a payload.
func neutralProbePoint(p probePoint, token string) (probePoint, bool) {
	ctlURL, ctlBody, ok := neutralProbeValues(p.URL, p.Body, token)
	if !ok {
		return probePoint{}, false
	}
	return probePoint{URL: ctlURL, Method: displayOr(p.Method, "GET"), Body: ctlBody}, true
}

func neutralProbeValues(rawURL, body, token string) (string, string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", "", false
	}
	substituted := false
	if q := u.RawQuery; q != "" {
		values, err := url.ParseQuery(q)
		if err != nil {
			return "", "", false
		}
		for name, list := range values {
			for i := range list {
				list[i] = token
			}
			values[name] = list
			substituted = true
		}
		u.RawQuery = values.Encode()
	}
	ctlBody := body
	if body != "" && probeBodyType(body) == "form" {
		values, err := url.ParseQuery(body)
		if err != nil {
			return "", "", false
		}
		for name, list := range values {
			for i := range list {
				list[i] = token
			}
			values[name] = list
			substituted = true
		}
		ctlBody = values.Encode()
	}
	if !substituted {
		return "", "", false
	}
	return u.String(), ctlBody, true
}

// probeParamEcho reports whether the target puts a parameter value back into the
// response body. dalfox judges the reflected context, so a value that never comes
// back means the sink is elsewhere: a later admin page, a stored row, or a DOM
// assignment that only a browser performs.
func (r *deepRun) probeParamEcho(p probePoint, creds probeCreds) (bool, string, int) {
	marker := probeControlToken()
	echo, ok := neutralProbePoint(p, marker)
	if !ok {
		return true, marker, 0
	}
	resp := scanner.NewDeepClient(r.probeTimeout()).Do(r.ctx, r.probeRequest(echo.URL, echo.Method, echo.Body, creds))
	if resp.Error != "" {
		return true, marker, resp.StatusCode
	}
	// The marker is plain alphanumerics, so it survives both transit unchanged:
	// it is looked for in the body as it arrived, before any noise stripping that
	// would erase a token of its own length.
	return strings.Contains(resp.Body, marker), marker, resp.StatusCode
}

func probeControlToken() string {
	return "jwctl" + strings.ToUpper(strconv.FormatInt(time.Now().UnixNano(), 36))
}

var reProbeDynamicToken = regexp.MustCompile(`[0-9a-zA-Z+/=]{16,}`)

// probeBodyDiffers separates a payload that changed the page from the dynamic
// noise every request carries (CSRF tokens, cache busters). The shared prefix and
// suffix are dropped and only what is left counts, so two copies of the same page
// differing in one token are the same page.
func probeBodyDiffers(payload, control, token string) bool {
	a, b := normalizeProbeBody(payload, token), normalizeProbeBody(control, token)
	if a == b {
		return false
	}
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	j := 0
	for j < len(a)-i && j < len(b)-i && a[len(a)-1-j] == b[len(b)-1-j] {
		j++
	}
	longest := len(a)
	if len(b) > longest {
		longest = len(b)
	}
	if longest == 0 {
		return true
	}
	return (len(a)-i-j+len(b)-i-j)*100 > 2*longest
}

func normalizeProbeBody(body, token string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	if token != "" {
		body = strings.ReplaceAll(body, token, "CTL")
	}
	body = reProbeDynamicToken.ReplaceAllString(body, "TOK")
	return strings.Join(strings.Fields(body), " ")
}

// probePayloadParam names the parameter carrying the payload so the confirmed
// record points at the value a reader has to reproduce. The value stays in its
// wire form: a decoded wide-byte payload is no longer the bytes that work.
func probePayloadParam(p probePoint) (name, where, value string) {
	query := ""
	if u, err := url.Parse(strings.TrimSpace(p.URL)); err == nil {
		query = u.RawQuery
	}
	for _, part := range []struct{ raw, location string }{{query, "GET"}, {p.Body, "POST"}} {
		if strings.TrimSpace(part.raw) == "" {
			continue
		}
		for _, pair := range strings.Split(part.raw, "&") {
			key, val, ok := strings.Cut(pair, "=")
			if !ok || key == "" {
				continue
			}
			if wideByteQuoteBypass(val) {
				return key, part.location, val
			}
			if name == "" {
				name, where, value = key, part.location, val
			}
		}
	}
	return name, where, value
}

func (r *deepRun) probeToolVersion(class string) string {
	if class == scanner.InjectionXSS {
		return scanner.DalfoxVersion()
	}
	return scanner.SQLMapVersion()
}

// credsForPoint lets the session the POC used reach the tool. Task-level
// credentials win, because the operator supplied them on purpose.
func (r *deepRun) credsForPoint(creds probeCreds, p probePoint) probeCreds {
	if creds.Cookie == "" && strings.TrimSpace(p.Cookie) != "" {
		creds.Cookie = strings.TrimSpace(p.Cookie)
	}
	return creds
}

// verifyProbePoint runs the owning tool on one point and replays what the tool
// proved so the finding carries raw packets, not just a tool sentence.
func (r *deepRun) verifyProbePoint(class string, p probePoint, creds probeCreds) probeResult {
	if class == scanner.InjectionXSS {
		return r.verifyXSSPoint(p, creds)
	}
	return r.verifySQLiPoint(p, creds)
}

// sqlmapProbeOptions builds the tool options for one point. A point with a body
// or a non-GET method must travel as a raw request file (-r): --url only makes
// sqlmap test the GET variant of the same URL, which reports a POST injection
// point as "not injectable".
func (r *deepRun) sqlmapProbeOptions(p probePoint, creds probeCreds) scanner.SQLMapOptions {
	opts := scanner.SQLMapOptions{
		Level:          intParam(r.task.Params, "level", 3),
		Risk:           intParam(r.task.Params, "risk", 2),
		Threads:        intParam(r.task.Params, "threads", 2),
		TimeoutSeconds: intParam(r.task.Params, "request_timeout", 15),
		DelaySeconds:   intParam(r.task.Params, "delay", 0),
		Retries:        intParam(r.task.Params, "retries", 1),
		Techniques:     stringParam(r.task.Params, "techniques"),
		DBMS:           stringParam(r.task.Params, "dbms"),
		Cookie:         creds.Cookie,
		Headers:        creds.Headers,
		Params:         p.Params,
		WallSeconds:    intParam(r.task.Params, "wall_seconds", 240),
	}
	if p.Body != "" || !strings.EqualFold(p.Method, "GET") {
		opts.RawRequest = probeRequestText(r.probeRequest(p.URL, displayOr(p.Method, "POST"), p.Body, creds))
		opts.Cookie = ""
		opts.Headers = nil
	}
	return opts
}

func (r *deepRun) verifySQLiPoint(p probePoint, creds probeCreds) probeResult {
	opts := r.sqlmapProbeOptions(p, creds)
	run := scanner.RunSQLMap(r.ctx, p.URL, opts)
	res := probeResult{Tool: "sqlmap", Elapsed: run.Elapsed}
	if run.Missing {
		res.Err = run.Err
		res.Verdict = "tool_unavailable"
		return res
	}
	if run.Err != nil {
		res.Err = run.Err
		res.Verdict = "error"
		res.Detail = truncateText(run.Log, 1500)
		return res
	}
	if !run.Found() {
		res.Verdict = "not_reproduced"
		res.Detail = "sqlmap 未确认任何注入点。" + sqlmapLogDigest(run.Log)
		res.Baseline = r.replayBaseline(p, creds)
		return res
	}
	base := r.replayBaseline(p, creds)
	proved := 0
	for _, inj := range run.Injections {
		pi := probeInjection{
			Param: inj.Param, Where: inj.Where, Kind: inj.Type, Title: inj.Title, Payload: inj.Payload,
			Baseline: base.response, BaselineReq: base.request, StatusCode: base.status,
		}
		req, resp, code, note := r.replaySQLiInjection(p, inj, creds)
		pi.Request, pi.Response, pi.StatusCode = req, resp, code
		if note != "" {
			pi.ReplayNote = note
		} else {
			pi.Proved, pi.ReplayNote = probeReplayProof(inj.Payload, resp, code)
		}
		if pi.Proved {
			proved++
		}
		res.Injections = append(res.Injections, pi)
	}
	// A tool verdict a replay cannot show is not something a reader can verify,
	// so it stays 待复核 instead of confirming the finding.
	if proved > 0 {
		res.Verdict = verdict.Confirmed
		res.Name = fmt.Sprintf("sqlmap 确认 SQL 注入：%s", strings.Join(injectionLabels(res.Injections), "、"))
	} else {
		res.Verdict = verdict.NeedsReview
		res.Name = fmt.Sprintf("sqlmap 判定可注入但复放未见特征：%s", strings.Join(injectionLabels(res.Injections), "、"))
	}
	res.Detail = sqlmapEvidence(run, p, res.Injections)
	return res
}

func (r *deepRun) verifyXSSPoint(p probePoint, creds probeCreds) probeResult {
	opts := scanner.DalfoxOptions{
		Target:              p.URL,
		Method:              p.Method,
		Data:                p.Body,
		Params:              p.Params,
		Cookie:              creds.Cookie,
		Headers:             creds.Headers,
		Workers:             intParam(r.task.Params, "workers", 8),
		RateLimit:           intParam(r.task.Params, "rate_limit", 20),
		TimeoutSeconds:      intParam(r.task.Params, "request_timeout", 10),
		DelayMS:             intParam(r.task.Params, "delay_ms", 0),
		ScanTimeoutSeconds:  intParam(r.task.Params, "scan_timeout", 120),
		MaxPayloadsPerParam: intParam(r.task.Params, "max_payloads", 30),
		Stored:              boolParam(r.task.Params, "stored"),
		StoredURL:           stringParam(r.task.Params, "stored_url"),
		BlindURL:            stringParam(r.task.Params, "blind_url"),
		WallSeconds:         intParam(r.task.Params, "wall_seconds", 240),
	}
	if host, err := url.Parse(p.URL); err == nil {
		opts.ScopeHost = host.Host
	}
	run := scanner.RunDalfox(r.ctx, opts)
	res := probeResult{Tool: "dalfox", Elapsed: run.Elapsed}
	if run.Missing {
		res.Err = run.Err
		res.Verdict = "tool_unavailable"
		return res
	}
	if run.Err != nil {
		// dalfox exits non-zero when its own preflight shows the session it was
		// handed does not authenticate. That is the target asking for a login, the
		// same case the reachability gate catches, so it is reported as such rather
		// than as a tool crash: the POC verdict stays and dalfox's words say what to
		// supply.
		if blocker, blocked := run.Blocked(p.URL); blocked && blocker.NeedsSession() {
			res.Verdict = "session_needed"
			res.Detail = truncateText(blocker.ErrorMessage, 500)
			// Replay the point once ourselves: the redirect the tool saw is the
			// evidence, and it is the packet an operator can reproduce with.
			res.Baseline = r.replayBaseline(p, creds)
			return res
		}
		res.Err = run.Err
		res.Verdict = "error"
		res.Detail = truncateText(run.Log, 1500)
		return res
	}
	if len(run.Findings) == 0 {
		res.Verdict = "not_reproduced"
		res.Detail = "dalfox 未发现反射点或可执行 XSS。"
		res.Baseline = r.replayBaseline(p, creds)
		return res
	}
	base := r.replayBaseline(p, creds)
	verified, proved := 0, 0
	for _, f := range run.Findings {
		pi := probeInjection{
			Param: f.Param, Where: f.Location, Kind: f.Verdict(), Title: displayOr(f.TypeDescription, f.Message),
			Payload: f.Payload, Baseline: base.response, BaselineReq: base.request, StatusCode: base.status,
		}
		req, resp, code, note := r.replayXSSFinding(p, f, creds)
		pi.Request, pi.Response, pi.StatusCode = req, resp, code
		if note != "" {
			pi.ReplayNote = note
		} else {
			pi.Proved, pi.ReplayNote = probeReplayProof(f.Payload, resp, code)
		}
		if pi.Proved {
			proved++
		}
		res.Injections = append(res.Injections, pi)
		if f.Verdict() == "verified" {
			verified++
		}
	}
	// Reflection alone is not a proven XSS: dalfox marks those as [r], so the
	// finding stays needs_review for a human to decide. The replay has to show
	// dalfox's own marker too, otherwise nothing in the packet proves execution.
	if verified > 0 && proved > 0 {
		res.Verdict = verdict.Confirmed
	} else {
		res.Verdict = verdict.NeedsReview
	}
	res.Name = fmt.Sprintf("dalfox 验证 XSS：%d 个可执行点 / %d 个反射点（复放可见 %d 个）", verified, len(run.Findings), proved)
	res.Detail = dalfoxEvidence(run, p, res.Injections)
	return res
}

type baselineExchange struct {
	request, response string
	status            int
}

// replayBaseline sends the untouched point so the report shows the difference
// the tool based its verdict on.
func (r *deepRun) replayBaseline(p probePoint, creds probeCreds) baselineExchange {
	req := r.probeRequest(p.URL, p.Method, p.Body, creds)
	resp := scanner.NewDeepClient(r.probeTimeout()).Do(r.ctx, req)
	if resp.Error != "" {
		return baselineExchange{}
	}
	return baselineExchange{
		request:  probeRequestText(req),
		response: cleanHTTPText(rawHTTPResponse(resp), maxStoredHTTPResponse),
		status:   resp.StatusCode,
	}
}

func (r *deepRun) probeTimeout() time.Duration {
	return time.Duration(intParam(r.task.Params, "replay_timeout", 20)) * time.Second
}

// replaySQLiInjection rebuilds the request sqlmap proved with the exact payload
// it printed, so the packet in the report is the one that works.
func (r *deepRun) replaySQLiInjection(p probePoint, inj scanner.SQLMapInjection, creds probeCreds) (string, string, int, string) {
	if strings.TrimSpace(inj.Payload) == "" {
		return "", "", 0, "sqlmap 没有给出可复放的 payload"
	}
	req := r.probeRequest(p.URL, p.Method, p.Body, creds)
	switch strings.ToLower(strings.TrimSpace(inj.Where)) {
	case "get", "uri", "query":
		req.URL = withProbeQuery(p.URL, inj.Payload)
	case "post", "body", "put", "data":
		req.Method = "POST"
		req.Body = inj.Payload
		req.BodyType = probeBodyType(inj.Payload)
	case "cookie":
		req.Cookies = mergeProbeCookie(creds.Cookie, inj.Payload)
	default:
		if !isProbeHeaderName(inj.Where) {
			return "", "", 0, "未知的注入位置: " + inj.Where
		}
		if req.Headers == nil {
			req.Headers = map[string]string{}
		}
		req.Headers[inj.Where] = inj.Payload
	}
	resp := scanner.NewDeepClient(r.probeTimeout()).Do(r.ctx, req)
	if resp.Error != "" {
		return probeRequestText(req), "", 0, "复放请求失败: " + resp.Error
	}
	return probeRequestText(req), cleanHTTPText(rawHTTPResponse(resp), maxStoredHTTPResponse), resp.StatusCode, ""
}

// withProbeQuery replaces the query string of an URL with sqlmap's payload.
func withProbeQuery(rawURL, payload string) string {
	clean := strings.TrimSpace(rawURL)
	if i := strings.Index(clean, "#"); i >= 0 {
		clean = clean[:i]
	}
	encoded := encodeProbeQuery(strings.TrimSpace(payload))
	if i := strings.Index(clean, "?"); i >= 0 {
		return clean[:i] + "?" + encoded
	}
	return clean + "?" + encoded
}

func mergeProbeCookie(existing, payload string) []string {
	existing = strings.TrimSpace(existing)
	payload = strings.TrimSpace(payload)
	switch {
	case existing == "":
		return []string{payload}
	case payload == "":
		return []string{existing}
	default:
		return []string{existing + "; " + payload}
	}
}

func isProbeHeaderName(where string) bool {
	name := strings.TrimSpace(where)
	if name == "" || strings.ContainsAny(name, "\r\n :") {
		return false
	}
	switch strings.ToLower(name) {
	case "get", "uri", "query", "post", "body", "put", "data", "cookie", "host":
		return false
	}
	return true
}

// encodeProbeQuery escapes the characters a URI query cannot carry literally
// while keeping the %XX escapes sqlmap already produced.
func encodeProbeQuery(q string) string {
	var b strings.Builder
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c == ' ':
			b.WriteString("%20")
		case c == '"':
			b.WriteString("%22")
		case c == '<':
			b.WriteString("%3C")
		case c == '>':
			b.WriteString("%3E")
		case c == '#':
			b.WriteString("%23")
		case c == '`':
			b.WriteString("%60")
		case c == '%':
			if i+2 < len(q) && isHex(q[i+1]) && isHex(q[i+2]) {
				b.WriteByte(c)
			} else {
				b.WriteString("%25")
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

var (
	reProbeHexLiteral   = regexp.MustCompile(`0[xX]([0-9a-fA-F]+)`)
	reProbeDalfoxMark   = regexp.MustCompile(`dlx[0-9a-fA-F]{3,}`)
	reProbeLeadingDigit = regexp.MustCompile(`^[0-9]`)
)

// probeProofMarkers returns the byte strings a response has to contain for the
// payload's effect to be visible: sqlmap wraps injected output in 0xHEX markers
// and dalfox stamps every PoC with a class=dlxxxxx marker.
func probeProofMarkers(payload string) []string {
	out := []string{}
	for _, m := range reProbeDalfoxMark.FindAllString(payload, -1) {
		out = append(out, m)
	}
	for _, m := range reProbeHexLiteral.FindAllStringSubmatch(payload, -1) {
		if s := decodeProbeHex(m[1]); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// decodeProbeHex turns sqlmap's marker literals into printable text; anything
// with control bytes in it is not something a reviewer can find in a response.
func decodeProbeHex(s string) string {
	if len(s)%2 != 0 {
		return ""
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) < 3 {
		return ""
	}
	for _, b := range raw {
		if b < 0x20 || b > 0x7e {
			return ""
		}
	}
	return string(raw)
}

// probeReplayProof checks the replayed response against the payload's markers.
// Blind and time-based techniques leave no marker at all, so those stay allowed:
// their packet is still the one to reproduce, only the timing claim is tool-side.
func probeReplayProof(payload, response string, status int) (bool, string) {
	markers := probeProofMarkers(payload)
	if len(markers) == 0 {
		return true, ""
	}
	for _, m := range markers {
		if strings.Contains(response, m) {
			return true, ""
		}
	}
	note := "复放响应中没有出现 payload 特征串 " + strings.Join(markers, "、")
	if status >= 300 && status < 400 || status == 401 || status == 403 {
		note += fmt.Sprintf("（响应 %d：该靶点很可能需要登录会话，在专项任务参数里补 cookie 后复测）", status)
	}
	return false, note
}

// reProbeTaint matches injection syntax a POC left inside a parameter value.
// sqlmap aborts on such values ("tainted parameter values") and dalfox reflects
// the POC instead of testing the point, so probe values are reset first.
var reProbeTaint = regexp.MustCompile(`(?i)['"\\]|%27|%22|%5c|--|#|/\*|<|>|%3c|%3e|\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\b|\bsubstr\s*\(|\bconcat\s*\(|information_schema|alert\s*\(|onerror|onload|javascript:`)

// sanitizeProbeTarget rewrites tainted query/body values in the shape a
// specialized tool expects, leaving every other value untouched.
func sanitizeProbeTarget(rawURL, body string) (string, string) {
	cut := strings.TrimSpace(rawURL)
	if i := strings.Index(cut, "#"); i >= 0 {
		cut = cut[:i]
	}
	u, err := url.Parse(cut)
	if err == nil && u.RawQuery != "" {
		parts := strings.Split(u.RawQuery, "&")
		changed := false
		for i, part := range parts {
			k, v, ok := strings.Cut(part, "=")
			if !ok {
				continue
			}
			if nv, tainted := benignProbeValue(v); tainted {
				parts[i] = k + "=" + nv
				changed = true
			}
		}
		if changed {
			u.RawQuery = strings.Join(parts, "&")
			cut = u.String()
		}
	}
	if body != "" && !strings.Contains(body, "\n") && strings.Contains(body, "=") && !strings.HasPrefix(strings.TrimSpace(body), "{") {
		parts := strings.Split(body, "&")
		for i, part := range parts {
			k, v, ok := strings.Cut(part, "=")
			if !ok {
				continue
			}
			if nv, tainted := benignProbeValue(v); tainted {
				parts[i] = k + "=" + nv
			}
		}
		body = strings.Join(parts, "&")
	}
	return cut, body
}

// benignProbeValue replaces a payload-shaped value with a plain one that keeps
// the parameter's shape (a value starting with a digit stays numeric) so the
// tool tests the same spot instead of aborting on tainted input.
func benignProbeValue(v string) (string, bool) {
	decoded := v
	if d, err := url.QueryUnescape(v); err == nil {
		decoded = d
	}
	if !reProbeTaint.MatchString(decoded) {
		return v, false
	}
	if reProbeLeadingDigit.MatchString(strings.TrimSpace(decoded)) {
		return "1", true
	}
	return "test", true
}

// replayXSSFinding re-sends the request dalfox verified so the response bytes
// on file are Jingwei's own capture, not a tool's summary.
func (r *deepRun) replayXSSFinding(p probePoint, f scanner.DalfoxFinding, creds probeCreds) (string, string, int, string) {
	rawURL := strings.TrimSpace(f.URL)
	if rawURL == "" {
		rawURL = p.URL
	}
	req := r.probeRequest(rawURL, displayOr(f.Method, p.Method), p.Body, creds)
	// dalfox's own raw request carries the injection exactly where it tested it
	// (query, body or header), so it wins over the reconstructed request.
	if f.Request != "" {
		if parsed, err := parseRawRequest(f.Request, rawURL); err == nil {
			for _, h := range creds.Headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
					continue
				}
				if parsed.Headers == nil {
					parsed.Headers = map[string]string{}
				}
				parsed.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
			if creds.Cookie != "" && len(parsed.Cookies) == 0 {
				parsed.Cookies = append(parsed.Cookies, creds.Cookie)
			}
			parsed.Timeout = req.Timeout
			req = parsed
		}
	}
	resp := scanner.NewDeepClient(r.probeTimeout()).Do(r.ctx, req)
	if resp.Error != "" {
		return probeRequestText(req), "", 0, "复放请求失败: " + resp.Error
	}
	return probeRequestText(req), cleanHTTPText(rawHTTPResponse(resp), maxStoredHTTPResponse), resp.StatusCode, ""
}

// probeRequest builds the replay request with the session material the point
// needs.
func (r *deepRun) probeRequest(rawURL, method, body string, creds probeCreds) scanner.DeepRequest {
	req := scanner.DeepRequest{
		Method:  displayOr(method, "GET"),
		URL:     rawURL,
		Body:    body,
		Timeout: r.probeTimeout(),
	}
	if body != "" && strings.ToUpper(req.Method) != "GET" {
		req.BodyType = probeBodyType(body)
	}
	for _, h := range creds.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			continue
		}
		if req.Headers == nil {
			req.Headers = map[string]string{}
		}
		req.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	if creds.Cookie != "" {
		req.Cookies = append(req.Cookies, creds.Cookie)
	}
	return req
}

// probeBodyType labels a request body so the packet declares the Content-Type a
// form POST really carries. sqlmap injects into form fields, and a saved packet
// without that header cannot be replayed against a server that only parses the
// body when it is announced as urlencoded.
func probeBodyType(body string) string {
	if body == "" || strings.ContainsRune(body, '\n') {
		return "raw"
	}
	for _, field := range strings.Split(body, "&") {
		name, _, ok := strings.Cut(field, "=")
		if !ok || name == "" {
			return "raw"
		}
		for _, c := range []byte(name) {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '_' || c == '-' || c == '.' || c == '%' || c == '[' || c == ']':
			default:
				return "raw"
			}
		}
	}
	return "form"
}

// probeRequestText renders the request exactly as it goes on the wire so the
// report packet and the sent bytes cannot drift apart.
func probeRequestText(req scanner.DeepRequest) string {
	u, err := url.Parse(req.URL)
	target := req.URL
	if err == nil {
		target = u.RequestURI()
		if target == "" {
			target = "/"
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", strings.ToUpper(displayOr(req.Method, "GET")), target)
	if err == nil && u.Host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	}
	keys := make([]string, 0, len(req.Headers))
	for k := range req.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, req.Headers[k])
	}
	for _, c := range req.Cookies {
		fmt.Fprintf(&b, "Cookie: %s\r\n", c)
	}
	if req.Body != "" && strings.ToUpper(req.Method) != "GET" {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(req.Body))
		// An explicit header from the task wins, the way it overrides the derived
		// one on the wire, so the packet never carries two Content-Type lines.
		if !hasProbeContentType(req.Headers) {
			switch req.BodyType {
			case "json":
				b.WriteString("Content-Type: application/json\r\n")
			case "form":
				b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
			}
		}
	}
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(req.Body)
	return b.String()
}

// hasProbeContentType reports whether the caller already pinned a Content-Type.
func hasProbeContentType(headers map[string]string) bool {
	for k := range headers {
		if strings.EqualFold(strings.TrimSpace(k), "Content-Type") {
			return true
		}
	}
	return false
}

// recordProbeResult stores one exploit record per verified point; the record is
// what the 深度利用 page and the automatic-exploit tab render.
func (r *deepRun) recordProbeResult(class string, p probePoint, res probeResult) db.ExploitRecord {
	name := displayOr(res.Name, scanner.ToolForInjection(class)+" 专项验证")
	severity := "high"
	if class == scanner.InjectionXSS && res.Verdict != verdict.Confirmed {
		severity = "medium"
	}
	rec := db.ExploitRecord{
		TaskID:     r.task.ID,
		Mode:       r.task.Kind,
		TemplateID: displayOr(p.TemplateID, scanner.ToolForInjection(class)),
		Name:       name,
		Severity:   severity,
		Target:     p.URL,
		Verdict:    displayOr(res.Verdict, "error"),
		Evidence:   truncateText(res.Detail, 16_000),
		ElapsedMs:  int(res.Elapsed.Milliseconds()),
	}
	for _, inj := range res.Injections {
		if inj.Request == "" {
			continue
		}
		if rec.Request == "" {
			rec.Request = cleanHTTPText(inj.Request, maxStoredHTTPRequest)
			rec.Response = cleanHTTPText(inj.Response, maxStoredHTTPResponse)
			code := inj.StatusCode
			if code > 0 {
				rec.StatusCode = &code
			}
		}
		rec.Extracted = append(rec.Extracted, fmt.Sprintf("%s 参数 %s：%s（payload %s）",
			displayOr(inj.Where, "位置"), inj.Param, inj.Kind, truncateText(inj.Payload, 200)))
	}
	if len(rec.Extracted) == 0 && res.Err != nil {
		rec.Extracted = append(rec.Extracted, "错误: "+res.Err.Error())
	}
	if rec.Request == "" && res.Baseline.request != "" {
		rec.Request = cleanHTTPText(res.Baseline.request, maxStoredHTTPRequest)
		rec.Response = cleanHTTPText(res.Baseline.response, maxStoredHTTPResponse)
		if res.Baseline.status > 0 {
			code := res.Baseline.status
			rec.StatusCode = &code
		}
	}
	if _, err := r.pg.AddExploitRecord(rec); err != nil {
		r.logf("probe", "写入专项验证记录失败 %s: %v", p.URL, err)
	}
	return rec
}

// applyProbeConfirmation upgrades the linked finding with the tool's verdict and
// binds the replayed packets as proof evidence.
func (r *deepRun) applyProbeConfirmation(class string, p probePoint, res probeResult, rec db.ExploitRecord) {
	note := fmt.Sprintf("%s 专项验证确认（深度任务 #%d）：%s",
		scanner.ToolForInjection(class), r.task.ID, truncateText(res.Name, 200))
	if len(res.Injections) > 0 {
		inj := res.Injections[0]
		note += fmt.Sprintf("\n注入参数: %s（%s）\n类型: %s\n标题: %s\npayload: %s",
			inj.Param, displayOr(inj.Where, "-"), inj.Kind, displayOr(inj.Title, "-"), truncateText(inj.Payload, 400))
	}
	exchanges := probeExchanges(res)
	ids := r.probeLinkedFindings(p)
	if len(ids) == 0 && boolParam(r.task.Params, "write_finding") {
		r.writeFinding(rec)
		return
	}
	for _, id := range ids {
		if _, found, _, err := r.pg.ConfirmFinding(r.ctx, id, note); err != nil {
			r.logf("probe", "确认发现 #%d 失败: %v", id, err)
			continue
		} else if !found {
			continue
		}
		r.markConfirmed(id)
		if len(exchanges) > 0 {
			if err := r.s.evidenceStore().SaveRawExchanges(r.ctx, id, exchanges); err != nil {
				r.logf("probe", "绑定专项验证报文失败 #%d: %v", id, err)
			}
		}
		r.applyProbeArtifacts(id, rec, exchanges)
	}
}

// applyProbeArtifacts replaces the POC packet on the finding with the
// specialized tool's proven packet; the nuclei packets stay bound as support.
func (r *deepRun) applyProbeArtifacts(id int64, rec db.ExploitRecord, exchanges []evidence.RawExchange) {
	f, err := r.pg.GetFinding(id)
	if err != nil || f == nil {
		return
	}
	auto := report.BuildFindingReport(report.FindingReportInput{
		FindingID:       id,
		Name:            displayOr(f.Name, rec.Name),
		VulnClass:       f.VulnClass,
		Severity:        f.Severity,
		Status:          db.FindingConfirmed,
		Summary:         f.Summary,
		Evidence:        f.Evidence,
		TaskDescription: fmt.Sprintf("#%d %s", r.task.ID, r.task.Name),
		Source:          fmt.Sprintf("深度利用任务 #%d（%s 专项验证）", r.task.ID, rec.Mode),
		TemplateID:      rec.TemplateID,
		Host:            rec.Target,
		MatchedAt:       rec.Target,
		Type:            rec.Mode,
		Extracted:       rec.Extracted,
		HTTPRequest:     rec.Request,
		HTTPResponse:    rec.Response,
		GeneratedAt:     time.Now(),
	})
	if err := r.pg.SetFindingHTTPArtifactsAndAutoReport(id, rec.Request, rec.Response, auto); err != nil {
		r.logf("probe", "回写专项报文失败 #%d: %v", id, err)
	}
}

// probeExchanges turns replayed packets into evidence bindings; the injected
// request is the proof, the untouched baseline supports it.
func probeExchanges(res probeResult) []evidence.RawExchange {
	out := []evidence.RawExchange{}
	for _, inj := range res.Injections {
		if strings.TrimSpace(inj.Request) == "" {
			continue
		}
		note := fmt.Sprintf("%s 专项验证注入报文（参数 %s，类型 %s）", res.Tool, displayOr(inj.Param, "-"), displayOr(inj.Kind, "-"))
		if inj.ReplayNote != "" {
			note += "；" + inj.ReplayNote
		}
		out = append(out, evidence.RawExchange{
			Request:  cleanHTTPText(inj.Request, maxStoredHTTPRequest),
			Response: cleanHTTPText(inj.Response, maxStoredHTTPResponse),
			Role:     "proof",
			Note:     note,
		})
		if strings.TrimSpace(inj.BaselineReq) != "" && strings.TrimSpace(inj.Baseline) != "" {
			out = append(out, evidence.RawExchange{
				Request:  cleanHTTPText(inj.BaselineReq, maxStoredHTTPRequest),
				Response: cleanHTTPText(inj.Baseline, maxStoredHTTPResponse),
				Role:     "supporting",
				Note:     "未注入的对照请求（差异即为专项工具的判定依据）",
			})
		}
	}
	if len(out) == 0 && strings.TrimSpace(res.Baseline.request) != "" && strings.TrimSpace(res.Baseline.response) != "" {
		out = append(out, evidence.RawExchange{
			Request:  cleanHTTPText(res.Baseline.request, maxStoredHTTPRequest),
			Response: cleanHTTPText(res.Baseline.response, maxStoredHTTPResponse),
			Role:     "supporting",
			Note:     res.Tool + " 专项验证未复现注入点，此为未注入的原始请求与响应",
		})
	}
	return out
}

// probeLinkedFindings resolves which findings a point stands for: the IDs the
// scan bound to it, or, failing that, the findings its POC template created.
func (r *deepRun) probeLinkedFindings(p probePoint) []int64 {
	if len(p.FindingIDs) > 0 {
		return p.FindingIDs
	}
	return templateFindingIDs(r.task.Params, p.TemplateID)
}

// demotePOCVerdicts withdraws what a POC template asserted but the specialized
// tool could not reproduce. Only a finding that really claims this injection
// class on a page the tool could reach is touched: a template tagged "sqli" can
// still describe a weak-password or CSRF issue, and a 3xx/4xx baseline means the
// request never reached the handler, so in neither case does the tool's negative
// say anything. Findings this run proved stay confirmed, and rows a human already
// triaged (误报/已修复/已处理) are never rewritten.
func (r *deepRun) demotePOCVerdicts(class string, res probeResult, p probePoint) int {
	note := fmt.Sprintf("%s 专项验证（深度任务 #%d）未能复现该注入点，已撤销 POC 模板给出的确认判定，退回待人工复核。对照请求返回 HTTP %d，判定依据：%s",
		res.Tool, r.task.ID, res.Baseline.status, truncateText(res.Detail, 600))
	reopened := 0
	exchanges := probeExchanges(res)
	for _, id := range r.probeLinkedFindings(p) {
		if r.confirmedFindings[id] {
			continue
		}
		f, err := r.pg.GetFinding(id)
		if err != nil {
			r.logf("probe", "读取发现 #%d 失败: %v", id, err)
			continue
		}
		if f == nil || f.Status != db.FindingConfirmed {
			continue
		}
		if !scanner.ClaimsInjection(class, f.Name, f.Summary) {
			r.logf("probe", "发现 #%d（%s）的判定主题不是注入漏洞，%s 的负向结果不改变其状态",
				id, displayOr(f.Name, f.VulnClass), res.Tool)
			continue
		}
		_, found, changed, err := r.pg.ReopenFinding(r.ctx, id, note)
		if err != nil {
			r.logf("probe", "撤销发现 #%d 的 POC 判定失败: %v", id, err)
			continue
		}
		if !found || !changed {
			continue
		}
		reopened++
		r.logf("probe", "发现 #%d（%s）判定撤销：已确认 → 待处理，%s 未能复现",
			id, displayOr(f.Name, f.VulnClass), res.Tool)
		if len(exchanges) > 0 {
			if err := r.s.evidenceStore().SaveRawExchanges(r.ctx, id, exchanges); err != nil {
				r.logf("probe", "绑定专项验证对照报文失败 #%d: %v", id, err)
			}
		}
	}
	return reopened
}

func (r *deepRun) markConfirmed(id int64) {
	if r.confirmedFindings == nil {
		r.confirmedFindings = map[int64]bool{}
	}
	r.confirmedFindings[id] = true
}

func injectionLabels(injections []probeInjection) []string {
	out := []string{}
	for _, inj := range injections {
		out = append(out, fmt.Sprintf("%s %s 参数 %s", displayOr(inj.Where, "-"), inj.Kind, inj.Param))
	}
	return out
}

func sqlmapEvidence(run scanner.SQLMapRun, p probePoint, injections []probeInjection) string {
	var b strings.Builder
	fmt.Fprintf(&b, "专项工具: sqlmap %s\n检测目标: %s\n耗时: %s\n", displayOr(run.Version, ""), p.URL, run.Elapsed.Round(time.Millisecond))
	if run.DBMS != "" {
		fmt.Fprintf(&b, "后端数据库: %s\n", run.DBMS)
	}
	if run.Tech != "" {
		fmt.Fprintf(&b, "Web 服务指纹: %s\n", run.Tech)
	}
	if run.OS != "" {
		fmt.Fprintf(&b, "服务器操作系统: %s\n", run.OS)
	}
	b.WriteString("判定: sqlmap 确认以下参数可注入（每条 payload 均可直接复放）\n")
	for i, inj := range injections {
		fmt.Fprintf(&b, "\n%d) 参数 %s（%s）\n   技术: %s\n   标题: %s\n   payload: %s\n",
			i+1, inj.Param, displayOr(inj.Where, "-"), inj.Kind, displayOr(inj.Title, "-"), inj.Payload)
		if inj.StatusCode > 0 {
			fmt.Fprintf(&b, "   复放响应: HTTP %d\n", inj.StatusCode)
		}
		if inj.ReplayNote != "" {
			fmt.Fprintf(&b, "   复放说明: %s\n", inj.ReplayNote)
		}
	}
	b.WriteString("\nsqlmap 原始输出（节选）:\n" + sqlmapLogDigest(run.Log))
	return b.String()
}

func dalfoxEvidence(run scanner.DalfoxRun, p probePoint, injections []probeInjection) string {
	var b strings.Builder
	fmt.Fprintf(&b, "专项工具: dalfox %s\n检测目标: %s\n耗时: %s\n", displayOr(run.Version, ""), p.URL, run.Elapsed.Round(time.Millisecond))
	fmt.Fprintf(&b, "结论: %d 个发现（可执行 XSS %d 个），失败请求 %d 个",
		len(run.Findings), run.Vulnerable(), run.FailedRequests)
	if run.Incomplete {
		b.WriteString("（dalfox 提前结束，未扫完全部 payload，阴性结论仅供参考）")
	}
	b.WriteString("\n")
	for i, inj := range injections {
		fmt.Fprintf(&b, "\n%d) 参数 %s（%s）\n   判定: %s\n   标题: %s\n   payload: %s\n",
			i+1, inj.Param, displayOr(inj.Where, "-"), inj.Kind, displayOr(inj.Title, "-"), inj.Payload)
		if inj.StatusCode > 0 {
			fmt.Fprintf(&b, "   复放响应: HTTP %d\n", inj.StatusCode)
		}
		if inj.ReplayNote != "" {
			fmt.Fprintf(&b, "   复放说明: %s\n", inj.ReplayNote)
		}
	}
	return b.String()
}

// sqlmapLogDigest keeps the decision-bearing lines out of the long per-payload
// test list so the evidence field stays readable.
func sqlmapLogDigest(log string) string {
	want := []string{"heuristic", "appears to be", "is vulnerable", "does not seem", "do not appear",
		"back-end DBMS", "web application technology", "parametric", "Title:", "Payload:", "Type:", "Parameter:"}
	lines := []string{}
	for _, line := range strings.Split(log, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		for _, w := range want {
			if strings.Contains(trimmed, w) {
				lines = append(lines, trimmed)
				break
			}
		}
	}
	if len(lines) > 120 {
		lines = lines[len(lines)-120:]
	}
	if len(lines) == 0 {
		return truncateText(log, 1200)
	}
	return strings.Join(lines, "\n")
}
