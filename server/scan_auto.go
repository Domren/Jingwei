package server

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scanner"
)

const (
	maxAutoDeepHosts     = 10
	maxAutoDeepTemplates = 50
	// A deep task runs under a fixed wall clock and sqlmap needs minutes per
	// point, so one task holds at most maxPoints points and gets the whole budget.
	// Points past the cap are not dropped: they start a second task of the same
	// class, so a lab module with more injections than the cap still gets every
	// point decided by the tool rather than left on a POC verdict.
	maxAutoSQLiPoints = 8
	maxAutoXSSPoints  = 10
	// wall_seconds bounds ONE point, so the per-class budget is divided by the
	// point count; a flat per-point value would let a full 10-point XSS run blow
	// past the deep task deadline and report nothing.
	autoSQLiBudgetSec = 720
	autoXSSBudgetSec  = 660
	autoProbeMinSec   = 45
	autoProbeMaxSec   = 300
)

// autoProbeWall seconds per point for one class, given how many points it has.
func autoProbeWall(budget, points int) int {
	if points < 1 {
		points = 1
	}
	sec := budget / points
	if sec < autoProbeMinSec {
		sec = autoProbeMinSec
	}
	if sec > autoProbeMaxSec {
		sec = autoProbeMaxSec
	}
	return sec
}

// autoHostGroup is the unit of automatic post-scan exploitation: every matched
// template for one web origin is replayed by a single deep task.
type autoHostGroup struct {
	target     string
	templates  []string
	findings   map[string][]int64 // template id -> linked finding ids
	injections map[string][]probePoint
	wafPath    string
	wafParam   string
	maxRank    int
}

// autoExploit queues specialized injection verification, verification/exploitation,
// WAF bypass and optional webshell injection tasks for the scan hits. It
// deliberately uses the exact templates that matched instead of re-fingerprinting
// the target, so the automatic stage is cheap and deterministic. SQLi and XSS
// hits are handed to sqlmap / dalfox instead of a POC replay: a template only
// proves a response looked interesting, while those tools prove the parameter is
// an injection point. Finding IDs are carried into the deep task so a confirmed
// result marks the scan finding instead of creating a duplicate.
func (r *scanRun) autoExploit(results []scanner.NucleiResult, findingIDs map[string]int64, summary map[string]any) {
	if len(results) == 0 || r.ctx.Err() != nil || r.s.deepMgr == nil {
		return
	}
	groups, skipped := groupAutoResults(results, findingIDs)
	if len(groups) == 0 {
		return
	}
	r.logf("auto", "开始自动验证/利用：%d 个主机分组（命中低于 medium 的 %d 条结果仅保留发现）", len(groups), skipped)
	if len(groups) > maxAutoDeepHosts {
		r.logf("auto", "自动利用主机数 %d 超过上限 %d，仅处理前 %d 个", len(groups), maxAutoDeepHosts, maxAutoDeepHosts)
		groups = groups[:maxAutoDeepHosts]
	}

	taskIDs := []int64{}
	hosts := 0
	shells := 0
	probes := 0
	probePoints := 0
	queuedTemplates := 0
	for _, g := range groups {
		if r.ctx.Err() != nil {
			break
		}
		hosts++
		scanID := r.task.ID
		handled, probeIDs, points := r.queueAutoInjections(g, scanID)
		probes += len(probeIDs)
		probePoints += points
		taskIDs = append(taskIDs, probeIDs...)

		templates := make([]string, 0, len(g.templates))
		for _, id := range g.templates {
			if !handled[id] {
				templates = append(templates, id)
			}
		}
		if len(templates) > maxAutoDeepTemplates {
			templates = templates[:maxAutoDeepTemplates]
		}
		if len(templates) > 0 {
			queuedTemplates += len(templates)
			task, err := r.pg.CreateDeepTask(db.DeepTaskInput{
				Name:   "自动验证/利用 · " + g.target,
				Kind:   db.DeepTaskExploit,
				Target: g.target,
				Params: map[string]any{
					"matched_template_ids":    templates,
					"finding_ids_by_template": g.findings,
					"repeats":                 1,
					"write_finding":           false,
					"java_chains":             "auto",
					"java_cmd":                "id",
					"source":                  "scan",
				},
				ScanTaskID: &scanID,
				AutoRun:    true,
			})
			if err != nil {
				r.logf("auto", "创建自动利用任务失败 %s: %v", g.target, err)
			} else {
				taskIDs = append(taskIDs, task.ID)
			}
		} else {
			r.logf("auto", "%s：命中模板全部交给专项工具验证，不再重复执行 POC", g.target)
		}

		if g.wafPath != "" {
			wafTask, err := r.pg.CreateDeepTask(db.DeepTaskInput{
				Name:   "自动 WAF 绕过 · " + g.target,
				Kind:   db.DeepTaskWAFBypass,
				Target: g.target,
				Params: map[string]any{
					"base_url":         g.target,
					"path":             g.wafPath,
					"param":            g.wafParam,
					"only_if_detected": true,
					"source":           "scan",
				},
				ScanTaskID: &scanID,
				AutoRun:    true,
			})
			if err != nil {
				r.logf("auto", "创建自动 WAF 任务失败 %s: %v", g.target, err)
			} else {
				taskIDs = append(taskIDs, wafTask.ID)
			}
		}

		if r.task.WebshellInject && g.maxRank >= severityRank("high") {
			if shellTask, ok := r.queueAutoWebshell(g, scanID); ok {
				taskIDs = append(taskIDs, shellTask)
				shells++
			}
		}
	}

	if len(taskIDs) == 0 {
		r.logf("auto", "没有可排队的自动利用任务")
		return
	}
	r.setProgress("auto", map[string]any{"auto_tasks": len(taskIDs), "auto_hosts": hosts})
	summary["auto_tasks"] = taskIDs
	summary["auto_hosts"] = hosts
	summary["auto_templates"] = queuedTemplates
	summary["auto_probes"] = probes
	summary["auto_probe_points"] = probePoints
	summary["auto_webshell"] = shells
	summary["auto_skipped"] = skipped
	r.logf("auto", "已排队 %d 个自动任务（%d 个主机，%d 个模板，%d 个专项注入任务/%d 个注入点，%d 个 Webshell 尝试）",
		len(taskIDs), hosts, queuedTemplates, probes, probePoints, shells)
	r.s.deepMgr.wakeup()
}

// queueAutoInjections creates one sqlmap / dalfox task per proven injection
// class for the host. The returned map holds the template ids the specialized
// tools now own, so autoExploit can drop them from the generic POC replay.
func (r *scanRun) queueAutoInjections(g autoHostGroup, scanID int64) (map[string]bool, []int64, int) {
	handled := map[string]bool{}
	ids := []int64{}
	points := 0
	for _, class := range []string{scanner.InjectionSQLi, scanner.InjectionXSS} {
		pts := g.injections[class]
		if len(pts) == 0 {
			continue
		}
		kind, label := db.DeepTaskSQLiProbe, "SQL 注入"
		maxPoints, budget := maxAutoSQLiPoints, autoSQLiBudgetSec
		if class == scanner.InjectionXSS {
			kind, label = db.DeepTaskXSSProbe, "XSS"
			maxPoints, budget = maxAutoXSSPoints, autoXSSBudgetSec
		}
		batches, owned := planAutoProbeClass(pts, maxPoints)
		for id := range owned {
			handled[id] = true
		}
		for i, batch := range batches {
			wall := autoProbeWall(budget, len(batch))
			name := "自动" + label + "专项验证 · " + g.target
			if len(batches) > 1 {
				name = fmt.Sprintf("%s（第 %d/%d 批）", name, i+1, len(batches))
			}
			params := map[string]any{
				"points":                  autoProbeParams(batch),
				"finding_ids_by_template": g.findings,
				"max_points":              len(batch),
				"wall_seconds":            wall,
				"source":                  "scan",
			}
			task, err := r.pg.CreateDeepTask(db.DeepTaskInput{
				Name:       name,
				Kind:       kind,
				Target:     g.target,
				Params:     params,
				ScanTaskID: &scanID,
				AutoRun:    true,
			})
			if err != nil {
				r.logf("auto", "创建自动%s专项验证任务失败 %s: %v（%d 个注入点未经专项工具验证，发现保持待复核）",
					label, g.target, err, len(batch))
				continue
			}
			ids = append(ids, task.ID)
			points += len(batch)
			r.logf("auto", "%s：%s 命中 %d 个注入点，改用专项工具逐点验证（任务 #%d，每点上限 %d 秒）",
				g.target, label, len(batch), task.ID, wall)
		}
	}
	return handled, ids, points
}

// planAutoProbeClass decides one class's specialized runs. Every hit template
// becomes tool-owned so no POC verdict can survive beside the tool's answer, and
// the points are cut into batches of maxPoints: one deep task cannot outlast the
// executor's deadline, so a lab module with more points than the cap is verified
// over several tasks instead of dropping the tail.
func planAutoProbeClass(pts []probePoint, maxPoints int) (batches [][]probePoint, owned map[string]bool) {
	owned = make(map[string]bool, len(pts))
	for _, p := range pts {
		if p.TemplateID != "" {
			owned[p.TemplateID] = true
		}
	}
	// Order before cutting. The group is built in the order nuclei printed its
	// events, and that order changes between runs, so an over-cap class verified a
	// different subset each round: a point confirmed last time could go unmeasured
	// this time for a reason no reader can follow.
	ordered := append([]probePoint{}, pts...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].TemplateID != ordered[j].TemplateID {
			return ordered[i].TemplateID < ordered[j].TemplateID
		}
		if ordered[i].Method != ordered[j].Method {
			return ordered[i].Method < ordered[j].Method
		}
		return ordered[i].URL < ordered[j].URL
	})
	if maxPoints < 1 {
		maxPoints = 1
	}
	for start := 0; start < len(ordered); start += maxPoints {
		end := start + maxPoints
		if end > len(ordered) {
			end = len(ordered)
		}
		batches = append(batches, ordered[start:end])
	}
	return batches, owned
}

// autoProbeParams encodes the points in the shape collectProbePoints reads.
func autoProbeParams(pts []probePoint) []any {
	out := make([]any, 0, len(pts))
	for _, p := range pts {
		item := map[string]any{
			"url":         p.URL,
			"method":      p.Method,
			"data":        p.Body,
			"template_id": p.TemplateID,
			"source":      p.Source,
		}
		if len(p.Params) > 0 {
			item["params"] = append([]string{}, p.Params...)
		}
		if p.Cookie != "" {
			item["cookie"] = p.Cookie
		}
		if len(p.FindingIDs) > 0 {
			item["finding_ids"] = append([]int64{}, p.FindingIDs...)
		}
		out = append(out, item)
	}
	return out
}

func (r *scanRun) queueAutoWebshell(g autoHostGroup, scanID int64) (int64, bool) {
	params := r.task.WebshellParams
	uploadPath := strings.TrimSpace(stringParam(params, "upload_path"))
	if uploadPath == "" {
		r.logf("auto", "%s：已启用 Webshell 注入但未配置上传路径，跳过", g.target)
		return 0, false
	}
	uploadURL := joinHostPath(g.target, uploadPath)
	if uploadURL == "" {
		r.logf("auto", "%s：无法拼接 Webshell 上传地址", g.target)
		return 0, false
	}
	landURL := ""
	if landPath := strings.TrimSpace(stringParam(params, "land_path")); landPath != "" {
		landURL = joinHostPath(g.target, landPath)
	}
	task, err := r.pg.CreateDeepTask(db.DeepTaskInput{
		Name:   "自动 Webshell 注入 · " + g.target,
		Kind:   db.DeepTaskWebshellInject,
		Target: g.target,
		Params: map[string]any{
			"upload_url": uploadURL,
			"land_url":   landURL,
			"shell_type": displayOr(stringParam(params, "shell_type"), "php"),
			"password":   stringParam(params, "password"),
			"field_name": displayOr(stringParam(params, "field_name"), "file"),
			"source":     "scan",
		},
		ScanTaskID: &scanID,
		AutoRun:    true,
	})
	if err != nil {
		r.logf("auto", "创建自动 Webshell 任务失败 %s: %v", g.target, err)
		return 0, false
	}
	return task.ID, true
}

// groupAutoResults groups scan hits by target origin and keeps only medium+
// findings for automatic exploitation. Lower-severity hits stay as findings.
// findingIDs maps a hit key to the persisted finding so the deep task can
// confirm that exact row. Hits whose template tests an injection class are also
// recorded as probe points for the tool that owns that class.
func groupAutoResults(results []scanner.NucleiResult, findingIDs map[string]int64) ([]autoHostGroup, int) {
	byTarget := map[string]*autoHostGroup{}
	order := []string{}
	skipped := 0
	for _, res := range results {
		if severityRank(res.Severity) < severityRank("medium") {
			skipped++
			continue
		}
		target := autoResultTarget(res)
		if target == "" {
			skipped++
			continue
		}
		g := byTarget[target]
		if g == nil {
			g = &autoHostGroup{target: target, findings: map[string][]int64{}, injections: map[string][]probePoint{}}
			byTarget[target] = g
			order = append(order, target)
		}
		if !containsString(g.templates, res.TemplateID) {
			g.templates = append(g.templates, res.TemplateID)
		}
		if id := findingIDs[scanResultKey(res)]; id > 0 && !containsID(g.findings[res.TemplateID], id) {
			g.findings[res.TemplateID] = append(g.findings[res.TemplateID], id)
		}
		// Only the template's own wording and tags decide the class: an id like
		// pikachu-sqli-iu-edit names the lesson page, not the weakness, and its
		// finding may describe a CSRF or weak-credential issue sqlmap cannot judge.
		if class := scanner.ClassifyInjection(res.Name, strings.Join(res.Tags, ",")); class != "" {
			point := autoProbePoint(res, findingIDs)
			if point.URL != "" && !containsProbePoint(g.injections[class], point) {
				g.injections[class] = append(g.injections[class], point)
			}
		}
		if rank := severityRank(res.Severity); rank > g.maxRank {
			g.maxRank = rank
		}
		if g.wafPath == "" {
			if path, param := wafProbeTarget(res); path != "" {
				g.wafPath, g.wafParam = path, param
			}
		}
	}
	out := make([]autoHostGroup, 0, len(order))
	for _, target := range order {
		g := byTarget[target]
		if len(g.templates) == 0 {
			continue
		}
		sort.Strings(g.templates)
		out = append(out, *g)
	}
	return out, skipped
}

// autoResultTarget picks the base URL nuclei was invoked with. A Host value
// carrying a scheme is the user-supplied base, so its path is preserved; the
// MatchedAt fallback is reduced to the origin because it points at one
// endpoint that templates should build their own paths from.
func autoResultTarget(res scanner.NucleiResult) string {
	if base := normalizeWebBase(res.Host, true); base != "" {
		return base
	}
	return normalizeWebBase(res.MatchedAt, false)
}

func normalizeWebBase(raw string, keepPath bool) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	u.RawQuery = ""
	u.Fragment = ""
	if !keepPath {
		u.Path = ""
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return strings.TrimRight(u.String(), "/")
}

// wafProbeTarget extracts a relative path and the first query parameter from a
// matched URL, so WAF bypass probes exercise the endpoint that matched.
func wafProbeTarget(res scanner.NucleiResult) (string, string) {
	raw := strings.TrimSpace(res.MatchedAt)
	if raw == "" {
		raw = strings.TrimSpace(res.Host)
	}
	if raw == "" {
		return "/", ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "/", ""
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	param := ""
	for key := range u.Query() {
		param = key
		break
	}
	return path, param
}

func joinHostPath(base, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return u.Scheme + "://" + u.Host + path
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// autoProbePoint turns one injection hit into a point for the specialized
// verifier. The stored raw request wins over matched-at because a POST injection
// only exists in the body.
func autoProbePoint(res scanner.NucleiResult, findingIDs map[string]int64) probePoint {
	p := probePoint{URL: strings.TrimSpace(res.MatchedAt), Method: "GET", TemplateID: res.TemplateID, Source: "scan"}
	if id := findingIDs[scanResultKey(res)]; id > 0 {
		p.FindingIDs = []int64{id}
	}
	if req, err := parseRawRequest(res.Request, res.Host); err == nil && strings.TrimSpace(req.URL) != "" {
		p.URL = req.URL
		if method := strings.ToUpper(strings.TrimSpace(req.Method)); method != "" {
			p.Method = method
		}
		p.Body = req.Body
		p.Cookie = usableSession(strings.Join(req.Cookies, "; "))
	} else if curl, ok := scanner.ParseCurlRequest(res.Curl); ok {
		// nuclei prints the raw request only for some hits. Its curl command is
		// always there, and a POC that injects through a form loses its whole
		// point without the method and body read off it: sqlmap would be handed
		// the plain page and report a real injection point as absent.
		p.URL = curl.URL
		if method := strings.ToUpper(strings.TrimSpace(curl.Method)); method != "" {
			p.Method = method
		}
		p.Body = curl.Body
		p.Cookie = usableSession(curl.Cookie)
	}
	if !strings.HasPrefix(p.URL, "http://") && !strings.HasPrefix(p.URL, "https://") {
		return probePoint{}
	}
	return p
}

// usableSession drops a session header still redacted as *** by whatever
// captured it. A placeholder is not a session: sqlmap or dalfox would only be
// redirected, and the negative verdict that follows describes a missing login,
// not the injection the POC claimed.
func usableSession(cookie string) string {
	cookie = strings.TrimSpace(cookie)
	if cookie == "" || strings.Contains(cookie, "*") {
		return ""
	}
	return cookie
}

func containsProbePoint(points []probePoint, want probePoint) bool {
	for _, p := range points {
		if p.TemplateID == want.TemplateID && p.Method == want.Method && p.Body == want.Body && strings.EqualFold(p.URL, want.URL) {
			return true
		}
	}
	return false
}

func containsID(items []int64, want int64) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
