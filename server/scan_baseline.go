package server

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/evidence"
	"github.com/Autumn-27/jingwei/report"
	"github.com/Autumn-27/jingwei/scanner"
)

// Fixed penetration baseline: every scan must try web-login weak credentials,
// not only hosts whose POCs happen to match. The check itself is the vendored
// WebCrack engine (dictionary + universal-password attempt + length/fail-word
// judgement + recheck), wired in as a scan step with bounded targets.
const (
	maxWeakPassTargets    = 8
	weakPassPerURLSeconds = 90
	weakPassDelayMS       = 50
)

// weakPassCandidate is one login-page URL offered to the weak credential check.
type weakPassCandidate struct {
	URL   string
	Score int
}

// weakPassCandidates ranks web services and app-layer systems by how much they
// look like a login page: an explicit login path first, then a login-titled
// page, then admin consoles, then everything else. The ranking keeps the run
// bounded: a scan only spends its budget on the most promising pages.
func weakPassCandidates(services []scanner.WebService, apps []scanner.AppSystem) []weakPassCandidate {
	seen := map[string]bool{}
	out := []weakPassCandidate{}
	add := func(rawURL, path, title string) {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" || seen[rawURL] {
			return
		}
		seen[rawURL] = true
		out = append(out, weakPassCandidate{URL: rawURL, Score: weakPassScore(path, title)})
	}
	for _, svc := range services {
		p := ""
		if u, err := url.Parse(svc.URL); err == nil {
			p = u.Path
		}
		add(svc.URL, p, svc.Title)
	}
	for _, app := range apps {
		add(app.URL, app.Path, app.Title)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return len(out[i].URL) < len(out[j].URL)
	})
	if len(out) > maxWeakPassTargets {
		out = out[:maxWeakPassTargets]
	}
	return out
}

func weakPassScore(path, title string) int {
	p := strings.ToLower(path)
	t := strings.ToLower(title)
	switch {
	case containsAny(p, "login", "signin", "logon", "log-in", "denglu", "cas/", "/sso"):
		return 100
	case containsAny(t, "登录", "登陆", "login", "sign in", "sign-in", "统一认证", "身份认证"):
		return 80
	case containsAny(p, "admin", "manage", "manager", "console", "backend", "backstage", "weadmin", "/oa", "/sys"):
		return 60
	case containsAny(t, "管理", "后台", "admin", "console", "dashboard", "面板"):
		return 50
	default:
		return 10
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// runWeakPassBaseline executes the fixed weak-credential step and writes one
// finding per valid credential pair, with the successful login request/response
// as reproducible evidence.
func (r *scanRun) runWeakPassBaseline(services []scanner.WebService, apps []scanner.AppSystem, assets *scanAssetIndex, summary map[string]any) int {
	candidates := weakPassCandidates(services, apps)
	// 从根/子路径系统爬取真正含登录表单的页面，优先作为弱口令检测目标；
	// 找不到表单页时退回「根 + 系统入口」候选（WebCrack 会自行判空跳过）。
	formURLs := scanner.DiscoverLoginForms(r.ctx, services, apps, scanner.LoginFormOptions{
		MaxPages: 120, Concurrency: 8, Timeout: 8 * time.Second,
		Logf: func(format string, args ...any) { r.logf("weakpass", format, args...) },
	})
	if len(formURLs) > 0 {
		forms := make([]weakPassCandidate, 0, len(formURLs))
		for _, u := range formURLs {
			p := ""
			if parsed, err := url.Parse(u); err == nil {
				p = parsed.Path
			}
			forms = append(forms, weakPassCandidate{URL: u, Score: weakPassScore(p, "")})
		}
		sort.SliceStable(forms, func(i, j int) bool { return forms[i].Score > forms[j].Score })
		if len(forms) > maxWeakPassTargets {
			forms = forms[:maxWeakPassTargets]
		}
		r.logf("weakpass", "应用层发现：定位到 %d 个含登录表单的页面（取前 %d 个）", len(formURLs), len(forms))
		candidates = forms
	}
	summary["weak_pass_targets"] = len(candidates)
	if len(candidates) == 0 {
		return 0
	}
	if !scanner.WebCrackAvailable() {
		r.logf("weakpass", "webcrack 未安装（镜像缺少 /app/tools/webcrack 或 python3），跳过弱口令基线步骤")
		return 0
	}
	urls := make([]string, 0, len(candidates))
	for _, c := range candidates {
		urls = append(urls, c.URL)
	}
	r.logf("weakpass", "固定基线：对 %d 个登录页候选执行 Web 弱口令/万能密码检测（每个最多 %ds）", len(urls), weakPassPerURLSeconds)
	r.setProgress("weakpass", map[string]any{"targets": len(urls)})

	run := scanner.RunWebCrack(r.ctx, scanner.WebCrackOptions{
		URLs:          urls,
		PerURLSeconds: weakPassPerURLSeconds,
		DelayMS:       weakPassDelayMS,
		TimeoutSecond: len(urls)*weakPassPerURLSeconds + 30,
	})
	if run.Missing {
		r.logf("weakpass", "webcrack 不可用：%v", run.Err)
		return 0
	}
	if run.Err != nil && len(run.Results) == 0 {
		r.logf("weakpass", "弱口令检测未完成：%v（耗时 %s）", run.Err, run.Elapsed.Round(time.Second))
		return 0
	}
	// 每个 URL 单独失败不影响其他候选：逐条带 error 的只记日志。
	failed := 0
	for _, res := range run.Results {
		if !res.Found && strings.TrimSpace(res.Error) != "" {
			failed++
			r.logf("weakpass", "%s 检测失败：%s", res.URL, res.Error)
		}
	}
	summary["weak_pass_failed"] = failed

	found := 0
	for _, res := range run.Results {
		if !res.Found || r.ctx.Err() != nil {
			continue
		}
		if r.recordWeakPass(res, assets) {
			found++
		}
	}
	summary["weak_pass_found"] = found
	r.logf("weakpass", "弱口令基线完成：%d 个候选，%d 个确认凭据（耗时 %s）", len(urls), found, run.Elapsed.Round(time.Second))
	return found
}

func (r *scanRun) recordWeakPass(res scanner.WebCrackResult, assets *scanAssetIndex) bool {
	universal := strings.EqualFold(res.Kind, "universal")
	templateID := "web-login-weakpass"
	name := "Web 登录弱口令"
	kindLabel := "弱口令"
	severity := "high"
	if universal {
		templateID = "web-login-universal-password"
		name = "Web 登录万能密码（认证绕过）"
		kindLabel = "万能密码"
	}
	host := res.URL
	if u, err := url.Parse(res.URL); err == nil {
		host = u.Host
	}
	if minRank := severityRank(r.task.MinSeverity); minRank > 0 && severityRank(severity) < minRank {
		return false
	}
	req := cleanPacketText(res.Request, maxStoredHTTPRequest, false)
	resp := cleanPacketText(res.Response, maxStoredHTTPResponse, false)

	var b strings.Builder
	fmt.Fprintf(&b, "验证通过的凭据: %s / %s\n", res.Username, res.Password)
	fmt.Fprintf(&b, "检测类型: %s\n", kindLabel)
	fmt.Fprintf(&b, "登录地址: %s\n", res.URL)
	fmt.Fprintf(&b, "尝试组合: %d 次 · 耗时 %dms\n", res.Attempts, res.ElapsedMS)
	b.WriteString("判定方式: 失败响应长度基线对比 + 失败关键字黑名单 + 成功后二次复验（WebCrack 引擎）\n")
	b.WriteString("风险说明: 登录接口存在可直接登入的凭据（或万能密码绕过），攻击者可获得后台业务权限。\n")
	if len(res.Log) > 0 {
		fmt.Fprintf(&b, "引擎日志尾: %s\n", strings.Join(res.Log, " | "))
	}
	evidenceText := b.String()

	summary := fmt.Sprintf("%s：%s 可登录（%s/%s），成功响应已二次复验（自动化漏扫 #%d）",
		name, res.URL, res.Username, res.Password, r.task.ID)
	dedupe := fmt.Sprintf("weakpass:%s:%s:%s", templateID, res.URL, res.Username)
	assetIDs := assets.idsFor(res.URL, host)

	var findingID int64
	if r.task.CreateFindings {
		id, created, err := r.pg.UpsertFinding(0, 0, templateID, name, severity, summary, evidenceText,
			fmt.Sprintf("scan:%d", r.task.ID), assetIDs, dedupe)
		if err != nil {
			r.logf("weakpass", "写入弱口令发现失败 %s: %v", res.URL, err)
		} else {
			findingID = id
			autoReport := report.BuildFindingReport(report.FindingReportInput{
				FindingID:       id,
				Name:            name,
				VulnClass:       templateID,
				Severity:        severity,
				Status:          db.FindingPending,
				Summary:         summary,
				Evidence:        evidenceText,
				TaskDescription: fmt.Sprintf("#%d %s", r.task.ID, r.task.Name),
				Source:          fmt.Sprintf("自动化漏扫任务 #%d（固定基线：WebCrack 登录弱口令检测）", r.task.ID),
				TemplateID:      templateID,
				Host:            host,
				MatchedAt:       res.URL,
				Type:            "http",
				HTTPRequest:     req,
				HTTPResponse:    resp,
				GeneratedAt:     time.Now(),
			})
			if err := r.pg.SetFindingHTTPArtifactsAndAutoReport(id, req, resp, autoReport); err != nil {
				r.logf("weakpass", "保存弱口令原始报文/报告失败 %s: %v", res.URL, err)
			}
			if req != "" {
				raws := []evidence.RawExchange{{
					Request:  req,
					Response: resp,
					Role:     "proof",
					Note:     fmt.Sprintf("使用 %s/%s 登录成功的请求与响应", res.Username, res.Password),
				}}
				if err := r.s.evidenceStore().SaveRawExchanges(r.ctx, id, raws); err != nil {
					r.logf("weakpass", "保存弱口令证据报文失败 %s: %v", res.URL, err)
				}
			}
			if created {
				r.logf("weakpass", "新增%s发现 #%d：%s（%s/%s）", kindLabel, id, res.URL, res.Username, res.Password)
			}
		}
	}

	if _, err := r.pg.AddScanTaskResult(r.task.ID, findingID, db.ScanTaskResult{
		TemplateID: templateID,
		Name:       name,
		Severity:   severity,
		Host:       host,
		MatchedAt:  res.URL,
		Type:       "http",
		Extracted:  []string{fmt.Sprintf("%s/%s", res.Username, res.Password)},
		Raw: map[string]any{
			"tool":       "webcrack",
			"kind":       res.Kind,
			"attempts":   res.Attempts,
			"elapsed_ms": res.ElapsedMS,
			"login_url":  res.URL,
			"username":   res.Username,
			"password":   res.Password,
			"source":     "baseline",
		},
	}); err != nil {
		r.logf("weakpass", "保存弱口令扫描结果失败 %s: %v", res.URL, err)
		return findingID > 0
	}
	return findingID > 0
}

// ---------------------------------------------------------------------------
// 固定基线第二步：SQL 注入 / XSS。POC 命中只能证明「响应看起来有趣」，而这两个
// 类别要由 sqlmap/dalfox 证明参数确实是注入点；工具要有得跑，前提是拿到参数位置。
// 所以这里对已发现的页面做只读参数枚举，并为每个来源排队专项验证任务——
// 与 nuclei 是否命中无关，命中时也照跑（只跳过工具已经在跑的参数位置）。
// ---------------------------------------------------------------------------

const (
	maxBaselineSeeds      = 24
	maxBaselineProbeHosts = 5
	baselineHarvestPoints = 80
	baselineHarvestSecs   = 8
)

// baselineSeeds lists the pages the parameter enumeration reads: every web
// service plus every app-layer system, bounded.
func baselineSeeds(services []scanner.WebService, apps []scanner.AppSystem) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if seen[raw] || !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			return
		}
		if u, err := url.Parse(raw); err != nil || u.Host == "" {
			return
		}
		seen[raw] = true
		out = append(out, raw)
	}
	for _, svc := range services {
		add(svc.URL)
	}
	for _, app := range apps {
		add(app.URL)
	}
	if len(out) > maxBaselineSeeds {
		out = out[:maxBaselineSeeds]
	}
	return out
}

// runInjectionBaseline queues the fixed SQL/XSS verification over the parameter
// locations the discovered pages expose. It returns the number of deep tasks it
// created.
func (r *scanRun) runInjectionBaseline(services []scanner.WebService, apps []scanner.AppSystem, summary map[string]any, covered map[string]bool) int {
	seeds := baselineSeeds(services, apps)
	summary["baseline_pages"] = len(seeds)
	if len(seeds) == 0 {
		return 0
	}
	if r.s.deepMgr == nil {
		r.logf("baseline", "深度任务执行器不可用，跳过 SQL/XSS 注入基线步骤")
		return 0
	}
	r.logf("baseline", "固定基线：只读枚举 %d 个已发现页面的参数位置", len(seeds))
	r.setProgress("baseline", map[string]any{"baseline_pages": len(seeds)})
	pts := scanner.HarvestParams(r.ctx, seeds, scanner.HarvestOptions{
		MaxPages:    len(seeds),
		MaxPoints:   baselineHarvestPoints,
		Concurrency: baselineConcurrency(r.task.Concurrency),
		Timeout:     time.Duration(baselineHarvestSecs) * time.Second,
		Logf:        func(format string, args ...any) { r.logf("baseline", format, args...) },
	})
	if r.ctx.Err() != nil {
		return 0
	}

	type originPoints struct {
		origin string
		points []probePoint
	}
	byOrigin := map[string]*originPoints{}
	seenLocation := map[string]bool{}
	dupSkipped := 0
	for _, p := range pts {
		point := probePoint{
			URL:    strings.TrimSpace(p.URL),
			Method: displayOr(strings.ToUpper(strings.TrimSpace(p.Method)), "GET"),
			Body:   p.Body,
			Params: append([]string{}, p.Params...),
			Source: "baseline",
			Cookie: usableSession(p.Cookie),
		}
		origin := probeOrigin(point.URL)
		if origin == "" {
			continue
		}
		key := probeLocationKey(point.Method, point.URL, point.Body)
		if key == "" {
			continue
		}
		if covered[key] {
			dupSkipped++
			continue
		}
		if seenLocation[key] {
			continue
		}
		seenLocation[key] = true
		g := byOrigin[origin]
		if g == nil {
			g = &originPoints{origin: origin}
			byOrigin[origin] = g
		}
		g.points = append(g.points, point)
	}

	// Rank origins by how much parameter surface they expose, then keep the run
	// bounded: each origin costs at most one sqlmap batch and one dalfox batch.
	ranked := make([]*originPoints, 0, len(byOrigin))
	for _, g := range byOrigin {
		ranked = append(ranked, g)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if len(ranked[i].points) != len(ranked[j].points) {
			return len(ranked[i].points) > len(ranked[j].points)
		}
		return ranked[i].origin < ranked[j].origin
	})
	if len(ranked) > maxBaselineProbeHosts {
		r.logf("baseline", "参数来源 %d 个站点超过上限 %d，仅验证参数最多的 %d 个",
			len(ranked), maxBaselineProbeHosts, maxBaselineProbeHosts)
		ranked = ranked[:maxBaselineProbeHosts]
	}

	scanID := r.task.ID
	tasks := 0
	queuedPoints := 0
	for _, g := range ranked {
		if r.ctx.Err() != nil {
			break
		}
		group := autoHostGroup{
			target:   g.origin,
			findings: map[string][]int64{},
			injections: map[string][]probePoint{
				scanner.InjectionSQLi: capProbePoints(g.points, maxAutoSQLiPoints),
				scanner.InjectionXSS:  capProbePoints(g.points, maxAutoXSSPoints),
			},
		}
		_, ids, points := r.queueAutoInjections(group, scanID, "baseline")
		tasks += len(ids)
		queuedPoints += points
	}
	summary["baseline_points"] = queuedPoints
	summary["baseline_tasks"] = tasks
	if dupSkipped > 0 {
		summary["baseline_covered_by_poc"] = dupSkipped
		r.logf("baseline", "%d 个参数位置已由 POC 命中排队专项验证，基线跳过以免重复跑同一参数", dupSkipped)
	}
	if tasks > 0 {
		r.s.deepMgr.wakeup()
	}
	r.logf("baseline", "注入基线排队完成：%d 个来源、%d 个注入点、%d 个专项验证任务",
		len(ranked), queuedPoints, tasks)
	return tasks
}

func capProbePoints(pts []probePoint, max int) []probePoint {
	if max < 1 {
		max = 1
	}
	if len(pts) <= max {
		return append([]probePoint{}, pts...)
	}
	return append([]probePoint{}, pts[:max]...)
}

// probeOrigin reduces a URL to the scheme://host:port the deep task is aimed at,
// so the executor's same-host check cannot reject a point over a path difference.
func probeOrigin(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func baselineConcurrency(taskConcurrency int) int {
	if taskConcurrency < 1 {
		return 1
	}
	if taskConcurrency > 6 {
		return 6
	}
	return taskConcurrency
}
