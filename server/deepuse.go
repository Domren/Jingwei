package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/artex/scanner"
	"github.com/Autumn-27/artex/verdict"
)

// deepManager runs the deep-exploitation tasks (verification, exploitation,
// WAF bypass, webshell injection) one at a time inside the server process.
type deepManager struct {
	s    *Server
	wake chan struct{}

	mu     sync.Mutex
	cancel map[int64]context.CancelFunc
}

func newDeepManager(s *Server) *deepManager {
	return &deepManager{s: s, wake: make(chan struct{}, 1), cancel: map[int64]context.CancelFunc{}}
}

func (m *deepManager) start(ctx context.Context) {
	if m == nil || m.s.m.pg == nil {
		return
	}
	if n, err := m.s.m.pg.RecoverInterruptedDeepTasks(); err != nil {
		log.Printf("[deep] recover interrupted tasks: %v", err)
	} else if n > 0 {
		log.Printf("[deep] 启动时将 %d 个中断的深度利用任务标记为失败", n)
	}
	go m.loop(ctx)
}

func (m *deepManager) wakeup() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *deepManager) loop(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		for {
			task, err := m.s.m.pg.ClaimNextDeepTask()
			if err != nil {
				log.Printf("[deep] claim queued task: %v", err)
				break
			}
			if task == nil {
				break
			}
			m.run(ctx, task)
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-ticker.C:
		}
	}
}

func (m *deepManager) run(parent context.Context, task *db.DeepTask) {
	timeout := 15 * time.Minute
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	m.mu.Lock()
	m.cancel[task.ID] = cancel
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.cancel, task.ID)
		m.mu.Unlock()
	}()

	run := &deepRun{s: m.s, pg: m.s.m.pg, task: task, ctx: ctx, progress: map[string]any{}}
	status, stage, errMsg, summary := run.execute()
	if summary == nil {
		summary = map[string]any{}
	}
	if err := m.s.m.pg.FinishDeepTask(task.ID, status, stage, errMsg, summary); err != nil {
		log.Printf("[deep %d] finish: %v", task.ID, err)
	}
	log.Printf("[deep %d] %s (%s)", task.ID, status, stage)
}

func (m *deepManager) cancelTask(id int64) {
	m.mu.Lock()
	cancel := m.cancel[id]
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

type deepRun struct {
	s    *Server
	pg   *db.DB
	task *db.DeepTask
	ctx  context.Context

	mu       sync.Mutex
	progress map[string]any

	// confirmedFindings guards against appending the same verification note on
	// every repeat; access is confined to the single task goroutine.
	confirmedFindings map[int64]bool
}

func (r *deepRun) logf(stage, format string, args ...any) {
	line := fmt.Sprintf("[%s] %s", stage, fmt.Sprintf(format, args...))
	log.Printf("[deep %d] %s", r.task.ID, line)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.pg.UpdateDeepTaskProgress(r.task.ID, stage, r.progress, line); err != nil {
		log.Printf("[deep %d] update progress: %v", r.task.ID, err)
	}
}

func (r *deepRun) setProgress(stage string, values map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range values {
		r.progress[k] = v
	}
	if err := r.pg.UpdateDeepTaskProgress(r.task.ID, stage, r.progress, ""); err != nil {
		log.Printf("[deep %d] update progress: %v", r.task.ID, err)
	}
}

func (r *deepRun) execute() (status, stage, errMsg string, summary map[string]any) {
	summary = map[string]any{"kind": r.task.Kind, "target": r.task.Target}
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[deep %d] panic: %v\n%s", r.task.ID, rec, debug.Stack())
			status, stage, errMsg = "failed", "failed", fmt.Sprintf("深度利用内部错误: %v", rec)
			summary = map[string]any{"kind": r.task.Kind, "target": r.task.Target}
		}
	}()

	if err := r.checkTargetAllowed(); err != nil {
		return "failed", "failed", err.Error(), summary
	}

	switch r.task.Kind {
	case db.DeepTaskVerify:
		return r.runVerify(summary)
	case db.DeepTaskExploit:
		return r.runExploit(summary)
	case db.DeepTaskWAFBypass:
		return r.runWAFBypass(summary)
	case db.DeepTaskWebshellInject:
		return r.runWebshellInject(summary)
	case db.DeepTaskSQLiProbe:
		return r.runSQLiProbe(summary)
	case db.DeepTaskXSSProbe:
		return r.runXSSProbe(summary)
	default:
		return "failed", "failed", "未知的深度利用任务类型: " + r.task.Kind, summary
	}
}

// checkTargetAllowed enforces the global asset blocklist before any packet is
// sent by a deep-exploitation task.
func (r *deepRun) checkTargetAllowed() error {
	rules, err := r.pg.ListAssetInterceptRules()
	if err != nil {
		return errors.New("加载资产拦截规则失败: " + err.Error())
	}
	targets := r.targets()
	for _, t := range targets {
		if reason, blocked := scanTargetBlockReason(rules, []scanner.Target{t}); blocked {
			return errors.New("目标命中资产拦截规则，已拒绝执行：" + reason)
		}
	}
	return nil
}

// targets returns every URL the task is going to touch, so each one is checked
// against the blocklist.
func (r *deepRun) targets() []scanner.Target {
	out := []scanner.Target{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if t, err := scanner.ParseTarget(raw); err == nil {
			out = append(out, t)
		}
	}
	add(r.task.Target)
	switch r.task.Kind {
	case db.DeepTaskWebshellInject:
		add(stringParam(r.task.Params, "upload_url"))
		add(stringParam(r.task.Params, "land_url"))
	case db.DeepTaskWAFBypass:
		add(stringParam(r.task.Params, "base_url"))
	case db.DeepTaskSQLiProbe, db.DeepTaskXSSProbe:
		for _, u := range stringSliceParam(r.task.Params, "urls") {
			add(u)
		}
		for _, raw := range mapSliceParam(r.task.Params, "points") {
			if s, ok := raw["url"].(string); ok {
				add(s)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- 参数读取

func stringParam(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	v, ok := params[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

func intParam(params map[string]any, key string, def int) int {
	if params == nil {
		return def
	}
	switch t := params[key].(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
	}
	return def
}

func boolParam(params map[string]any, key string) bool {
	if params == nil {
		return false
	}
	switch t := params[key].(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	}
	return false
}

func intSliceParam(params map[string]any, key string) []int64 {
	if params == nil {
		return []int64{}
	}
	return uniqueIDs(idsFromAny(params[key]))
}

// templateFindingIDs returns the findings linked to one template. Scan-created
// tasks pass a per-template map; LLM tools pass a flat list that applies to any
// template they confirm.
func templateFindingIDs(params map[string]any, templateID string) []int64 {
	if params != nil {
		switch m := params["finding_ids_by_template"].(type) {
		case map[string]any:
			if ids := idsFromAny(m[templateID]); len(ids) > 0 {
				return uniqueIDs(ids)
			}
		case map[string][]int64:
			if ids := m[templateID]; len(ids) > 0 {
				return uniqueIDs(ids)
			}
		}
	}
	return intSliceParam(params, "finding_ids")
}

func idsFromAny(raw any) []int64 {
	out := []int64{}
	switch t := raw.(type) {
	case []any:
		for _, v := range t {
			switch n := v.(type) {
			case float64:
				out = append(out, int64(n))
			case string:
				if id, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64); err == nil {
					out = append(out, id)
				}
			}
		}
	case []float64:
		for _, n := range t {
			out = append(out, int64(n))
		}
	case []int64:
		out = append(out, t...)
	case []int:
		for _, n := range t {
			out = append(out, int64(n))
		}
	case json.Number:
		if id, err := t.Int64(); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func stringSliceParam(params map[string]any, key string) []string {
	out := []string{}
	if params == nil {
		return out
	}
	raw, ok := params[key]
	if !ok {
		return out
	}
	switch t := raw.(type) {
	case []any:
		for _, v := range t {
			if s, ok := v.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
	case []string:
		for _, s := range t {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func mapParam(params map[string]any, key string) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	raw, ok := params[key]
	if !ok {
		return out
	}
	if m, ok := raw.(map[string]any); ok {
		for k, v := range m {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- 验证 / 利用

// selectDeepTemplates resolves the POC templates a verification or exploitation
// task runs: either the ones the user picked, or the ones matching the target
// fingerprint.
func (r *deepRun) selectDeepTemplates(target string) ([]db.POCTemplate, error) {
	if keys := stringSliceParam(r.task.Params, "matched_template_ids"); len(keys) > 0 {
		r.logf("match", "使用漏扫命中的 %d 个 POC 模板直接复现", len(keys))
		return r.pg.POCTemplatesByTemplateIDs(keys)
	}
	ids := intSliceParam(r.task.Params, "template_ids")
	if len(ids) > 0 {
		return r.pg.POCTemplatesByIDs(ids)
	}
	metas, err := r.pg.ListEnabledPOCMetadata()
	if err != nil {
		return nil, fmt.Errorf("加载 POC 元数据失败: %w", err)
	}
	techs, err := r.targetTechnologies(target)
	if err != nil {
		return nil, err
	}
	if len(techs) == 0 {
		return nil, errors.New("未能识别目标技术指纹，请指定要验证的 POC 模板")
	}
	r.logf("match", "目标技术指纹 %d 个：%s", len(techs), strings.Join(techs, ", "))
	smeta := make([]scanner.TemplateMeta, 0, len(metas))
	for _, p := range metas {
		if p.Protocol == "workflow" {
			continue
		}
		smeta = append(smeta, scanner.TemplateMeta{ID: p.ID, TemplateID: p.TemplateID, Name: p.Name, Tags: p.Tags})
	}
	matched := scanner.MatchTemplates(techs, smeta)
	if len(matched) == 0 {
		return nil, errors.New("指纹未命中任何 POC 模板，请指定要验证的 POC 模板")
	}
	if len(matched) > 50 {
		r.logf("match", "指纹命中 %d 个 POC，仅取前 50 个执行", len(matched))
		matched = matched[:50]
	}
	r.logf("match", "指纹命中 %d 个 POC", len(matched))
	return r.pg.POCTemplatesByIDs(matched)
}

// targetTechnologies fingerprints the target so the matching POCs can be
// selected without the user picking templates by hand.
func (r *deepRun) targetTechnologies(target string) ([]string, error) {
	targets, err := scanner.ParseTargets([]string{target})
	if err != nil {
		return nil, err
	}
	res, err := scanner.Discover(r.ctx, targets, scanner.DiscoverOptions{
		Ports:         "web",
		Concurrency:   50,
		Timeout:       900 * time.Millisecond,
		MaxProbes:     50,
		MaxPortChecks: 2000,
		Logf:          func(format string, args ...any) { r.logf("discover", format, args...) },
	})
	if err != nil {
		return nil, fmt.Errorf("目标探测失败: %w", err)
	}
	techs := []string{}
	seen := map[string]bool{}
	for _, svc := range res.Services {
		for _, tech := range svc.Technologies {
			if seen[tech] {
				continue
			}
			seen[tech] = true
			techs = append(techs, tech)
		}
	}
	sort.Strings(techs)
	return techs, nil
}

// runVerify replays the selected POC templates against the target and records
// whether the issue reproduces.
func (r *deepRun) runVerify(summary map[string]any) (string, string, string, map[string]any) {
	target := strings.TrimSpace(r.task.Target)
	if target == "" {
		return "failed", "failed", "缺少目标地址", summary
	}
	templates, err := r.selectDeepTemplates(target)
	if err != nil {
		return "failed", "failed", err.Error(), summary
	}
	repeats := intParam(r.task.Params, "repeats", 1)
	if repeats < 1 {
		repeats = 1
	}
	if repeats > 5 {
		repeats = 5
	}
	r.logf("verify", "开始漏洞验证：%d 个 POC × %d 次复现", len(templates), repeats)

	chainConfirmed := r.runJavaChains(templates, target, "verify", summary)
	hits, needsReview, attempted := r.replayTemplates(templates, target, repeats, "verify", chainConfirmed)
	confirmed := hits - needsReview
	if confirmed < 0 {
		confirmed = 0
	}
	summary["templates"] = len(templates)
	summary["attempted"] = attempted
	summary["hits"] = hits
	summary["needs_review"] = needsReview
	summary["confirmed"] = confirmed
	summary["findings_confirmed"] = r.confirmedFindingCount()
	r.setProgress("verify", map[string]any{"attempted": attempted, "confirmed": confirmed, "needs_review": needsReview})
	r.logf("verify", "验证完成：%d/%d 个 POC 可复现，%d 个需人工复核，%d 个关联发现已确认", confirmed, attempted, needsReview, r.confirmedFindingCount())
	return "done", "done", "", summary
}

// runExploit replays the POC templates (or a hand-written request) and keeps
// the full request/response evidence of every hit.
func (r *deepRun) runExploit(summary map[string]any) (string, string, string, map[string]any) {
	target := strings.TrimSpace(r.task.Target)
	if target == "" {
		return "failed", "failed", "缺少目标地址", summary
	}
	if raw := stringParam(r.task.Params, "custom_request"); raw != "" {
		return r.runCustomExploit(target, raw, summary)
	}
	templates, err := r.selectDeepTemplates(target)
	if err != nil {
		return "failed", "failed", err.Error(), summary
	}
	r.logf("exploit", "开始漏洞利用：%d 个 POC", len(templates))
	chainConfirmed := r.runJavaChains(templates, target, "exploit", summary)
	hits, needsReview, attempted := r.replayTemplates(templates, target, 1, "exploit", chainConfirmed)
	confirmed := hits - needsReview
	if confirmed < 0 {
		confirmed = 0
	}
	summary["templates"] = len(templates)
	summary["attempted"] = attempted
	summary["hits"] = hits
	summary["needs_review"] = needsReview
	summary["findings_confirmed"] = r.confirmedFindingCount()
	r.setProgress("exploit", map[string]any{"hits": hits, "needs_review": needsReview})
	r.logf("exploit", "利用完成：%d/%d 个 POC 命中（%d 个需复核），%d 个关联发现已确认", hits, attempted, needsReview, r.confirmedFindingCount())
	return "done", "done", "", summary
}

// replayTemplates runs the POC templates against the target and stores the
// evidence of every match. All templates share one nuclei pass per repetition
// so a wide POC set does not cost one process spawn each. Templates already
// confirmed by java-chains are not marked as not reproduced.
//
// Every hit is classified by the verdict package: clean hits are confirmed,
// weak hits (status-only matcher, missing response, XSS without reflection…)
// are stored as needs_review instead of being counted as confirmed. A
// confirmed hit confirms the finding that the scan linked to the template.
//
// It returns the number of matching templates, how many of them need review,
// and the number attempted.
func (r *deepRun) replayTemplates(templates []db.POCTemplate, target string, repeats int, mode string, chainConfirmed map[string]bool) (int, int, int) {
	runnable := make([]scanner.NucleiTemplate, 0, len(templates))
	byID := map[string]db.POCTemplate{}
	for _, tpl := range templates {
		if strings.TrimSpace(tpl.Content) == "" || tpl.Protocol == "workflow" {
			continue
		}
		runnable = append(runnable, scanner.NucleiTemplate{ID: tpl.TemplateID, Content: tpl.Content})
		byID[tpl.TemplateID] = tpl
	}
	if len(runnable) == 0 {
		return 0, 0, 0
	}
	matched := map[string]bool{}
	weak := map[string]bool{}
	hits := 0
	ranOut := false
	for round := 0; round < repeats; round++ {
		if r.ctx.Err() != nil {
			ranOut = true
			break
		}
		run := scanner.RunNuclei(r.ctx, runnable, []string{target},
			scanner.NucleiOptions{RateLimit: 25, Concurrency: 5, TimeoutSeconds: 180})
		if run.Err != nil && len(run.Results) == 0 {
			r.logf(mode, "nuclei 执行失败: %v", run.Err)
			ranOut = true
			break
		}
		for _, res := range run.Results {
			tpl := byID[res.TemplateID]
			decision := assessNucleiHit(res, tpl)
			if decision.NeedsManualReview() {
				weak[res.TemplateID] = true
			}
			if !matched[res.TemplateID] {
				matched[res.TemplateID] = true
				hits++
			}
			rec := db.ExploitRecord{
				TaskID:     r.task.ID,
				Mode:       mode,
				TemplateID: res.TemplateID,
				Name:       displayOr(res.Name, displayOr(tpl.Name, res.TemplateID)),
				Severity:   strings.ToLower(displayOr(res.Severity, tpl.Severity)),
				Target:     displayOr(res.MatchedAt, target),
				Verdict:    decision.Verdict,
				Request:    cleanHTTPText(displayOr(res.Request, stringFromRaw(res.Raw, "request")), maxStoredHTTPRequest),
				Response:   cleanHTTPText(displayOr(res.Response, stringFromRaw(res.Raw, "response")), maxStoredHTTPResponse),
				Extracted:  res.Extracted,
				Curl:       res.Curl,
				Evidence:   formatDeepEvidence(res, tpl) + "\n\n" + verdictEvidence(decision),
				ElapsedMs:  int(run.Elapsed.Milliseconds()),
			}
			if code, ok := intFromRaw(res.Raw, "response-code"); ok {
				rec.StatusCode = &code
			}
			if _, err := r.pg.AddExploitRecord(rec); err != nil {
				r.logf(mode, "写入记录失败 %s: %v", res.TemplateID, err)
			}
			if decision.Verdict != verdict.Confirmed {
				r.logf(mode, "%s 命中证据不足，标记待复核: %s", res.TemplateID, strings.Join(decision.Reasons, "；"))
				continue
			}
			note := fmt.Sprintf("自动复现确认：深度任务 #%d 使用模板 %s 在 %s 复现命中（类别 %s，判定 confirmed）。",
				r.task.ID, res.TemplateID, displayOr(res.MatchedAt, target), decision.Class)
			confirmed := r.confirmLinkedFindings(mode, res.TemplateID, note)
			ids := templateFindingIDs(r.task.Params, res.TemplateID)
			if confirmed == 0 && boolParam(r.task.Params, "write_finding") && mode == "exploit" {
				if id := r.writeFinding(rec); id > 0 {
					ids = append(ids, id)
				}
			}
			r.attachHitExchanges(res, ids)
		}
	}
	if !ranOut {
		for id := range chainConfirmed {
			if !matched[id] {
				hits++
			}
		}
		for _, tpl := range templates {
			if matched[tpl.TemplateID] || chainConfirmed[tpl.TemplateID] || strings.TrimSpace(tpl.Content) == "" || tpl.Protocol == "workflow" {
				continue
			}
			if _, err := r.pg.AddExploitRecord(db.ExploitRecord{
				TaskID:     r.task.ID,
				Mode:       mode,
				TemplateID: tpl.TemplateID,
				Name:       displayOr(tpl.Name, tpl.TemplateID),
				Severity:   strings.ToLower(tpl.Severity),
				Target:     target,
				Verdict:    "not_reproduced",
				Evidence:   "重放未命中匹配条件",
			}); err != nil {
				r.logf(mode, "写入记录失败 %s: %v", tpl.TemplateID, err)
			}
		}
	}
	return hits, len(weak), len(runnable)
}

// confirmLinkedFindings marks every finding linked to a template as confirmed.
// The same finding is confirmed once per task even when several repeats hit.
func (r *deepRun) confirmLinkedFindings(stage, templateID, note string) int {
	ids := templateFindingIDs(r.task.Params, templateID)
	if len(ids) == 0 {
		return 0
	}
	if r.confirmedFindings == nil {
		r.confirmedFindings = map[int64]bool{}
	}
	confirmed := 0
	for _, id := range ids {
		if r.confirmedFindings[id] {
			continue
		}
		from, found, changed, err := r.pg.ConfirmFinding(r.ctx, id, note)
		if err != nil {
			r.logf(stage, "更新发现 #%d 失败: %v", id, err)
			continue
		}
		if !found {
			continue
		}
		r.confirmedFindings[id] = true
		confirmed++
		if changed {
			r.logf(stage, "发现 #%d 状态 %s → confirmed", id, displayOr(from, "unknown"))
		}
	}
	return confirmed
}

func (r *deepRun) confirmedFindingCount() int { return len(r.confirmedFindings) }

// runCustomExploit sends a hand-written raw HTTP request and stores the
// response as evidence.
func (r *deepRun) runCustomExploit(target, raw string, summary map[string]any) (string, string, string, map[string]any) {
	req, err := parseRawRequest(raw, target)
	if err != nil {
		return "failed", "failed", err.Error(), summary
	}
	client := scanner.NewDeepClient(20 * time.Second)
	r.logf("exploit", "发送自定义请求 %s %s", req.Method, req.URL)
	resp := client.Do(r.ctx, req)
	if resp.Error != "" {
		return "failed", "failed", "请求失败: " + resp.Error, summary
	}
	verdict := "executed"
	if resp.StatusCode >= 500 {
		verdict = "server_error"
	}
	rec := db.ExploitRecord{
		TaskID:     r.task.ID,
		Mode:       "exploit",
		TemplateID: "custom-request",
		Name:       "自定义请求",
		Target:     respFinalURL(req.URL, target),
		Verdict:    verdict,
		Request:    cleanHTTPText(raw, maxStoredHTTPRequest),
		Response:   cleanHTTPText(rawHTTPResponse(resp), maxStoredHTTPResponse),
		Evidence:   fmt.Sprintf("HTTP %d，响应 %d 字节，耗时 %d ms", resp.StatusCode, resp.Length, resp.Elapsed.Milliseconds()),
		ElapsedMs:  int(resp.Elapsed.Milliseconds()),
	}
	status := resp.StatusCode
	rec.StatusCode = &status
	if _, err := r.pg.AddExploitRecord(rec); err != nil {
		return "failed", "failed", "写入记录失败: " + err.Error(), summary
	}
	if boolParam(r.task.Params, "write_finding") {
		r.writeFinding(rec)
	}
	summary["status_code"] = resp.StatusCode
	summary["length"] = resp.Length
	r.setProgress("exploit", map[string]any{"status_code": resp.StatusCode})
	return "done", "done", "", summary
}

// parseRawRequest turns a raw HTTP request (as copied from a browser or
// interceptor) into a DeepRequest. The host line of the request is replaced by
// the task target when the target was given.
func parseRawRequest(raw, target string) (scanner.DeepRequest, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	if len(lines) < 2 {
		return scanner.DeepRequest{}, errors.New("原始请求格式不正确")
	}
	head := strings.Fields(strings.TrimSpace(lines[0]))
	if len(head) < 2 {
		return scanner.DeepRequest{}, errors.New("原始请求缺少请求行")
	}
	method := strings.ToUpper(head[0])
	path := head[1]
	body := ""
	if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		body = raw[idx+2:]
	}
	req := scanner.DeepRequest{Method: method, Body: body}
	base := strings.TrimSpace(target)
	if base != "" {
		u, err := url.Parse(base)
		if err != nil {
			return req, fmt.Errorf("目标地址无效: %w", err)
		}
		if u.Host == "" {
			return req, errors.New("目标地址无效")
		}
		// Rebuild the URL by concatenation so an already-encoded request target
		// (e.g. /api?x=%27) is replayed byte-for-byte instead of being
		// double-encoded ("?" must stay a query separator).
		switch {
		case strings.HasPrefix(path, "http://"), strings.HasPrefix(path, "https://"):
			req.URL = path
		case strings.HasPrefix(path, "/"):
			req.URL = u.Scheme + "://" + u.Host + path
		default:
			req.URL = u.Scheme + "://" + u.Host + "/" + path
		}
	} else {
		if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
			return req, errors.New("缺少目标地址，无法还原请求 URL")
		}
		req.URL = path
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		value := strings.TrimSpace(line[i+1:])
		if name == "" {
			continue
		}
		if strings.EqualFold(name, "Host") {
			continue
		}
		if strings.EqualFold(name, "Content-Length") {
			continue
		}
		if strings.EqualFold(name, "Cookie") {
			for _, c := range strings.Split(value, ";") {
				if c = strings.TrimSpace(c); c != "" {
					req.Cookies = append(req.Cookies, c)
				}
			}
			continue
		}
		if req.Headers == nil {
			req.Headers = map[string]string{}
		}
		req.Headers[name] = value
	}
	return req, nil
}

func respFinalURL(reqURL, target string) string {
	if strings.TrimSpace(reqURL) != "" {
		return reqURL
	}
	return target
}

// writeFinding stores an exploitation result in the global findings list. The
// dedupe key merges repeated runs of the same template against the same
// endpoint, so an LLM rerun updates the existing finding instead of duplicating
// it. Existing triage status is preserved by UpsertFinding. It returns the finding
// id so the caller can bind the rest of the exploit chain to it.
func (r *deepRun) writeFinding(rec db.ExploitRecord) int64 {
	// exploit 记录里的报文可能来自非 HTTP 协议（MySQL/Redis 响应是二进制），
	// 非法 UTF-8 会让整条 findings 写入失败，所以入库前先转成可存的文本。
	rec.Name = scanner.PacketText(rec.Name)
	rec.TemplateID = scanner.PacketText(rec.TemplateID)
	rec.Target = scanner.PacketText(rec.Target)
	rec.Evidence = scanner.PacketText(rec.Evidence)
	rec.Curl = scanner.PacketText(rec.Curl)
	for i := range rec.Extracted {
		rec.Extracted[i] = scanner.PacketText(rec.Extracted[i])
	}
	summary := fmt.Sprintf("%s 在 %s 命中（深度利用 #%d）", displayOr(rec.Name, rec.TemplateID), rec.Target, r.task.ID)
	key := findingDedupeKey(rec.TemplateID, rec.Target)
	req := cleanHTTPText(rec.Request, maxStoredHTTPRequest)
	resp := cleanHTTPText(rec.Response, maxStoredHTTPResponse)
	id, created, err := r.pg.UpsertFinding(0, 0, rec.TemplateID, rec.Name, rec.Severity, summary, rec.Evidence,
		fmt.Sprintf("deep:%d", r.task.ID), nil, key)
	if err != nil {
		r.logf("exploit", "写入发现失败 %s: %v", rec.TemplateID, err)
		return 0
	}
	if !created {
		r.logf("exploit", "命中已合并到既有发现 #%d（%s）", id, rec.TemplateID)
	}
	autoReport := report.BuildFindingReport(report.FindingReportInput{
		FindingID:       id,
		Name:            rec.Name,
		VulnClass:       rec.TemplateID,
		Severity:        rec.Severity,
		Status:          db.FindingPending,
		Summary:         summary,
		Evidence:        rec.Evidence,
		TaskDescription: fmt.Sprintf("#%d %s", r.task.ID, r.task.Name),
		Source:          fmt.Sprintf("深度利用任务 #%d（%s，模板 %s）", r.task.ID, rec.Mode, rec.TemplateID),
		TemplateID:      rec.TemplateID,
		Host:            rec.Target,
		MatchedAt:       rec.Target,
		Type:            rec.Mode,
		Curl:            rec.Curl,
		Extracted:       rec.Extracted,
		HTTPRequest:     req,
		HTTPResponse:    resp,
		GeneratedAt:     time.Now(),
	})
	if err := r.pg.SetFindingHTTPArtifactsAndAutoReport(id, req, resp, autoReport); err != nil {
		r.logf("exploit", "保存原始 HTTP/报告失败 %s: %v", rec.TemplateID, err)
	}
	return id
}

// attachHitExchanges binds every request/response nuclei recorded for one hit to
// the findings it produced. A template that needs several requests to prove
// itself — upload a shell then call it, inject then read the row back — only
// reports the exchange its matcher fired on, so without the sequence the finding
// shows the last check and hides the request that actually abused the flaw.
func (r *deepRun) attachHitExchanges(res scanner.NucleiResult, ids []int64) {
	store := r.s.evidenceStore()
	if store == nil || res.TemplateID == "" || len(res.Exchanges) < 2 || len(ids) == 0 {
		return
	}
	raws := make([]evidence.RawExchange, 0, len(res.Exchanges))
	for _, ex := range res.Exchanges {
		req := cleanHTTPText(ex.Request, maxStoredHTTPRequest)
		if strings.TrimSpace(req) == "" {
			continue
		}
		role, note := "supporting", "模板复现序列中的报文"
		if ex.Request == res.Request && ex.Response == res.Response {
			role, note = "proof", "nuclei 命中的验证报文"
		}
		raws = append(raws, evidence.RawExchange{
			Request:  req,
			Response: cleanHTTPText(ex.Response, maxStoredHTTPResponse),
			Role:     role,
			Note:     note,
		})
	}
	if len(raws) < 2 {
		return
	}
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if err := store.SaveRawExchanges(r.ctx, id, raws); err != nil {
			r.logf("evidence", "保存发现 #%d 的复现报文序列失败 %s: %v", id, res.TemplateID, err)
		}
	}
}

// rawHTTPResponse reconstructs the wire response for hand-written requests; the
// deep client captures headers and body separately.
func rawHTTPResponse(resp scanner.DeepResponse) string {
	if resp.StatusCode == 0 && resp.Error != "" {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	keys := make([]string, 0, len(resp.Headers))
	for key := range resp.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range resp.Headers[key] {
			fmt.Fprintf(&b, "%s: %s\r\n", key, value)
		}
	}
	b.WriteString("\r\n")
	b.WriteString(resp.Body)
	return b.String()
}

func formatDeepEvidence(res scanner.NucleiResult, tpl db.POCTemplate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "模板: %s (%s)\n", displayOr(tpl.Name, tpl.TemplateID), tpl.TemplateID)
	fmt.Fprintf(&b, "匹配地址: %s\n", displayOr(res.MatchedAt, res.Host))
	if len(res.Extracted) > 0 {
		fmt.Fprintf(&b, "提取结果: %s\n", strings.Join(res.Extracted, ", "))
	}
	if res.Curl != "" {
		fmt.Fprintf(&b, "curl: %s\n", res.Curl)
	}
	return b.String()
}

func stringFromRaw(raw map[string]any, key string) string {
	if raw == nil {
		return ""
	}
	if v, ok := raw[key].(string); ok {
		return v
	}
	return ""
}

func intFromRaw(raw map[string]any, key string) (int, bool) {
	if raw == nil {
		return 0, false
	}
	switch t := raw[key].(type) {
	case float64:
		return int(t), true
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n, true
		}
	}
	return 0, false
}

func truncateText(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	return s[:limit] + "\n...[已截断]"
}

// ---------------------------------------------------------------- WAF 绕过

func (r *deepRun) runWAFBypass(summary map[string]any) (string, string, string, map[string]any) {
	base := stringParam(r.task.Params, "base_url")
	if base == "" {
		base = strings.TrimSpace(r.task.Target)
	}
	if base == "" {
		return "failed", "failed", "缺少目标地址", summary
	}
	path := stringParam(r.task.Params, "path")
	if path == "" {
		path = "/"
	}
	param := stringParam(r.task.Params, "param")
	payload := stringParam(r.task.Params, "payload")
	if payload == "" {
		payload = "' union select 1,2,3--"
	}
	keywords := stringSliceParam(r.task.Params, "keywords")

	client := scanner.NewDeepClient(15 * time.Second)
	r.logf("waf", "探测 WAF: %s", base)
	det := scanner.DetectWAF(r.ctx, client, base)
	summary["waf_detected"] = det.Detected
	summary["waf_vendor"] = det.Vendor
	summary["waf_blocked"] = det.Blocked
	summary["evidence"] = det.Evidence
	r.logf("waf", "WAF 识别: %s（拦截=%v，证据 %d 条）", displayOr(det.Vendor, "未识别"), det.Blocked, len(det.Evidence))
	if !det.Detected && boolParam(r.task.Params, "only_if_detected") {
		summary["skipped"] = true
		summary["skip_reason"] = "未检测到 WAF，跳过变形测试"
		r.logf("waf", "未检测到 WAF，跳过变形测试")
		return "done", "done", "", summary
	}

	variants := scanner.BuildBypassVariants(path, param, payload)
	r.logf("waf", "开始绕过测试：%d 种变形", len(variants))
	probes := scanner.RunBypassProbes(r.ctx, client, base, variants, keywords)
	bypassed, blocked := 0, 0
	for _, p := range probes {
		if p.Verdict == "bypassed" {
			bypassed++
		}
		if p.Verdict == "blocked" {
			blocked++
		}
		rec := db.WAFBypassResult{
			TaskID:      r.task.ID,
			Target:      base,
			WAFDetected: det.Detected,
			WAFVendor:   det.Vendor,
			Variant:     p.Name,
			VariantDesc: p.Desc,
			Method:      p.Method,
			Path:        p.Path,
			Verdict:     p.Verdict,
			Note:        p.Note,
			RespLength:  p.Length,
		}
		if p.StatusCode > 0 {
			code := p.StatusCode
			rec.StatusCode = &code
		}
		if _, err := r.pg.AddWAFBypassResult(rec); err != nil {
			r.logf("waf", "写入结果失败 %s: %v", p.Name, err)
		}
	}
	summary["variants"] = len(probes)
	summary["bypassed"] = bypassed
	summary["blocked"] = blocked
	r.setProgress("waf", map[string]any{"bypassed": bypassed, "blocked": blocked})
	r.logf("waf", "绕过测试完成：%d 种变形可绕过，%d 种被拦截", bypassed, blocked)
	return "done", "done", "", summary
}

// ---------------------------------------------------------------- Webshell 注入

func (r *deepRun) runWebshellInject(summary map[string]any) (string, string, string, map[string]any) {
	uploadURL := stringParam(r.task.Params, "upload_url")
	if uploadURL == "" {
		return "failed", "failed", "缺少上传地址", summary
	}
	shellType := stringParam(r.task.Params, "shell_type")
	password := stringParam(r.task.Params, "password")
	fieldName := stringParam(r.task.Params, "field_name")
	fileName := stringParam(r.task.Params, "file_name")
	landURL := stringParam(r.task.Params, "land_url")
	extra := mapParam(r.task.Params, "extra")
	headers := mapParam(r.task.Params, "headers")

	payload := scanner.BuildShellPayload(shellType, password)
	if fileName == "" && landURL != "" {
		if u, err := url.Parse(landURL); err == nil {
			if base := path.Base(u.Path); base != "." && base != "/" && base != "" {
				fileName = base
			}
		}
	}
	if fileName != "" {
		payload.Filename = fileName
	}
	client := scanner.NewDeepClient(20 * time.Second)
	r.logf("inject", "上传 webshell 到 %s（类型 %s，字段 %q）", uploadURL, payload.Type, displayOr(fieldName, "raw"))
	res := scanner.UploadWebshell(r.ctx, client, uploadURL, fieldName, payload.Filename, []byte(payload.Content), extra, headers)
	summary["upload_status"] = res.StatusCode
	summary["upload_success"] = res.Success
	if !res.Success {
		summary["upload_note"] = res.Note
		r.logf("inject", "上传失败: %s", res.Note)
		return "failed", "failed", "webshell 上传失败: " + res.Note, summary
	}
	r.logf("inject", "上传完成（HTTP %d）", res.StatusCode)

	alive, note := false, "未提供落地地址，跳过存活验证"
	if landURL != "" {
		alive, note = scanner.CheckShellAlive(r.ctx, client, landURL, payload)
		r.logf("inject", "落地验证 %s: %s", landURL, note)
	}
	name := displayOr(stringParam(r.task.Params, "name"), payload.Filename)
	ws, err := r.pg.CreateWebshell(db.WebshellInput{
		Name:      name,
		URL:       landURL,
		ShellType: payload.Type,
		Password:  payload.Password,
		Target:    displayOr(r.task.Target, uploadURL),
		Source:    "inject",
		TaskID:    &r.task.ID,
		Note:      truncateText(res.Response, 2000),
	})
	if err != nil {
		return "failed", "failed", "写入 webshell 记录失败: " + err.Error(), summary
	}
	status := "unknown"
	if alive {
		status = "alive"
	}
	if err := r.pg.UpdateWebshellState(ws.ID, status, "", res.Note); err != nil {
		r.logf("inject", "更新 webshell 状态失败: %v", err)
	}
	r.s.registerWebshellResource(ws, uploadURL, landURL)
	summary["webshell_id"] = ws.ID
	summary["alive"] = alive
	summary["note"] = note
	r.setProgress("inject", map[string]any{"webshell_id": ws.ID, "alive": alive})
	return "done", "done", "", summary
}

// ---------------------------------------------------------------- HTTP API

// shellAllowed rejects a webshell URL that hits the global asset blocklist.
// The webshell endpoints talk to arbitrary URLs, so they need the same gate
// the scan pipeline applies.
func shellAllowed(pg *db.DB, rawURL string) (string, bool) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", true
	}
	t, err := scanner.ParseTarget(rawURL)
	if err != nil {
		return "", true
	}
	rules, err := pg.ListAssetInterceptRules()
	if err != nil {
		return "加载资产拦截规则失败: " + err.Error(), false
	}
	if reason, blocked := scanTargetBlockReason(rules, []scanner.Target{t}); blocked {
		return reason, false
	}
	return "", true
}

// listDeepTasks returns the deep-exploitation task list.
func (s *Server) listDeepTasks(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	tasks, total, err := pg.ListDeepTasks(q.Get("kind"), atoiDefault(q.Get("limit"), 50), atoiDefault(q.Get("offset"), 0))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, t := range tasks {
		t.Log = ""
	}
	writeJSON(w, 200, map[string]any{"tasks": tasks, "total": total})
}

// createDeepTask queues a deep-exploitation task.
func (s *Server) createDeepTask(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req db.DeepTaskInput
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	req.Kind = strings.ToLower(strings.TrimSpace(req.Kind))
	switch req.Kind {
	case db.DeepTaskVerify, db.DeepTaskExploit, db.DeepTaskWAFBypass, db.DeepTaskWebshellInject,
		db.DeepTaskSQLiProbe, db.DeepTaskXSSProbe:
	default:
		writeErr(w, 400, "任务类型必须是 verify、exploit、waf_bypass、webshell_inject、sqli_probe 或 xss_probe")
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		writeErr(w, 400, "缺少目标地址")
		return
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rules, err := pg.ListAssetInterceptRules()
	if err != nil {
		writeErr(w, 500, "加载资产拦截规则失败: "+err.Error())
		return
	}
	probe := &deepRun{s: s, pg: pg, task: &db.DeepTask{Kind: req.Kind, Target: req.Target, Params: req.Params}}
	if reason, blocked := scanTargetBlockReason(rules, probe.targets()); blocked {
		writeErr(w, 400, "目标命中资产拦截规则，已拒绝创建："+reason)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = deepTaskLabel(req.Kind) + " " + req.Target
	}
	task, err := pg.CreateDeepTask(req)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if s.deepMgr != nil {
		s.deepMgr.wakeup()
	}
	writeJSON(w, 201, task)
}

func deepTaskLabel(kind string) string {
	switch kind {
	case db.DeepTaskVerify:
		return "漏洞验证"
	case db.DeepTaskExploit:
		return "漏洞利用"
	case db.DeepTaskWAFBypass:
		return "WAF 绕过"
	case db.DeepTaskWebshellInject:
		return "Webshell 注入"
	case db.DeepTaskSQLiProbe:
		return "SQL 注入专项验证"
	case db.DeepTaskXSSProbe:
		return "XSS 专项验证"
	default:
		return "深度利用"
	}
}

// getDeepTask returns one deep task with its records.
func (s *Server) getDeepTask(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	task, err := pg.GetDeepTask(id)
	if errors.Is(err, db.ErrDeepTaskNotFound) {
		writeErr(w, 404, "深度利用任务不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := map[string]any{"task": task}
	if records, err := pg.ListExploitRecords(id); err == nil {
		out["records"] = records
	}
	if results, err := pg.ListWAFBypassResults(id); err == nil {
		out["waf_results"] = results
	}
	writeJSON(w, 200, out)
}

// deleteDeepTask removes a finished deep task.
func (s *Server) deleteDeepTask(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ok2, err := pg.DeleteDeepTask(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok2 {
		writeErr(w, 400, "任务仍在执行，无法删除")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// cancelDeepTask stops a queued or running deep task.
func (s *Server) cancelDeepTask(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ok2, err := pg.CancelDeepTask(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok2 {
		writeErr(w, 400, "任务已结束，无法停止")
		return
	}
	if s.deepMgr != nil {
		s.deepMgr.cancelTask(id)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// listWebshells returns the managed webshells.
func (s *Server) listWebshells(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	shells, total, err := pg.ListWebshells(q.Get("target"), atoiDefault(q.Get("limit"), 50), atoiDefault(q.Get("offset"), 0))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"webshells": shells, "total": total})
}

// createWebshell registers a webshell by hand.
func (s *Server) createWebshell(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req db.WebshellInput
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		writeErr(w, 400, "缺少 webshell 地址")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if reason, allowed := shellAllowed(pg, req.URL); !allowed {
		writeErr(w, 400, "webshell 地址命中资产拦截规则，已拒绝："+reason)
		return
	}
	shell, err := pg.CreateWebshell(req)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.registerWebshellResource(shell, req.URL, "")
	writeJSON(w, 201, shell)
}

// updateWebshell edits a webshell record.
func (s *Server) updateWebshell(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 webshell ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req db.WebshellInput
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if reason, allowed := shellAllowed(pg, req.URL); !allowed {
		writeErr(w, 400, "webshell 地址命中资产拦截规则，已拒绝："+reason)
		return
	}
	if err := pg.UpdateWebshell(id, req); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	shell, err := pg.GetWebshell(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// The endpoint may have changed: close the old ledger entry and register
	// the new one so the port audit never points at a stale URL.
	if s.resourceMgr != nil {
		s.releaseWebshellResource(id, "webshell 地址变更")
		s.registerWebshellResource(shell, req.URL, "")
	}
	writeJSON(w, 200, shell)
}

// deleteWebshell removes a webshell record.
func (s *Server) deleteWebshell(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 webshell ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ok2, err := pg.DeleteWebshell(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok2 {
		writeErr(w, 404, "webshell 不存在")
		return
	}
	s.releaseWebshellResource(id, "webshell 已删除")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// checkWebshell probes whether a webshell still answers.
func (s *Server) checkWebshell(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 webshell ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	shell, err := pg.GetWebshell(id)
	if err != nil {
		writeErr(w, 404, "webshell 不存在")
		return
	}
	if strings.TrimSpace(shell.URL) == "" {
		writeErr(w, 400, "该 webshell 没有可用地址")
		return
	}
	if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
		writeErr(w, 400, "webshell 地址命中资产拦截规则，已拒绝："+reason)
		return
	}
	payload := scanner.BuildShellPayload(shell.ShellType, shell.Password)
	client := scanner.NewDeepClient(15 * time.Second)
	alive, note := scanner.CheckShellAlive(s.ctx, client, shell.URL, payload)
	status := "dead"
	if alive {
		status = "alive"
	}
	if err := pg.UpdateWebshellState(shell.ID, status, "", note); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"alive": alive, "status": status, "note": note})
}

// execWebshellCommand runs one command through a webshell.
func (s *Server) execWebshellCommand(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 webshell ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Command string `json:"command"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		writeErr(w, 400, "命令不能为空")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	shell, err := pg.GetWebshell(id)
	if err != nil {
		writeErr(w, 404, "webshell 不存在")
		return
	}
	if strings.TrimSpace(shell.URL) == "" {
		writeErr(w, 400, "该 webshell 没有可用地址")
		return
	}
	if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
		writeErr(w, 400, "webshell 地址命中资产拦截规则，已拒绝："+reason)
		return
	}
	payload := scanner.BuildShellPayload(shell.ShellType, shell.Password)
	client := scanner.NewDeepClient(20 * time.Second)
	out, err := scanner.RunShellCommand(s.ctx, client, shell.URL, payload, req.Command)
	if err != nil {
		writeErr(w, 500, "命令执行失败: "+err.Error())
		return
	}
	_ = pg.UpdateWebshellState(shell.ID, "alive", truncateText(out, 8000), "")
	writeJSON(w, 200, map[string]any{"output": out})
}
