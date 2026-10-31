package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/pocparse"
	"github.com/Autumn-27/jingwei/scanner"
)

const (
	maxPOCUploadBytes  = 2 << 20
	maxPOCRunTargets   = 50
	maxPOCRunTemplates = 200
	maxPOCRunOutput    = 8 << 20
)

func (s *Server) pgListPOCs(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	f := db.POCFilter{
		Query:    strings.TrimSpace(q.Get("q")),
		Severity: strings.TrimSpace(q.Get("severity")),
		Source:   strings.TrimSpace(q.Get("source")),
		Protocol: strings.TrimSpace(q.Get("protocol")),
		Page:     atoiDefault(q.Get("page"), 0),
		Size:     atoiDefault(q.Get("size"), 50),
	}
	switch q.Get("enabled") {
	case "true":
		v := true
		f.Enabled = &v
	case "false":
		v := false
		f.Enabled = &v
	}
	items, total, err := pg.ListPOCTemplates(f)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"pocs": items, "total": total})
}

func (s *Server) pgPOCStats(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	stats, err := pg.POCStats()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, stats)
}

func (s *Server) pgGetPOC(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 POC ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	p, err := pg.GetPOCTemplate(id)
	if errors.Is(err, db.ErrPOCNotFound) {
		writeErr(w, 404, "POC 不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) pgCreatePOC(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPOCUploadBytes)
	var req struct {
		Content   string `json:"content"`
		Source    string `json:"source"`
		SourceURL string `json:"source_url"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误或内容超过 2MB")
		return
	}
	tpl, err := pocparse.Parse([]byte(req.Content), "")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = "manual"
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	p, err := pg.CreatePOCTemplate(tpl, source, strings.TrimSpace(req.SourceURL))
	if errors.Is(err, db.ErrPOCDuplicate) {
		writeErr(w, 409, "模板 ID 已存在："+tpl.TemplateID)
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, p)
}

func (s *Server) pgUpdatePOC(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 POC ID")
		return
	}
	var req struct {
		Name        *string `json:"name"`
		Severity    *string `json:"severity"`
		Description *string `json:"description"`
		Enabled     *bool   `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			writeErr(w, 400, "名称不能为空")
			return
		}
		req.Name = &name
	}
	if req.Severity != nil {
		sev := strings.ToLower(strings.TrimSpace(*req.Severity))
		switch sev {
		case "info", "low", "medium", "high", "critical", "unknown":
			req.Severity = &sev
		default:
			writeErr(w, 400, "无效的危险等级")
			return
		}
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	p, err := pg.UpdatePOCTemplate(id, req.Name, req.Severity, req.Description, req.Enabled)
	if errors.Is(err, db.ErrPOCNotFound) {
		writeErr(w, 404, "POC 不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) pgDeletePOC(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 POC ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	deleted, err := pg.DeletePOCTemplate(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !deleted {
		writeErr(w, 404, "POC 不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": 1})
}

type pocRunResult struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched_at"`
	Type       string `json:"type"`
	Timestamp  string `json:"timestamp"`
	Curl       string `json:"curl_command,omitempty"`
}

// pgRunPOCs executes selected nuclei templates against the supplied targets.
// It runs inside the application container (same sandbox as agent bash), so
// templates get the same trust model as any other tool input.
func (s *Server) pgRunPOCs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs            []int64  `json:"ids"`
		Targets        []string `json:"targets"`
		TimeoutSeconds int      `json:"timeout_seconds"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	ids := uniqueIDs(req.IDs)
	if len(ids) == 0 {
		writeErr(w, 400, "请至少选择一个 POC")
		return
	}
	if len(ids) > maxPOCRunTemplates {
		writeErr(w, 400, fmt.Sprintf("单次最多执行 %d 个 POC", maxPOCRunTemplates))
		return
	}
	targets := cleanTargets(req.Targets)
	if len(targets) == 0 {
		writeErr(w, 400, "请至少填写一个目标")
		return
	}
	if len(targets) > maxPOCRunTargets {
		writeErr(w, 400, fmt.Sprintf("单次最多 %d 个目标", maxPOCRunTargets))
		return
	}
	timeout := req.TimeoutSeconds
	if timeout <= 0 {
		timeout = 180
	}
	if timeout < 10 {
		timeout = 10
	}
	if timeout > 600 {
		timeout = 600
	}

	pg := s.pg(w)
	if pg == nil {
		return
	}
	templates, err := pg.POCTemplatesByIDs(ids)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(templates) == 0 {
		writeErr(w, 400, "未找到可用模板（可能已被禁用）")
		return
	}
	runnable := templates[:0]
	for _, tpl := range templates {
		if tpl.Protocol != "workflow" {
			runnable = append(runnable, tpl)
		}
	}
	if len(runnable) == 0 {
		writeErr(w, 400, "所选模板均为 workflow（工作流），暂不支持在此直接执行")
		return
	}
	templates = runnable

	nuclei, err := exec.LookPath("nuclei")
	if err != nil {
		writeErr(w, 503, "nuclei 未安装：请重新构建镜像，或在宿主机安装 nuclei 后重启服务")
		return
	}

	tmp, err := os.MkdirTemp("", "jingwei-poc-*")
	if err != nil {
		writeErr(w, 500, "创建临时目录失败: "+err.Error())
		return
	}
	defer os.RemoveAll(tmp)

	targetFile := filepath.Join(tmp, "targets.txt")
	if err := os.WriteFile(targetFile, []byte(strings.Join(targets, "\n")+"\n"), 0o600); err != nil {
		writeErr(w, 500, "写入目标失败: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Second)
	defer cancel()

	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxPOCRunOutput, 256<<10
	runGroup := func(dir string, tpls []scanner.NucleiTemplate, dast bool) error {
		tplDir := filepath.Join(tmp, dir)
		if err := os.Mkdir(tplDir, 0o700); err != nil {
			return err
		}
		for i, tpl := range tpls {
			name := fmt.Sprintf("%03d-%s.yaml", i, safeFilePart(tpl.ID))
			if err := os.WriteFile(filepath.Join(tplDir, name), []byte(tpl.Content), 0o600); err != nil {
				return fmt.Errorf("写入模板失败: %w", err)
			}
		}
		args := []string{
			"-t", tplDir,
			"-l", targetFile,
			"-jsonl",
			"-silent",
			"-no-color",
			"-disable-update-check",
			"-no-interactsh",
			"-rate-limit", "50",
			"-concurrency", "25",
			"-timeout", "10",
			"-retries", "1",
		}
		// The two template kinds cannot share an invocation: -dast loads only
		// fuzzing templates, and without it they are disabled as default.
		if dast {
			args = append(args, "-dast")
		}
		cmd := exec.CommandContext(ctx, nuclei, args...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		return cmd.Run()
	}

	in := make([]scanner.NucleiTemplate, 0, len(templates))
	for _, tpl := range templates {
		in = append(in, scanner.NucleiTemplate{ID: tpl.TemplateID, Content: tpl.Content})
	}
	// Browser-driven templates load only under -headless, which downloads
	// Chromium at scan time; drop them instead of letting nuclei exit with
	// "no templates provided for scan".
	in, headlessSkipped := scanner.RunnableTemplates(in)
	if len(in) == 0 {
		writeErr(w, 400, "所选模板均为 headless 浏览器模板，需安装浏览器并以 -headless 运行，暂不支持在此直接执行")
		return
	}
	legacy, dastTemplates := scanner.SplitDASTTemplates(in)

	started := time.Now()
	var runErr error
	for _, g := range []struct {
		dir  string
		tpls []scanner.NucleiTemplate
		dast bool
	}{{"legacy", legacy, false}, {"dast", dastTemplates, true}} {
		if len(g.tpls) == 0 || ctx.Err() != nil {
			continue
		}
		if err := runGroup(g.dir, g.tpls, g.dast); err != nil && runErr == nil {
			runErr = err
		}
	}
	elapsed := time.Since(started)
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)

	results := parseNucleiJSONL(stdout.String())
	resp := map[string]any{
		"ok":               runErr == nil,
		"results":          results,
		"result_count":     len(results),
		"stdout":           stdout.String(),
		"stderr":           stderr.String(),
		"elapsed_ms":       elapsed.Milliseconds(),
		"timed_out":        timedOut,
		"template_count":   len(in),
		"target_count":     len(targets),
		"headless_skipped": headlessSkipped,
	}
	if runErr != nil {
		if timedOut {
			resp["error"] = fmt.Sprintf("执行超时（%ds），已终止", timeout)
		} else if exitErr, ok := runErr.(*exec.ExitError); ok {
			resp["error"] = fmt.Sprintf("nuclei 退出码 %d", exitErr.ExitCode())
		} else {
			resp["error"] = runErr.Error()
		}
	}
	writeJSON(w, 200, resp)
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return len(p), nil
	}
	remain := b.limit - b.buf.Len()
	if remain <= 0 {
		return len(p), nil
	}
	if len(p) > remain {
		_, _ = b.buf.Write(p[:remain])
		_, _ = b.buf.WriteString("\n…（输出已截断）")
		b.limit = 0
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) String() string { return b.buf.String() }

func uniqueIDs(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func cleanTargets(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		for _, field := range strings.Fields(raw) {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			if _, ok := seen[field]; ok {
				continue
			}
			seen[field] = struct{}{}
			out = append(out, field)
		}
	}
	return out
}

func safeFilePart(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == 0 || r == ' ' {
			return '-'
		}
		return r
	}, s)
	if len(s) > 120 {
		s = s[:120]
	}
	if s == "" {
		return "template"
	}
	return s
}

func parseNucleiJSONL(raw string) []pocRunResult {
	out := []pocRunResult{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		r := pocRunResult{
			TemplateID: asString(m["template-id"]),
			Host:       asString(m["host"]),
			MatchedAt:  asString(m["matched-at"]),
			Type:       asString(m["type"]),
			Timestamp:  asString(m["timestamp"]),
			Curl:       asString(m["curl-command"]),
		}
		if info, ok := m["info"].(map[string]any); ok {
			r.Name = asString(info["name"])
			r.Severity = asString(info["severity"])
		}
		out = append(out, r)
	}
	return out
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}
