package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
	actool "github.com/Autumn-27/norma/tool"
)

// 凭据复用：把漏扫弱口令命中的账号在目标内网登录页上做精确验证。
// 只跑「这一组账号密码」，不走字典；每个目标都先过任务范围检查。

const (
	intranetReuseMaxURLs  = 5
	intranetReusePerURL   = 20 * time.Second
	intranetReuseMaxTotal = 300 * time.Second
)

type intranetReuseInput struct {
	CredentialID   int64    `json:"credential_id"`
	TaskID         int64    `json:"task_id"`
	URLs           []string `json:"urls"`
	Proxy          string   `json:"proxy"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

type intranetReuseTarget struct {
	URL       string `json:"url"`
	Host      string `json:"host,omitempty"`
	Status    string `json:"status"` // valid | invalid | skipped | error
	Username  string `json:"username,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Request   string `json:"request,omitempty"`
	Response  string `json:"response,omitempty"`
	Cookie    string `json:"cookie,omitempty"`
	Attempts  int    `json:"attempts,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// intranetCredentialURL returns the credential's login URL, or one derived from
// host/port/protocol when the record has no URL.
func intranetCredentialURL(c *db.IntranetCredential) string {
	if c == nil {
		return ""
	}
	if u := strings.TrimSpace(c.URL); u != "" {
		return u
	}
	host := strings.TrimSpace(c.Host)
	if host == "" {
		return ""
	}
	scheme := displayOr(strings.ToLower(strings.TrimSpace(c.Protocol)), "http")
	if c.Port > 0 && !(scheme == "http" && c.Port == 80) && !(scheme == "https" && c.Port == 443) {
		return scheme + "://" + intranetHostPort(host, c.Port)
	}
	return scheme + "://" + host
}

// normalizeIntranetReuseURL accepts a bare host/path and yields an absolute URL.
func normalizeIntranetReuseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return raw
}

func intranetURLHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func (s *Server) intranetReuseCredential(ctx context.Context, pg *db.DB, in intranetReuseInput) (map[string]any, error) {
	cred, err := pg.GetIntranetCredential(in.CredentialID)
	if err != nil {
		return nil, errors.New("凭据不存在")
	}
	if !scanner.WebCrackAvailable() {
		return nil, errors.New("WebCrack 不可用（需要 python3 与 tools/webcrack），无法复用验证")
	}
	taskID := in.TaskID
	if taskID <= 0 && cred.TaskID != nil {
		taskID = *cred.TaskID
	}
	urls := make([]string, 0, intranetReuseMaxURLs)
	seen := map[string]bool{}
	addURL := func(raw string) {
		if len(urls) >= intranetReuseMaxURLs {
			return
		}
		u := normalizeIntranetReuseURL(raw)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		urls = append(urls, u)
	}
	for _, raw := range in.URLs {
		addURL(raw)
	}
	if len(in.URLs) == 0 {
		addURL(intranetCredentialURL(cred))
	}
	if len(urls) == 0 {
		if len(in.URLs) > 0 {
			return nil, errors.New("urls 均无法解析，请传完整的 http(s) 登录页地址")
		}
		return nil, errors.New("没有可复用的目标地址：请传入 urls，或先给凭据登记登录 URL")
	}
	proxy := strings.TrimSpace(in.Proxy)
	if proxy != "" {
		norm, perr := scanner.NormalizeProxyURL(proxy)
		if perr != nil {
			return nil, fmt.Errorf("代理地址无效: %v", perr)
		}
		proxy = norm
	}

	// Scope is checked before the credential leaves the platform: a host outside
	// the task's approved scope is skipped, not silently tested.
	targets := make([]intranetReuseTarget, 0, len(urls))
	for _, raw := range urls {
		item := intranetReuseTarget{URL: raw, Host: intranetURLHost(raw)}
		if item.Host == "" {
			item.Status, item.Error = "skipped", "无法解析目标地址"
			targets = append(targets, item)
			continue
		}
		if reason, allowed := s.intranetTargetAllowed(pg, taskID, item.Host); !allowed {
			item.Status, item.Error = "skipped", reason
			targets = append(targets, item)
			continue
		}
		targets = append(targets, item)
	}
	allowed := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.Status == "" {
			allowed = append(allowed, t.URL)
		}
	}
	if len(allowed) == 0 {
		return map[string]any{
			"credential": cred, "targets": targets, "task_id": taskID,
			"proxy": redactProxyURL(proxy), "note": "所有目标都未通过范围检查或无法解析，未发起验证",
		}, nil
	}

	timeout := time.Duration(in.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > intranetReuseMaxTotal {
		timeout = intranetReuseMaxTotal
	}
	run := scanner.RunWebCrack(ctx, scanner.WebCrackOptions{
		URLs:          allowed,
		Pairs:         []string{cred.Username + ":" + cred.Password},
		PerURLSeconds: int(intranetReusePerURL / time.Second),
		TimeoutSecond: int(timeout / time.Second),
		Proxy:         proxy,
	})
	if run.Missing {
		return nil, run.Err
	}
	byURL := make(map[string]scanner.WebCrackResult, len(run.Results))
	for _, res := range run.Results {
		byURL[res.URL] = res
	}
	found := 0
	attempted := 0
	for i := range targets {
		if targets[i].Status != "" {
			continue
		}
		res, ok := byURL[targets[i].URL]
		if !ok {
			targets[i].Status, targets[i].Error = "error", "WebCrack 未返回该目标的验证结果"
			continue
		}
		targets[i].Attempts = res.Attempts
		targets[i].ElapsedMS = res.ElapsedMS
		targets[i].Request = truncateIntranetOutput(res.Request, 6000)
		targets[i].Response = truncateIntranetOutput(res.Response, 6000)
		if res.Error != "" {
			targets[i].Status, targets[i].Error = "error", res.Error
			continue
		}
		attempted++
		if !res.Found {
			targets[i].Status = "invalid"
			continue
		}
		found++
		targets[i].Status = "valid"
		targets[i].Username = res.Username
		targets[i].Kind = res.Kind
		targets[i].Cookie = res.Cookie
		host, port, scheme := intranetTargetParts(targets[i].URL)
		if _, uerr := pg.UpsertIntranetCredential(db.IntranetCredentialInput{
			Host: host, Port: port, Protocol: scheme, URL: targets[i].URL,
			Username: cred.Username, Password: cred.Password, Source: "reuse",
			TaskID:   taskID,
			Evidence: fmt.Sprintf("%s：复用凭据 #%d 登录成功（%s）", targets[i].URL, cred.ID, displayOr(res.Kind, "weak")),
		}); uerr != nil {
			targets[i].Error = "登录成功但登记凭据失败: " + uerr.Error()
		}
	}

	status := ""
	evidence := ""
	sameHostTried := 0
	credHost := strings.ToLower(strings.TrimSpace(cred.Host))
	for _, target := range targets {
		if (target.Status == "valid" || target.Status == "invalid") && target.Host == credHost {
			sameHostTried++
		}
	}
	switch {
	case found > 0:
		status = db.IntranetCredValid
		evidence = fmt.Sprintf("复用验证成功：%d/%d 个目标接受该凭据（凭据 #%d）", found, attempted, cred.ID)
	case sameHostTried > 0:
		// Only a rejection on the credential's own host says the credential
		// itself went stale; other hosts reject it because they are different
		// login surfaces.
		status = db.IntranetCredInvalid
		evidence = fmt.Sprintf("原目标 %s 拒绝该凭据（复用尝试 %d 次）", cred.Host, sameHostTried)
	}
	if status != "" {
		if updated, merr := pg.MarkIntranetCredentialUsed(cred.ID, status, evidence); merr == nil && updated != nil {
			cred = updated
		}
	}

	res := map[string]any{
		"credential": cred, "targets": targets, "task_id": taskID,
		"proxy": redactProxyURL(proxy), "elapsed_ms": run.Elapsed.Milliseconds(),
	}
	if status == "" && attempted > 0 {
		res["note"] = "目标拒绝该凭据，但未在原目标上复验，凭据状态保持不变"
	}
	if run.Err != nil {
		res["error"] = run.Err.Error()
	}
	if len(targets) < len(urls) {
		res["note"] = fmt.Sprintf("目标过多，仅验证前 %d 个", intranetReuseMaxURLs)
	}
	return res, nil
}

// intranetTargetParts derives the credential ledger key from a URL.
func intranetTargetParts(raw string) (host string, port int, scheme string) {
	scheme = "http"
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", 0, scheme
	}
	if u.Scheme != "" {
		scheme = strings.ToLower(u.Scheme)
	}
	host = strings.ToLower(u.Hostname())
	if p, perr := strconv.Atoi(u.Port()); perr == nil && p > 0 {
		port = p
	}
	return host, port, scheme
}

func (s *Server) listIntranetCredentials(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	taskID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("task_id")), 10, 64)
	scanTaskID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("scan_task_id")), 10, 64)
	rows, err := pg.ListIntranetCredentials(db.IntranetCredentialFilter{
		Host: q.Get("host"), Status: q.Get("status"), TaskID: taskID, ScanTaskID: scanTaskID,
		Limit: atoiDefault(q.Get("limit"), 100),
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"credentials": rows, "total": len(rows)})
}

func (s *Server) reuseIntranetCredential(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req intranetReuseInput
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	res, err := s.intranetReuseCredential(r.Context(), pg, req)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// ---------------------------------------------------------------------------
// LLM 工具
// ---------------------------------------------------------------------------

func (s *Server) toolIntranetCredentials() actool.CoreTool {
	return roTool("intranet_credentials",
		"查询内网凭据台账：漏扫弱口令命中与横向复用验证过的账号。返回 host/username/password/status/source/url/finding_id 等，可用 intranet_cred_reuse 对目标登录页做精确复用验证。",
		objSchema(map[string]any{
			"host":         strParam("按主机过滤（可选，小写主机名或 IP）"),
			"status":       strParam("untested / valid / invalid（可选）"),
			"task_id":      intranetIntParam("按归属任务过滤（可选）"),
			"scan_task_id": intranetIntParam("按漏扫任务过滤（可选）"),
			"limit":        intranetIntParam("最多返回条数，默认 50，最大 500"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Host       string `json:"host"`
				Status     string `json:"status"`
				TaskID     int64  `json:"task_id"`
				ScanTaskID int64  `json:"scan_task_id"`
				Limit      int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.Limit <= 0 {
				a.Limit = 50
			}
			rows, err := pg.ListIntranetCredentials(db.IntranetCredentialFilter{
				Host: a.Host, Status: a.Status, TaskID: a.TaskID, ScanTaskID: a.ScanTaskID, Limit: a.Limit,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"credentials": rows, "total": len(rows)})
		})
}

func (s *Server) toolIntranetCredReuse() actool.CoreTool {
	return wrTool("intranet_cred_reuse",
		"用凭据台账里已命中的账号对一批内网登录页做精确复用验证（只试这一组账号密码，不走字典）。urls 省略时用凭据登记的登录地址；目标必须通过任务范围检查（严格模式下需先经范围审批）。可用 proxy 指定隧道出站，例如 socks5://<目标主机>:<监听端口>。验证成功会把凭据标记 valid，并按目标登记新的复用凭据；返回每个目标的原始请求/响应报文。",
		objSchema(map[string]any{
			"credential_id":   intranetIntParam("凭据台账 ID（必填）"),
			"urls":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "登录页地址列表（可选，最多 5 个；省略则用凭据登记的地址）"},
			"proxy":           strParam("出站代理（可选）：socks5://host:port 或 http://host:port"),
			"task_id":         intranetIntParam("归属任务 ID（可选，默认凭据归属/当前任务）"),
			"timeout_seconds": intranetIntParam("总超时秒数，默认 300，最大 300"),
		}, "credential_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a intranetReuseInput
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if a.CredentialID <= 0 {
				return actool.Errorf("credential_id 必填"), nil
			}
			if a.TaskID <= 0 {
				a.TaskID = intranetCtxTaskID(ctx)
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			res, err := s.intranetReuseCredential(ctx, pg, a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(res)
		})
}
