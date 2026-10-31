package server

import (
	"strings"

	"github.com/Autumn-27/jingwei/db"
)

// 弱口令到 Webshell 的自动链：WebCrack 证明凭据可登录之后，用这次登录拿到的
// 会话直接去尝试上传 webshell。没有会话的「上传」请求只会被踢回登录页，所以
// 链路的每一步都以真实的登录响应为依据，而不是猜测。上传地址仍来自扫描任务的
// webshell 配置，链本身不发明端点。

// loginCookieFromResponse extracts the Cookie header value from a raw login
// response. Set-Cookie attributes (Path/HttpOnly/...) are not part of a Cookie
// header, so they are stripped; a cookie definition that appears after a comma
// (requests joins repeated Set-Cookie headers that way) starts a new pair. A
// repeated cookie name keeps the last value the server sent, matching browsers.
func loginCookieFromResponse(raw string) string {
	jars := map[string]string{}
	order := []string{}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			break // end of the header block; the body is not header material
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "Set-Cookie") {
			continue
		}
		for _, segment := range strings.Split(value, ";") {
			for _, pair := range splitCookieDefinitions(segment) {
				cookieName, cookieValue, ok := strings.Cut(pair, "=")
				cookieName = strings.TrimSpace(cookieName)
				if !ok || cookieName == "" || isSetCookieAttribute(cookieName) {
					continue
				}
				if _, seen := jars[cookieName]; !seen {
					order = append(order, cookieName)
				}
				jars[cookieName] = strings.TrimSpace(cookieValue)
			}
		}
	}
	parts := make([]string, 0, len(order))
	for _, name := range order {
		parts = append(parts, name+"="+jars[name])
	}
	return strings.Join(parts, "; ")
}

// splitCookieDefinitions cuts a Set-Cookie segment at commas that introduce a
// new cookie. requests joins repeated headers with ", ", so the second cookie
// often starts inside a segment that began as an attribute ("Path=/, sid=1");
// a comma inside an Expires date yields a tail without "=" that the caller
// drops.
func splitCookieDefinitions(segment string) []string {
	out := []string{}
	for {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return out
		}
		i := strings.Index(segment, ",")
		if i < 0 {
			return append(out, segment)
		}
		out = append(out, strings.TrimSpace(segment[:i]))
		segment = segment[i+1:]
	}
}

// isSetCookieAttribute names the Set-Cookie parameters that look like a
// name=value pair but are not cookies themselves. A cookie literally named
// "path" or "expires" is the price of parsing a joined header without a real
// cookie parser.
func isSetCookieAttribute(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "path", "domain", "expires", "max-age", "samesite", "secure", "httponly",
		"priority", "partitioned", "version", "comment":
		return true
	}
	return false
}

// webshellTaskParams assembles the upload parameters from the scan's webshell
// configuration. Both the weak-pass chain and the POC-driven chain call this,
// so the two paths cannot drift apart on defaults or path joining.
func (r *scanRun) webshellTaskParams(target string, headers map[string]string, source string) (map[string]any, string) {
	params := r.task.WebshellParams
	uploadPath := strings.TrimSpace(stringParam(params, "upload_path"))
	if uploadPath == "" {
		return nil, "已启用 Webshell 注入但未配置上传路径"
	}
	uploadURL := joinHostPath(target, uploadPath)
	if uploadURL == "" {
		return nil, "无法拼接 Webshell 上传地址"
	}
	landURL := ""
	if landPath := strings.TrimSpace(stringParam(params, "land_path")); landPath != "" {
		landURL = joinHostPath(target, landPath)
	}
	out := map[string]any{
		"upload_url": uploadURL,
		"land_url":   landURL,
		"shell_type": displayOr(stringParam(params, "shell_type"), "php"),
		"password":   stringParam(params, "password"),
		"field_name": displayOr(stringParam(params, "field_name"), "file"),
		"source":     source,
		"proxy":      r.task.Proxy,
	}
	if len(headers) > 0 {
		out["headers"] = headers
	}
	return out, ""
}

// shellQueued reports whether an upload is already queued for this target's
// origin, so the two chains do not upload to one host twice.
func (r *scanRun) shellQueued(target string) bool {
	origin := normalizeWebBase(target, false)
	return origin != "" && r.shellHosts[origin]
}

func (r *scanRun) markShellQueued(target string) {
	origin := normalizeWebBase(target, false)
	if origin == "" {
		return
	}
	if r.shellHosts == nil {
		r.shellHosts = map[string]bool{}
	}
	r.shellHosts[origin] = true
}

// queueWeakPassWebshell chains a proven weak credential into a webshell upload
// on the same origin, carrying the session the successful login established.
// The chain is one attempt per origin per scan: several credential hits on one
// host do not queue duplicate uploads.
func (r *scanRun) queueWeakPassWebshell(loginURL, cookie string) (int64, bool) {
	if !r.task.WebshellInject || r.s == nil || r.s.deepMgr == nil {
		return 0, false
	}
	origin := normalizeWebBase(loginURL, false)
	if origin == "" || r.shellQueued(origin) {
		return 0, false
	}
	headers := map[string]string{}
	if cookie != "" {
		headers["Cookie"] = cookie
	}
	params, errMsg := r.webshellTaskParams(origin, headers, "weakpass")
	if errMsg != "" {
		r.logf("weakpass", "%s：%s，跳过基于弱口令的 Webshell 链", origin, errMsg)
		return 0, false
	}
	params["login_url"] = loginURL
	scanID := r.task.ID
	task, err := r.pg.CreateDeepTask(db.DeepTaskInput{
		Name:       "弱口令自动 Webshell 注入 · " + origin,
		Kind:       db.DeepTaskWebshellInject,
		Target:     origin,
		Params:     params,
		ScanTaskID: &scanID,
		AutoRun:    true,
	})
	if err != nil {
		r.logf("weakpass", "创建弱口令 Webshell 任务失败 %s: %v", origin, err)
		return 0, false
	}
	r.markShellQueued(origin)
	session := "无登录会话"
	if cookie != "" {
		session = "携带登录会话"
	}
	r.logf("weakpass", "凭据可登录 %s，已排队 Webshell 注入任务 #%d（%s）", loginURL, task.ID, session)
	r.s.deepMgr.wakeup()
	return task.ID, true
}
