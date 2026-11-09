package scanner

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// HTTP 表单类控制台：Jenkins（crumb + 表单）、WebLogic 控制台、JBoss/WildFly 管理台。
//
// 真机验证状态（2026-11-09）：
//   - Jenkins：已在真机 Jenkins LTS 验证 hit/deny。真机暴露并修掉两处——2.x 的登录端点是
//     /j_spring_security_check（不是 1.x 的 Acegi），且 whoAmI 对匿名用户也回
//     "authenticated":true（匿名本身是一个 Authentication），只看这个字段会把任何口令
//     都判成命中，必须连 name 一起看。
//   - JBoss/WildFly：已在真机 WildFly 25 验证 hit/deny。管理台的认证点是 /management 的
//     HTTP Digest（ManagementRealm），Basic 带着正确口令也是 401；/console 未认证直接 302，
//     根本不做认证，用它当探针永远判不出结论。
//   - WebLogic：未在真机验证（官方镜像需 Oracle 账号接受协议、约 12GB；替代路径要老版
//     wls zip + JDK8）。流程按 /console/login/LoginForm.jsp → j_security_check →
//     console.portal 写成，但只在进程内协议桩上验过。
//
// 与 http-basic 那类「一发一看」不同，表单登录是多轮：先取 crumb/cookie、再提交表单、
// 最后用一个受保护的认证探针确认会话真的被接受。三条纪律沿用整个模块：
//   - hit 必须拿到握手层「接受」信号：登录被接受（302 到成功页）还不够，还要认证探针
//     明确回「已认证」；只有两步都成立才写 hit。
//   - 每轮都是一次真实 HTTP 往返，字节全部进证据。多轮共用一个 credWire，每轮换一条
//     TCP 连接（Connection: close），w.req/w.resp 自然累积，末尾仍由 defer res.syncWire(w)
//     一次性快照——不另造一套证据通道。
//   - Try 末尾做「无凭据对照」：用空凭据把整条流程再跑一遍，也能进就说明控制台没设认证，
//     非空凭据不构成可用凭据（防误报，和 httpOutcome 的 anonOpen 同口径）。

type formResult int

const (
	formAccepted     formResult = iota // 服务端接受了凭据且认证探针确认了会话
	formDenied                         // 服务端明确拒绝（登录页 / 401 / loginError）
	formInconclusive                   // 形状认不出、探针未确认，不能下口令结论
)

type formCredAdapter struct{ protocol string }

func (a formCredAdapter) Protocol() string { return a.protocol }

// formPath 把 CredParamPath 当应用前缀（Jenkins 常挂在 /jenkins 下），拼上协议固定路径。
func formPath(ep CredEndpoint, p string) string {
	base := strings.TrimRight(strings.TrimSpace(CredParam(ep, CredParamPath, "")), "/")
	return base + p
}

// formRequest 构造带自定义头的 HTTP/1.1 请求。Connection: close 让每一轮都在自己的
// 连接里收尾，服务端发完即关，read 不必靠静默期等。
func formRequest(method, path, host string, headers []string, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	b.WriteString("User-Agent: Jingwei-CredScan\r\n")
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Connection: close\r\n")
	for _, h := range headers {
		b.WriteString(h)
		b.WriteString("\r\n")
	}
	if body != "" {
		b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	if body != "" {
		b.WriteString(body)
	}
	return []byte(b.String())
}

func formBody(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, url.QueryEscape(pairs[i])+"="+url.QueryEscape(pairs[i+1]))
	}
	return strings.Join(parts, "&")
}

func formSetCookie(hdr map[string]string) string {
	raw := hdr["set-cookie"]
	if raw == "" {
		return ""
	}
	if i := strings.Index(raw, ";"); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}

// formJSONString 从扁平 JSON 里取一个字符串字段（crumb / crumbRequestField）。
// 只为这两个无转义的短字段服务，不引完整 JSON 解析。
func formJSONString(body []byte, key string) string {
	needle := `"` + key + `"`
	s := string(body)
	i := strings.Index(s, needle)
	if i < 0 {
		return ""
	}
	rest := s[i+len(needle):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	rest = rest[j+1:]
	k := strings.Index(rest, `"`)
	if k < 0 {
		return ""
	}
	return rest[:k]
}

func newFormWire(ctx context.Context) *credWire {
	w := &credWire{idle: credReadIdle, deadline: time.Now().Add(credAttemptTimeout)}
	if dl, ok := ctx.Deadline(); ok && dl.Before(w.deadline) {
		w.deadline = dl
	}
	return w
}

// formRound 新开一条连接发一个请求、读一个响应，然后关闭连接。w 复用是为了让
// req/resp 跨轮累积——证据是整条登录流程的字节，不是最后一轮的。
func formRound(ctx context.Context, w *credWire, addr string, req []byte) (int, map[string]string, []byte, error) {
	d := net.Dialer{Timeout: credDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, nil, nil, err
	}
	w.conn = conn
	_ = conn.SetDeadline(w.deadline)
	defer conn.Close()
	if err := w.write(req); err != nil {
		return 0, nil, nil, err
	}
	return httpReadResponse(w)
}

func (a formCredAdapter) identifyPath(ep CredEndpoint) string {
	switch a.protocol {
	case "jenkins":
		return formPath(ep, "/login")
	case "jboss-console":
		// WildFly/JBoss AS 7+ 的认证点在管理接口上：/console 只是静态页面，
		// 未认证也回 302，拿不到任何凭据判定。真机 WildFly 25 实测。
		return formPath(ep, "/management")
	}
	return formPath(ep, "/console")
}

func (a formCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w := newFormWire(ctx)
	defer func() {
		if w.conn != nil {
			_ = w.conn.Close()
		}
	}()
	req := formRequest("GET", a.identifyPath(ep), ep.Host, nil, "")
	status, hdr, body, err := formRound(ctx, w, credAddr(ep), req)
	if err != nil {
		return false, "", err
	}
	if status == 0 {
		return false, credPreview(w.resp), nil
	}
	proof := httpProof(a.protocol, status, hdr, body)
	return proof != "", httpBanner(a.protocol, status, hdr, proof), nil
}

func (a formCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w := newFormWire(ctx)
	defer func() {
		res.syncWire(w)
		if w.conn != nil {
			_ = w.conn.Close()
		}
	}()
	addr := credAddr(ep)
	state, banner, err := a.login(ctx, w, addr, ep, cred)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = banner
	switch state {
	case formDenied:
		res.Outcome = CredDeny
	case formInconclusive:
		res.Outcome = CredInconclusive
		res.Reason = banner
	case formAccepted:
		// 无凭据对照：整条流程用空凭据再跑一遍。字节同样并入本次尝试的证据。
		w2 := newFormWire(ctx)
		anonState, _, _ := a.login(ctx, w2, addr, ep, Credential{})
		w.req = append(w.req, w2.req...)
		w.resp = append(w.resp, w2.resp...)
		if w2.conn != nil {
			_ = w2.conn.Close()
		}
		if anonState == formAccepted {
			res.Outcome = CredDeny
			res.Reason = "该控制台不带凭据也能登录（未启用认证），非空凭据不构成可用凭据"
		} else {
			res.Outcome = CredHit
		}
	}
	return res, nil
}

func (a formCredAdapter) login(ctx context.Context, w *credWire, addr string, ep CredEndpoint,
	cred Credential) (formResult, string, error) {
	switch a.protocol {
	case "jenkins":
		return jenkinsLogin(ctx, w, addr, ep, cred)
	case "weblogic-console":
		return weblogicLogin(ctx, w, addr, ep, cred)
	case "jboss-console":
		return jbossLogin(ctx, w, addr, ep, cred)
	default:
		return formInconclusive, "未识别的表单协议", nil
	}
}

// jenkinsLogin：crumb/cookie → j_acegi_security_check → whoAmI 认证探针。
func jenkinsLogin(ctx context.Context, w *credWire, addr string, ep CredEndpoint,
	cred Credential) (formResult, string, error) {
	// 轮 1：crumb + 会话 cookie。关掉 CSRF 时这步是 404，crumb 留空继续。
	req1 := formRequest("GET", formPath(ep, "/crumbIssuer/api/json"), ep.Host, nil, "")
	st1, h1, b1, err := formRound(ctx, w, addr, req1)
	if err != nil {
		return formInconclusive, "", err
	}
	cookie := formSetCookie(h1)
	crumb, crumbField := "", "Jenkins-Crumb"
	if st1 == 200 {
		crumb = formJSONString(b1, "crumb")
		if f := formJSONString(b1, "crumbRequestField"); f != "" {
			crumbField = f
		}
	}
	// 轮 2：提交登录表单。
	headers := []string{}
	if cookie != "" {
		headers = append(headers, "Cookie: "+cookie)
	}
	if crumb != "" {
		headers = append(headers, crumbField+": "+crumb)
	}
	body := formBody("j_username", cred.Username, "j_password", cred.Password,
		"from", formPath(ep, "/"), "Submit", "Sign in")
	// Jenkins 2.x 起登录端点改成了 /j_spring_security_check（1.x 才是 Acegi 那个）。
	// 先打新的，404 再回退旧的：端点不对的代价是「谁都被判 inconclusive」，不是误报，
	// 但同样等于没验。
	req2 := formRequest("POST", formPath(ep, "/j_spring_security_check"), ep.Host, headers, body)
	st2, h2, b2, err := formRound(ctx, w, addr, req2)
	if err != nil {
		return formInconclusive, "", err
	}
	if st2 == 404 {
		req2 = formRequest("POST", formPath(ep, "/j_acegi_security_check"), ep.Host, headers, body)
		st2, h2, b2, err = formRound(ctx, w, addr, req2)
		if err != nil {
			return formInconclusive, "", err
		}
	}
	loc2 := strings.ToLower(h2["location"])
	low2 := strings.ToLower(string(b2))
	if strings.Contains(loc2, "loginerror") || strings.Contains(loc2, "login?error") ||
		(st2 == 200 && (strings.Contains(low2, "invalid username") ||
			strings.Contains(low2, "loginerror") || strings.Contains(low2, "j_acegi_security_check"))) {
		return formDenied, fmt.Sprintf("Jenkins 登录被拒绝 (HTTP %d)", st2), nil
	}
	if st2 != 301 && st2 != 302 && st2 != 303 {
		return formInconclusive, fmt.Sprintf("Jenkins 登录应答 HTTP %d，既非重定向也未明确拒绝", st2), nil
	}
	if c2 := formSetCookie(h2); c2 != "" {
		cookie = c2
	}
	// 轮 3：认证探针。只有它明确回「已认证」才算握手层接受。
	vh := []string{}
	if cookie != "" {
		vh = append(vh, "Cookie: "+cookie)
	}
	req3 := formRequest("GET", formPath(ep, "/whoAmI/api/json?tree=authenticated,name"), ep.Host, vh, "")
	st3, _, b3, err := formRound(ctx, w, addr, req3)
	if err != nil {
		return formInconclusive, "", err
	}
	low3 := strings.ToLower(string(b3))
	// whoAmI 对匿名用户也回 "authenticated":true（匿名本身是一个 Authentication），
	// 只看这个字段会把任何口令都判成命中。必须连 name 一起看：真登录才有用户名。
	name3 := strings.ToLower(formJSONString(b3, "name"))
	switch {
	case st3 == 200 && strings.Contains(low3, `"authenticated":true`) && name3 != "" && name3 != "anonymous":
		return formAccepted, fmt.Sprintf("Jenkins 会话已认证 (HTTP %d→%d→%d, user=%s)", st1, st2, st3, name3), nil
	case st3 == 200 && (name3 == "anonymous" || strings.Contains(low3, `"authenticated":false`)):
		return formDenied, "Jenkins 登录未建立认证会话（探针仍是匿名）", nil
	case st3 == 401 || st3 == 403:
		return formDenied, fmt.Sprintf("Jenkins 认证探针 HTTP %d", st3), nil
	default:
		return formInconclusive, fmt.Sprintf("Jenkins 认证探针 HTTP %d，未确认会话", st3), nil
	}
}

// weblogicLogin：登录页 cookie → j_security_check → console.portal 主页探针。
func weblogicLogin(ctx context.Context, w *credWire, addr string, ep CredEndpoint,
	cred Credential) (formResult, string, error) {
	req1 := formRequest("GET", formPath(ep, "/console/login/LoginForm.jsp"), ep.Host, nil, "")
	st1, h1, _, err := formRound(ctx, w, addr, req1)
	if err != nil {
		return formInconclusive, "", err
	}
	cookie := formSetCookie(h1)
	headers := []string{}
	if cookie != "" {
		headers = append(headers, "Cookie: "+cookie)
	}
	body := formBody("j_username", cred.Username, "j_password", cred.Password,
		"j_character_encoding", "UTF-8")
	req2 := formRequest("POST", formPath(ep, "/console/j_security_check"), ep.Host, headers, body)
	st2, h2, b2, err := formRound(ctx, w, addr, req2)
	if err != nil {
		return formInconclusive, "", err
	}
	loc2 := strings.ToLower(h2["location"])
	low2 := strings.ToLower(string(b2))
	if strings.Contains(loc2, "loginform") || strings.Contains(loc2, "login.jsp") ||
		(st2 == 200 && (strings.Contains(low2, "authentication denied") ||
			strings.Contains(low2, "loginform") || strings.Contains(low2, "invalid"))) {
		return formDenied, fmt.Sprintf("WebLogic 控制台登录被拒绝 (HTTP %d)", st2), nil
	}
	if c2 := formSetCookie(h2); c2 != "" {
		cookie = c2
	}
	vh := []string{}
	if cookie != "" {
		vh = append(vh, "Cookie: "+cookie)
	}
	req3 := formRequest("GET", formPath(ep, "/console/console.portal"), ep.Host, vh, "")
	st3, h3, b3, err := formRound(ctx, w, addr, req3)
	if err != nil {
		return formInconclusive, "", err
	}
	loc3 := strings.ToLower(h3["location"])
	low3 := strings.ToLower(string(b3))
	if st3 >= 200 && st3 < 300 && !strings.Contains(loc3, "login") &&
		strings.Contains(low3, "weblogic") && !strings.Contains(low3, "loginform") {
		return formAccepted, fmt.Sprintf("WebLogic 控制台会话已认证 (HTTP %d→%d→%d)", st1, st2, st3), nil
	}
	if st3 == 401 || st3 == 403 || strings.Contains(loc3, "login") {
		return formDenied, fmt.Sprintf("WebLogic 控制台认证探针 HTTP %d", st3), nil
	}
	return formInconclusive, fmt.Sprintf("WebLogic 控制台认证探针 HTTP %d，既非主页也非拒绝", st3), nil
}

// ── HTTP Digest（WildFly/JBoss 管理接口用） ─────────────────────────────────
//
// WildFly 与 JBoss AS 7+ 的管理接口（9990/management）用 ManagementRealm 的
// HTTP Digest 认证，Basic 一律 401——带对了口令也拿不到 200。真机 WildFly 25
// 实测：`curl -u admin:正确口令 /management` 仍回 401 + Digest 质询。
//
// /console 更不走认证：未认证直接 302 到 index.html，用它做认证探针会永远
// 判不出结论。认证点必须是 /management。

// splitDigestParams 按逗号切分认证头参数，跳过引号内的逗号。
func splitDigestParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// parseDigestChallenge 解析 "Digest realm=..., nonce=..., qop=..." 里的键值。
func parseDigestChallenge(h string) map[string]string {
	low := strings.ToLower(h)
	i := strings.Index(low, "digest")
	if i < 0 {
		return nil
	}
	m := map[string]string{}
	for _, part := range splitDigestParams(h[i+len("digest"):]) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"`)
		if k != "" {
			m[k] = v
		}
	}
	return m
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", sum)
}

func digestCNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "jwlabcnonce"
	}
	return fmt.Sprintf("%x", b)
}

// digestAuthorization 按 RFC 7616 算 Authorization 头（MD5 / qop=auth）。
func digestAuthorization(cred Credential, ch map[string]string, method, uri string) string {
	realm, nonce := ch["realm"], ch["nonce"]
	ha1 := md5hex(cred.Username + ":" + realm + ":" + cred.Password)
	ha2 := md5hex(method + ":" + uri)

	var resp, extra string
	if q := ch["qop"]; q != "" {
		// 服务端可能给 qop="auth,auth-int"，只取 auth（auth-int 要对正文做哈希）。
		ncs := "00000001"
		cn := digestCNonce()
		resp = md5hex(ha1 + ":" + nonce + ":" + ncs + ":" + cn + ":auth:" + ha2)
		extra = fmt.Sprintf(`, qop=auth, nc=%s, cnonce="%s"`, ncs, cn)
	} else {
		resp = md5hex(ha1 + ":" + nonce + ":" + ha2)
	}
	out := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=MD5%s`,
		cred.Username, realm, nonce, uri, resp, extra)
	if op := ch["opaque"]; op != "" {
		out += fmt.Sprintf(`, opaque="%s"`, op)
	}
	return out
}

// jbossLogin：先裸请一次 /management 拿质询，再按质询类型（Digest 优先）重发。
// 空凭据这一轮仍会走完整流程——服务端的 401 就是「无凭据对照」的结果。
func jbossLogin(ctx context.Context, w *credWire, addr string, ep CredEndpoint,
	cred Credential) (formResult, string, error) {
	path := formPath(ep, "/management")

	req1 := formRequest("GET", path, ep.Host, nil, "")
	st1, h1, _, err := formRound(ctx, w, addr, req1)
	if err != nil {
		return formInconclusive, "", err
	}
	challenge := h1["www-authenticate"]
	if st1 >= 200 && st1 < 300 {
		// 管理接口不要求认证：空凭据是可用凭据，非空不算命中（与 SMB 那条同一口径）。
		if cred.Username == "" && cred.Password == "" {
			return formAccepted, fmt.Sprintf("管理接口不要求认证 (HTTP %d)，空凭据即可", st1), nil
		}
		return formDenied, fmt.Sprintf("管理接口不要求认证 (HTTP %d)，非空凭据不构成可用凭据", st1), nil
	}
	if challenge == "" {
		return formInconclusive, fmt.Sprintf("JBoss 管理接口返回 HTTP %d，但未给出认证质询", st1), nil
	}

	low := strings.ToLower(challenge)
	var auth string
	switch {
	case strings.Contains(low, "digest"):
		ch := parseDigestChallenge(challenge)
		if ch == nil || ch["nonce"] == "" {
			return formInconclusive, "Digest 质询无法解析：" + credPreview([]byte(challenge)), nil
		}
		auth = digestAuthorization(cred, ch, "GET", path)
	case strings.Contains(low, "basic"):
		token := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
		auth = "Basic " + token
	default:
		return formInconclusive, "认证方式既非 Digest 也非 Basic：" + credPreview([]byte(challenge)), nil
	}

	req2 := formRequest("GET", path, ep.Host, []string{"Authorization: " + auth}, "")
	st2, _, b2, err := formRound(ctx, w, addr, req2)
	if err != nil {
		return formInconclusive, "", err
	}
	switch {
	case st2 >= 200 && st2 < 300:
		return formAccepted, fmt.Sprintf("JBoss 管理接口接受该凭据 (HTTP %d)", st2), nil
	case st2 == 401 || st2 == 403:
		return formDenied, fmt.Sprintf("JBoss 管理接口拒绝该凭据 (HTTP %d)", st2), nil
	}
	return formInconclusive, fmt.Sprintf("JBoss 管理接口返回 HTTP %d，未确认凭据：%s",
		st2, credPreview(b2)), nil
}

func init() {
	RegisterCredAdapter(formCredAdapter{protocol: "jenkins"})
	RegisterCredAdapter(formCredAdapter{protocol: "weblogic-console"})
	RegisterCredAdapter(formCredAdapter{protocol: "jboss-console"})
}
