package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// HTTP 家族的凭据适配器：Basic 认证、WebDAV、Tomcat 管理台、Elasticsearch。
//
// 它们的共同点是「发一个请求，看状态码」，差别只在方法、路径与「怎么算确认了这个协议」。
// 识别时不带凭据：一个 401 说明这里要认证，一个 200 说明资源是开的——两者都是事实，
// 但只有后者能直接判「未启用认证」。
//
// 一条重要的防误报：对同一路径不带凭据再发一次，如果也返回 2xx/3xx，说明资源根本没设认证，
// 那么「带凭据 200」不能算这组凭据可用——那会把任意一串字符都报成弱口令。
type httpCredAdapter struct {
	protocol string
	method   string
	path     string
	extra    string // 额外请求行（如 PROPFIND 的 Depth）
}

func (a httpCredAdapter) Protocol() string { return a.protocol }

func (a httpCredAdapter) reqPath(ep CredEndpoint) string {
	p := strings.TrimSpace(ep.Params[CredParamPath])
	if p == "" {
		return a.path
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func (a httpCredAdapter) request(path, auth string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", a.method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", "@host@")
	b.WriteString(uaHeaderLine())
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Connection: close\r\n")
	if auth != "" {
		fmt.Fprintf(&b, "Authorization: %s\r\n", auth)
	}
	if a.extra != "" {
		b.WriteString(a.extra)
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

func (a httpCredAdapter) Identify(ctx context.Context, ep CredEndpoint) (bool, string, error) {
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return false, "", err
	}
	defer w.close()
	status, hdr, body, err := a.exchange(w, ep.Host, a.reqPath(ep), "")
	if err != nil {
		return false, "", err
	}
	if status == 0 {
		return false, credPreview(w.resp), nil
	}
	proof := httpProof(a.protocol, status, hdr, body)
	return proof != "", httpBanner(a.protocol, status, hdr, proof), nil
}

// httpProof 只有拿到「这个协议特有」的证据才确认，HTTP 本身不算：
// 任何 Web 服务都会回 HTTP/1.1，凭这一点认下 WebDAV 就等于按端口猜协议。
func httpProof(protocol string, status int, hdr map[string]string, body []byte) string {
	switch protocol {
	case "tomcat-console":
		server := strings.ToLower(hdr["server"])
		realm := hdr["www-authenticate"]
		if strings.Contains(server, "tomcat") {
			return "Server: " + hdr["server"]
		}
		if strings.Contains(strings.ToLower(realm), "tomcat") {
			return "WWW-Authenticate: " + realm
		}
		if strings.Contains(strings.ToLower(string(body)), "tomcat") {
			return "页面含 Tomcat 标记"
		}
		return ""
	case "elasticsearch":
		if strings.Contains(strings.ToLower(hdr["x-elastic-product"]), "elasticsearch") {
			return "X-Elastic-Product: " + hdr["x-elastic-product"]
		}
		if status == 200 && (strings.Contains(string(body), `"cluster_name"`) || strings.Contains(string(body), `"version"`)) {
			return "根路径返回 Elasticsearch 集群信息"
		}
		// 开了 X-Pack 的 ES 对未认证请求只回 401 + security_exception，不带产品头。
		if status == 401 && (strings.Contains(string(body), "security_exception") ||
			strings.Contains(string(body), "missing authentication credentials")) {
			return "401 响应体是 Elasticsearch security_exception"
		}
		return ""
	case "webdav":
		if hdr["dav"] != "" {
			return "DAV: " + hdr["dav"]
		}
		if status == 207 {
			return "PROPFIND 返回 207 Multi-Status"
		}
		// 需要认证的 DAV 目录不会在 401 里暴露 DAV 头，但「服务器接受 PROPFIND 这条
		// 非通用方法并给出 HTTP 响应」本身就是证据；真正的 DAV 语义由带凭据的
		// PROPFIND 结果（207 / 405）在 Try 里落实，认错也只落到「不可判定」。
		if status == 401 || status == 403 || status == 405 {
			return fmt.Sprintf("PROPFIND 有 HTTP 响应（%d），待认证确认", status)
		}
		return ""
	case "jenkins":
		// 只认 Jenkins 特有的东西：X-Jenkins / X-Jenkins-Session 响应头，或登录页里的
		// j_acegi_security_check / j_spring_security_check 表单动作。任意 200 页面不算数。
		if v := hdr["x-jenkins"]; v != "" {
			return "X-Jenkins: " + v
		}
		if v := hdr["x-jenkins-session"]; v != "" {
			return "X-Jenkins-Session: " + v
		}
		low := strings.ToLower(string(body))
		if (status == 200 || status == 401 || status == 403) &&
			(strings.Contains(low, "jenkins") || strings.Contains(low, "j_acegi_security_check") ||
				strings.Contains(low, "j_spring_security_check")) {
			return "页面含 Jenkins 特有标记"
		}
		return ""
	case "jboss-console":
		// ManagementRealm / JBoss / WildFly 的 realm 名是它特有的，一般 Web 服务器不会用。
		if v := hdr["www-authenticate"]; v != "" &&
			(strings.Contains(strings.ToLower(v), "managementrealm") ||
				strings.Contains(strings.ToLower(v), "jboss") || strings.Contains(strings.ToLower(v), "wildfly")) {
			return "WWW-Authenticate: " + v
		}
		if v := hdr["server"]; v != "" &&
			(strings.Contains(strings.ToLower(v), "jboss") || strings.Contains(strings.ToLower(v), "wildfly") ||
				strings.Contains(strings.ToLower(v), "undertow")) {
			return "Server: " + v
		}
		low := strings.ToLower(string(body))
		if strings.Contains(low, "jboss") || strings.Contains(low, "wildfly") {
			return "页面含 JBoss/WildFly 标记"
		}
		return ""
	default:
		// http-basic 就是「这个端口说 HTTP」；没有比这更强的证据，也不需要。
		if status == 401 || status == 403 || status == 200 || status == 301 || status == 302 {
			return fmt.Sprintf("HTTP %d", status)
		}
		return ""
	}
}

func httpBanner(protocol string, status int, hdr map[string]string, proof string) string {
	name := strings.ToUpper(strings.ReplaceAll(protocol, "-", " "))
	parts := []string{name, fmt.Sprintf("HTTP %d", status)}
	if srv := hdr["server"]; srv != "" {
		parts = append(parts, srv)
	}
	if hdr["www-authenticate"] != "" {
		parts = append(parts, strings.TrimSpace(hdr["www-authenticate"]))
	}
	if proof != "" {
		parts = append(parts, proof)
	}
	return strings.Join(parts, " · ")
}

// exchange 发一次请求并解析状态行、头部与正文。auth 为空表示不带 Authorization。
func (a httpCredAdapter) exchange(w *credWire, host, path, auth string) (int, map[string]string, []byte, error) {
	req := strings.ReplaceAll(string(a.request(path, auth)), "@host@", host)
	if err := w.write([]byte(req)); err != nil {
		return 0, nil, nil, err
	}
	return httpReadResponse(w)
}

// httpReadResponse 先按行读头部（每行都进证据），再按 Content-Length 读正文；
// 没有长度也没 chunked 时就按静默期收尾。不能盲读：静默期一过就返回，
// 慢响应会被截成「没有状态行」的假失败。
func httpReadResponse(w *credWire) (int, map[string]string, []byte, error) {
	hdr := map[string]string{}
	status := 0
	for i := 0; i < 100; i++ {
		line, err := w.readLine(8 << 10)
		if err != nil {
			if len(line) == 0 {
				return 0, nil, nil, err
			}
		}
		text := strings.TrimRight(string(line), "\r\n")
		if text == "" {
			break
		}
		if strings.HasPrefix(text, "HTTP/") {
			fields := strings.Fields(text)
			if len(fields) >= 2 {
				status, _ = strconv.Atoi(fields[1])
			}
			continue
		}
		if k, v, ok := strings.Cut(text, ":"); ok {
			hdr[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if status == 0 {
		return 0, nil, nil, fmt.Errorf("响应里没有 HTTP 状态行")
	}
	var body []byte
	if n, err := strconv.Atoi(hdr["content-length"]); err == nil && n > 0 {
		if n > credReadMax {
			n = credReadMax
		}
		body, _ = w.readN(n) // 正文读不全不算失败：状态码已经在手里
	} else if !strings.Contains(strings.ToLower(hdr["transfer-encoding"]), "chunked") {
		body, _ = w.read()
	}
	return status, hdr, body, nil
}

// httpOutcome 把状态码翻译成结论。403 刻意不判命中：那是「可能有效但无权」，
// 报告里多一条假命中比少一条更糟。
func httpOutcome(res CredAttempt, status int, anonOpen bool) CredAttempt {
	if strings.TrimSpace(res.Banner) == "" {
		res.Banner = fmt.Sprintf("HTTP %d", status)
	}
	switch {
	case status == 401 || status == 407:
		res.Outcome = CredDeny
	case status == 403:
		res.Outcome = CredInconclusive
		res.Reason = "服务端返回 403：可能是凭据有效但无权访问，不计入命中"
	case status >= 200 && status < 400:
		if anonOpen {
			res.Outcome = CredDeny
			res.Reason = "该路径不带凭据也返回成功（未启用认证），非空凭据不构成可用凭据"
			return res
		}
		res.Outcome = CredHit
	default:
		res.Outcome = CredInconclusive
		res.Reason = fmt.Sprintf("服务端返回 HTTP %d，无法据此判定凭据", status)
	}
	return res
}

func (a httpCredAdapter) Try(ctx context.Context, ep CredEndpoint, cred Credential) (res CredAttempt, err error) {
	res = credNewAttempt(cred)
	w, err := credDial(ctx, credAddr(ep))
	if err != nil {
		return res.withErr(err)
	}
	defer w.close()
	defer func() { res.syncWire(w) }()

	auth := ""
	if cred.Username != "" || cred.Password != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password))
	}
	status, hdr, body, err := a.exchange(w, ep.Host, a.reqPath(ep), auth)
	if err != nil {
		return res.withErr(err)
	}
	res.Banner = httpBanner(a.protocol, status, hdr, httpProof(a.protocol, status, hdr, body))

	// 无凭据的对照：只有带凭据成功、不带凭据不成功，才能说「这组凭据可用」。
	anonOpen := false
	if auth != "" && status >= 200 && status < 400 {
		if w2, derr := credDial(ctx, credAddr(ep)); derr == nil {
			if st2, _, _, e2 := a.exchange(w2, ep.Host, a.reqPath(ep), ""); e2 == nil && st2 >= 200 && st2 < 400 {
				anonOpen = true
			}
			w2.close()
		}
	}
	return httpOutcome(res, status, anonOpen), nil
}

func init() {
	RegisterCredAdapter(httpCredAdapter{protocol: "http-basic", method: http.MethodGet, path: "/"})
	RegisterCredAdapter(httpCredAdapter{protocol: "webdav", method: "PROPFIND", path: "/", extra: "Depth: 0\r\n"})
	RegisterCredAdapter(httpCredAdapter{protocol: "tomcat-console", method: http.MethodGet, path: "/manager/html"})
	RegisterCredAdapter(httpCredAdapter{protocol: "elasticsearch", method: http.MethodGet, path: "/"})
}
