package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/Autumn-27/jingwei/scanner"
)

// http_send：把「向目标发一条 HTTP 请求」收口到平台的强制 UA 工具（欠账 R20 序 5，
// 负责人拍板的修法②——不用镜像 .curlrc 的省事路线，改口径统一的工具路线）。
//
// 背景：R20 的 UA 收口此前只覆盖自研组件（credscan/dirfuzz/nuclei/sqlmap/dalfox/
// repeater），模型经 Bash 自调 curl 仍发 `User-Agent: curl/...`（11-11 实机 8 处以上）。
// 本工具是模型发 HTTP 的正规通道：
//   - UA 强制取 scanner.BrowserUA()——调用方给的 User-Agent 被覆盖，不合并；
//   - 默认经记录代理出站（流量进 MITM 录制，可直接引用为漏洞证据）；
//   - 不跟随重定向（3xx 原样返回，重定向目标同样要过 guard 范围检查）；
//   - 响应封顶防刷屏。
//
// 范围与敏感外发检查由 guard 的 preToolUse 统一覆盖（checkTargets + egressCheckTool），
// 本工具不做第二套范围判定。Bash 自调 curl 的兜底收口见 curlRCContent/writeCurlRC。
const (
	httpSendTimeout = 30 * time.Second
	httpSendMaxBody = 64 << 10 // 响应正文回传上限；超出截断并标注
)

// SetHTTPProxy 给本 ToolSet 的 http_send 注入记录代理与 CA（worker.execute 每次接线）。
// addr 为空 = 直连；caCert 为空 = 系统证书池（本地 httptest 夹具用）。
func (t *ToolSet) SetHTTPProxy(addr, caCert string) {
	t.httpProxy = strings.TrimSpace(addr)
	t.httpCACert = strings.TrimSpace(caCert)
}

// forceBrowserUA 把调用方给的头部归一到平台 UA 口径：User-Agent 一律强制覆盖
// （ApplyBrowserUA 的空值语义 = 删除该头，保证「原生无头」是真空着，不会留半截）。
func forceBrowserUA(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers)+1)
	for k, v := range headers {
		if strings.EqualFold(strings.TrimSpace(k), "user-agent") {
			continue // 调用方的 UA 不参与合并，最后统一由平台设置
		}
		out[strings.TrimSpace(k)] = v
	}
	scanner.ApplyBrowserUA(func(k, v string) { out[k] = v }, func(k string) { delete(out, k) })
	return out
}

// curlRCContent 生成运行时 .curlrc 的内容（R20 序 5 对 Bash 自调 curl 的兜底收口）：
// 把 curl 的默认 UA 收口到平台口径。BrowserUA() 为空（none 模式）时返回空串、不写
// 文件——curl 退回它自己的默认，这是「原生无头」口径的自然延伸。
func curlRCContent() string {
	ua := scanner.BrowserUA()
	if ua == "" {
		return ""
	}
	return "user-agent = \"" + ua + "\"\n"
}

// writeCurlRC 把 .curlrc 落到 dir（通常为本次 run 的工作目录），返回是否写入。
// 失败返回 false 不阻断 run——curl 收口是纵深防御的一层，不是发请求的前提。
func writeCurlRC(dir string) bool {
	content := curlRCContent()
	if content == "" || dir == "" {
		return false
	}
	if err := os.WriteFile(filepath.Join(dir, ".curlrc"), []byte(content), 0o644); err != nil {
		return false
	}
	return true
}

const httpSendDescription = "向目标发送一条 HTTP 请求并返回响应（状态码、响应头、正文）。对目标的 HTTP 探测与利用请求一律用本工具发送：User-Agent 由平台强制统一（你给的 User-Agent 会被覆盖），默认经记录代理出站（请求/响应自动留痕，可直接引用为漏洞证据）。不要用 curl 造 HTTP 请求。"

var httpSendSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"url":     map[string]any{"type": "string", "description": "完整 URL，含 http/https 与端口"},
		"method":  map[string]any{"type": "string", "description": "HTTP 方法；默认 GET"},
		"headers": map[string]any{"type": "object", "description": "额外请求头（键值对）；User-Agent 强制由平台设置，传了也会被覆盖"},
		"body":    map[string]any{"type": "string", "description": "请求体；GET/HEAD 留空"},
	},
	"required": []string{"url"},
}

func (t *ToolSet) httpSend() actool.CoreTool {
	return writeTool("http_send", httpSendDescription, httpSendSchema, t.runHTTPSend)
}

func (t *ToolSet) runHTTPSend(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var a struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return actool.Errorf("invalid input: " + err.Error()), nil
	}
	rawURL := strings.TrimSpace(a.URL)
	if rawURL == "" {
		return actool.Errorf("url 必填"), nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return actool.Errorf(fmt.Sprintf("url 无效（须为 http/https 完整地址）：%q", rawURL)), nil
	}
	method := strings.ToUpper(strings.TrimSpace(a.Method))
	if method == "" {
		method = http.MethodGet
	}

	client, cerr := t.httpSendClient()
	if cerr != nil {
		return actool.Errorf("http_send 客户端构建失败: " + cerr.Error()), nil
	}
	req, rerr := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(a.Body))
	if rerr != nil {
		return actool.Errorf("http_send 构造请求失败: " + rerr.Error()), nil
	}
	for k, v := range forceBrowserUA(a.Headers) {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return actool.Text(fmt.Sprintf("http_send 失败：%v", err)), nil
	}
	defer resp.Body.Close()
	body, truncated := readHTTPSendBody(resp.Body, httpSendMaxBody)
	respHeaders := map[string]string{}
	for k, vs := range resp.Header {
		respHeaders[k] = strings.Join(vs, ", ")
	}
	out := map[string]any{
		"status":         resp.StatusCode,
		"headers":        respHeaders,
		"body":           body,
		"body_truncated": truncated,
		"elapsed_ms":     time.Since(start).Milliseconds(),
		"url":            rawURL,
	}
	b, _ := json.Marshal(out)
	return actool.Text(string(b)), nil
}

// httpSendClient 构建本工具的 HTTP 客户端：走记录代理（如有）+ 信任其 CA；不跟随
// 重定向——3xx 的 Location 由模型决定下一步，重定向后的目标同样要过范围检查。
func (t *ToolSet) httpSendClient() (*http.Client, error) {
	tlsConf := &tls.Config{} //nolint:gosec // 目标多为自签/MITM 重签，CA 由记录代理注入
	if t.httpCACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(t.httpCACert)) {
			return nil, fmt.Errorf("代理 CA 无法解析")
		}
		tlsConf.RootCAs = pool
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConf,
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	if t.httpProxy != "" {
		addr := t.httpProxy
		if !strings.Contains(addr, "://") {
			addr = "http://" + addr
		}
		pu, err := url.Parse(addr)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   httpSendTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// readHTTPSendBody 封顶读响应正文；超出上限截断并标注，避免一个 giant 响应刷爆一轮上下文。
func readHTTPSendBody(r io.Reader, limit int) (string, bool) {
	b, _ := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	truncated := false
	if len(b) > limit {
		b = b[:limit]
		truncated = true
	}
	return string(b), truncated
}
