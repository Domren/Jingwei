package evidence

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/report"
)

// 取证面板（forensic panel）。
//
// 报告里的截图以前只能人工上传，于是交付出去常常是"没有图"。这里把已经抓到
// 的真实请求/响应直接渲染成一张 PNG：左边是逐字报文，命中漏洞的那一段被高亮，
// 右上角是采集时刻的时钟（公历年月日 + 时分秒），底部写明采集时间与来源。
//
// 渲染不引入新依赖：容器里已经有 Playwright 下载的 Chromium，用它的
// headless shell 直接 `--screenshot` 就能出图。

// ShotSpec is everything the panel shows.
type ShotSpec struct {
	Title      string    // 漏洞标题
	Subtitle   string    // 副标题（目标 / 步骤说明）
	Target     string    // 受影响地址
	Request    string    // 原始请求报文
	Response   string    // 原始响应报文
	HLStart    int       // 响应里命中片段的起点（绝对偏移）
	HLEnd      int       // 响应里命中片段的终点
	HasHL      bool      // 是否有命中片段
	Conclusion string    // 这一步证明了什么
	CapturedAt time.Time // 采集时刻
	Footer     string    // 底部说明
}

// shotClockSize is the panel canvas. Wide enough for a full HTTP head plus a
// few hundred bytes of body, tall enough for the decisive response fragment.
const (
	shotWidth  = 1600
	shotHeight = 1000
)

// HTML renders the panel. The clock sits in the top-right corner like a camera
// overlay: big monospace time, with the date under it.
func (s ShotSpec) HTML() string {
	now := s.CapturedAt
	if now.IsZero() {
		now = time.Now()
	}
	loc := now.In(time.FixedZone("CST", 8*3600))
	weekday := []string{"星期日", "星期一", "星期二", "星期三", "星期四", "星期五", "星期六"}[int(loc.Weekday())]

	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><style>`)
	b.WriteString(`
*{box-sizing:border-box}
html,body{margin:0;padding:0;height:100%;background:#070d18;color:#e6edf7;
 font-family:"WenQuanYi Zen Hei","Noto Sans CJK SC","Microsoft YaHei",system-ui,sans-serif}
.wrap{position:relative;display:flex;flex-direction:column;width:100%;height:100%;padding:30px 34px 24px;
 background:radial-gradient(1200px 600px at 78% -10%,#1b2b46 0%,#070d18 62%)}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:40px;flex:0 0 auto}
.head{flex:1 1 auto;min-width:0;padding-top:6px}
.clock{flex:0 0 auto;min-width:340px;padding:18px 30px 16px;border-radius:18px;
 background:rgba(148,178,224,.16);border:1px solid rgba(190,214,255,.18);text-align:center}
.clock .t{font-family:"DejaVu Sans Mono",Consolas,monospace;font-size:70px;font-weight:700;line-height:1.05;
 letter-spacing:3px;color:#fff;text-shadow:0 2px 18px rgba(0,0,0,.45)}
.clock .d{margin-top:6px;font-size:21px;color:#dbe6f7;letter-spacing:1px}
.clock .w{margin-top:2px;font-size:17px;color:#9fb4d4}
.h1{font-size:30px;font-weight:700;letter-spacing:.5px}
.sub{margin-top:6px;font-size:16px;color:#9fb4d4;word-break:break-all}
.target{margin-top:8px;display:inline-block;padding:3px 10px;border-radius:6px;background:rgba(56,138,221,.18);
 border:1px solid rgba(86,160,240,.3);font-size:14px;color:#bcd8f7;font-family:"DejaVu Sans Mono",Consolas,monospace}
.cols{display:flex;gap:18px;margin-top:16px;flex:1 1 auto;min-height:0}
.block{border:1px solid rgba(148,178,224,.16);border-radius:12px;overflow:hidden;background:rgba(6,12,24,.55);
 flex:1 1 50%;display:flex;flex-direction:column;min-height:0}
.lab{display:flex;align-items:center;gap:10px;padding:8px 14px;background:rgba(148,178,224,.10);
 font-size:14px;color:#b9cbe6;letter-spacing:1px;flex:0 0 auto}
.lab .n{font-family:"DejaVu Sans Mono",Consolas,monospace;color:#6ea8f0}
pre{margin:0;padding:14px 16px;font-family:"DejaVu Sans Mono",Consolas,monospace;font-size:13.5px;line-height:1.6;
 white-space:pre-wrap;word-break:break-all;color:#d7e3f4;flex:1 1 auto;overflow:hidden}
mark{background:#fde68a;color:#111827;border-radius:3px;padding:0 2px;box-shadow:0 0 0 1px rgba(250,204,21,.55)}
.concl{margin-top:14px;padding:12px 16px;border-left:3px solid #f59e0b;background:rgba(245,158,11,.10);
 border-radius:0 10px 10px 0;font-size:16px;color:#f6dfb0;flex:0 0 auto}
.concl b{color:#fbbf24}
.foot{margin-top:auto;display:flex;justify-content:space-between;flex:0 0 auto;padding-top:10px;
 font-size:13px;color:#7e93b3;border-top:1px solid rgba(148,178,224,.14)}
`)
	b.WriteString(`</style></head><body><div class="wrap">`)

	b.WriteString(`<div class="top"><div class="head">`)
	fmt.Fprintf(&b, `<div class="h1">%s</div>`, html.EscapeString(s.Title))
	if s.Subtitle != "" {
		fmt.Fprintf(&b, `<div class="sub">%s</div>`, html.EscapeString(s.Subtitle))
	}
	if s.Target != "" {
		fmt.Fprintf(&b, `<div class="target">%s</div>`, html.EscapeString(s.Target))
	}
	b.WriteString(`</div>`)
	fmt.Fprintf(&b, `<div class="clock"><div class="t">%s</div><div class="d">%s</div><div class="w">%s</div></div></div>`,
		loc.Format("15:04:05"), loc.Format("2006年01月02日"), weekday)

	// 左边请求、右边响应——对着看最省事，也和代理工具的取证习惯一致。
	b.WriteString(`<div class="cols">`)
	fmt.Fprintf(&b, `<div class="block"><div class="lab"><span class="n">01</span>请求 REQUEST</div><pre>%s</pre></div>`,
		html.EscapeString(s.Request))
	fmt.Fprintf(&b, `<div class="block"><div class="lab"><span class="n">02</span>响应 RESPONSE</div><pre>%s</pre></div>`,
		s.highlightedResponse())
	b.WriteString(`</div>`)

	if s.Conclusion != "" {
		fmt.Fprintf(&b, `<div class="concl"><b>结论：</b>%s</div>`, html.EscapeString(s.Conclusion))
	}

	footer := s.Footer
	if footer == "" {
		footer = "Jingwei 自动取证 · 报文取自本次会话抓包，内容未作修改"
	}
	// 时钟是「报文采集时刻」，不是「出图时刻」——取证图上的时间必须是证据发生
	// 的时间；出图时刻单列出来，两者都写明白，事后不会有人拿它当证据时间。
	rendered := time.Now().In(loc.Location())
	fmt.Fprintf(&b, `<div class="foot"><span>采集时间 %s　·　生成于 %s（北京时间）</span><span>%s</span></div>`,
		loc.Format("2006-01-02 15:04:05"), rendered.Format("2006-01-02 15:04:05"), html.EscapeString(footer))

	b.WriteString(`</div></body></html>`)
	return b.String()
}

// highlightedResponse renders the response with the decisive fragment marked.
func (s ShotSpec) highlightedResponse() string {
	if !s.HasHL || s.HLStart < 0 || s.HLEnd > len(s.Response) || s.HLStart >= s.HLEnd {
		return html.EscapeString(s.Response)
	}
	head := s.Response[:s.HLStart]
	mark := s.Response[s.HLStart:s.HLEnd]
	tail := s.Response[s.HLEnd:]
	return html.EscapeString(head) + "<mark>" + html.EscapeString(mark) + "</mark>" + html.EscapeString(tail)
}

// findShotBrowser locates a Chromium/headless-shell binary for the screenshot.
func findShotBrowser() string {
	if p := strings.TrimSpace(os.Getenv("JINGWEI_SHOT_BROWSER")); p != "" {
		return p
	}
	patterns := []string{
		"/root/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell",
		"/root/.cache/ms-playwright/chromium-*/chrome-linux64/chrome",
		"/ms-playwright/chromium-*/chrome-linux64/chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/usr/bin/google-chrome",
	}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, m := range matches {
			if info, err := os.Stat(m); err == nil && !info.IsDir() {
				return m
			}
		}
	}
	return ""
}

// RenderShotPNG renders a panel HTML into a PNG using the headless browser.
func RenderShotPNG(ctx context.Context, panelHTML string, width, height int) ([]byte, error) {
	bin := findShotBrowser()
	if bin == "" {
		return nil, errors.New("未找到可用的 Chromium/headless shell，无法生成取证截图")
	}
	dir, err := os.MkdirTemp("", "jingwei-shot-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	htmlPath := filepath.Join(dir, "panel.html")
	pngPath := filepath.Join(dir, "panel.png")
	if err := os.WriteFile(htmlPath, []byte(panelHTML), 0o644); err != nil {
		return nil, err
	}
	if width <= 0 {
		width = shotWidth
	}
	if height <= 0 {
		height = shotHeight
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin,
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--hide-scrollbars",
		"--force-device-scale-factor=1",
		"--virtual-time-budget=3000",
		"--run-all-compositor-stages-before-draw",
		fmt.Sprintf("--window-size=%d,%d", width, height),
		"--screenshot="+pngPath,
		"file://"+htmlPath,
	)
	cmd.Env = append(os.Environ(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("截图渲染失败: %v: %s", err, strings.TrimSpace(string(out)))
	}
	png, err := os.ReadFile(pngPath)
	if err != nil {
		return nil, err
	}
	if len(png) == 0 {
		return nil, errors.New("截图渲染结果为空")
	}
	return png, nil
}

// CaptureFindingShot renders the forensic panel of a finding from its bound
// traffic and stores it as an evidence screenshot.
func (s *Store) CaptureFindingShot(ctx context.Context, findingID int64) (int64, error) {
	f, err := s.DB.GetFinding(findingID)
	if err != nil {
		return 0, err
	}
	if f == nil {
		return 0, errors.New("漏洞不存在")
	}
	traffic, err := s.DB.GetFindingTraffic(ctx, findingID)
	if err != nil {
		return 0, err
	}
	if traffic == nil || len(traffic.Bindings) == 0 {
		return 0, errors.New("该漏洞没有绑定流量报文，无法自动取证")
	}
	binding := pickShotBinding(f, traffic.Bindings)
	// 面板显示的文本与匹配用的文本必须是同一份，否则高亮会落在错字节上。
	req := report.NormalizeEvidenceText(s.rawPacket(binding.Snapshot, "request"))
	resp := report.NormalizeEvidenceText(s.rawPacket(binding.Snapshot, "response"))
	if strings.TrimSpace(req) == "" && strings.TrimSpace(resp) == "" {
		return 0, errors.New("该漏洞绑定的报文没有可展示的内容")
	}

	spec := ShotSpec{
		Title:      shotTitle(f),
		Target:     binding.Snapshot.URL,
		Request:    req,
		Response:   resp,
		CapturedAt: shotCapturedAt(binding.Snapshot),
	}
	if f.Reproduction != nil {
		spec.Subtitle = f.Reproduction.EntryPoint
		if len(f.Reproduction.Prerequisites) > 0 {
			spec.Subtitle = strings.TrimSpace(spec.Subtitle + " · 前置：" + strings.Join(f.Reproduction.Prerequisites, "；"))
		}
	}
	// 高亮命中片段 + 按命中裁剪，保证证据一定落在可视区内。
	respText, hlStart, hlEnd, marked := resp, 0, 0, false
	if start, end, ok := shotHighlight(f, req, resp); ok {
		// 证据正则会连同上下文一起匹配，面板只要点睛的一小段，别糊一大片。
		if end-start > 220 {
			end = start + 220
		}
		respText, hlStart, hlEnd, marked = clipPanelText(resp, start, end, true, panelIdleKeep)
	} else {
		respText, _, _, _ = clipPanelText(resp, 0, 0, false, panelIdleKeep)
	}
	reqText, _, _, _ := clipPanelText(req, 0, 0, false, panelReqKeep)
	spec.Request = reqText
	spec.Response = respText
	spec.HLStart, spec.HLEnd, spec.HasHL = hlStart, hlEnd, marked
	if spec.Conclusion == "" && f.Reproduction != nil && len(f.Reproduction.Steps) > 0 {
		spec.Conclusion = strings.TrimSpace(f.Reproduction.Steps[0].Proves + " " + f.Reproduction.Steps[0].Expected)
	}

	png, err := RenderShotPNG(ctx, spec.HTML(), shotWidth, shotHeight)
	if err != nil {
		return 0, err
	}
	caption := fmt.Sprintf("自动取证 %s %s · %s", binding.Snapshot.Method, binding.Snapshot.URL,
		spec.CapturedAt.In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05"))
	return s.DB.AddFindingScreenshot(findingID, caption, base64.StdEncoding.EncodeToString(png))
}

// RenderPagePNG opens a URL in the headless browser and screenshots the
// rendered page. 报文取证图证明「服务端返回了什么字节」，页面图证明「用户看到了
// 什么」——两者是不同的证据，报告里都要有。证书错误一律忽略：靶场基本都是自签
// 证书，否则一半目标截不出来。
func RenderPagePNG(ctx context.Context, rawURL string, width, height int) ([]byte, error) {
	target := strings.TrimSpace(rawURL)
	if target == "" {
		return nil, errors.New("目标地址为空，无法页面取证")
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	bin := findShotBrowser()
	if bin == "" {
		return nil, errors.New("未找到可用的 Chromium/headless shell，无法页面取证")
	}
	dir, err := os.MkdirTemp("", "jingwei-page-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	pngPath := filepath.Join(dir, "page.png")
	if width <= 0 {
		width = shotWidth
	}
	if height <= 0 {
		height = 1400
	}
	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin,
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--hide-scrollbars",
		"--ignore-certificate-errors",
		"--force-device-scale-factor=1",
		// 让 JS 与异步请求有时间跑完，否则截到的是白屏骨架。
		"--virtual-time-budget=6000",
		fmt.Sprintf("--window-size=%d,%d", width, height),
		"--screenshot="+pngPath,
		target,
	)
	cmd.Env = append(os.Environ(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("页面渲染失败: %v: %s", err, strings.TrimSpace(string(out)))
	}
	png, err := os.ReadFile(pngPath)
	if err != nil {
		return nil, err
	}
	if len(png) == 0 {
		return nil, errors.New("页面渲染结果为空（目标可能不可达）")
	}
	return png, nil
}

// CapturePageShot screenshots the rendered page of a finding's target and stores
// it next to the packet evidence.
func (s *Store) CapturePageShot(ctx context.Context, findingID int64) (int64, error) {
	f, err := s.DB.GetFinding(findingID)
	if err != nil {
		return 0, err
	}
	if f == nil {
		return 0, errors.New("漏洞不存在")
	}
	traffic, err := s.DB.GetFindingTraffic(ctx, findingID)
	if err != nil {
		return 0, err
	}
	if traffic == nil || len(traffic.Bindings) == 0 {
		return 0, errors.New("该漏洞没有绑定流量报文，拿不到目标地址")
	}
	binding := pickShotBinding(f, traffic.Bindings)
	target := strings.TrimSpace(binding.Snapshot.URL)
	png, err := RenderPagePNG(ctx, target, shotWidth, 1400)
	if err != nil {
		return 0, err
	}
	caption := fmt.Sprintf("页面取证 %s · %s", target,
		time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05"))
	return s.DB.AddFindingScreenshot(findingID, caption, base64.StdEncoding.EncodeToString(png))
}

// CaptureShot renders and stores the forensic panel of a finding. It is the
// host-facing entry point (the agent recorder uses it right after a finding is
// confirmed), so reports carry an image without anyone uploading one.
func (s *Store) CaptureShot(ctx context.Context, findingID int64) (int64, error) {
	return s.CaptureFindingShot(ctx, findingID)
}

// unescapeLines turns literal "\r\n" / "\n" escape sequences into real line
// breaks. Some capture paths (agent-supplied raw packets, JSON round-trips)
// store the two characters backslash-r instead of a real CRLF, and a panel that
// prints "\r\n" as text looks broken.
//
// It only fires for text that has NO real line break at all: that rules out
// content that legitimately contains escaped newlines (a JSON body), so the
// bytes shown stay the bytes captured.
func unescapeLines(s string) string {
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return s
	}
	if !strings.Contains(s, `\r\n`) && !strings.Contains(s, `\n`) {
		return s
	}
	s = strings.ReplaceAll(s, `\r\n`, "\r\n")
	return strings.ReplaceAll(s, `\n`, "\n")
}

// shotCapturedAt is the moment the packet was actually captured — the time the
// evidence panel must show. Only when the snapshot carries no timestamp (older
// data) does it fall back to now.
func shotCapturedAt(s db.TrafficEvidenceSnapshot) time.Time {
	if s.CapturedAt > 0 {
		return time.Unix(s.CapturedAt, 0)
	}
	return time.Now()
}

// shotTitle renders the panel headline.
func shotTitle(f *db.DBFinding) string {
	name := strings.TrimSpace(f.Name)
	if name == "" {
		name = strings.TrimSpace(f.VulnClass)
	}
	if name == "" {
		name = "漏洞取证"
	}
	sev := strings.TrimSpace(f.Severity)
	if sev != "" {
		return fmt.Sprintf("%s · %s", name, strings.ToUpper(sev))
	}
	return name
}

// pickShotBinding prefers the packet the first reproduction step points at,
// then a "proof" binding, and finally the first one.
func pickShotBinding(f *db.DBFinding, bindings []db.FindingTrafficBinding) db.FindingTrafficBinding {
	if f.Reproduction != nil {
		for _, st := range f.Reproduction.Steps {
			if st.SnapshotID == "" {
				continue
			}
			for _, b := range bindings {
				if b.SnapshotID == st.SnapshotID {
					return b
				}
			}
		}
	}
	for _, b := range bindings {
		if strings.EqualFold(b.Role, "proof") {
			return b
		}
	}
	return bindings[0]
}

// Panel clipping: a real response is often a 30 KB HTML page, and the decisive
// fragment usually sits far below the fold. Both sides are therefore clipped —
// the head stays complete (status line + headers), the body keeps a window
// around the evidence — so the highlighted bytes are always on screen.
const (
	panelCtxBefore = 300  // 命中片段之前保留多少字节（少留一点，让高亮靠上）
	panelCtxAfter  = 1500 // 命中片段之后保留多少字节
	panelIdleKeep  = 2600 // 没有命中时，正文最多展示多少字节
	panelReqKeep   = 3600 // 请求最多展示多少字节
)

// clipPanelText trims one message for the panel and returns the highlight range
// inside the text that is actually printed. hasHL=false means "nothing marked".
func clipPanelText(raw string, hlStart, hlEnd int, hasHL bool, idleKeep int) (text string, start, end int, marked bool) {
	valid := hasHL && hlStart >= 0 && hlEnd <= len(raw) && hlStart < hlEnd
	if !valid {
		if idleKeep <= 0 || len(raw) <= idleKeep {
			return raw, 0, 0, false
		}
		return raw[:idleKeep] + fmt.Sprintf("\n…（后略 %d 字节，完整报文见证据包）", len(raw)-idleKeep), 0, 0, false
	}
	_, _, bodyOffset := splitPacketAt(raw)
	if bodyOffset > len(raw) {
		bodyOffset = 0
	}
	head := raw[:bodyOffset]
	from := hlStart - panelCtxBefore
	if from < bodyOffset {
		from = bodyOffset
	}
	to := hlEnd + panelCtxAfter
	if to > len(raw) {
		to = len(raw)
	}
	var b strings.Builder
	b.WriteString(head)
	if from > bodyOffset {
		fmt.Fprintf(&b, "…（前略 %d 字节）…\n", from-bodyOffset)
	}
	segStart := b.Len()
	b.WriteString(raw[from:to])
	start = segStart + (hlStart - from)
	end = segStart + (hlEnd - from)
	if to < len(raw) {
		fmt.Fprintf(&b, "\n…（后略 %d 字节，完整报文见证据包）", len(raw)-to)
	}
	return b.String(), start, end, true
}

// shotHighlight locates the decisive fragment inside the response.
func shotHighlight(f *db.DBFinding, req, resp string) (int, int, bool) {
	reqHead, reqBody, _ := splitPacketAt(req)
	_, respBody, bodyOffset := splitPacketAt(resp)
	target := ""
	if fields := strings.Fields(reqHead); len(fields) > 1 {
		target = fields[1]
	}
	start, end, ok := report.EvidenceMatchRange(f.VulnClass, f.Name, target, reqBody, respBody)
	if !ok {
		return 0, 0, false
	}
	return bodyOffset + start, bodyOffset + end, true
}

// splitPacketAt splits a raw HTTP message into head and body and reports where
// the body starts inside the original text. The offset is what turns a match
// found in the body into a position in the text the panel actually prints.
func splitPacketAt(raw string) (head, body string, bodyOffset int) {
	for _, sep := range []string{"\r\n\r\n", "\n\n"} {
		if i := strings.Index(raw, sep); i >= 0 {
			return raw[:i], raw[i+len(sep):], i + len(sep)
		}
	}
	return raw, "", len(raw)
}

// rawPacket assembles a snapshot's head + body back into the original bytes.
// The head is unescaped first: some capture paths store the head with literal
// "\r\n" text, which would otherwise hide the head/body boundary from the
// highlight matcher and leave the panel printing "\r\n" as text.
func (s *Store) rawPacket(snapshot db.TrafficEvidenceSnapshot, side string) string {
	head := snapshot.ReqHead
	if side == "response" {
		head = snapshot.RespHead
	}
	head = unescapeLines(head)
	f, length, err := s.OpenBody(snapshot, side)
	if err != nil {
		return head
	}
	defer f.Close()
	buf := make([]byte, length)
	n, _ := f.Read(buf)
	return head + string(buf[:n])
}
