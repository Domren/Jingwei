package report

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// FindingsHTMLOptions controls the print-ready HTML report.
type FindingsHTMLOptions struct {
	GeneratedAt time.Time
	ScopeLabel  string // 例如「当前筛选结果」「全部发现」
	Title       string
}

type htmlTaskGroup struct {
	ID          int64
	Title       string
	Description string
	Findings    []*db.DBFinding
}

// FindingsHTML renders a paginated, print-ready report: a cover page, a table of
// contents, one chapter per task and one page per finding. Raw HTTP packets are
// embedded verbatim (never regenerated); missing packets are called out
// explicitly instead of being replaced with a fabricated request.
func FindingsHTML(fs []*db.DBFinding, opts FindingsHTMLOptions) []byte {
	at := opts.GeneratedAt
	if at.IsZero() {
		at = time.Now()
	}
	items := append([]*db.DBFinding(nil), fs...)
	sortFindingsForExport(items)
	tasks := groupFindingsByTask(items)

	counts := map[string]int{}
	assets := map[int64]bool{}
	for _, f := range items {
		counts[strings.ToLower(strings.TrimSpace(f.Severity))]++
		for _, id := range f.AssetIDs {
			if id > 0 {
				assets[id] = true
			}
		}
	}
	total := len(items)
	title := nz(strings.TrimSpace(opts.Title), "渗透测试与漏洞扫描报告")
	scope := nz(strings.TrimSpace(opts.ScopeLabel), "发现汇总")
	reportNo := "JW-" + at.Format("20060102-150405")

	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	fmt.Fprintf(&b, "<title>%s</title>\n", h(title))
	b.WriteString(`<style>
:root{--ink:#172033;--muted:#667085;--line:#e3e8ef;--brand:#0f4c81;--brand-soft:#e8f1f8;
--crit:#b42318;--high:#d92d20;--med:#b54708;--low:#175cd3;--ok:#067647}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:#eef2f6}
body{font-family:"Noto Sans SC","Microsoft YaHei","PingFang SC","Segoe UI",Arial,sans-serif;
color:var(--ink);font-size:10.5pt;line-height:1.7}
.page{max-width:210mm;margin:0 auto;background:#fff;padding:16mm 14mm 18mm}
h1,h2,h3,h4{line-height:1.35;margin:0}
a{color:var(--brand);text-decoration:none}
table{width:100%;border-collapse:collapse;font-size:9.5pt}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f7f9fc;color:#344054;font-weight:600}
pre{font-family:"JetBrains Mono","Cascadia Code",Consolas,"Courier New",monospace;font-size:8.2pt;line-height:1.5;
background:#0b1220;color:#e6edf7;border-radius:6px;padding:10px 12px;white-space:pre-wrap;word-break:break-all;margin:8px 0 14px}
pre.evidence{background:#f7f9fc;color:#1d2939;border:1px solid var(--line)}
pre.md{background:#fbfcfe;color:#1d2939;border:1px solid var(--line)}
.muted{color:var(--muted)}
.small{font-size:9pt}
.toolbar{position:sticky;top:0;z-index:5;display:flex;gap:10px;align-items:center;justify-content:space-between;
background:#0f4c81;color:#fff;padding:8px 14px;font-size:9.5pt}
.toolbar button{background:#fff;color:#0f4c81;border:0;border-radius:5px;padding:5px 12px;font-weight:600;cursor:pointer}
.cover{page-break-after:always;min-height:247mm;display:flex;flex-direction:column;justify-content:space-between;
padding:10mm 6mm;border-top:8px solid var(--brand)}
.cover-top{display:flex;justify-content:space-between;align-items:center;font-size:9.5pt;color:var(--muted)}
.brand{font-size:15pt;font-weight:700;color:var(--brand);letter-spacing:.08em}
.brand span{font-weight:400;font-size:10pt;color:var(--muted);letter-spacing:.18em}
.conf{border:1px solid var(--line);border-radius:999px;padding:2px 12px}
.kicker{letter-spacing:.28em;color:var(--brand);font-size:9pt;font-weight:700;margin:0 0 10px}
.cover h1{font-size:30pt;margin:0 0 12px;letter-spacing:.04em}
.cover .subtitle{font-size:13pt;color:var(--muted);margin:0 0 26px}
.cover-stats{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px}
.stat{min-width:88px;border:1px solid var(--line);border-radius:8px;padding:10px 14px;background:#fff}
.stat b{display:block;font-size:19pt;line-height:1.2}
.stat span{font-size:8.5pt;color:var(--muted)}
.stat.crit b{color:var(--crit)}.stat.high b{color:var(--high)}.stat.med b{color:var(--med)}.stat.low b{color:var(--low)}
.cover-meta{border-top:1px solid var(--line);padding-top:14px;color:var(--muted);font-size:9.5pt;display:grid;gap:4px}
.toc{page-break-after:always}
.toc h2{font-size:18pt;margin-bottom:14px}
.toc ol{list-style:none;padding-left:0;margin:0}
.toc ol ol{padding-left:18px}
.toc li{margin:5px 0}
.toc a::after{content:leader('.') target-counter(attr(href),page)}
.toc .lvl1{font-weight:600;margin-top:10px}
.summary h2,.method h2{font-size:16pt;margin:0 0 12px;padding-bottom:6px;border-bottom:2px solid var(--brand)}
.summary{page-break-after:always}
.summary h3{font-size:12pt;margin:16px 0 8px}
.chapter{page-break-before:always}
.chapter-head{display:flex;gap:12px;align-items:flex-start;border-bottom:2px solid var(--brand);padding-bottom:10px;margin-bottom:12px}
.chapter-no{flex:0 0 auto;background:var(--brand);color:#fff;border-radius:6px;padding:2px 10px;font-weight:700;font-size:12pt}
.chapter-head h2{font-size:17pt}
.finding{page-break-before:always}
.finding-head{display:flex;gap:12px;align-items:flex-start;border-bottom:1px solid var(--line);padding-bottom:10px;margin-bottom:12px}
.finding-no{flex:0 0 auto;color:var(--brand);font-weight:700;font-size:13pt;min-width:36px}
.finding-head h3{font-size:15pt;flex:1}
.finding-target{color:var(--muted);font-size:9.5pt;word-break:break-all}
.sev{flex:0 0 auto;border-radius:999px;padding:2px 10px;font-size:8.5pt;font-weight:700;border:1px solid currentColor}
.sev-critical{color:#fff;background:var(--crit);border-color:var(--crit)}
.sev-high{color:var(--high);background:#fef3f2}
.sev-medium{color:var(--med);background:#fffaeb}
.sev-low{color:var(--low);background:#eff8ff}
.sev-info{color:var(--muted);background:#f8fafc}
.finding h4{font-size:11.5pt;margin:16px 0 6px;color:var(--brand)}
.steps{margin:6px 0 0;padding-left:20px}
.steps li{margin:4px 0}
details{margin:6px 0 10px}
summary{cursor:pointer;color:var(--brand);font-weight:600;font-size:9.5pt}
.tag{display:inline-block;background:var(--brand-soft);color:var(--brand);border-radius:4px;padding:0 6px;font-size:8.5pt;margin-right:4px}
.method{page-break-before:always}
.method ul{padding-left:18px}
.method li{margin:4px 0}
@media print{
  html,body{background:#fff}
  .page{max-width:none;margin:0;padding:0}
  .no-print{display:none!important}
  a{color:inherit}
  pre{page-break-inside:auto}
  table{page-break-inside:auto}
  tr{page-break-inside:avoid}
}
@page{size:A4;margin:18mm 15mm 20mm;
  @bottom-center{content:"精卫 Jingwei · 第 " counter(page) " 页 / 共 " counter(pages) " 页";font-size:8.5pt;color:#667085}
}
</style></head><body>`)
	b.WriteString(`<div class="toolbar no-print"><span>打印或「另存为 PDF」时自动按 A4 分页：封面、目录、任务章节、每条漏洞独立成页。</span><button onclick="window.print()">打印 / 另存为 PDF</button></div>`)
	b.WriteString(`<main class="page">`)

	// ---- Cover ----
	b.WriteString(`<section class="cover">`)
	b.WriteString(`<div class="cover-top"><div class="brand">精卫 <span>JINGWEI</span></div><div class="conf">内部资料 · 授权测试专用</div></div>`)
	b.WriteString(`<div class="cover-main">`)
	b.WriteString(`<p class="kicker">SECURITY ASSESSMENT REPORT</p>`)
	fmt.Fprintf(&b, "<h1>%s</h1>\n", h(title))
	fmt.Fprintf(&b, `<p class="subtitle">%s · 共 %d 条漏洞发现</p>`, h(scope), total)
	b.WriteString(`<div class="cover-stats">`)
	fmt.Fprintf(&b, `<div class="stat"><b>%d</b><span>漏洞总数</span></div>`, total)
	fmt.Fprintf(&b, `<div class="stat crit"><b>%d</b><span>严重</span></div>`, counts["critical"])
	fmt.Fprintf(&b, `<div class="stat high"><b>%d</b><span>高危</span></div>`, counts["high"])
	fmt.Fprintf(&b, `<div class="stat med"><b>%d</b><span>中危</span></div>`, counts["medium"])
	fmt.Fprintf(&b, `<div class="stat low"><b>%d</b><span>低危</span></div>`, counts["low"])
	fmt.Fprintf(&b, `<div class="stat"><b>%d</b><span>任务</span></div>`, len(tasks))
	fmt.Fprintf(&b, `<div class="stat"><b>%d</b><span>关联资产</span></div>`, len(assets))
	b.WriteString(`</div></div>`)
	b.WriteString(`<div class="cover-meta">`)
	fmt.Fprintf(&b, `<div>报告编号：%s</div>`, h(reportNo))
	fmt.Fprintf(&b, `<div>生成时间：%s</div>`, h(at.Format("2006-01-02 15:04:05")))
	fmt.Fprintf(&b, `<div>报告范围：%s</div>`, h(scope))
	b.WriteString(`<div>说明：本报告仅用于已授权的安全测试。原始报文（HTTP 报文，或非 HTTP 协议的原始请求/响应数据）来自实际抓取/扫描记录，未采集到的会明确标注，不会以推测内容替代。</div>`)
	b.WriteString(`</div></section>`)

	// ---- TOC ----
	b.WriteString(`<section class="toc"><h2>目录</h2><ol>`)
	b.WriteString(`<li class="lvl1"><a href="#summary">报告摘要</a></li>`)
	for i, task := range tasks {
		fmt.Fprintf(&b, `<li class="lvl1"><a href="#task-%d">%d. %s</a><ol>`, i+1, i+1, h(task.Title))
		for j, f := range task.Findings {
			fmt.Fprintf(&b, `<li><a href="#finding-%d">%d.%d %s</a></li>`, f.ID, i+1, j+1, h(findingTitle(f)))
		}
		b.WriteString(`</ol></li>`)
	}
	b.WriteString(`<li class="lvl1"><a href="#method">测试方法与数据说明</a></li>`)
	b.WriteString(`</ol></section>`)

	// ---- Summary ----
	b.WriteString(`<section class="summary" id="summary"><h2>报告摘要</h2>`)
	b.WriteString(`<h3>严重等级分布</h3><table><thead><tr><th>严重等级</th><th>数量</th></tr></thead><tbody>`)
	for _, s := range []struct{ key, label string }{
		{"critical", "严重"}, {"high", "高危"}, {"medium", "中危"}, {"low", "低危"},
	} {
		fmt.Fprintf(&b, `<tr><td>%s</td><td>%d</td></tr>`, s.label, counts[s.key])
	}
	if others := total - counts["critical"] - counts["high"] - counts["medium"] - counts["low"]; others > 0 {
		fmt.Fprintf(&b, `<tr><td>其他/待评估</td><td>%d</td></tr>`, others)
	}
	b.WriteString(`</tbody></table>`)

	b.WriteString(`<h3>任务与系统概况</h3><table><thead><tr><th>任务</th><th>总数</th><th>严重</th><th>高危</th><th>中危</th><th>低危</th><th>最近发现</th></tr></thead><tbody>`)
	for _, task := range tasks {
		c := map[string]int{}
		var last time.Time
		for _, f := range task.Findings {
			c[strings.ToLower(strings.TrimSpace(f.Severity))]++
			if f.CreatedAt.After(last) {
				last = f.CreatedAt
			}
		}
		fmt.Fprintf(&b, `<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td></tr>`,
			h(task.Title), len(task.Findings), c["critical"], c["high"], c["medium"], c["low"], h(fmtTime(last)))
	}
	b.WriteString(`</tbody></table>`)
	b.WriteString(`<p class="muted small">每条漏洞页均包含复现验证步骤、验证数据和原始报文；非 HTTP 协议的发现展示其协议原始数据。报文缺失时会标注“未采集”，不会伪造。</p>`)
	b.WriteString(`</section>`)

	// ---- Chapters & findings ----
	for i, task := range tasks {
		fmt.Fprintf(&b, `<section class="chapter" id="task-%d"><div class="chapter-head"><div class="chapter-no">%d</div><div><h2>%s</h2>`, i+1, i+1, h(task.Title))
		if task.Description != "" && task.Description != task.Title {
			fmt.Fprintf(&b, `<div class="muted small">%s</div>`, h(task.Description))
		}
		b.WriteString(`</div></div>`)
		b.WriteString(`<table><thead><tr><th>#</th><th>严重等级</th><th>漏洞</th><th>目标</th><th>状态</th><th>发现时间</th></tr></thead><tbody>`)
		for j, f := range task.Findings {
			fmt.Fprintf(&b, `<tr><td>%d.%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				i+1, j+1, h(severityLabel(f.Severity)), h(findingTitle(f)), h(findingTargetLabel(f)),
				h(findingStatusLabel(f.Status)), h(fmtTime(f.CreatedAt)))
		}
		b.WriteString(`</tbody></table></section>`)

		for j, f := range task.Findings {
			writeFindingHTML(&b, f, fmt.Sprintf("%d.%d", i+1, j+1))
		}
	}

	// ---- Method ----
	b.WriteString(`<section class="method" id="method"><h2>测试方法与数据说明</h2><ul>`)
	b.WriteString(`<li><strong>资产发现：</strong>对授权目标执行 TCP 端口探测（默认 Top1000 + 常见服务端口），对开放端口进行 HTTP/HTTPS 探测与被动指纹识别（服务 Banner、TLS 证书），非 Web 服务也会登记为资产。</li>`)
	b.WriteString(`<li><strong>漏洞扫描：</strong>根据识别到的技术栈匹配 POC 模板，使用 nuclei 执行模板；模板命中后保存原始请求与响应报文，并写入漏洞记录。</li>`)
	b.WriteString(`<li><strong>验证与利用：</strong>对命中结果进行人工/LLM 复核与必要的深度验证；只有实际抓取到的请求、响应和提取结果会被写入本报告。</li>`)
	b.WriteString(`<li><strong>报文真实性：</strong>“原始 HTTP 报文／原始协议报文”章节展示的是抓包/扫描器记录的实际字节；若某条发现未采集到报文，会明确写明，不使用构造内容填充。</li>`)
	b.WriteString(`<li><strong>复测说明：</strong>重放请求时请保持方法、路径、Host、请求头和正文一致；动态令牌、时间戳、Cookie 等可能需要按当前会话更新，更新点会在验证步骤中说明。</li>`)
	b.WriteString(`<li><strong>授权声明：</strong>本报告仅面向已获得书面授权的资产与测试窗口，请勿将报告中的目标、凭据与利用步骤用于未授权环境。</li>`)
	b.WriteString(`</ul></section>`)

	b.WriteString(`</main></body></html>`)
	return []byte(b.String())
}

func writeFindingHTML(b *strings.Builder, f *db.DBFinding, number string) {
	in := FindingReportInputFromDB(f)
	steps, data := verificationSteps(in)
	fmt.Fprintf(b, `<section class="finding" id="finding-%d">`, f.ID)
	b.WriteString(`<div class="finding-head">`)
	fmt.Fprintf(b, `<div class="finding-no">%s</div><div style="flex:1"><h3>%s</h3><div class="finding-target">%s</div></div>`, h(number), h(findingTitle(f)), h(findingTargetLabel(f)))
	fmt.Fprintf(b, `<span class="sev %s">%s</span>`, h(severityClass(f.Severity)), h(severityLabel(f.Severity)))
	b.WriteString(`</div>`)

	b.WriteString(`<table><tbody>`)
	meta := [][2]string{
		{"漏洞编号", fmt.Sprintf("#%d", f.ID)},
		{"漏洞类型", nz(f.VulnClass, "未分类")},
		{"处理状态", findingStatusLabel(f.Status)},
		{"所属任务", findingOwnerLabel(f)},
		{"发现时间", fmtTime(f.CreatedAt)},
		{"数据来源", findingSource(f.Worker)},
	}
	for _, row := range meta {
		fmt.Fprintf(b, `<tr><th style="width:22%%">%s</th><td>%s</td></tr>`, h(row[0]), h(row[1]))
	}
	b.WriteString(`</tbody></table>`)

	b.WriteString(`<h4>漏洞概述</h4>`)
	fmt.Fprintf(b, `<p>%s</p>`, h(nz(strings.TrimSpace(f.Summary), "（未填写概述，详见下方证据与验证数据）")))

	b.WriteString(`<h4>验证步骤</h4><ol class="steps">`)
	for _, step := range steps {
		fmt.Fprintf(b, `<li>%s</li>`, h(step))
	}
	b.WriteString(`</ol>`)

	if len(data) > 0 {
		b.WriteString(`<h4>验证数据</h4><table><thead><tr><th style="width:24%">项目</th><th>值</th></tr></thead><tbody>`)
		for _, row := range data {
			fmt.Fprintf(b, `<tr><td>%s</td><td class="small" style="word-break:break-all">%s</td></tr>`, h(row.Label), h(row.Value))
		}
		b.WriteString(`</tbody></table>`)
	}

	hasPackets := strings.TrimSpace(f.HTTPRequest) != "" || strings.TrimSpace(f.HTTPResponse) != ""
	packetHeading, reqTitle, respTitle, missingNote := packetLabels(in, hasPackets)
	b.WriteString(`<h4>` + packetHeading + `</h4>`)
	if !hasPackets {
		b.WriteString(`<p class="muted">` + h(missingNote) + `</p>`)
	} else {
		req, reqTrunc := truncateHTMLPacket(f.HTTPRequest)
		resp, respTrunc := truncateHTMLPacket(f.HTTPResponse)
		fmt.Fprintf(b, `<details open><summary>%s</summary>`, reqTitle)
		if req == "" {
			b.WriteString(`<p class="muted">未采集到请求报文。</p>`)
		} else {
			fmt.Fprintf(b, `<pre class="http">%s</pre>`, h(req))
			if reqTrunc {
				b.WriteString(`<p class="muted small">请求报文过长，页面仅展示前 192 KiB；完整字节见证据包。</p>`)
			}
		}
		fmt.Fprintf(b, `</details><details open><summary>%s</summary>`, respTitle)
		if resp == "" {
			b.WriteString(`<p class="muted">未采集到响应报文。</p>`)
		} else {
			fmt.Fprintf(b, `<pre class="http">%s</pre>`, h(resp))
			if respTrunc {
				b.WriteString(`<p class="muted small">响应报文过长，页面仅展示前 192 KiB；完整字节见证据包。</p>`)
			}
		}
		b.WriteString(`</details>`)
	}

	if e := strings.TrimSpace(sanitizeEvidence(f.Evidence)); e != "" {
		b.WriteString(`<h4>证据</h4>`)
		fmt.Fprintf(b, `<pre class="evidence">%s</pre>`, h(truncateText(e, 20000)))
	}
	if len(f.TrafficBindings) > 0 {
		b.WriteString(`<h4>关联流量证据</h4><ul class="small">`)
		for _, binding := range f.TrafficBindings {
			fmt.Fprintf(b, `<li>证据 #%d · %s — <span class="tag">%s</span> %s，状态码 %d</li>`,
				binding.ID, h(binding.Role), h(binding.Snapshot.Method), h(binding.Snapshot.URL), binding.Snapshot.Status)
		}
		b.WriteString(`</ul>`)
	}

	guidance := guidanceFor(f.VulnClass + " " + f.Name)
	b.WriteString(`<h4>影响与危害</h4>`)
	fmt.Fprintf(b, `<p>%s</p>`, h(guidance.Impact))
	b.WriteString(`<h4>根因分析</h4>`)
	fmt.Fprintf(b, `<p>%s</p>`, h(guidance.RootCause))
	b.WriteString(`<h4>修复建议</h4>`)
	fmt.Fprintf(b, `<p>%s</p>`, h(guidance.Remediation))

	if rep := strings.TrimSpace(f.Report); rep != "" && !db.IsAutoReport(rep) {
		b.WriteString(`<h4>详细分析报告（原文）</h4><details><summary>展开查看 LLM/人工报告</summary>`)
		fmt.Fprintf(b, `<pre class="md">%s</pre></details>`, h(truncateText(stripCurlArtifacts(toValidText(rep), curlOmittedNote), 60000)))
	}
	b.WriteString(`</section>`)
}

// FindingReportInputFromDB keeps the HTML and Markdown renderers on the same
// view of a stored finding.
func FindingReportInputFromDB(f *db.DBFinding) FindingReportInput {
	ev := parseEvidenceDetail(f.Evidence)
	in := FindingReportInput{
		FindingID:       f.ID,
		Name:            f.Name,
		VulnClass:       f.VulnClass,
		Severity:        f.Severity,
		Status:          f.Status,
		Summary:         f.Summary,
		Evidence:        f.Evidence,
		TaskDescription: f.TaskDescription,
		Source:          findingSource(f.Worker),
		TemplateID:      ev.templateID,
		Host:            ev.host,
		MatchedAt:       ev.matchedAt,
		Type:            ev.kind,
		Curl:            ev.curl,
		Extracted:       ev.extracted,
		HTTPRequest:     f.HTTPRequest,
		HTTPResponse:    f.HTTPResponse,
		GeneratedAt:     f.CreatedAt,
	}
	if in.TemplateID == "" {
		in.TemplateID = f.VulnClass
	}
	return in
}

func groupFindingsByTask(fs []*db.DBFinding) []htmlTaskGroup {
	order := []string{}
	byKey := map[string]*htmlTaskGroup{}
	for _, f := range fs {
		key := "none"
		title := "未关联任务"
		desc := strings.TrimSpace(f.TaskDescription)
		switch {
		case f.TaskID != nil && *f.TaskID > 0:
			key = fmt.Sprintf("task-%d", *f.TaskID)
			title = fmt.Sprintf("任务 #%d", *f.TaskID)
			if desc != "" {
				title = truncateText(strings.Join(strings.Fields(desc), " "), 70)
			}
		case f.ScanTaskID != nil && *f.ScanTaskID > 0:
			key = fmt.Sprintf("scan-%d", *f.ScanTaskID)
			title = fmt.Sprintf("漏扫任务 #%d", *f.ScanTaskID)
			if name := strings.TrimSpace(f.ScanTaskName); name != "" {
				title = truncateText(strings.Join(strings.Fields(name), " "), 70)
			}
			desc = "无 LLM 自动化漏洞扫描"
		}
		g := byKey[key]
		if g == nil {
			g = &htmlTaskGroup{ID: 0, Title: title, Description: desc}
			if f.TaskID != nil {
				g.ID = *f.TaskID
			}
			byKey[key] = g
			order = append(order, key)
		}
		g.Findings = append(g.Findings, f)
	}
	out := make([]htmlTaskGroup, 0, len(order))
	for _, key := range order {
		g := byKey[key]
		sort.SliceStable(g.Findings, func(i, j int) bool {
			ri, rj := sevRank[g.Findings[i].Severity], sevRank[g.Findings[j].Severity]
			if ri != rj {
				return ri < rj
			}
			return g.Findings[i].CreatedAt.After(g.Findings[j].CreatedAt)
		})
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := sevRank[out[i].Findings[0].Severity], sevRank[out[j].Findings[0].Severity]
		if ri != rj {
			return ri < rj
		}
		return len(out[i].Findings) > len(out[j].Findings)
	})
	return out
}

// findingOwnerLabel names the task that owns a finding for the report metadata:
// Agent task description first, then the scan task that produced it.
func findingOwnerLabel(f *db.DBFinding) string {
	if desc := strings.TrimSpace(f.TaskDescription); desc != "" {
		return desc
	}
	if f.TaskID != nil && *f.TaskID > 0 {
		return fmt.Sprintf("任务 #%d", *f.TaskID)
	}
	if f.ScanTaskID != nil && *f.ScanTaskID > 0 {
		if name := strings.TrimSpace(f.ScanTaskName); name != "" {
			return fmt.Sprintf("漏扫任务：%s", name)
		}
		return fmt.Sprintf("漏扫任务 #%d", *f.ScanTaskID)
	}
	return "未关联任务"
}

func findingTargetLabel(f *db.DBFinding) string {
	ev := parseEvidenceDetail(f.Evidence)
	if ev.matchedAt != "" {
		return ev.matchedAt
	}
	if ev.host != "" {
		return ev.host
	}
	if reqStart, _, _, _ := parseMessageHead(f.HTTPRequest); reqStart != "" {
		if fields := strings.Fields(reqStart); len(fields) > 1 {
			return fields[1]
		}
	}
	return "—"
}

func findingStatusLabel(status string) string {
	switch status {
	case db.FindingPending, "":
		return "待处理"
	case db.FindingInProgress:
		return "处理中"
	case db.FindingConfirmed:
		return "已确认"
	case db.FindingResolved:
		return "已处理"
	case db.FindingFixed:
		return "已修复"
	case db.FindingFalsePositive:
		return "误报"
	case db.FindingIgnored:
		return "忽略"
	case db.FindingDuplicate:
		return "重复"
	case db.FindingRiskAccepted:
		return "风险接受"
	}
	return status
}

func severityClass(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high", "medium", "low":
		return "sev-" + strings.ToLower(strings.TrimSpace(sev))
	}
	return "sev-info"
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04:05")
}

func h(s string) string { return html.EscapeString(toValidText(s)) }

func truncateText(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	return s[:limit] + "\n…（已截断）"
}

func truncateHTMLPacket(s string) (string, bool) {
	const limit = 192 << 10
	s = strings.TrimSpace(toValidText(s))
	if len(s) <= limit {
		return s, false
	}
	return s[:limit], true
}
