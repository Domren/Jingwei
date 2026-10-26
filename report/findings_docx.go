package report

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// FindingsDOCXOptions controls the Word report.
type FindingsDOCXOptions struct {
	GeneratedAt time.Time
	ScopeLabel  string // 例如「当前筛选结果」「全部发现」
	Title       string
}

const (
	docxPageWidth   = 9360 // A4 minus 2×1247 twips margins
	docxPacketLimit = 192 << 10
)

// FindingsDOCX renders a paginated Word report: cover, updatable table of
// contents, one chapter per task and one page per finding. Raw HTTP packets are
// written verbatim into monospace blocks; missing packets are called out
// explicitly instead of being replaced with a fabricated request.
func FindingsDOCX(fs []*db.DBFinding, opts FindingsDOCXOptions) ([]byte, error) {
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

	b := &docxBuilder{}
	b.para("精卫 JINGWEI · 内部资料 · 授权测试专用", "Small")
	b.spacer(2400)
	b.para(title, "Title")
	b.para(fmt.Sprintf("%s · 共 %d 条漏洞发现", scope, total), "Subtitle")
	b.spacer(400)
	b.table(nil, [][]string{
		{"漏洞总数", fmt.Sprintf("%d", total), "严重", fmt.Sprintf("%d", counts["critical"])},
		{"高危", fmt.Sprintf("%d", counts["high"]), "中危", fmt.Sprintf("%d", counts["medium"])},
		{"低危", fmt.Sprintf("%d", counts["low"]), "任务", fmt.Sprintf("%d", len(tasks))},
		{"关联资产", fmt.Sprintf("%d", len(assets)), "报告编号", reportNo},
	}, []int{2000, 2680, 2000, 2680}, false)
	b.spacer(400)
	b.kv([]string{"生成时间", at.Format("2006-01-02 15:04:05")})
	b.kv([]string{"报告范围", scope})
	b.para("说明：本报告仅用于已授权的安全测试。原始报文（HTTP 报文，或非 HTTP 协议的原始请求/响应数据）来自实际抓取/扫描记录，未采集到的会明确标注，不会以推测内容替代。", "Small")
	b.pageBreak()

	b.para("目录", "TOCHeading")
	b.tocField()
	b.para("提示：Word 打开时会自动更新目录；若页码未刷新，请右键目录 →「更新域」。", "Small")
	b.pageBreak()

	b.heading("报告摘要", 1, false)
	b.heading("严重等级分布", 2, false)
	sevRows := [][]string{}
	for _, s := range []struct{ key, label string }{
		{"critical", "严重"}, {"high", "高危"}, {"medium", "中危"}, {"low", "低危"},
	} {
		sevRows = append(sevRows, []string{s.label, fmt.Sprintf("%d", counts[s.key])})
	}
	if others := total - counts["critical"] - counts["high"] - counts["medium"] - counts["low"]; others > 0 {
		sevRows = append(sevRows, []string{"其他/待评估", fmt.Sprintf("%d", others)})
	}
	b.table([]string{"严重等级", "数量"}, sevRows, []int{4680, 4680}, false)

	b.heading("任务与系统概况", 2, false)
	taskRows := [][]string{}
	for _, task := range tasks {
		c := map[string]int{}
		var last time.Time
		for _, f := range task.Findings {
			c[strings.ToLower(strings.TrimSpace(f.Severity))]++
			if f.CreatedAt.After(last) {
				last = f.CreatedAt
			}
		}
		taskRows = append(taskRows, []string{
			task.Title, fmt.Sprintf("%d", len(task.Findings)), fmt.Sprintf("%d", c["critical"]),
			fmt.Sprintf("%d", c["high"]), fmt.Sprintf("%d", c["medium"]), fmt.Sprintf("%d", c["low"]),
			fmtTime(last),
		})
	}
	b.table([]string{"任务", "总数", "严重", "高危", "中危", "低危", "最近发现"}, taskRows,
		[]int{2560, 800, 800, 800, 800, 800, 2800}, false)
	b.para("每条漏洞页均包含复现验证步骤、验证数据和原始报文；非 HTTP 协议的发现展示其协议原始数据。报文缺失时会标注“未采集”，不会伪造。", "Small")
	b.pageBreak()

	for i, task := range tasks {
		b.heading(fmt.Sprintf("%d. %s", i+1, task.Title), 1, true)
		if task.Description != "" && task.Description != task.Title {
			b.para(task.Description, "Small")
		}
		rows := [][]string{}
		for j, f := range task.Findings {
			rows = append(rows, []string{
				fmt.Sprintf("%d.%d", i+1, j+1), severityLabel(f.Severity), findingTitle(f),
				findingTargetLabel(f), findingStatusLabel(f.Status), fmtTime(f.CreatedAt),
			})
		}
		b.table([]string{"#", "严重等级", "漏洞", "目标", "状态", "发现时间"}, rows,
			[]int{700, 1100, 3000, 2100, 1000, 1460}, false)
		for j, f := range task.Findings {
			b.finding(f, fmt.Sprintf("%d.%d", i+1, j+1))
		}
	}

	b.heading("测试方法与数据说明", 1, true)
	for _, item := range []string{
		"资产发现：对授权目标执行 TCP 端口探测（默认 Top1000 + 常见服务端口），对开放端口进行 HTTP/HTTPS 探测与被动指纹识别（服务 Banner、TLS 证书），非 Web 服务也会登记为资产。",
		"漏洞扫描：根据识别到的技术栈匹配 POC 模板，使用 nuclei 执行模板；模板命中后保存原始请求与响应报文，并写入漏洞记录。",
		"验证与利用：对命中结果进行人工/LLM 复核与必要的深度验证；只有实际抓取到的请求、响应和提取结果会被写入本报告。",
		"报文真实性：“原始 HTTP 报文／原始协议报文”章节展示的是抓包/扫描器记录的实际字节；若某条发现未采集到报文，会明确写明，不使用构造内容填充。",
		"复测说明：重放请求时请保持方法、路径、Host、请求头和正文一致；动态令牌、时间戳、Cookie 等可能需要按当前会话更新，更新点会在验证步骤中说明。",
		"授权声明：本报告仅面向已获得书面授权的资产与测试窗口，请勿将报告中的目标、凭据与利用步骤用于未授权环境。",
	} {
		b.bullet(item)
	}

	doc, err := b.documentXML()
	if err != nil {
		return nil, err
	}
	return packDOCX(doc, title, at)
}

func trafficRoleLabel(role string) string {
	switch role {
	case "proof":
		return "漏洞证明"
	case "verification":
		return "补充验证"
	case "baseline":
		return "正常对照"
	case "supporting":
		return "辅助证据"
	default:
		return nz(role, "证据")
	}
}

func (b *docxBuilder) finding(f *db.DBFinding, number string) {
	in := FindingReportInputFromDB(f)
	steps, data := verificationSteps(in)
	b.heading(fmt.Sprintf("%s %s", number, findingTitle(f)), 2, true)
	b.kv([]string{"严重等级", severityLabel(f.Severity)})
	b.kv([]string{"目标", findingTargetLabel(f)})
	b.kv([]string{"漏洞编号", fmt.Sprintf("#%d", f.ID)})
	b.kv([]string{"漏洞类型", nz(f.VulnClass, "未分类")})
	b.kv([]string{"处理状态", findingStatusLabel(f.Status)})
	b.kv([]string{"所属任务", findingOwnerLabel(f)})
	b.kv([]string{"发现时间", fmtTime(f.CreatedAt)})
	b.kv([]string{"数据来源", findingSource(f.Worker)})

	b.heading("漏洞概述", 3, false)
	b.para(nz(strings.TrimSpace(f.Summary), "（未填写概述，详见下方证据与验证数据）"), "")

	b.heading("验证步骤", 3, false)
	for i, step := range steps {
		b.numbered(i+1, step)
	}

	if len(data) > 0 {
		b.heading("验证数据", 3, false)
		rows := make([][]string, 0, len(data))
		for _, row := range data {
			rows = append(rows, []string{row.Label, row.Value})
		}
		b.table([]string{"项目", "值"}, rows, []int{2200, 7160}, false)
	}

	hasPackets := strings.TrimSpace(f.HTTPRequest) != "" || strings.TrimSpace(f.HTTPResponse) != ""
	packetHeading, reqTitle, respTitle, missingNote := packetLabels(in, hasPackets)
	b.heading(packetHeading, 3, false)
	if !hasPackets {
		b.para(missingNote, "Small")
	} else {
		b.heading(reqTitle, 3, false)
		if strings.TrimSpace(f.HTTPRequest) == "" {
			b.para("未采集到请求报文。", "Small")
		} else {
			b.code(f.HTTPRequest, docxPacketLimit)
			if len(f.HTTPRequest) > docxPacketLimit {
				b.para("请求报文过长，仅展示前 192 KiB；完整字节见证据包。", "Small")
			}
		}
		b.heading(respTitle, 3, false)
		if strings.TrimSpace(f.HTTPResponse) == "" {
			b.para("未采集到响应报文。", "Small")
		} else {
			b.code(f.HTTPResponse, docxPacketLimit)
			if len(f.HTTPResponse) > docxPacketLimit {
				b.para("响应报文过长，仅展示前 192 KiB；完整字节见证据包。", "Small")
			}
		}
	}

	extras := 0
	for _, packet := range f.EvidencePackets {
		if packet.Primary {
			continue
		}
		if extras == 0 {
			b.heading("全部验证报文（按复现顺序）", 3, false)
			b.para("以下为绑定到该发现的其余真实流量报文，按复现顺序排列；主验证报文已在上方展示。", "Small")
		}
		extras++
		b.heading(fmt.Sprintf("证据 #%d · %s — %s %s，状态码 %d",
			packet.BindingID, trafficRoleLabel(packet.Role), packet.Snapshot.Method, packet.Snapshot.URL, packet.Snapshot.Status), 3, false)
		if note := strings.TrimSpace(packet.Note); note != "" {
			b.para(note, "Small")
		}
		if packet.Repeated > 0 {
			b.para(fmt.Sprintf("后续复测中该步骤又被采集 %d 次，响应字节一致，此处展示最近一次抓包。", packet.Repeated), "Small")
		}
		b.para("请求报文", "Small")
		if strings.TrimSpace(packet.HTTPRequest) == "" {
			b.para("未采集到请求报文。", "Small")
		} else {
			b.code(packet.HTTPRequest, docxPacketLimit)
		}
		b.para("响应报文", "Small")
		if strings.TrimSpace(packet.HTTPResponse) == "" {
			b.para("未采集到响应报文。", "Small")
		} else {
			b.code(packet.HTTPResponse, docxPacketLimit)
		}
	}
	if f.EvidencePacketOmitted > 0 {
		b.para(fmt.Sprintf("另有 %d 组报文属于超出展示上限的复现步骤，未逐条列出，完整字节见证据包 ZIP。", f.EvidencePacketOmitted), "Small")
	}

	if e := strings.TrimSpace(sanitizeEvidence(f.Evidence)); e != "" {
		b.heading("证据", 3, false)
		b.code(truncateText(e, 20000), 0)
	}
	if len(f.TrafficBindings) > 0 {
		b.heading("关联流量证据", 3, false)
		if len(f.EvidencePackets) == 0 {
			for _, binding := range f.TrafficBindings {
				b.bullet(fmt.Sprintf("证据 #%d · %s — %s %s，状态码 %d",
					binding.ID, binding.Role, binding.Snapshot.Method, binding.Snapshot.URL, binding.Snapshot.Status))
			}
		} else {
			// The sequence above already prints the bound packets; repeating every
			// binding as a bullet only made the report grow with each re-test round.
			b.para(fmt.Sprintf("该发现共绑定 %d 组流量证据，其中 %d 组按复现顺序在上方展示，其余为重复轮次对同一步骤的再次采集；全部字节见证据包 ZIP。",
				len(f.TrafficBindings), len(f.EvidencePackets)), "Small")
		}
	}

	guidance := guidanceFor(f.VulnClass + " " + f.Name)
	b.heading("影响与危害", 3, false)
	b.para(guidance.Impact, "")
	b.heading("根因分析", 3, false)
	b.para(guidance.RootCause, "")
	b.heading("修复建议", 3, false)
	b.para(guidance.Remediation, "")

	if rep := strings.TrimSpace(f.Report); rep != "" && !db.IsAutoReport(rep) {
		b.heading("详细分析报告（原文）", 3, false)
		b.code(truncateText(stripCurlArtifacts(toValidText(rep), curlOmittedNote), 60000), 0)
	}
}

// ---- OOXML builders ----

type docxBuilder struct {
	body strings.Builder
}

func (b *docxBuilder) spacer(twips int) {
	if twips <= 0 {
		return
	}
	fmt.Fprintf(&b.body, `<w:p><w:pPr><w:spacing w:before="0" w:after="0" w:line="%d" w:lineRule="auto"/></w:pPr></w:p>`, twips)
}

func (b *docxBuilder) para(text, style string) {
	b.body.WriteString(`<w:p>`)
	b.pPr(style, false, false, 0)
	b.run(text, false, style == "Code", style == "Small")
	b.body.WriteString(`</w:p>`)
}

func (b *docxBuilder) heading(text string, level int, pageBreakBefore bool) {
	style := fmt.Sprintf("Heading%d", level)
	b.body.WriteString(`<w:p>`)
	b.pPr(style, pageBreakBefore, true, 0)
	b.run(text, true, false, false)
	b.body.WriteString(`</w:p>`)
}

func (b *docxBuilder) bullet(text string) {
	b.body.WriteString(`<w:p>`)
	b.body.WriteString(`<w:pPr><w:spacing w:after="60"/><w:ind w:left="420" w:hanging="240"/></w:pPr>`)
	b.run("• "+text, false, false, false)
	b.body.WriteString(`</w:p>`)
}

func (b *docxBuilder) numbered(n int, text string) {
	b.body.WriteString(`<w:p>`)
	b.body.WriteString(`<w:pPr><w:spacing w:after="60"/><w:ind w:left="420" w:hanging="300"/></w:pPr>`)
	b.run(fmt.Sprintf("%d. %s", n, text), false, false, false)
	b.body.WriteString(`</w:p>`)
}

// pPr emits children in the order CT_PPr requires: pStyle, keepNext,
// pageBreakBefore, ..., ind.
func (b *docxBuilder) pPr(style string, pageBreakBefore, keepNext bool, ind int) {
	b.body.WriteString(`<w:pPr>`)
	if style != "" {
		fmt.Fprintf(&b.body, `<w:pStyle w:val="%s"/>`, style)
	}
	if keepNext {
		b.body.WriteString(`<w:keepNext/>`)
	}
	if pageBreakBefore {
		b.body.WriteString(`<w:pageBreakBefore/>`)
	}
	if ind > 0 {
		fmt.Fprintf(&b.body, `<w:ind w:left="%d"/>`, ind)
	}
	b.body.WriteString(`</w:pPr>`)
}

func (b *docxBuilder) run(text string, bold, mono, small bool) {
	b.body.WriteString(`<w:r>`)
	if bold || mono || small {
		b.body.WriteString(`<w:rPr>`)
		if mono {
			b.body.WriteString(`<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>`)
		}
		if bold {
			b.body.WriteString(`<w:b/>`)
		}
		if small {
			if mono {
				b.body.WriteString(`<w:sz w:val="16"/><w:szCs w:val="16"/>`)
			} else {
				b.body.WriteString(`<w:sz w:val="18"/><w:szCs w:val="18"/>`)
			}
		}
		b.body.WriteString(`</w:rPr>`)
	}
	b.body.WriteString(`<w:t xml:space="preserve">`)
	b.body.WriteString(docxEscape(text))
	b.body.WriteString(`</w:t></w:r>`)
}

func (b *docxBuilder) pageBreak() {
	b.body.WriteString(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`)
}

func (b *docxBuilder) tocField() {
	b.body.WriteString(`<w:p><w:pPr><w:pStyle w:val="TOC1"/></w:pPr>`)
	b.body.WriteString(`<w:r><w:fldChar w:fldCharType="begin"/></w:r>`)
	b.body.WriteString(`<w:r><w:instrText xml:space="preserve"> TOC \o "1-2" \h \z \u </w:instrText></w:r>`)
	b.body.WriteString(`<w:r><w:fldChar w:fldCharType="separate"/></w:r>`)
	b.body.WriteString(`<w:r><w:t>（目录将在打开文档时自动更新）</w:t></w:r>`)
	b.body.WriteString(`<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>`)
}

func (b *docxBuilder) kv(row []string) {
	b.table(nil, [][]string{row}, []int{2600, 6760}, true)
}

func (b *docxBuilder) code(text string, limit int) {
	text = docxSafe(text)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	truncated := false
	if limit > 0 && len(text) > limit {
		text = text[:limit]
		truncated = true
	}
	lines := strings.Split(text, "\n")
	b.body.WriteString(`<w:p><w:pPr><w:pStyle w:val="Code"/></w:pPr>`)
	for i, line := range lines {
		if i > 0 {
			b.body.WriteString(`<w:r><w:br/></w:r>`)
		}
		if line == "" {
			continue
		}
		b.body.WriteString(`<w:r><w:t xml:space="preserve">`)
		b.body.WriteString(docxEscape(line))
		b.body.WriteString(`</w:t></w:r>`)
	}
	if truncated {
		b.body.WriteString(`<w:r><w:br/></w:r><w:r><w:t xml:space="preserve">…（已截断，完整字节见证据包）</w:t></w:r>`)
	}
	b.body.WriteString(`</w:p>`)
}

func (b *docxBuilder) table(headers []string, rows [][]string, widths []int, boldFirstCol bool) {
	cols := len(widths)
	if cols == 0 {
		return
	}
	totalWidth := 0
	for _, w := range widths {
		totalWidth += w
	}
	if totalWidth != docxPageWidth {
		scale := float64(docxPageWidth) / float64(totalWidth)
		scaled := make([]int, cols)
		sum := 0
		for i, w := range widths {
			scaled[i] = int(float64(w) * scale)
			sum += scaled[i]
		}
		scaled[cols-1] += docxPageWidth - sum
		widths = scaled
	}
	b.body.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="` + fmt.Sprint(docxPageWidth) + `" w:type="dxa"/>`)
	b.body.WriteString(`<w:tblBorders>`)
	for _, edge := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		fmt.Fprintf(&b.body, `<w:%s w:val="single" w:sz="4" w:space="0" w:color="E3E8EF"/>`, edge)
	}
	b.body.WriteString(`</w:tblBorders><w:tblLayout w:type="fixed"/><w:tblCellMar><w:top w:w="60" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="60" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>`)
	for _, w := range widths {
		fmt.Fprintf(&b.body, `<w:gridCol w:w="%d"/>`, w)
	}
	b.body.WriteString(`</w:tblGrid>`)
	writeRow := func(cells []string, header bool) {
		b.body.WriteString(`<w:tr>`)
		if header {
			// A table that overflows one page must carry its column names onto the
			// next page, otherwise the continuation rows read as unlabeled data.
			b.body.WriteString(`<w:trPr><w:tblHeader/></w:trPr>`)
		}
		for i := 0; i < cols; i++ {
			text := ""
			if i < len(cells) {
				text = cells[i]
			}
			shade := header || (boldFirstCol && i == 0)
			b.body.WriteString(`<w:tc><w:tcPr>`)
			fmt.Fprintf(&b.body, `<w:tcW w:w="%d" w:type="dxa"/>`, widths[i])
			if shade {
				b.body.WriteString(`<w:shd w:val="clear" w:color="auto" w:fill="F7F9FC"/>`)
			}
			b.body.WriteString(`</w:tcPr><w:p><w:pPr><w:spacing w:after="0"/><w:jc w:val="left"/></w:pPr>`)
			b.body.WriteString(`<w:r>`)
			if header || (boldFirstCol && i == 0) {
				b.body.WriteString(`<w:rPr><w:b/></w:rPr>`)
			}
			b.body.WriteString(`<w:t xml:space="preserve">`)
			b.body.WriteString(docxEscape(text))
			b.body.WriteString(`</w:t></w:r></w:p></w:tc>`)
		}
		b.body.WriteString(`</w:tr>`)
	}
	if len(headers) > 0 {
		writeRow(headers, true)
	}
	for _, row := range rows {
		writeRow(row, false)
	}
	b.body.WriteString(`</w:tbl><w:p><w:pPr><w:spacing w:after="0"/></w:pPr></w:p>`)
}

func (b *docxBuilder) documentXML() ([]byte, error) {
	var out strings.Builder
	out.WriteString(xmlDecl)
	out.WriteString(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>`)
	out.WriteString(b.body.String())
	out.WriteString(`<w:sectPr><w:footerReference w:type="default" r:id="rId3"/>`)
	out.WriteString(`<w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1247" w:right="1247" w:bottom="1440" w:left="1247" w:header="720" w:footer="720" w:gutter="0"/>`)
	out.WriteString(`<w:cols w:space="708"/><w:docGrid w:linePitch="312"/></w:sectPr></w:body></w:document>`)
	return []byte(out.String()), nil
}

const xmlDecl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

func packDOCX(document []byte, title string, at time.Time) ([]byte, error) {
	parts := []struct {
		name string
		data []byte
	}{
		{"[Content_Types].xml", []byte(contentTypesXML)},
		{"_rels/.rels", []byte(packageRelsXML)},
		{"docProps/core.xml", []byte(fmt.Sprintf(corePropsXML, docxEscape(title), at.UTC().Format("2006-01-02T15:04:05Z"), at.UTC().Format("2006-01-02T15:04:05Z")))},
		{"docProps/app.xml", []byte(appPropsXML)},
		{"word/document.xml", document},
		{"word/styles.xml", []byte(stylesXML)},
		{"word/settings.xml", []byte(settingsXML)},
		{"word/footer1.xml", []byte(footerXML)},
		{"word/_rels/document.xml.rels", []byte(documentRelsXML)},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, part := range parts {
		w, err := zw.Create(part.name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(part.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func docxSafe(s string) string {
	s = toValidText(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r == '\n' || r == '\r' || r >= 0x20 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var docxEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")

func docxEscape(s string) string { return docxEscaper.Replace(docxSafe(s)) }

const contentTypesXML = xmlDecl + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>` +
	`<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>` +
	`<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>` +
	`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
	`<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>` +
	`</Types>`

const packageRelsXML = xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
	`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
	`<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>` +
	`</Relationships>`

const documentRelsXML = xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
	`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>` +
	`<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>` +
	`</Relationships>`

const corePropsXML = xmlDecl + `<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
	`<dc:title>%s</dc:title><dc:creator>精卫 Jingwei</dc:creator><cp:lastModifiedBy>精卫 Jingwei</cp:lastModifiedBy>` +
	`<dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">%s</dcterms:modified>` +
	`</cp:coreProperties>`

const appPropsXML = xmlDecl + `<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">` +
	`<Application>精卫 Jingwei</Application><AppVersion>1.0</AppVersion></Properties>`

const settingsXML = xmlDecl + `<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
	`<w:defaultTabStop w:val="420"/><w:updateFields w:val="true"/>` +
	`<w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat>` +
	`</w:settings>`

const footerXML = xmlDecl + `<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
	`<w:p><w:pPr><w:jc w:val="center"/></w:pPr>` +
	`<w:r><w:rPr><w:color w:val="667085"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr><w:t xml:space="preserve">精卫 Jingwei · 第 </w:t></w:r>` +
	`<w:fldSimple w:instr=" PAGE "><w:r><w:rPr><w:color w:val="667085"/><w:sz w:val="17"/></w:rPr><w:t>1</w:t></w:r></w:fldSimple>` +
	`<w:r><w:rPr><w:color w:val="667085"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr><w:t xml:space="preserve"> 页 / 共 </w:t></w:r>` +
	`<w:fldSimple w:instr=" NUMPAGES "><w:r><w:rPr><w:color w:val="667085"/><w:sz w:val="17"/></w:rPr><w:t>1</w:t></w:r></w:fldSimple>` +
	`<w:r><w:rPr><w:color w:val="667085"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr><w:t xml:space="preserve"> 页</w:t></w:r></w:p></w:ftr>`

const stylesXML = xmlDecl + `<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
	`<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Microsoft YaHei" w:cs="Calibri"/>` +
	`<w:color w:val="172033"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-US" w:eastAsia="zh-CN"/></w:rPr></w:rPrDefault>` +
	`<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="300" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>` +
	`<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>` +
	`<w:pPr><w:spacing w:before="0" w:after="200"/><w:jc w:val="left"/></w:pPr>` +
	`<w:rPr><w:b/><w:color w:val="0F4C81"/><w:sz w:val="64"/><w:szCs w:val="64"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>` +
	`<w:pPr><w:spacing w:after="240"/></w:pPr><w:rPr><w:color w:val="667085"/><w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>` +
	`<w:pPr><w:keepNext/><w:keepLines/><w:pBdr><w:bottom w:val="single" w:sz="12" w:space="6" w:color="0F4C81"/></w:pBdr>` +
	`<w:spacing w:before="240" w:after="160"/><w:outlineLvl w:val="0"/></w:pPr>` +
	`<w:rPr><w:b/><w:color w:val="0F4C81"/><w:sz w:val="36"/><w:szCs w:val="36"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>` +
	`<w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="240" w:after="120"/><w:outlineLvl w:val="1"/></w:pPr>` +
	`<w:rPr><w:b/><w:color w:val="172033"/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>` +
	`<w:pPr><w:keepNext/><w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="2"/></w:pPr>` +
	`<w:rPr><w:b/><w:color w:val="0F4C81"/><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="TOCHeading"><w:name w:val="TOC Heading"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>` +
	`<w:pPr><w:spacing w:before="0" w:after="240"/></w:pPr>` +
	`<w:rPr><w:b/><w:color w:val="0F4C81"/><w:sz w:val="36"/><w:szCs w:val="36"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="TOC1"><w:name w:val="toc 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:spacing w:after="80"/></w:pPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="TOC2"><w:name w:val="toc 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:spacing w:after="40"/><w:ind w:left="240"/></w:pPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/><w:qFormat/>` +
	`<w:pPr><w:pBdr><w:top w:val="single" w:sz="4" w:space="4" w:color="E3E8EF"/><w:left w:val="single" w:sz="4" w:space="4" w:color="E3E8EF"/>` +
	`<w:bottom w:val="single" w:sz="4" w:space="4" w:color="E3E8EF"/><w:right w:val="single" w:sz="4" w:space="4" w:color="E3E8EF"/></w:pBdr>` +
	`<w:shd w:val="clear" w:color="auto" w:fill="F2F4F7"/>` +
	`<w:spacing w:before="60" w:after="160" w:line="240" w:lineRule="auto"/><w:ind w:left="120" w:right="120"/></w:pPr>` +
	`<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:color w:val="1D2939"/><w:sz w:val="16"/><w:szCs w:val="16"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Small"><w:name w:val="Small"/><w:basedOn w:val="Normal"/><w:qFormat/>` +
	`<w:rPr><w:color w:val="667085"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr></w:style>` +
	`</w:styles>`
