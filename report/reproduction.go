package report

import (
	"fmt"
	"strings"

	"github.com/Autumn-27/jingwei/db"
)

// 结构化复现过程与步骤级报文的渲染。
//
// 数据来自 findings.reproduction（agent 在 report_finding 落库时写下的真实过程），
// 其中每一步的 snapshot_id 指向本漏洞已绑定的流量快照。渲染规则：
//   - 步骤的请求/响应优先取**真实报文**（快照里抓到的字节），取不到才退回 agent
//     记录的原文——两者都是真实内容，区别只在于是抓包抓到的还是 agent 抄下来的；
//   - 响应一律走命中片段裁剪，避免整页 HTML/JSON 噪音灌进报告；
//   - 每一步紧跟它自己的报文和「对应流量证据 #N」，读者不用在章节之间来回翻。

// reproPacketLimit bounds one step's verbatim request/response in the rendered
// report. Steps are meant to carry the decisive slice, not a whole page dump.
const reproPacketLimit = 12000

type reproStepView struct {
	No         int
	Request    string
	Response   string
	Expected   string
	Proves     string
	BindingID  int64
	Role       string
	URL        string
	FromPacket bool
}

type reproView struct {
	EntryPoint    string
	Prerequisites []string
	Provenance    string
	Steps         []reproStepView
}

// anyFromPacket reports whether at least one step was rendered from captured
// bytes (rather than the agent's transcribed text).
func (v *reproView) anyFromPacket() bool {
	if v == nil {
		return false
	}
	for _, st := range v.Steps {
		if st.FromPacket {
			return true
		}
	}
	return false
}

// buildReproView turns the stored reproduction into render-ready rows, joining
// each step with the hydrated packet it resolved to.
func buildReproView(f *db.DBFinding) *reproView {
	if f == nil || f.Reproduction == nil || len(f.Reproduction.Steps) == 0 {
		return nil
	}
	packets := make(map[string]*db.FindingEvidencePacket, len(f.EvidencePackets))
	for i := range f.EvidencePackets {
		if id := f.EvidencePackets[i].Snapshot.ID; id != "" {
			packets[id] = &f.EvidencePackets[i]
		}
	}
	v := &reproView{
		EntryPoint:    strings.TrimSpace(f.Reproduction.EntryPoint),
		Prerequisites: f.Reproduction.Prerequisites,
		Provenance:    strings.TrimSpace(f.Reproduction.Provenance),
	}
	for i, st := range f.Reproduction.Steps {
		row := reproStepView{No: i + 1, Expected: st.Expected, Proves: st.Proves}
		req := strings.TrimSpace(st.Request)
		resp := strings.TrimSpace(st.Response)
		if pkt := packets[st.SnapshotID]; pkt != nil {
			row.BindingID, row.Role, row.URL = pkt.BindingID, pkt.Role, pkt.Snapshot.URL
			if captured := strings.TrimSpace(pkt.HTTPRequest); captured != "" {
				req, row.FromPacket = captured, true
			}
			if captured := strings.TrimSpace(pkt.HTTPResponse); captured != "" {
				resp = captured
			}
		}
		target, body := requestTargetAndBody(req)
		row.Request = truncateText(req, reproPacketLimit)
		// 响应只留「响应头 + 命中漏洞片段」；没有头体分界的短片段原样保留。
		row.Response, _ = clipHTTPResponseForReport(f.VulnClass, f.Name, target, body, resp)
		v.Steps = append(v.Steps, row)
	}
	return v
}

// requestTargetAndBody pulls the request-target and body out of a raw request
// packet so the response clipper can trim around the right place.
func requestTargetAndBody(req string) (target, body string) {
	start, _, b, ok := parseMessageHead(req)
	if !ok {
		return "", ""
	}
	if fields := strings.Fields(start); len(fields) > 1 {
		target = fields[1]
	}
	return target, b
}

// --- HTML ---

func writeReproductionHTML(b *strings.Builder, v *reproView) {
	if v == nil || len(v.Steps) == 0 {
		return
	}
	b.WriteString(`<h4>复现过程</h4>`)
	if v.EntryPoint != "" || v.Provenance != "" || len(v.Prerequisites) > 0 {
		b.WriteString(`<table><tbody>`)
		if v.EntryPoint != "" {
			fmt.Fprintf(b, `<tr><th style="width:22%%">入口点</th><td class="small" style="word-break:break-all">%s</td></tr>`, h(v.EntryPoint))
		}
		if len(v.Prerequisites) > 0 {
			var items strings.Builder
			for _, p := range v.Prerequisites {
				fmt.Fprintf(&items, `<li>%s</li>`, h(p))
			}
			fmt.Fprintf(b, `<tr><th>前置条件</th><td class="small"><ul style="margin:0;padding-left:18px">%s</ul></td></tr>`, items.String())
		}
		if v.Provenance != "" {
			fmt.Fprintf(b, `<tr><th>攻击链来源</th><td class="small">%s</td></tr>`, h(v.Provenance))
		}
		b.WriteString(`</tbody></table>`)
	}
	b.WriteString(`<div class="repro">`)
	for _, st := range v.Steps {
		b.WriteString(`<div class="repro-step">`)
		fmt.Fprintf(b, `<div class="repro-head"><span class="repro-no">步骤 %d</span>`, st.No)
		if st.Expected != "" {
			fmt.Fprintf(b, `<span class="repro-tag">预期：%s</span>`, h(st.Expected))
		}
		if st.Proves != "" {
			fmt.Fprintf(b, `<span class="repro-tag">证明：%s</span>`, h(st.Proves))
		}
		b.WriteString(`</div>`)
		if st.Request != "" {
			fmt.Fprintf(b, `<details open><summary>请求</summary><pre class="http">%s</pre></details>`, h(st.Request))
		}
		if st.Response != "" {
			fmt.Fprintf(b, `<details open><summary>响应</summary><pre class="http">%s</pre></details>`, h(st.Response))
		}
		if st.BindingID > 0 {
			fmt.Fprintf(b, `<p class="muted small">对应流量证据 #%d（%s）%s</p>`, st.BindingID, h(nz(st.Role, "supporting")), h(st.URL))
		} else if st.Request != "" {
			b.WriteString(`<p class="muted small">该步骤未关联到已绑定流量，报文取自执行记录原文。</p>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
}

// --- DOCX ---

func writeReproductionDOCX(b *docxBuilder, v *reproView) {
	if v == nil || len(v.Steps) == 0 {
		return
	}
	b.heading("复现过程", 3, false)
	if v.EntryPoint != "" {
		b.kv([]string{"入口点", v.EntryPoint})
	}
	for _, p := range v.Prerequisites {
		b.bullet("前置条件：" + p)
	}
	if v.Provenance != "" {
		b.kv([]string{"攻击链来源", v.Provenance})
	}
	for _, st := range v.Steps {
		title := fmt.Sprintf("步骤 %d", st.No)
		if st.Expected != "" {
			title += " — 预期：" + st.Expected
		}
		if st.Proves != "" {
			title += "｜证明：" + st.Proves
		}
		b.numbered(st.No, title)
		if st.Request != "" {
			b.para("请求", "Small")
			b.code(st.Request, reproPacketLimit)
		}
		if st.Response != "" {
			b.para("响应", "Small")
			b.code(st.Response, reproPacketLimit)
		}
		if st.BindingID > 0 {
			b.para(fmt.Sprintf("对应流量证据 #%d（%s）%s", st.BindingID, nz(st.Role, "supporting"), st.URL), "Small")
		} else if st.Request != "" {
			b.para("该步骤未关联到已绑定流量，报文取自执行记录原文。", "Small")
		}
	}
}
