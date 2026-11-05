package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// 弱口令检测报告：内部版与对外版是两份不同的叙事，不是同一份加个水印。
//
// 内部版给操作员/复核者：每一行结果都在（命中、拒绝、连不上、锁定、不可判定、不支持），
// 外加原始协议报文附录，任何一条结论都能照着字节复现。
// 对外版只放已确认的命中与「覆盖到了哪里」——未测与不支持的协议必须**显式列出**，
// 不能留空让人误以为「测过了没问题」。口令在对外版里打码：确认存在弱口令是结论，
// 把客户系统还在用的口令印在交付件上是另一回事。

// CredReportInput 是一次弱口令检测任务的渲染输入。
type CredReportInput struct {
	TaskID      int64
	Name        string
	Targets     []string
	Protocols   []string
	DictProfile string
	Status      string
	CreatedAt   time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
	Summary     map[string]any
	Rows        []*db.CredResult
	GeneratedAt time.Time
	Internal    bool
}

var credOutcomeOrder = []string{"hit", "deny", "unreachable", "locked", "inconclusive", "unsupported"}

var credOutcomeLabel = map[string]string{
	"hit": "命中", "deny": "明确拒绝", "unreachable": "连不上",
	"locked": "账号锁定", "inconclusive": "不可判定", "unsupported": "暂不支持",
}

// CredscanMarkdown 渲染任务报告。
func CredscanMarkdown(in CredReportInput) string {
	if in.GeneratedAt.IsZero() {
		in.GeneratedAt = time.Now()
	}
	var b strings.Builder
	version := "对外版"
	title := "弱口令检测报告"
	if in.Internal {
		version = "内部版"
	}
	fmt.Fprintf(&b, "# %s（%s）\n\n", title, version)
	fmt.Fprintf(&b, "- **任务**：#%d %s\n", in.TaskID, nz(in.Name, "（未命名）"))
	fmt.Fprintf(&b, "- **生成时间**：%s\n", in.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "- **目标**：%s\n", strings.Join(in.Targets, "、"))
	fmt.Fprintf(&b, "- **协议**：%s\n", strings.Join(in.Protocols, "、"))
	fmt.Fprintf(&b, "- **字典**：%s\n", nz(in.DictProfile, "builtin"))
	if in.StartedAt != nil {
		end := in.GeneratedAt
		if in.FinishedAt != nil {
			end = *in.FinishedAt
		}
		fmt.Fprintf(&b, "- **用时**：%s\n", end.Sub(*in.StartedAt).Round(time.Second))
	}
	b.WriteString("\n")

	hits := make([]*db.CredResult, 0)
	byOutcome := map[string][]*db.CredResult{}
	for _, r := range in.Rows {
		byOutcome[r.Outcome] = append(byOutcome[r.Outcome], r)
		if r.Outcome == "hit" {
			hits = append(hits, r)
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Host != hits[j].Host {
			return hits[i].Host < hits[j].Host
		}
		if hits[i].Port != hits[j].Port {
			return hits[i].Port < hits[j].Port
		}
		return hits[i].Username < hits[j].Username
	})

	// 一、结论
	b.WriteString("## 一、结论\n\n")
	if len(hits) == 0 {
		b.WriteString("本次检测**未发现**可用弱口令。\n\n")
	} else {
		fmt.Fprintf(&b, "本次检测发现 **%d** 组可用凭据（%d 个端点）。\n\n", len(hits), len(distinctEndpoints(hits)))
	}
	b.WriteString("| 协议 | 结果行 |")
	for _, o := range credOutcomeOrder {
		fmt.Fprintf(&b, " %s |", credOutcomeLabel[o])
	}
	b.WriteString("\n| :-- | --: | --: | --: | --: | --: | --: |\n")
	protocols := in.Protocols
	if len(protocols) == 0 {
		seen := map[string]bool{}
		for _, r := range in.Rows {
			if !seen[r.Protocol] {
				seen[r.Protocol] = true
				protocols = append(protocols, r.Protocol)
			}
		}
		sort.Strings(protocols)
	}
	zeroRows := 0
	for _, p := range protocols {
		rowCount := 0
		cells := make([]int, len(credOutcomeOrder))
		for i, o := range credOutcomeOrder {
			for _, r := range byOutcome[o] {
				if r.Protocol == p {
					cells[i]++
					rowCount++
				}
			}
		}
		if rowCount == 0 {
			zeroRows++
			continue
		}
		fmt.Fprintf(&b, "| %s | %d |", p, rowCount)
		for _, n := range cells {
			fmt.Fprintf(&b, " %d |", n)
		}
		b.WriteString("\n")
	}
	if zeroRows > 0 {
		fmt.Fprintf(&b, "\n> 有 %d 个勾选的协议没有产出任何结果行——这代表**没测**，不代表没问题。\n", zeroRows)
	}
	b.WriteString("\n")

	// 二、命中
	b.WriteString("## 二、可用凭据\n\n")
	if len(hits) == 0 {
		b.WriteString("（无）\n\n")
	} else {
		if in.Internal {
			b.WriteString("| 端点 | 协议 | 账号 | 口令 | TLS | 证据 |\n| :-- | :-- | :-- | :-- | :-- | :-- |\n")
			for _, r := range hits {
				tls := ""
				if r.TLS {
					tls = "是"
				}
				fmt.Fprintf(&b, "| %s:%d | %s | %s | %s | %s | 见附录 |\n",
					r.Host, r.Port, r.Protocol, mdCell(r.Username), mdCell(r.Password), tls)
			}
		} else {
			b.WriteString("| 端点 | 协议 | 账号 | 口令 |\n| :-- | :-- | :-- | :-- |\n")
			for _, r := range hits {
				fmt.Fprintf(&b, "| %s:%d | %s | %s | %s |\n",
					r.Host, r.Port, r.Protocol, mdCell(r.Username), maskCred(r.Password))
			}
			b.WriteString("\n> 对外版对口令做了脱敏；完整凭据见平台凭据库或内部版报告。\n")
		}
		b.WriteString("\n")
	}

	// 三、覆盖与未测项：对外版也要写，不能空着
	b.WriteString("## 三、覆盖与未测项\n\n")
	tested := map[string]int{}
	for _, r := range in.Rows {
		if r.Outcome == "deny" || r.Outcome == "hit" {
			tested[r.Protocol]++
		}
	}
	for _, p := range protocols {
		if tested[p] == 0 {
			fmt.Fprintf(&b, "- **%s**：没有完成任何一次有效认证判定（未测 / 不支持），本次不对该协议下结论。\n", p)
		}
	}
	if n := len(byOutcome["inconclusive"]); n > 0 {
		fmt.Fprintf(&b, "- **不可判定 %d 行**：超时、预算耗尽、握手失败或为避免锁定而停手；这些不是「已排除」。\n", n)
	}
	if n := len(byOutcome["unreachable"]); n > 0 {
		fmt.Fprintf(&b, "- **连不上 %d 行**：端口无监听或网络不可达。\n", n)
	}
	if n := len(byOutcome["locked"]); n > 0 {
		fmt.Fprintf(&b, "- **账号锁定 %d 行**：服务端提示锁定，已立即停手，余下口令组未再尝试。\n", n)
	}
	if n := len(byOutcome["unsupported"]); n > 0 {
		fmt.Fprintf(&b, "- **暂不支持 %d 行**：该协议的握手形态本平台不实现，未发起连接。\n", n)
	}
	b.WriteString("\n")

	// 四、附录
	if in.Internal {
		b.WriteString("## 四、附录：原始协议报文\n\n")
		b.WriteString("每条命中与拒绝都带原始请求/响应字节与复现命令；TLS 通道内的明文已标明。\n\n")
		for _, o := range credOutcomeOrder {
			rows := byOutcome[o]
			if len(rows) == 0 {
				continue
			}
			fmt.Fprintf(&b, "### %s（%d 行）\n\n", credOutcomeLabel[o], len(rows))
			for _, r := range rows {
				fmt.Fprintf(&b, "#### %s:%d · %s · %s\n\n", r.Host, r.Port, r.Protocol, mdCell(r.Username))
				if strings.TrimSpace(r.Reason) != "" {
					fmt.Fprintf(&b, "- 判定说明：%s\n", strings.ReplaceAll(r.Reason, "\n", " "))
				}
				if strings.TrimSpace(r.Banner) != "" {
					fmt.Fprintf(&b, "- Banner：`%s`\n", oneLine(r.Banner, 200))
				}
				if strings.TrimSpace(r.Evidence) == "" {
					b.WriteString("\n（该行没有字节证据）\n\n")
					continue
				}
				b.WriteString("\n```text\n")
				b.WriteString(strings.TrimRight(r.Evidence, "\n"))
				b.WriteString("\n```\n\n")
			}
		}
	}
	return b.String()
}

func distinctEndpoints(rows []*db.CredResult) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		out[fmt.Sprintf("%s:%d", r.Host, r.Port)] = true
	}
	return out
}

// mdCell 防止单行内容把 Markdown 表格撑断。
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	return s
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// maskCred 对外版的口令脱敏：保留首尾各一个字符，太短就整段遮住。
func maskCred(p string) string {
	if p == "" {
		return "—"
	}
	if len([]rune(p)) <= 3 {
		return "***"
	}
	r := []rune(p)
	return string(r[:1]) + "***" + string(r[len(r)-1:])
}
