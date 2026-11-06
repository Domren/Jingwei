package report

import (
	"fmt"
	"strings"
	"time"
)

// 痕迹矩阵（G4）：把「本次维持留下了什么、怎么证明清掉了、清掉之后还剩什么」自动写进报告，
// 而不是靠操作者的经验补一段话。
//
// 三条口径要先说清楚，否则这张表会被读成它想避免的误会：
//   - 「已验证清除」只意味着**验证命令的输出里不再出现那个痕迹**。撤销命令退出码为 0 不算证据
//     （命令跑成功但删错对象的情况真实存在）。
//   - 「撤销后仍然存在的痕迹」不是「没清干净」：认证日志、事件日志、任务计划程序记录、mtime
//     这些要么没有权限改，要么改了就是新的破坏。把它们列出来，操作者才知道该不该继续维持。
//   - 这张表描述的是平台自己造成的后果，不是对任何具体检测产品的规避建议。

// 清除结论。值由服务端按台账状态与验证输出一一映射，界面与报告共用同一套词。
const (
	TraceVerdictCleared      = "已验证清除"
	TraceVerdictFailed       = "撤销失败，仍在目标上"
	TraceVerdictUnverified   = "未配置验证命令，无法复核"
	TraceVerdictActive       = "仍在维持中（本轮未撤销）"
	TraceVerdictNoProfile    = "没有痕迹档案（kind 未登记）"
	TraceVerdictNotAttempted = "本轮未执行撤销"
)

// TraceMatrixRow 是一种维持手段在本机/本任务上的痕迹。
type TraceMatrixRow struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Host string `json:"host"`
	// Landed 是本次实际落地的位置：文件路径、任务名、注册表值名、单元文件名等。
	Landed []string `json:"landed"`
	// Traces / Residue 来自 db.ArtifactTraceProfileFor，报告里逐条列出。
	Traces  []string `json:"traces"`
	Residue []string `json:"residue"`
	Verify  string   `json:"verify"`
	Verdict string   `json:"verdict"`
	// Detail 是这一条的复核原文摘要（验证输出里的关键行），没有就留空。
	Detail string `json:"detail"`
}

// TraceMatrixInput 是一次撤离（或维持复核）的痕迹矩阵输入。
type TraceMatrixInput struct {
	Rows []TraceMatrixRow
	// LedgerExternal 是账外残留扫描发现的东西：不在台账里、但目标上确实存在。
	LedgerExternal []string
	// Unknown 是扫描没能做完的部分（没有会话、Windows 侧未覆盖、台账读取失败）。
	Unknown     []string
	Hostname    string
	GeneratedAt time.Time
}

// TraceMatrixMarkdown 渲染痕迹矩阵一节。
func TraceMatrixMarkdown(in TraceMatrixInput) string {
	var b strings.Builder
	b.WriteString("## 维持痕迹矩阵\n\n")
	at := in.GeneratedAt
	if at.IsZero() {
		at = time.Now()
	}
	subject := "本轮维持与清理"
	if strings.TrimSpace(in.Hostname) != "" {
		subject += "（目标 " + strings.TrimSpace(in.Hostname) + "）"
	}
	fmt.Fprintf(&b, "%s · 生成于 %s\n\n", subject, at.Format("2006-01-02 15:04:05"))
	b.WriteString("> 「已验证清除」只表示验证命令的输出里不再出现该痕迹；撤销命令的退出码不作为证据。\n")
	b.WriteString("> 「撤销后仍然存在的痕迹」不是没清干净，而是当前权限与技术上清不掉或不该动的东西。\n")
	b.WriteString("> 本节描述平台自身造成的后果，不构成对具体检测产品的规避建议。\n\n")

	b.WriteString("### 本次留下的东西与清除结论\n\n")
	if len(in.Rows) == 0 {
		b.WriteString("本轮没有登记任何维持落地物，因此没有需要清除的痕迹。\n\n")
	} else {
		b.WriteString("| 手段 | 本次落地点 | 部署后留下的痕迹 | 清除验证方式 | 结论 |\n")
		b.WriteString("| :-- | :-- | :-- | :-- | :-- |\n")
		for _, r := range in.Rows {
			name := mdCell(r.Name)
			if name == "—" {
				name = mdCell(r.Kind)
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				name,
				mdCell(joinBullets(r.Landed)),
				mdCell(joinBullets(r.Traces)),
				mdCell(r.Verify),
				mdCell(verdictCell(r)),
			))
		}
		b.WriteString("\n")
	}

	b.WriteString("### 撤销之后仍然存在的痕迹\n\n")
	residueRows := 0
	for _, r := range in.Rows {
		if len(r.Residue) == 0 {
			continue
		}
		residueRows++
		fmt.Fprintf(&b, "- **%s**（%s）\n", mdCell(firstNonEmpty(r.Name, r.Kind)), mdCell(r.Verdict))
		for _, line := range r.Residue {
			fmt.Fprintf(&b, "  - %s\n", strings.TrimSpace(line))
		}
	}
	if residueRows == 0 {
		b.WriteString("本轮没有可列出的残留项（没有登记维持手段，或该手段未登记残留说明）。\n")
	}
	b.WriteString("\n")

	b.WriteString("### 账外残留（不在台账里的发现）\n\n")
	if len(in.Unknown) > 0 {
		for _, u := range in.Unknown {
			fmt.Fprintf(&b, "- 未能复核：%s\n", strings.TrimSpace(u))
		}
		b.WriteString("\n上面这些是**没有检查过**的部分，不能当成「没有残留」。\n\n")
	}
	// 一条维持手段都没登记时，残留扫描根本没跑过——这时候说「没发现」是把自己没做
	// 的事写成结论。
	scanned := len(in.Rows) > 0 || len(in.Unknown) > 0
	if !scanned {
		b.WriteString("本轮没有登记维持落地物，因此也没有执行残留扫描：" +
			"这一节不代表目标上不存在其他持久化条目。\n\n")
	} else if len(in.LedgerExternal) == 0 {
		if len(in.Unknown) == 0 {
			b.WriteString("已扫描的类别里没有发现台账之外的持久化条目。\n\n")
		} else {
			b.WriteString("已扫描的类别里没有发现台账之外的持久化条目；未扫描的部分见上一条。\n\n")
		}
	} else {
		for _, e := range in.LedgerExternal {
			fmt.Fprintf(&b, "- %s\n", strings.TrimSpace(e))
		}
		b.WriteString("\n这些条目不在本轮台账里：平台没有部署它们，也就无法声称已经清除。" +
			"要么它们属于别的操作，要么是台账漏记——两种都必须人工确认后再交付报告。\n\n")
	}

	b.WriteString("### 这一节怎么读\n\n")
	b.WriteString("- **结论**一栏只有四种有效值：已验证清除、撤销失败仍在目标上、未配置验证命令无法复核、" +
		"仍在维持中。出现「无法复核」时不要把整节当成已清理。\n")
	b.WriteString("- **本次落地点**来自台账里记录的实际路径与名称，不是模板文案；同一手段多次落地会合并成一条。\n")
	b.WriteString("- 报告没有写的痕迹不等于没有痕迹：本节的覆盖面是「平台实现过的维持手段」，" +
		"人工操作（自己改的配置、自己拷的文件）需要另外说明。\n")
	return b.String()
}

func verdictCell(r TraceMatrixRow) string {
	verdict := strings.TrimSpace(r.Verdict)
	if verdict == "" {
		verdict = TraceVerdictNoProfile
	}
	if detail := strings.TrimSpace(r.Detail); detail != "" {
		return verdict + "：" + detail
	}
	return verdict
}

// joinBullets 把多条内容并成一个表格单元；两条以上时用分号分隔，避免表格被撑断。
func joinBullets(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		if s := strings.TrimSpace(it); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "；")
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
