package server

import (
	"fmt"
	"strings"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// 终端防护识别与补丁基线（F5）在服务层的落点。
//
// 采集复用 F3 的脚本库（只读命令、stdout 与结构化结果一起入库），判定复用 scanner 的纯函数，
// 这里只负责三件事：把结果写成**发现台账里的条目**（带稳定 dedupe key，重跑不堆积）、
// 把「没读到」与「没有」分开、以及把已识别的防护在后续动作里摆在决策者眼前。
//
// 一条纪律：这一层不输出任何规避建议。「检测到 Defender」之后该怎么做，是操作员与
// 授权范围决定的事；平台把事实与不确定性说清楚就已经尽责。

const (
	intranetScriptWinEndpoint = "win-endpoint"
	intranetScriptLinuxEP     = "linux-endpoint"
	intranetScriptWinHotfixes = "win-hotfixes"
	intranetScriptWinPatches  = "win-patches"

	findingClassEndpointSecurity = "endpoint_security"
	findingClassMissingPatch     = "missing_patch"
)

// endpointScriptIDs 是会产生终端侧结论的脚本；执行工具只回看这几条的运行记录。
var endpointScriptIDs = []string{intranetScriptWinEndpoint, intranetScriptLinuxEP, intranetScriptWinHotfixes, intranetScriptWinPatches, "win-systeminfo"}

// parseEndpointScript 把进程/服务列表变成结构化条目。
//
// items 里既有确认的产品（带依据），也有未登记的可疑名字（kind=unidentified）——
// 两类分开，报告就不会把「没登记过」写成「没有防护」。
func parseEndpointScript(osKind, output string) map[string]any {
	rep := scanner.IdentifyEndpointSecurity(osKind, output)
	items := make([]any, 0, len(rep.Matches)+len(rep.Unidentified))
	for _, m := range rep.Matches {
		items = append(items, map[string]any{
			"kind": "product", "product": m.Product, "vendor": m.Vendor,
			"category": m.Kind, "evidence": m.Token, "line": m.Line,
		})
	}
	for _, name := range rep.Unidentified {
		items = append(items, map[string]any{"kind": "unidentified", "product": name})
	}
	return map[string]any{
		"kind": "endpoint", "count": len(items), "items": items,
		"products": len(rep.Matches), "unidentified": len(rep.Unidentified),
		"unreadable": rep.Empty, "summary": rep.Summary(),
	}
}

// parsePatchScript 把 systeminfo / wmic qfe / Get-HotFix 的输出变成基线比对结果。
func parsePatchScript(output string) map[string]any {
	rep := scanner.AnalyzeWindowsPatches(output)
	items := make([]any, 0, len(rep.Items))
	for _, it := range rep.Items {
		items = append(items, map[string]any{
			"kind": "patch", "advisory": it.ID, "title": it.Title,
			"state": it.State, "matched": it.Matched, "note": it.Note,
		})
	}
	return map[string]any{
		"kind": "patches", "count": len(items), "items": items,
		"installed": len(rep.Installed), "os_name": rep.OSName, "os_build": rep.OSBuild,
		"incomplete": rep.Incomplete, "reason": rep.Reason, "summary": rep.Summary(),
	}
}

// recordEndpointFindings 把一次终端侧识别写进发现台账，返回一句要显示给操作员的说明。
//
// 三种情况刻意不写台账：读不到列表（Empty/Incomplete）、基线不完整、以及只有「未登记的可疑名字」
// ——那说明签名表没覆盖到，不是目标上有什么漏洞或缺什么补丁。把它们写成发现，
// 报告里就多了一条没有证据支撑的条目。
func (s *Server) recordEndpointFindings(pg *db.DB, sess *db.IntranetSession, taskID int64, scriptID string, parsed map[string]any) string {
	if pg == nil || sess == nil || parsed == nil {
		return ""
	}
	host := strings.TrimSpace(sess.Host)
	worker := "intranet-script:" + scriptID
	switch fmt.Sprint(parsed["kind"]) {
	case "endpoint":
		if unreadable, _ := parsed["unreadable"].(bool); unreadable {
			return "终端防护：没有读到进程/服务列表，本轮不做判断（不等于没有防护）"
		}
		products := 0
		for _, raw := range asAnySlice(parsed["items"]) {
			item, ok := raw.(map[string]any)
			if !ok || item["kind"] != "product" {
				continue
			}
			name, _ := item["product"].(string)
			if name == "" {
				continue
			}
			products++
			evidence := fmt.Sprintf("主机 %s（会话 #%d）· 依据进程/服务 %v：%v",
				firstNonEmpty(host, "未知"), sess.ID, item["evidence"], item["line"])
			_, _, err := pg.UpsertFinding(taskID, 0, findingClassEndpointSecurity,
				"目标存在终端防护："+name, "low",
				"在目标上运行着终端安全产品 "+name+"（厂商 "+fmt.Sprint(item["vendor"])+"，类别 "+fmt.Sprint(item["category"])+"）。"+
					"这条是环境事实，用于判断哪些动作会被记录或拦下；平台不据此提供任何规避建议。",
				evidence, worker, nil,
				fmt.Sprintf("endpoint:%d:%s", sess.ID, name))
			if err != nil {
				return "终端防护已识别，但写入发现台账失败：" + err.Error()
			}
		}
		if n, _ := parsed["unidentified"].(int); n > 0 {
			return fmt.Sprintf("终端防护：%d 条已写入发现台账；另有 %d 个进程名未登记，需人工确认（见本次运行记录）", products, n)
		}
		if products == 0 {
			return "终端防护：签名表内没有命中（表是人工整理的子集，未命中不等于没有防护）"
		}
		return fmt.Sprintf("终端防护：%d 条已写入发现台账", products)

	case "patches":
		if incomplete, _ := parsed["incomplete"].(bool); incomplete {
			return "补丁基线：没有读到完整的补丁列表，本轮不做缺失判断（不等于不缺补丁）"
		}
		installed, _ := parsed["installed"].(int)
		if installed == 0 {
			return "补丁基线：没有读到任何已安装补丁条目，不做缺失判断"
		}
		recorded, pending := 0, 0
		for _, raw := range asAnySlice(parsed["items"]) {
			item, ok := raw.(map[string]any)
			if !ok || item["kind"] != "patch" {
				continue
			}
			advisory, _ := item["advisory"].(string)
			if advisory == "" || item["state"] == "installed" {
				continue
			}
			pending++
			evidence := fmt.Sprintf("主机 %s（会话 #%d）· OS %s / build %s · 已安装补丁 %d 条 · 基线 KB 集合未出现",
				firstNonEmpty(host, "未知"), sess.ID, fmt.Sprint(parsed["os_name"]), fmt.Sprint(parsed["os_build"]), installed)
			// 严重度给 medium 而不是通告本身的 high：这是「基线未命中」，不是验证过的漏洞。
			// 累计更新会取代早期 KB 编号，一台打满补丁的机器也可能一条都不出现。
			_, _, err := pg.UpsertFinding(taskID, 0, findingClassMissingPatch,
				"补丁基线未命中："+advisory+"（"+fmt.Sprint(item["title"])+"，待确认）", "medium",
				"已安装补丁列表里没有出现基线 "+advisory+" 的任何 KB 编号。"+
					"**这不等于该漏洞存在**：累计更新可能已取代基线里的编号，也可能是策略或版本差异。"+
					"要确认请按 OS build 与小补丁级别核对官方安全更新，或用 WSUS/SCCM 的补丁清单比对。",
				evidence, worker, nil,
				fmt.Sprintf("patch:%d:%s", sess.ID, advisory))
			if err != nil {
				return "补丁基线结果已算出，但写入发现台账失败：" + err.Error()
			}
			recorded++
		}
		if recorded == 0 {
			return fmt.Sprintf("补丁基线：已安装 %d 条，基线关注项均已命中或无缺口", installed)
		}
		return fmt.Sprintf("补丁基线：%d 条未命中已写入发现台账（待确认，非验证结论）", pending)
	}
	return ""
}

// sessionEndpointNote 给 agent 工具用：把这台主机上已识别的终端防护随命令结果一起交回去。
// 这是「识别结果作为决策输入」的落点——worker 不必先猜再去查。
func sessionEndpointNote(pg *db.DB, sessionID int64) string {
	if pg == nil {
		return ""
	}
	runs, err := pg.ListIntranetScriptRuns(sessionID, 40)
	if err != nil {
		return ""
	}
	for _, run := range runs {
		if !containsString(endpointScriptIDs, run.ScriptID) || run.Status != "done" {
			continue
		}
		kind := fmt.Sprint(run.Parsed["kind"])
		if kind != "endpoint" {
			continue
		}
		var names []string
		for _, raw := range asAnySlice(run.Parsed["items"]) {
			item, ok := raw.(map[string]any)
			if !ok || item["kind"] != "product" {
				continue
			}
			if n, _ := item["product"].(string); n != "" {
				names = append(names, n)
			}
		}
		summary, _ := run.Parsed["summary"].(string)
		if len(names) == 0 {
			if strings.Contains(summary, "没有读到") {
				return "终端防护状态未知（此前一次收集没读到进程/服务列表）；做落地类动作前重新收集，不要假设没有防护"
			}
			return "终端防护：签名表未命中（表是人工整理的子集），未命中不等于没有防护"
		}
		return "终端防护：" + strings.Join(names, "、") + "（识别自本次会话的进程/服务列表；平台不提供规避建议）"
	}
	return ""
}

func asAnySlice(v any) []any {
	if out, ok := v.([]any); ok {
		return out
	}
	return nil
}
