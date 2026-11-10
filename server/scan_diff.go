package server

import (
	"net/http"

	"github.com/Autumn-27/jingwei/db"
)

// 两次扫描的增量视图：新增 / 消失 / 等级变化。
//
// 「消失」必须给出原因：目标本轮不可达与漏洞已修复在报告里是两件完全不同的事——
// 前者说明这次没测，后者才说明问题解决了。判定用本轮的结果行与资产发现：
// 同一个 host 本轮还出过任何结果/资产，就算可达；整台机器都没出现，才记不可达。
// 本轮一条结果都没有时不猜：写明「无法区分」。

type scanDiffItem struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched_at"`
	Key        string `json:"key"`
}

type scanSeverityChange struct {
	scanDiffItem
	OldSeverity string `json:"old_severity"`
	NewSeverity string `json:"new_severity"`
}

type scanGoneItem struct {
	scanDiffItem
	Reason string `json:"reason"`
}

type scanDiff struct {
	CurrentID       int64                `json:"current_id"`
	AgainstID       int64                `json:"against_id"`
	CurrentTotal    int                  `json:"current_total"`
	AgainstTotal    int                  `json:"against_total"`
	New             []scanDiffItem       `json:"new"`
	Gone            []scanGoneItem       `json:"gone"`
	SeverityChanged []scanSeverityChange `json:"severity_changed"`
}

func scanDiffKey(r db.ScanTaskResult) string {
	return r.TemplateID + "|" + r.MatchedAt + "|" + r.Host
}

// computeScanDiff 是纯函数：输入两轮结果与本轮可达主机集合，输出增量。
// 同样的 key 出现多次时以最后一条为准（同一模板同一地址重复命中不重复计数）。
func computeScanDiff(current, against []db.ScanTaskResult, reachable map[string]bool) scanDiff {
	// 三个列表必须是空数组而不是 null：界面直接读 diff.new.length / .map，
	// 没有增量的那一类如果序列化成 null，前端会抛 TypeError 把整个面板打白。
	out := scanDiff{
		CurrentTotal:    len(current),
		AgainstTotal:    len(against),
		New:             []scanDiffItem{},
		Gone:            []scanGoneItem{},
		SeverityChanged: []scanSeverityChange{},
	}
	cur := map[string]db.ScanTaskResult{}
	order := []string{}
	for _, r := range current {
		k := scanDiffKey(r)
		if _, ok := cur[k]; !ok {
			order = append(order, k)
		}
		cur[k] = r
	}
	seenBase := map[string]bool{}
	for _, r := range against {
		k := scanDiffKey(r)
		seenBase[k] = true
		c, ok := cur[k]
		if !ok {
			item := scanDiffItem{TemplateID: r.TemplateID, Name: r.Name, Severity: r.Severity,
				Host: r.Host, MatchedAt: r.MatchedAt, Key: k}
			reason := "已修复（本轮未复现）"
			if len(current) == 0 {
				reason = "本次扫描没有产出任何结果，无法区分「未修复」与「不可达」"
			} else if !reachable[r.Host] {
				reason = "目标不可达（本轮未发现该主机，不能算已修复）"
			}
			out.Gone = append(out.Gone, scanGoneItem{scanDiffItem: item, Reason: reason})
			continue
		}
		if c.Severity != r.Severity {
			out.SeverityChanged = append(out.SeverityChanged, scanSeverityChange{
				scanDiffItem: scanDiffItem{TemplateID: c.TemplateID, Name: c.Name, Severity: c.Severity,
					Host: c.Host, MatchedAt: c.MatchedAt, Key: k},
				OldSeverity: r.Severity, NewSeverity: c.Severity,
			})
		}
	}
	for _, k := range order {
		if seenBase[k] {
			continue
		}
		r := cur[k]
		out.New = append(out.New, scanDiffItem{TemplateID: r.TemplateID, Name: r.Name, Severity: r.Severity,
			Host: r.Host, MatchedAt: r.MatchedAt, Key: k})
	}
	return out
}

// scanDiffHandler 返回本轮相对基线的增量。against 省略时取最近一个已完成扫描。
func (s *Server) scanDiffHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的扫描任务 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	against := int64(atoiDefault(r.URL.Query().Get("against"), 0))
	if against == 0 {
		prev, err := pg.PreviousDoneScanTask(id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if prev == nil {
			writeErr(w, 404, "没有可作为基线的已完成扫描")
			return
		}
		against = prev.ID
	}
	if against == id {
		writeErr(w, 400, "基线不能是本轮自己")
		return
	}
	if _, err := pg.GetScanTask(against); err != nil {
		writeErr(w, 404, "基线扫描任务不存在")
		return
	}
	current, err := pg.ListScanTaskResultsForDiff(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	base, err := pg.ListScanTaskResultsForDiff(against)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 「本轮可达」= 本轮出过结果或登记过资产的 host。
	reachable := map[string]bool{}
	for _, res := range current {
		reachable[res.Host] = true
	}
	if assets, err := pg.ListScanTaskAssets(id, 2000); err == nil {
		for _, a := range assets {
			if a.Host != "" {
				reachable[a.Host] = true
			}
		}
	}
	diff := computeScanDiff(current, base, reachable)
	diff.CurrentID, diff.AgainstID = id, against
	writeJSON(w, 200, diff)
}
