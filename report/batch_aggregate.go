package report

// P7 · 批量任务跨任务汇总导出：把多个派生任务的 findings 按 dedupe_key
// （类+主机集合+接口族，1.6.3/R18 口径）归并去重，输出可导出汇总报告。
//
// 跨任务合并时先剥掉 dedupe_key 里的任务前缀（agent:<taskID>:），
// 这样同一根因在不同任务里的发现能合到一起；但类/主机/族不同的洞仍分开——
// 「不误合」由 deliveryGroupKey 的既有口径保证。

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Domren/jingwei/db"
)

// AggregatedFinding 是一条跨任务归并后的发现视图。
type AggregatedFinding struct {
	GroupKey   string  `json:"group_key"`
	Title      string  `json:"title"`
	Class      string  `json:"class"`
	Severity   string  `json:"severity"`
	Count      int     `json:"count"`
	TaskIDs    []int64 `json:"task_ids"`
	FindingIDs []int64 `json:"finding_ids"`
}

// CrossTaskDedupeKey 把 dedupe_key 的任务号归一成 0，使其可跨任务合并，
// 但保留 agent:<任务>:<类>:<主机>:<族> 的五段结构供 deliveryGroupKey 解析。
// 非本平台格式或非数字任务 id 原样返回，避免误伤存量 key。
func CrossTaskDedupeKey(key string) string {
	parts := strings.SplitN(strings.TrimSpace(key), ":", 3)
	if len(parts) == 3 && parts[0] == "agent" {
		if _, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			return "agent:0:" + parts[2]
		}
	}
	return key
}

func crossTaskGroupKey(f *db.DBFinding) string {
	c := *f
	c.DedupeKey = CrossTaskDedupeKey(f.DedupeKey)
	return deliveryGroupKey(&c)
}

// AggregateFindingsAcrossTasks 跨任务归并 findings，返回按 group key 排序的稳定结果。
func AggregateFindingsAcrossTasks(fs []*db.DBFinding) []AggregatedFinding {
	groups := map[string]*AggregatedFinding{}
	order := []string{}
	for _, f := range fs {
		if f == nil {
			continue
		}
		key := crossTaskGroupKey(f)
		g, ok := groups[key]
		if !ok {
			g = &AggregatedFinding{
				GroupKey: key, Title: findingTitle(f),
				Class: deliveryClassKey(f), Severity: f.Severity,
			}
			groups[key] = g
			order = append(order, key)
		}
		g.Count++
		g.FindingIDs = append(g.FindingIDs, f.ID)
		if f.TaskID != nil {
			g.TaskIDs = append(g.TaskIDs, *f.TaskID)
		}
		// 标题取信息量更大的一条（非空优先），保证汇总可读。
		if g.Title == "" && findingTitle(f) != "" {
			g.Title = findingTitle(f)
		}
	}
	sort.Strings(order)
	out := make([]AggregatedFinding, 0, len(order))
	for _, key := range order {
		g := groups[key]
		g.TaskIDs = uniqueSorted(g.TaskIDs)
		g.FindingIDs = uniqueSorted(g.FindingIDs)
		out = append(out, *g)
	}
	return out
}

func uniqueSorted(in []int64) []int64 {
	seen := map[int64]bool{}
	out := make([]int64, 0, len(in))
	for _, v := range in {
		if v > 0 && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// BatchAggregateMarkdown 导出站群级汇总报告。
func BatchAggregateMarkdown(batchName string, groups []AggregatedFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 批量任务汇总报告 — %s\n\n", nz(batchName, "未命名批次"))
	fmt.Fprintf(&b, "生成时间：%s\n\n", time.Now().UTC().Format(time.RFC3339))
	if len(groups) == 0 {
		b.WriteString("（无发现）\n")
		return b.String()
	}
	total := 0
	for _, g := range groups {
		total += g.Count
	}
	fmt.Fprintf(&b, "归并后发现族数：**%d**，原始发现条数：**%d**\n\n", len(groups), total)
	b.WriteString("| 归并键（类/主机/接口族） | 标题 | 严重度 | 任务数 | 原始条数 |\n|---|---|---|---|---|\n")
	for _, g := range groups {
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %d |\n",
			mdCell(g.GroupKey), mdCell(g.Title), nz(g.Severity, "-"), len(g.TaskIDs), g.Count)
	}
	return b.String()
}
