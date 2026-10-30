package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/Autumn-27/jingwei/agent"
	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/traffic"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) seedFindingWorkflowTools() {
	const hostSearchDescriptionFlag = "finding_workflow_tools_v3_host_search_description"
	if value, _, _ := s.m.pg.GetSetting(hostSearchDescriptionFlag); value != "true" {
		// Only replace the original built-in text. A user-edited description is
		// authoritative and must survive upgrades.
		legacy := "查询记录代理已抓取的目标流量（必须指定 host，可再按 URL 子串或正文关键词过滤）。body_contains 会在已抓取的请求/响应头与正文中做全文搜索，支持任意子串和中文（至少 3 个字符），可用来找响应里的密码、密钥、报错、内网地址等。仅返回极轻量索引(id/method/url/status/resp_len)，不含任何响应内容。默认只返回 3 条、每页最多 10 条；结果多时用 page 翻页（page=0 起）；要看某条的请求/响应原文用 traffic_get(id)。回看已访问资源、找端点先用它，避免重复 curl 同一 URL。"
		if _, err := s.m.pg.Exec(`UPDATE tools SET description=$1,updated_at=now() WHERE key='traffic_search' AND system AND description=$2`, traffic.TrafficSearchDescription, legacy); err != nil {
			// Log and leave the flag unset so the next startup retries; do not
			// return, or a transient error here would also skip the reporter
			// migration below — the two are independent.
			log.Printf("[evidence] upgrade traffic_search description: %v", err)
		} else {
			_ = s.m.pg.SetSetting(hostSearchDescriptionFlag, "true")
		}
	}
	const reportFindingDefaultsFlag = "finding_workflow_tools_v4_report_finding_defaults"
	if value, _, _ := s.m.pg.GetSetting(reportFindingDefaultsFlag); value != "true" {
		if err := s.upgradeReportFindingDefaults(); err != nil {
			// Leave the flag unset so the next startup retries.
			log.Printf("[evidence] upgrade report_finding defaults: %v", err)
		} else {
			_ = s.m.pg.SetSetting(reportFindingDefaultsFlag, "true")
		}
	}
	const flag = "finding_workflow_tools_v2_reporter"
	if value, _, _ := s.m.pg.GetSetting(flag); value == "true" {
		return
	}
	for _, key := range []string{"report_finding", "add_hint", "add_task_hint"} {
		row, err := s.m.pg.GetTool(key)
		if err != nil {
			log.Printf("[evidence] load %s: %v", key, err)
			return
		}
		if row == nil || !row.System {
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(row.Schema, &schema); err != nil {
			log.Printf("[evidence] invalid schema for %s: %v", key, err)
			return
		}
		if schema == nil {
			log.Printf("[evidence] missing object schema for %s", key)
			return
		}
		props := objectProperty(schema, "properties")
		if key == "report_finding" {
			if _, exists := props["evidence_hint_id"]; !exists {
				props["evidence_hint_id"] = map[string]any{"type": "integer", "description": "可选：本任务中对应此漏洞的 hint ID；读取该提示保存的 traffic_refs 一并绑定，无提示时省略"}
			}
		} else {
			if _, exists := props["traffic_refs"]; !exists {
				props["traffic_refs"] = agent.HintTrafficSchema()
			}
			hints := objectProperty(props, "hints")
			if _, exists := hints["type"]; !exists {
				hints["type"] = "array"
			}
			items := objectProperty(hints, "items")
			if _, ok := items["type"]; !ok {
				items["type"] = "object"
			}
			itemProps := objectProperty(items, "properties")
			for name, value := range map[string]any{"text": strParam("提示内容"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": agent.HintTrafficSchema()} {
				if _, exists := itemProps[name]; !exists {
					itemProps[name] = value
				}
			}
		}
		raw, _ := json.Marshal(schema)
		result, err := s.m.pg.Exec(`UPDATE tools SET schema=$2::jsonb,updated_at=now() WHERE key=$1 AND system AND schema=$3::jsonb`, key, string(raw), string(row.Schema))
		if err != nil {
			log.Printf("[evidence] upgrade %s: %v", key, err)
			return
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return
		} // preserve concurrent user edits
	}
	// Upgrade only the original default binding. Customized lists and enabled
	// flags survive; the one-time flag also preserves future user unbinding.
	readers := `["worker","reporter"]`
	for _, key := range []string{"traffic_search", "traffic_get", "traffic_blob"} {
		if _, err := s.m.pg.Exec(`UPDATE tools SET agents=$2::jsonb WHERE key=$1 AND system AND (agents='["worker"]'::jsonb OR (agents @> '["worker","planner","mainagent","auto","pentest"]'::jsonb AND jsonb_array_length(agents)=5))`, key, readers); err != nil {
			return
		}
	}
	if _, err := s.m.pg.Exec(`UPDATE tools SET agents=$1::jsonb WHERE key='get_finding_traffic' AND system AND agents @> '["auto","reporter"]'::jsonb AND jsonb_array_length(agents)=2`, `["auto","reporter","worker","planner","mainagent","pentest"]`); err != nil {
		return
	}
	// Replace the previous code default only; preserve customized binding lists.
	if _, err := s.m.pg.Exec(`UPDATE tools SET agents='["reporter"]'::jsonb WHERE key='bind_finding_traffic' AND system AND agents @> '["worker","planner","mainagent","auto","pentest"]'::jsonb AND jsonb_array_length(agents)=5`); err != nil {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("reporter", []string{"bind_finding_traffic"}); err != nil {
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// legacyReportFindingDescription is the seeded text from before the structured
// reproduction process became mandatory. Only this exact text is upgraded, so a
// user-authored description always survives the migration.
const legacyReportFindingDescription = "记录确认的漏洞。HTTP 漏洞的 evidence 用原始 HTTP 请求/响应报文（请求行、Host、关键请求头、响应状态行与关键响应片段）说明复现与验证结论，并配合 traffic_refs 绑定已采集的真实流量；非 HTTP 协议（Redis/MySQL/SSH 等）用 protocol 写明协议名，并把实际收发字节放进 raw_request/raw_response，evidence 写协议层结论。任何情况都不要用 curl 命令或口头描述代替报文。任务上下文传当前 intent_id。返回的 finding_id 是独立漏洞记录 ID，finding_node_id 是探索节点 ID（第一行保留该节点编号）。"

// upgradeReportFindingDefaults backfills parameters added to report_finding after
// an install was seeded. The stored system-tool schema is what the model sees,
// and SeedTool only inserts once, so an upgraded install otherwise keeps a
// schema without reproduction/cvss while the executor requires reproduction —
// every report_finding call then fails validation.
func (s *Server) upgradeReportFindingDefaults() error {
	row, err := s.m.pg.GetTool("report_finding")
	if err != nil {
		return err
	}
	if row == nil || !row.System {
		return nil
	}
	var schema map[string]any
	if err := json.Unmarshal(row.Schema, &schema); err != nil {
		return fmt.Errorf("invalid report_finding schema: %w", err)
	}
	if schema == nil {
		return errors.New("missing report_finding object schema")
	}
	desc, defaults := agent.ReportFindingDefaults()
	if mergeMissingToolProps(schema, defaults) {
		raw, err := json.Marshal(schema)
		if err != nil {
			return err
		}
		// Optimistic concurrency: if the row changed since we read it, leave the
		// flag unset and retry next start instead of overwriting a user edit.
		result, err := s.m.pg.Exec(`UPDATE tools SET schema=$1::jsonb,updated_at=now() WHERE key='report_finding' AND system AND schema=$2::jsonb`, string(raw), string(row.Schema))
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return errors.New("report_finding schema changed concurrently; will retry")
		}
	}
	if row.Description == legacyReportFindingDescription {
		if _, err := s.m.pg.Exec(`UPDATE tools SET description=$1,updated_at=now() WHERE key='report_finding' AND system AND description=$2`, desc, legacyReportFindingDescription); err != nil {
			return err
		}
	}
	return nil
}

// mergeMissingToolProps adds top-level properties and required entries that the
// code default declares but the stored schema lacks. Existing properties keep
// their user-edited descriptions; reports whether the schema changed.
func mergeMissingToolProps(schema, defaults map[string]any) bool {
	changed := false
	wantProps, _ := defaults["properties"].(map[string]any)
	props := objectProperty(schema, "properties")
	for name, spec := range wantProps {
		if _, exists := props[name]; !exists {
			props[name] = spec
			changed = true
		}
	}
	required := stringList(schema["required"])
	present := make(map[string]bool, len(required))
	for _, name := range required {
		present[name] = true
	}
	for _, name := range stringList(defaults["required"]) {
		if !present[name] {
			required = append(required, name)
			present[name] = true
			changed = true
		}
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return changed
}

func stringList(value any) []string {
	switch list := value.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func objectProperty(parent map[string]any, key string) map[string]any {
	value, ok := parent[key].(map[string]any)
	if !ok {
		value = map[string]any{}
		parent[key] = value
	}
	return value
}

func (s *Server) agentFindingTrafficAccess(ctx context.Context, id int64, write bool) error {
	if write {
		if err := s.checkCaseReviewScope(ctx, "bind_finding_traffic", findingCaseRequest{}); err != nil {
			return err
		}
	}
	if id <= 0 {
		return errors.New("finding_id 必须为独立漏洞记录 ID；不是探索节点 ID")
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		return err
	}
	if f == nil {
		return fmt.Errorf("%w：finding_id=%d。证据工具使用独立漏洞记录 ID，请从 list_task_findings / get_task_node_detail 的 finding_id 字段读取；不要传 id / finding_node_id", db.ErrFindingNotFound, id)
	}
	if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 {
		task := s.m.ResolveTask(strconv.FormatInt(ri.TaskID, 10))
		if task == nil {
			return errors.New("任务不存在")
		}
		_, inherited, allowed := findingProvenanceInTask(task, f.TaskID)
		if !allowed {
			return errors.New("当前任务不可读取该漏洞")
		}
		if write && inherited {
			return errors.New("继承漏洞的流量证据只读，请到来源任务修改")
		}
	}
	return nil
}

func (s *Server) toolBindFindingTraffic() actool.CoreTool {
	return wrTool("bind_finding_traffic", "为已登记漏洞补绑经核实的真实 HTTP 流量。finding_id 使用独立漏洞记录 ID；不要传探索节点 ID。同批引用全部成功或全部失败，重复引用不覆盖已有说明。补绑会使已有报告标记待更新；不要为补包重新探测或重复创建漏洞。",
		objSchema(map[string]any{"finding_id": strParam("独立漏洞记录 ID，从 list_task_findings / get_task_node_detail 的 finding_id 字段读取"), "traffic_refs": agent.HintTrafficSchema()}, "finding_id", "traffic_refs"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			if !s.m.pg.GetBool(settingAgentTrafficBinding, true) {
				return actool.Errorf("Agent 自动绑定流量已关闭；请在系统设置开启，或使用页面人工绑定。"), nil
			}
			var args struct {
				FindingID json.RawMessage `json:"finding_id"`
				Refs      []db.TrafficRef `json:"traffic_refs"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			id := parseProfileID(args.FindingID)
			if err := s.agentFindingTrafficAccess(ctx, id, true); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(args.Refs) == 0 {
				return actool.Errorf("补绑需要至少一条已核实的 traffic_refs；无流量无需调用此工具"), nil
			}
			list, err := s.evidenceStore().Bind(ctx, id, args.Refs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(trafficSummary(list))
		})
}
