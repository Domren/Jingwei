package server

import (
	"context"
	"encoding/json"

	actool "github.com/Autumn-27/norma/tool"
)

// resourceTools expose the shared managed-resource ledger to LLM agents. They
// read the same table the no-LLM pipeline writes, so both paths see identical
// callbacks/webshells/tunnels. Release is deliberately available: callbacks must
// be closed after use.
func (s *Server) resourceTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolListManagedResources(),
		s.toolReleaseManagedResource(),
		s.toolAuditLocalPorts(),
	}
}

func (s *Server) toolListManagedResources() actool.CoreTool {
	return roTool("list_managed_resources",
		"列出平台受管资源台账：JNDI/回调端口、Webshell、隧道等。包含归属、目标、端点、TTL 与状态。用于确认某个回调/隧道是否仍在使用，避免重复发布或遗留端口。",
		objSchema(map[string]any{
			"kind":   strParam("类型过滤：callback / webshell / tunnel / listener（可选）"),
			"status": strParam("状态过滤：active / released / expired（可选，默认全部）"),
			"limit":  map[string]any{"type": "integer", "description": "返回条数，默认 50，最大 200"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Kind   string `json:"kind"`
				Status string `json:"status"`
				Limit  int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if s.m == nil || s.m.pg == nil {
				return actool.Errorf("数据库未初始化"), nil
			}
			rows, total, err := s.m.pg.ListManagedResources(a.Kind, a.Status, a.Limit, 0)
			if err != nil {
				return actool.Errorf("读取受管资源失败: " + err.Error()), nil
			}
			out := make([]map[string]any, 0, len(rows))
			for i, r := range rows {
				if i >= 100 {
					break
				}
				item := map[string]any{
					"id":       r.ID,
					"kind":     r.Kind,
					"name":     r.Name,
					"endpoint": r.Endpoint,
					"target":   r.Target,
					"owner":    r.Owner,
					"status":   r.Status,
					"note":     r.Note,
				}
				if r.TaskID != nil {
					item["task_id"] = *r.TaskID
				}
				if r.ExpiresAt != nil {
					item["expires_at"] = r.ExpiresAt.Format("2006-01-02 15:04:05")
				}
				if len(r.Metadata) > 0 {
					item["metadata"] = r.Metadata
				}
				out = append(out, item)
			}
			return jsonResult(map[string]any{"resources": out, "total": total})
		})
}

func (s *Server) toolReleaseManagedResource() actool.CoreTool {
	return wrTool("release_managed_resource",
		"释放一个受管资源（如 java-chains 回调端口、隧道）。释放会尝试关闭对应的服务/端口，并标记台账为 released。仅在确认该资源不再使用后调用。",
		objSchema(map[string]any{
			"id":   map[string]any{"type": "integer", "description": "受管资源 ID"},
			"note": strParam("释放原因（可选）"),
		}, "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID   int64  `json:"id"`
				Note string `json:"note"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.ID <= 0 {
				return actool.Errorf("id 必填"), nil
			}
			if s.resourceMgr == nil {
				return actool.Errorf("资源管理器未就绪"), nil
			}
			note := a.Note
			if note == "" {
				note = "LLM 手动释放"
			}
			ok, err := s.resourceMgr.release(ctx, a.ID, note)
			if err != nil {
				return actool.Errorf("释放失败: " + err.Error()), nil
			}
			if !ok {
				return actool.Errorf("资源不存在或已释放"), nil
			}
			return jsonResult(map[string]any{"released": true, "id": a.ID})
		})
}

func (s *Server) toolAuditLocalPorts() actool.CoreTool {
	return roTool("audit_local_ports",
		"审计本机监听端口：列出 TCP 监听、所属进程，并标记受管（台账内）、平台自身与未受管的外网监听。用于自查是否遗留回调端口或意外暴露的服务。",
		objSchema(map[string]any{}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return jsonResult(s.auditLocalPorts(ctx))
		})
}
