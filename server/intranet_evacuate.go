package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	actool "github.com/Autumn-27/norma/tool"
)

// ---------------------------------------------------------------------------
// 撤离清理（P4）：以落地物台账为唯一依据，按登记逆序执行撤销并用验证命令确认；
// 随后拆除任务隧道、释放受管回调/监听资源、关闭会话，输出可审计的撤离报告。
// webshell 是人工投放的入口，平台只记录不自动删除，报告中列为残留提醒。
// ---------------------------------------------------------------------------

type intranetEvacuationOptions struct {
	TaskID        int64
	DryRun        bool
	CloseSessions bool
	Note          string
}

type intranetEvacuationItem struct {
	Type   string `json:"type"`
	ID     int64  `json:"id"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Host   string `json:"host"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type intranetEvacuationTotals struct {
	Total  int `json:"total"`
	Done   int `json:"done"`
	Failed int `json:"failed"`
}

type intranetEvacuationReport struct {
	TaskID     int64                    `json:"task_id"`
	DryRun     bool                     `json:"dry_run"`
	StartedAt  time.Time                `json:"started_at"`
	FinishedAt time.Time                `json:"finished_at"`
	Artifacts  intranetEvacuationTotals `json:"artifacts"`
	Tunnels    intranetEvacuationTotals `json:"tunnels"`
	Resources  intranetEvacuationTotals `json:"resources"`
	Sessions   intranetEvacuationTotals `json:"sessions"`
	Items      []intranetEvacuationItem `json:"items"`
	Residual   []string                 `json:"residual"`
	Summary    string                   `json:"summary"`
}

func intranetEvacuationDetail(out intranetExecOutcome) string {
	detail := strings.TrimSpace(out.Output)
	if detail == "" {
		detail = strings.TrimSpace(out.Note)
	}
	return truncateIntranetOutput(detail, 300)
}

func (r *intranetEvacuationReport) finish(dryRun bool) {
	r.FinishedAt = time.Now()
	if dryRun {
		r.Summary = fmt.Sprintf("撤离预览：待撤销落地物 %d 条、待拆除隧道 %d 条、待释放受管资源 %d 条、待关闭会话 %d 个",
			r.Artifacts.Total, r.Tunnels.Total, r.Resources.Total, r.Sessions.Total)
		return
	}
	r.Summary = fmt.Sprintf("撤离完成：落地物 %d/%d 已撤销并验证，隧道 %d/%d 已拆除，受管资源 %d/%d 已释放，会话关闭 %d/%d",
		r.Artifacts.Done, r.Artifacts.Total, r.Tunnels.Done, r.Tunnels.Total,
		r.Resources.Done, r.Resources.Total, r.Sessions.Done, r.Sessions.Total)
	if len(r.Residual) > 0 {
		r.Summary += fmt.Sprintf("；残留 %d 项，请按 residual 清单人工处理", len(r.Residual))
	} else {
		r.Summary += "；未发现残留"
	}
}

// intranetEvacuate runs the whole evacuation sequence in deployment-reverse
// order. It never aborts on one failure: every item is attempted and reported,
// so a retry or a human can pick up exactly what is left.
func (s *Server) intranetEvacuate(ctx context.Context, pg *db.DB, opts intranetEvacuationOptions) *intranetEvacuationReport {
	rep := &intranetEvacuationReport{
		TaskID: opts.TaskID, DryRun: opts.DryRun, StartedAt: time.Now(),
		Items: []intranetEvacuationItem{}, Residual: []string{},
	}
	note := strings.TrimSpace(opts.Note)
	if note == "" {
		note = "撤离清理"
	}

	// 1. 落地物：id 倒序即部署逆序，撤销后立即用 verify_command 验证。
	artifacts, err := pg.ListActiveIntranetArtifactsByTask(opts.TaskID)
	if err != nil {
		rep.Residual = append(rep.Residual, "读取落地物台账失败："+err.Error())
	}
	rep.Artifacts.Total = len(artifacts)
	for _, art := range artifacts {
		item := intranetEvacuationItem{
			Type: "artifact", ID: art.ID, Kind: art.Kind,
			Name: displayOr(art.Name, art.Path), Host: art.Host,
		}
		if opts.DryRun {
			item.Status = "planned"
			item.Detail = art.Path
		} else {
			_, _, verify, revoked, rerr := s.intranetRevokeArtifact(ctx, pg, art.ID, 0)
			if revoked {
				item.Status = "revoked"
				rep.Artifacts.Done++
				item.Detail = intranetEvacuationDetail(verify)
			} else {
				item.Status = "failed"
				rep.Artifacts.Failed++
				if rerr != nil {
					item.Detail = rerr.Error()
				} else {
					item.Detail = "撤销未通过验证"
				}
				rep.Residual = append(rep.Residual, fmt.Sprintf("落地物 #%d（%s %s）仍未撤销：%s",
					art.ID, art.Kind, displayOr(art.Name, art.Path), item.Detail))
			}
		}
		rep.Items = append(rep.Items, item)
	}

	// 2. 隧道：先于关闭会话拆除，拆除命令需要会话的 webshell 通道。
	tunnels, _, terr := pg.ListIntranetTunnels("", opts.TaskID, 0, 500, 0)
	if terr != nil {
		rep.Residual = append(rep.Residual, "读取隧道台账失败："+terr.Error())
	}
	for _, t := range tunnels {
		if t.Status == db.IntranetTunnelStopped {
			continue
		}
		rep.Tunnels.Total++
		item := intranetEvacuationItem{
			Type: "tunnel", ID: t.ID, Kind: t.Kind, Name: t.Name, Host: t.RemoteHost,
		}
		if opts.DryRun {
			item.Status = "planned"
			item.Detail = intranetHostPort(t.ListenHost, t.ListenPort)
			rep.Items = append(rep.Items, item)
			continue
		}
		if t.Status == db.IntranetTunnelPlanned {
			if _, serr := pg.SetIntranetTunnelStatus(t.ID, db.IntranetTunnelStopped, 0, "", note); serr != nil {
				item.Status = "failed"
				item.Detail = serr.Error()
				rep.Tunnels.Failed++
				rep.Residual = append(rep.Residual, fmt.Sprintf("隧道 #%d 标记停止失败：%v", t.ID, serr))
			} else {
				item.Status = "stopped"
				item.Detail = "未部署，无需执行拆除命令"
				rep.Tunnels.Done++
			}
			rep.Items = append(rep.Items, item)
			continue
		}
		usable := false
		if t.SessionID != nil && *t.SessionID > 0 {
			if sess, serr := pg.GetIntranetSession(*t.SessionID); serr == nil && sess.Status != db.IntranetSessionClosed {
				usable = true
			}
		}
		teardown := strings.TrimSpace(t.TeardownCommand)
		if teardown == "" {
			teardown = intranetKillCommand(ptrInt(t.PID))
		}
		switch {
		case !usable:
			item.Status = "failed"
			item.Detail = "绑定会话不可用，拆除命令未执行"
		case teardown == "":
			item.Status = "failed"
			item.Detail = "没有可执行的拆除命令（缺少 teardown_command/PID）"
		default:
			if s.resourceMgr != nil {
				if res, _ := pg.FindActiveManagedResourceByTunnel(t.ID); res != nil {
					_, _ = s.resourceMgr.release(ctx, res.ID, note)
				} else {
					s.intranetStopTunnel(ctx, t.ID, note)
				}
			} else {
				s.intranetStopTunnel(ctx, t.ID, note)
			}
			if fresh, gerr := pg.GetIntranetTunnel(t.ID); gerr == nil && fresh.Status == db.IntranetTunnelStopped {
				item.Status = "stopped"
				item.Detail = truncateIntranetOutput(strings.TrimSpace(fresh.Evidence), 300)
				rep.Tunnels.Done++
			} else {
				item.Status = "failed"
				item.Detail = "拆除后状态未变为 stopped"
				if gerr != nil {
					item.Detail = gerr.Error()
				}
			}
		}
		if item.Status != "stopped" {
			rep.Tunnels.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("隧道 #%d（%s -> %s）：%s",
				t.ID, intranetHostPort(t.ListenHost, t.ListenPort), intranetHostPort(t.RemoteHost, t.RemotePort), item.Detail))
		}
		rep.Items = append(rep.Items, item)
	}

	// 3. 受管资源：回调/监听端口直接释放；webshell 只提醒，不自动删除。
	resources, _, rerr := pg.ListManagedResources("", db.ManagedActive, 500, 0)
	if rerr != nil {
		rep.Residual = append(rep.Residual, "读取受管资源台账失败："+rerr.Error())
	}
	for _, res := range resources {
		if res.TaskID == nil || *res.TaskID != opts.TaskID {
			continue
		}
		if res.Kind == db.ManagedKindTunnel {
			continue // 由第 2 步的隧道拆除一并释放
		}
		if res.Kind == db.ManagedKindWebshell {
			rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）仍保留：平台不自动删除，请确认是否手动清除",
				res.ID, displayOr(res.Endpoint, res.Name)))
			continue
		}
		rep.Resources.Total++
		item := intranetEvacuationItem{
			Type: "resource", ID: res.ID, Kind: res.Kind, Name: res.Name, Host: res.Target,
		}
		if opts.DryRun {
			item.Status = "planned"
			item.Detail = res.Endpoint
		} else {
			ok := false
			var relErr error
			if s.resourceMgr != nil {
				ok, relErr = s.resourceMgr.release(ctx, res.ID, note)
			} else {
				_, ok, relErr = pg.ReleaseManagedResource(res.ID, note)
			}
			if ok {
				item.Status = "released"
				item.Detail = res.Endpoint
				rep.Resources.Done++
			} else {
				item.Status = "failed"
				item.Detail = "释放失败"
				if relErr != nil {
					item.Detail = relErr.Error()
				}
				rep.Resources.Failed++
				rep.Residual = append(rep.Residual, fmt.Sprintf("受管资源 #%d（%s %s）释放失败：%s",
					res.ID, res.Kind, res.Endpoint, item.Detail))
			}
		}
		rep.Items = append(rep.Items, item)
	}

	// 4. 会话：最后关闭；已关闭的会话不再列入 active 查询。
	sessions, _, serr := pg.ListIntranetSessions(db.IntranetSessionActive, opts.TaskID, 500, 0)
	if serr != nil {
		rep.Residual = append(rep.Residual, "读取会话失败："+serr.Error())
	}
	for _, sess := range sessions {
		rep.Sessions.Total++
		item := intranetEvacuationItem{
			Type: "session", ID: sess.ID, Kind: "session", Name: sess.Name, Host: sess.Host,
		}
		switch {
		case opts.DryRun:
			item.Status = "planned"
			item.Detail = sess.Cwd
		case !opts.CloseSessions:
			item.Status = "skipped"
			item.Detail = "按要求保留会话"
			rep.Residual = append(rep.Residual, fmt.Sprintf("会话 #%d（%s）按要求保留未关闭", sess.ID, displayOr(sess.Host, sess.Name)))
		default:
			if _, uerr := pg.UpdateIntranetSessionState(sess.ID, "", db.IntranetSessionClosed, note); uerr != nil {
				item.Status = "failed"
				item.Detail = uerr.Error()
				rep.Sessions.Failed++
				rep.Residual = append(rep.Residual, fmt.Sprintf("会话 #%d 关闭失败：%v", sess.ID, uerr))
			} else {
				item.Status = "closed"
				rep.Sessions.Done++
			}
		}
		rep.Items = append(rep.Items, item)
	}

	rep.finish(opts.DryRun)
	return rep
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

func (s *Server) evacuateIntranetTask(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		TaskID        int64  `json:"task_id"`
		DryRun        bool   `json:"dry_run"`
		CloseSessions *bool  `json:"close_sessions"`
		Note          string `json:"note"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.TaskID <= 0 {
		writeErr(w, 400, "task_id 必填")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	opts := intranetEvacuationOptions{TaskID: req.TaskID, DryRun: req.DryRun, CloseSessions: true, Note: req.Note}
	if req.CloseSessions != nil {
		opts.CloseSessions = *req.CloseSessions
	}
	writeJSON(w, 200, map[string]any{"report": s.intranetEvacuate(r.Context(), pg, opts)})
}

// ---------------------------------------------------------------------------
// LLM 工具
// ---------------------------------------------------------------------------

func (s *Server) toolIntranetEvacuate() actool.CoreTool {
	return wrTool("intranet_evacuate",
		"撤离清理（任务收尾必做）：按落地物台账 id 逆序执行每条 revoke_command 并用 verify_command 验证痕迹消失，随后拆除本任务隧道、释放受管回调/监听资源、关闭会话，返回逐项撤离报告与残留清单。dry_run=true 只预览不执行。webshell 不会自动删除，会列入 residual 提醒。执行前确认该任务已不需要维持权限；有 failed/residual 时如实汇报，不要声称已清理干净。",
		objSchema(map[string]any{
			"task_id":        intranetIntParam("任务 ID（可选，默认当前任务）"),
			"dry_run":        map[string]any{"type": "boolean", "description": "true=只预览将撤销/拆除/关闭的对象，不执行（默认 false）"},
			"close_sessions": map[string]any{"type": "boolean", "description": "是否关闭本任务活跃会话，默认 true"},
			"note":           strParam("报告备注（可选）"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID        int64  `json:"task_id"`
				DryRun        bool   `json:"dry_run"`
				CloseSessions *bool  `json:"close_sessions"`
				Note          string `json:"note"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if a.TaskID <= 0 {
				a.TaskID = intranetCtxTaskID(ctx)
			}
			if a.TaskID <= 0 {
				return actool.Errorf("需要 task_id（当前上下文没有任务）"), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			opts := intranetEvacuationOptions{TaskID: a.TaskID, DryRun: a.DryRun, CloseSessions: true, Note: a.Note}
			if a.CloseSessions != nil {
				opts.CloseSessions = *a.CloseSessions
			}
			return jsonResult(s.intranetEvacuate(ctx, pg, opts))
		})
}
