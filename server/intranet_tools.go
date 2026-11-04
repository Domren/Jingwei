package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/agent"
	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

// intranetTools exposes the two-phase intranet MVP to LLM agents. Every tool
// writes the same intranet_* tables the UI/API use, so human and agent work
// share one state (sessions, tunnels, pending scope approvals, handoffs).
func (s *Server) intranetTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolIntranetOpenSession(),
		s.toolIntranetExec(),
		s.toolIntranetUpload(),
		s.toolIntranetDownload(),
		s.toolIntranetBatchExec(),
		s.toolIntranetTunnel(),
		s.toolIntranetRecon(),
		s.toolIntranetCredentials(),
		s.toolIntranetCredRegister(),
		s.toolIntranetCredReuse(),
		s.toolIntranetPersist(),
		s.toolIntranetArtifacts(),
		s.toolIntranetArtifactRegister(),
		s.toolIntranetArtifactRevoke(),
		s.toolPHPSemiPersist(),
		s.toolIntranetEvacuate(),
		s.toolIntranetRequestScope(),
		s.toolIntranetHandoff(),
	}
}

func intranetCtxTaskID(ctx context.Context) int64 {
	if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 {
		return ri.TaskID
	}
	return intercept.TaskIDFromContext(ctx)
}

func (s *Server) intranetToolPG() (*db.DB, error) {
	if s.m == nil || s.m.pg == nil {
		return nil, errors.New("数据库未初始化")
	}
	return s.m.pg, nil
}

func intranetIntParam(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func (s *Server) toolIntranetOpenSession() actool.CoreTool {
	return wrTool("intranet_open_session",
		"打开一个可复用的内网会话（逻辑会话，不驻留进程；cwd 由平台维护）。默认 transport=webshell，把一个已登记的 webshell 提升为会话；内网主机只有 22 端口、没有 web 服务时用 transport=ssh，用凭据台账里的账号直接登录，凭据只在打开时读取、不复制进会话。两种 transport 打开时都会探测目标 OS/用户/可用工具并记录到会话事件，后续 intranet_exec/upload/download/batch_exec、权限维持与撤离台账都同样可用。SSH 目标必须先通过任务范围检查；只能经隧道接入时填 dial_host/dial_port（隧道监听地址），host 仍填它在内网段里的真实地址。",
		objSchema(map[string]any{
			"webshell_id":   intranetIntParam("已登记的 webshell ID（transport=webshell 时必填）"),
			"transport":     strParam("webshell（默认）或 ssh"),
			"credential_id": intranetIntParam("凭据台账 ID（transport=ssh 时必填；先用 intranet_cred_register 登记 ssh 账号口令）"),
			"port":          intranetIntParam("SSH 端口，默认 22"),
			"user":          strParam("SSH 登录账号（可选，默认取凭据里的 username）"),
			"dial_host":     strParam("实际连接地址（可选，默认用 host；经端口转发隧道接入时填隧道监听地址）"),
			"dial_port":     intranetIntParam("实际连接端口（可选，经隧道接入时填隧道监听端口）"),
			"name":          strParam("会话名称（可选）"),
			"host":          strParam("目标主机（webshell 会话可省略，默认从其地址推断；SSH 会话必填，写内网真实地址）"),
			"cwd":           strParam("初始工作目录，默认 /"),
			"task_id":       intranetIntParam("归属任务 ID（可选；任务运行中会自动带入当前任务）"),
			"note":          strParam("备注（可选）"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a intranetSessionDTO
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.TaskID <= 0 {
				a.TaskID = intranetCtxTaskID(ctx)
			}
			if db.NormalizeIntranetTransport(a.Transport) == db.IntranetTransportSSH {
				sess, info, serr := s.intranetOpenSSHSession(ctx, pg, intranetSSHSessionRequest{
					Name: a.Name, TaskID: a.TaskID, Host: a.Host, Port: a.Port,
					User: a.User, CredentialID: a.CredentialID,
					DialHost: a.DialHost, DialPort: a.DialPort,
					Cwd: a.Cwd, Note: a.Note,
				})
				out := map[string]any{"probe": info}
				if sess != nil {
					out["session"] = sess
				}
				if serr != nil {
					out["error"] = serr.Error()
					return jsonResult(out)
				}
				return jsonResult(out)
			}
			if a.WebshellID <= 0 {
				return actool.Errorf("webshell_id 必填（SSH 会话请传 transport=ssh 与 credential_id）"), nil
			}
			sess, info, err := s.intranetOpenSession(ctx, pg, a.WebshellID, a.TaskID, a.Name, a.Host, a.Cwd, a.Note)
			if err != nil {
				out := map[string]any{"error": err.Error(), "probe": info}
				if sess != nil {
					out["session"] = sess
				}
				return jsonResult(out)
			}
			return jsonResult(map[string]any{"session": sess, "probe": info})
		})
}

func (s *Server) toolIntranetExec() actool.CoreTool {
	return wrTool("intranet_exec",
		"在指定内网会话中执行一条命令并返回输出、当前目录与退出码。命令是真实执行的外部操作；先用 intranet_open_session/intranet_tunnel action=probe 了解环境。不要凭猜测下结论，输出为空或报错时如实说明。",
		objSchema(map[string]any{
			"session_id":      intranetIntParam("会话 ID（必填）"),
			"command":         strParam("要执行的命令（必填）"),
			"timeout_seconds": intranetIntParam("超时秒数，默认 60，最大 300"),
		}, "session_id", "command"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				SessionID      int64  `json:"session_id"`
				Command        string `json:"command"`
				TimeoutSeconds int    `json:"timeout_seconds"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			sess, err := s.intranetSession(pg, a.SessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			timeout := time.Duration(a.TimeoutSeconds) * time.Second
			if timeout <= 0 || timeout > 300*time.Second {
				timeout = intranetExecTimeout
			}
			out := s.intranetExec(ctx, pg, sess, a.Command, timeout)
			// timed_out / marker_ok are what let a worker tell "this command never
			// returns" apart from "this shell is dead" — without them a stopped
			// wait reads as a transport failure and the next tool call gives up on
			// a session that is still working.
			return jsonResult(map[string]any{"session_id": sess.ID, "cwd": out.Cwd, "output": out.Output, "exit_code": out.ExitCode, "is_error": out.IsError, "timed_out": out.TimedOut, "marker_ok": out.MarkerOK, "note": out.Note})
		})
}

func (s *Server) toolIntranetUpload() actool.CoreTool {
	return wrTool("intranet_upload",
		"通过内网会话上传文件（base64 分块写入目标路径）。content_base64 与 content 二选一；单次最大 4MB。会回读文件大小确认写入。",
		objSchema(map[string]any{
			"session_id":     intranetIntParam("会话 ID（必填）"),
			"path":           strParam("目标绝对路径（必填）"),
			"content_base64": strParam("文件内容的 base64（可选）"),
			"content":        strParam("纯文本内容（可选，适合小脚本）"),
		}, "session_id", "path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				SessionID     int64  `json:"session_id"`
				Path          string `json:"path"`
				ContentBase64 string `json:"content_base64"`
				Content       string `json:"content"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			payload := strings.TrimSpace(a.ContentBase64)
			if payload == "" {
				payload = base64.StdEncoding.EncodeToString([]byte(a.Content))
			}
			data, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return actool.Errorf("content_base64 无效"), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			sess, err := s.intranetSession(pg, a.SessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := s.intranetUpload(ctx, pg, sess, a.Path, data)
			res := map[string]any{"ok": err == nil, "path": a.Path, "bytes": len(data), "output": out.Output, "is_error": out.IsError, "note": out.Note}
			if err != nil {
				res["error"] = err.Error()
			}
			return jsonResult(res)
		})
}

func (s *Server) toolIntranetDownload() actool.CoreTool {
	return roTool("intranet_download",
		"从内网会话读取文件（base64）。默认最多 512KB，单次工具调用建议 ≤64KB；返回 size/total/truncated 与 content_base64。",
		objSchema(map[string]any{
			"session_id": intranetIntParam("会话 ID（必填）"),
			"path":       strParam("目标绝对路径（必填）"),
			"max_bytes":  intranetIntParam("最多读取字节数，默认 65536，最大 262144"),
		}, "session_id", "path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				SessionID int64  `json:"session_id"`
				Path      string `json:"path"`
				MaxBytes  int    `json:"max_bytes"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if a.MaxBytes <= 0 || a.MaxBytes > 256<<10 {
				a.MaxBytes = 64 << 10
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			sess, err := s.intranetSession(pg, a.SessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			data, total, truncated, out := s.intranetDownload(ctx, pg, sess, a.Path, a.MaxBytes)
			res := map[string]any{
				"size": len(data), "total": total, "truncated": truncated,
				"content_base64": base64.StdEncoding.EncodeToString(data),
				"is_error":       out.IsError, "note": out.Note, "output": out.Output,
			}
			if out.IsError {
				res["error"] = displayOr(out.Note, "下载失败")
			}
			return jsonResult(res)
		})
}

func (s *Server) toolIntranetBatchExec() actool.CoreTool {
	return wrTool("intranet_batch_exec",
		"对多个内网会话批量执行同一条命令（串行，最多 50 个）。不传 session_ids 时按 task_id 取该任务全部活跃会话。每个会话返回独立输出/退出码。",
		objSchema(map[string]any{
			"session_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "会话 ID 列表（可选）"},
			"task_id":         intranetIntParam("按任务取活跃会话（可选；任务运行中自动带入当前任务）"),
			"command":         strParam("要执行的命令（必填）"),
			"timeout_seconds": intranetIntParam("单会话超时秒数，默认 60，最大 180"),
		}, "command"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				SessionIDs     []int64 `json:"session_ids"`
				TaskID         int64   `json:"task_id"`
				Command        string  `json:"command"`
				TimeoutSeconds int     `json:"timeout_seconds"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if strings.TrimSpace(a.Command) == "" {
				return actool.Errorf("command 必填"), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(a.SessionIDs) == 0 && a.TaskID <= 0 {
				a.TaskID = intranetCtxTaskID(ctx)
			}
			timeout := time.Duration(a.TimeoutSeconds) * time.Second
			if timeout <= 0 || timeout > 180*time.Second {
				timeout = intranetExecTimeout
			}
			results, err := s.intranetBatchExec(ctx, pg, a.SessionIDs, a.TaskID, a.Command, timeout)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"results": results, "total": len(results)})
		})
}

func (s *Server) toolIntranetTunnel() actool.CoreTool {
	return wrTool("intranet_tunnel",
		"内网隧道生命周期（两阶段）：action=create 先登记计划（socks5/port_forward/reverse_forward），probe 探测目标环境，plan 生成部署命令（chisel/ssh 变体需要平台已配置 JINGWEI_PIVOT_SERVER，没有这些工具又需要端口转发时得手写 deploy_command），deploy 后台启动并登记受管资源（TTL 到期自动拆除），verify 校验监听，teardown 拆除并释放资源，status/list 查询。部署成功后会返回 access 提示（socks5 隧道给出可用的 socks5:// 代理地址）。隧道台账用 listen_side 记录监听端口开在哪一侧：target（socat；chisel client 不带 R:）或 pivot（chisel client 带 R:、ssh -R，监听开在控制端）；verify 与拆除复核都按这一侧做，在错误的一侧复核会把好隧道判成失败。要打只有目标可达的内网段，出口必须在目标侧——即控制端监听的 pivot 形态（chisel R: 或 ssh -R）；socat 也是目标侧出口，但监听在目标，平台得能直接连到目标那个端口。部署到未登记范围的内网主机前，先用 intranet_request_scope 申请并由人审批。",
		objSchema(map[string]any{
			"action":           strParam("create/probe/plan/deploy/verify/teardown/status/list（必填）"),
			"tunnel_id":        intranetIntParam("隧道 ID（除 create/list 外必填）"),
			"session_id":       intranetIntParam("绑定的会话 ID（create 必填）"),
			"task_id":          intranetIntParam("归属任务 ID（可选，默认当前任务）"),
			"name":             strParam("隧道名称（可选）"),
			"kind":             strParam("socks5 / port_forward / reverse_forward，默认 port_forward"),
			"listen_host":      strParam("监听地址：留空或 0.0.0.0 表示全接口（pivot 侧监听必须让平台进程拨得到，别填 127.0.0.1）"),
			"listen_port":      intranetIntParam("监听端口（1-65535）"),
			"listen_side":      strParam("监听端口所在侧：target（默认，socat/chisel 不带 R:）或 pivot（chisel 带 R:、ssh -R，监听开在控制端）；plan 自动选型会改写它，手写 deploy_command 时用这里纠正"),
			"remote_host":      strParam("转发目标主机"),
			"remote_port":      intranetIntParam("转发目标端口"),
			"deploy_command":   strParam("自定义部署命令（可选；支持 echo JW_PID:$! 便于回收）；plan 时传 auto 可按目标当前工具重新自动选型"),
			"verify_command":   strParam("自定义验证命令（可选）"),
			"teardown_command": strParam("自定义拆除命令（可选）"),
			"ttl_seconds":      intranetIntParam("部署后自动回收秒数，默认 3600，最大 86400"),
			"note":             strParam("备注（可选）"),
		}, "action"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Action          string `json:"action"`
				TunnelID        int64  `json:"tunnel_id"`
				SessionID       int64  `json:"session_id"`
				TaskID          int64  `json:"task_id"`
				Name            string `json:"name"`
				Kind            string `json:"kind"`
				ListenHost      string `json:"listen_host"`
				ListenPort      int    `json:"listen_port"`
				ListenSide      string `json:"listen_side"`
				RemoteHost      string `json:"remote_host"`
				RemotePort      int    `json:"remote_port"`
				DeployCommand   string `json:"deploy_command"`
				VerifyCommand   string `json:"verify_command"`
				TeardownCommand string `json:"teardown_command"`
				TTLSeconds      int    `json:"ttl_seconds"`
				Note            string `json:"note"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			side, sideErr := intranetListenSideArg(a.ListenSide)
			if sideErr != nil {
				return actool.Errorf(sideErr.Error()), nil
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			action := strings.ToLower(strings.TrimSpace(a.Action))
			if action == "" {
				return actool.Errorf("action 必填"), nil
			}
			if a.TaskID <= 0 {
				a.TaskID = intranetCtxTaskID(ctx)
			}
			if action == "create" {
				if a.SessionID <= 0 {
					return actool.Errorf("session_id 必填"), nil
				}
				if _, err := s.intranetSession(pg, a.SessionID); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				kind := strings.ToLower(strings.TrimSpace(a.Kind))
				if kind == "" {
					kind = db.IntranetTunnelKindPort
				}
				in := db.IntranetTunnelInput{
					Name: a.Name, SessionID: a.SessionID, TaskID: a.TaskID, Kind: kind,
					ListenHost: a.ListenHost, ListenPort: a.ListenPort, ListenSide: side,
					RemoteHost: intranetHost(a.RemoteHost), RemotePort: a.RemotePort,
					DeployCommand: a.DeployCommand, VerifyCommand: a.VerifyCommand,
					TeardownCommand: a.TeardownCommand, Note: a.Note,
				}
				s.resolveIntranetTunnelTask(pg, &in)
				if reason, allowed := shellAllowed(pg, in.RemoteHost); !allowed {
					return actool.Errorf("目标命中资产拦截规则：" + reason), nil
				}
				t, err := pg.CreateIntranetTunnel(in)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"tunnel": t})
			}
			if action == "list" {
				tunnels, total, err := pg.ListIntranetTunnels("", a.TaskID, a.SessionID, 100, 0)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"tunnels": tunnels, "total": total})
			}
			if a.TunnelID <= 0 {
				return actool.Errorf("tunnel_id 必填"), nil
			}
			t, err := pg.GetIntranetTunnel(a.TunnelID)
			if err != nil {
				return actool.Errorf("隧道不存在"), nil
			}
			switch action {
			case "status":
				return jsonResult(map[string]any{"tunnel": t, "access": s.intranetTunnelAccess(pg, t)})
			case "probe":
				if t.SessionID == nil || *t.SessionID <= 0 {
					return actool.Errorf("隧道未绑定会话"), nil
				}
				sess, err := s.intranetSession(pg, *t.SessionID)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				info, out := s.intranetProbe(ctx, pg, sess)
				return jsonResult(map[string]any{"probe": info, "result": out})
			case "plan":
				// 手写 deploy_command 时自动选型不参与，监听侧只能由操作员用 listen_side
				// 纠正——记错侧，verify 与拆除复核就站错边。
				if side != "" {
					if _, err := pg.UpdateIntranetTunnelPlan(t.ID, "", "", "", "", side); err != nil {
						return actool.Errorf(err.Error()), nil
					}
					if fresh, gerr := pg.GetIntranetTunnel(t.ID); gerr == nil {
						t = fresh
					}
				}
				updated, info, err := s.intranetPlanTunnel(ctx, pg, t, a.DeployCommand, a.VerifyCommand, a.TeardownCommand)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"tunnel": updated, "probe": info, "listen_side": updated.ListenSide})
			case "deploy":
				updated, out, err := s.intranetDeployTunnel(ctx, pg, t, time.Duration(a.TTLSeconds)*time.Second)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"tunnel": updated, "result": out, "access": s.intranetTunnelAccess(pg, updated)})
			case "verify":
				updated, out, err := s.intranetVerifyTunnel(ctx, pg, t)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"tunnel": updated, "result": out, "access": s.intranetTunnelAccess(pg, updated)})
			case "teardown":
				if s.resourceMgr != nil {
					if res, _ := pg.FindActiveManagedResourceByTunnel(t.ID); res != nil {
						_, _ = s.resourceMgr.release(ctx, res.ID, "agent 拆除隧道")
					} else {
						s.intranetStopTunnel(ctx, t.ID, "agent 拆除隧道")
					}
				} else {
					s.intranetStopTunnel(ctx, t.ID, "agent 拆除隧道")
				}
				updated, err := pg.GetIntranetTunnel(t.ID)
				if err != nil {
					return actool.Errorf("隧道不存在"), nil
				}
				return jsonResult(map[string]any{"tunnel": updated})
			default:
				return actool.Errorf("未知 action: " + action), nil
			}
		})
}

func (s *Server) toolIntranetRequestScope() actool.CoreTool {
	return wrTool("intranet_request_scope",
		"为内网主机/端口提交范围审批申请。申请是 pending 状态，必须由人在「内网渗透 → 范围审批」页面批准后才会写入任务授权范围；不要假设已批准，也不要在未批准时强行部署隧道。",
		objSchema(map[string]any{
			"task_id":    intranetIntParam("任务 ID（可选，默认当前任务）"),
			"host":       strParam("内网主机/IP（必填）"),
			"port":       intranetIntParam("端口（可选）"),
			"reason":     strParam("申请理由（建议写清目标来源与测试目的）"),
			"session_id": intranetIntParam("关联会话 ID（可选）"),
		}, "host"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID    int64  `json:"task_id"`
				Host      string `json:"host"`
				Port      int    `json:"port"`
				Reason    string `json:"reason"`
				SessionID int64  `json:"session_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if a.TaskID <= 0 {
				a.TaskID = intranetCtxTaskID(ctx)
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			row, created, err := pg.CreateIntranetScopeRequest(db.IntranetScopeRequestInput{
				TaskID: a.TaskID, Host: intranetHost(a.Host), Port: a.Port, Reason: a.Reason, SessionID: a.SessionID,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"request": row, "created": created, "note": "已提交，等待人工在范围审批页面批准"})
		})
}

func (s *Server) toolIntranetHandoff() actool.CoreTool {
	return wrTool("intranet_handoff",
		"把当前任务的内网成果交接给一个新任务：新任务继承来源关系并复制已登记范围（source=handoff），默认把来源任务的全部会话/隧道归属迁到新任务。可指定新的 goal/description；适合第一阶段侦察结束后转入第二阶段深入利用。",
		objSchema(map[string]any{
			"from_task_id": intranetIntParam("来源任务 ID（可选，默认当前任务）"),
			"name":         strParam("新任务名称（可选）"),
			"goal":         strParam("新任务目标（可选，默认继承原目标并注明交接）"),
			"description":  strParam("新任务描述（可选）"),
			"session_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "要迁移的会话 ID（可选，默认全部）"},
			"tunnel_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "要迁移的隧道 ID（可选，默认全部）"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a intranetHandoffDTO
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数格式错误"), nil
			}
			if a.FromTaskID <= 0 {
				a.FromTaskID = intranetCtxTaskID(ctx)
			}
			pg, err := s.intranetToolPG()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			task, warnings, err := s.intranetHandoff(pg, a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"task": task, "warnings": warnings})
		})
}
