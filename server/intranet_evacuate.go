package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
	actool "github.com/Autumn-27/norma/tool"
)

// ---------------------------------------------------------------------------
// 撤离清理（P4）：以落地物台账为唯一依据，按登记逆序执行撤销并用验证命令确认；
// 随后拆除任务隧道、释放受管回调/监听资源、关闭会话，输出可审计的撤离报告。
// webshell 仅在本任务会话绑定范围内探活/自删除，未开启时列为残留提醒。
// ---------------------------------------------------------------------------

type intranetEvacuationOptions struct {
	TaskID           int64
	DryRun           bool
	CloseSessions    bool
	DeleteWebshells  bool
	SkipResidualScan bool
	Note             string
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

// intranetEvacuationScan counts the active re-verification pass that runs after
// the revoke loop: revoked artifacts are probed again to catch "revoke returned
// OK but the trace is still there".
type intranetEvacuationScan struct {
	Checked int `json:"checked"`
	Present int `json:"present"`
	Gone    int `json:"gone"`
	Unknown int `json:"unknown"`
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
	Memshells  intranetEvacuationTotals `json:"memshells"`
	Webshells  intranetEvacuationTotals `json:"webshells"`
	Scan       intranetEvacuationScan   `json:"scan"`
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
		if r.Memshells.Total > 0 {
			r.Summary += fmt.Sprintf("、本任务内存马 %d 个", r.Memshells.Total)
		}
		if r.Webshells.Total > 0 {
			r.Summary += fmt.Sprintf("、本任务 webshell %d 个", r.Webshells.Total)
		}
		if r.Scan.Checked > 0 {
			r.Summary += fmt.Sprintf("；预扫描 %d 项，仍存在 %d 项", r.Scan.Checked, r.Scan.Present)
		}
		return
	}
	r.Summary = fmt.Sprintf("撤离完成：落地物 %d/%d 已撤销并验证，隧道 %d/%d 已拆除，受管资源 %d/%d 已释放，会话关闭 %d/%d",
		r.Artifacts.Done, r.Artifacts.Total, r.Tunnels.Done, r.Tunnels.Total,
		r.Resources.Done, r.Resources.Total, r.Sessions.Done, r.Sessions.Total)
	if r.Memshells.Total > 0 {
		r.Summary += fmt.Sprintf("，内存马 %d/%d 已确认移除", r.Memshells.Done, r.Memshells.Total)
	}
	if r.Webshells.Total > 0 {
		r.Summary += fmt.Sprintf("，webshell %d/%d 已确认清除", r.Webshells.Done, r.Webshells.Total)
	}
	if r.Scan.Checked > 0 {
		r.Summary += fmt.Sprintf("；残留复核 %d 项（仍存在 %d、未知 %d）", r.Scan.Checked, r.Scan.Present, r.Scan.Unknown)
	}
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
	revokedThisRun := make([]*db.IntranetArtifact, 0, len(artifacts))
	for _, art := range artifacts {
		item := intranetEvacuationItem{
			Type: "artifact", ID: art.ID, Kind: art.Kind,
			Name: displayOr(art.Name, art.Path), Host: art.Host,
		}
		if opts.DryRun {
			item.Status = "planned"
			item.Detail = art.Path
		} else {
			updated, _, verify, revoked, rerr := s.intranetRevokeArtifact(ctx, pg, art.ID, 0)
			if revoked {
				item.Status = "revoked"
				rep.Artifacts.Done++
				item.Detail = intranetEvacuationDetail(verify)
				if updated != nil {
					revokedThisRun = append(revokedThisRun, updated)
				} else {
					revokedThisRun = append(revokedThisRun, art)
				}
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

	// 1b. 残留复核：撤离后重新执行撤销验证命令，抓"撤销返回成功但痕迹仍在"
	// 的情况；dry-run 则复核当前活跃落地物，提前暴露无法清理的对象。
	if !opts.SkipResidualScan {
		targets := artifacts
		if !opts.DryRun {
			targets = revokedThisRun
		}
		s.intranetRescanArtifacts(ctx, pg, targets, rep)
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
				}
			}
			// 台账里的隧道仍要按自己的拆除命令再走一遍：资源回调只活在内存里，
			// release 未必真动过目标上的进程，而撤离报告必须反映目标的实际状态。
			s.intranetStopTunnel(ctx, t.ID, note)
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

	// 3. 受管资源：回调/监听端口直接释放；webshell/内存马由后续步骤处理。
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
			continue // 第 6 步统一探活/自删除，避免重复提醒
		}
		if res.Kind == db.ManagedKindMemshell {
			continue // 第 5 步随内存马移除一并释放
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

	// 5. 内存马：必须先于父 webshell 删除清理，否则会留下无平台记录的内存驻留端点。
	// 优先通过父 shell 反注册，失败再走端点自移除；未确认移除的父 shell 保留。
	blockedShells := s.intranetEvacuateMemshells(ctx, pg, opts.TaskID, rep, opts.DryRun)

	// 6. 本任务会话绑定的 webshell：先探活；显式开启 delete_webshells 时通过
	// v2 自删除操作清除载荷并做 404/标记复核，成功后才移除台账记录。
	s.intranetEvacuateWebshells(ctx, pg, opts.TaskID, rep, opts.DryRun, opts.DeleteWebshells, blockedShells)

	rep.finish(opts.DryRun)
	return rep
}

// intranetEvacuateMemshells removes every memory shell tied to the task (by
// task id or by its parent webshell) and returns the parent webshell ids that
// still carry an unremoved memory shell, so step 6 does not orphan them.
func (s *Server) intranetEvacuateMemshells(ctx context.Context, pg *db.DB, taskID int64,
	rep *intranetEvacuationReport, dryRun bool) map[int64]string {
	blocked := map[int64]string{}
	seen := map[int64]bool{}
	list := make([]*db.JavaMemshell, 0, 8)
	if byTask, _, err := pg.ListJavaMemshells(db.JavaMemshellFilter{TaskID: taskID, Limit: 500}); err != nil {
		rep.Residual = append(rep.Residual, "读取任务内存马失败："+err.Error())
	} else {
		for _, ms := range byTask {
			if !seen[ms.ID] {
				seen[ms.ID] = true
				list = append(list, ms)
			}
		}
	}
	shells, err := pg.ListWebshellsByIntranetTask(taskID)
	if err != nil {
		rep.Residual = append(rep.Residual, "读取任务 webshell（关联内存马）失败："+err.Error())
	}
	ids := make([]int64, 0, len(shells))
	for _, sh := range shells {
		ids = append(ids, sh.ID)
	}
	if len(ids) > 0 {
		if byShell, err := pg.ListJavaMemshellsByWebshells(ids); err != nil {
			rep.Residual = append(rep.Residual, "读取 webshell 关联内存马失败："+err.Error())
		} else {
			for _, ms := range byShell {
				if !seen[ms.ID] {
					seen[ms.ID] = true
					list = append(list, ms)
				}
			}
		}
	}

	for _, ms := range list {
		rep.Memshells.Total++
		label := displayOr(ms.Name, ms.URL)
		item := intranetEvacuationItem{
			Type: "memshell", ID: ms.ID, Kind: ms.Type, Name: label, Host: ms.Target,
		}
		if reason, allowed := shellAllowed(pg, ms.URL); !allowed {
			item.Status = "failed"
			item.Detail = "命中资产拦截规则：" + reason
			rep.Memshells.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("内存马 #%d（%s %s）被拦截规则阻止清理，需人工处理", ms.ID, ms.Type, label))
			blockMemshellParent(blocked, ms, "内存马被拦截规则阻止清理")
			rep.Items = append(rep.Items, item)
			continue
		}
		if dryRun {
			item.Status = "planned"
			item.Detail = ms.URL
			if payload, perr := s.memshellPayloadFor(ms); perr != nil {
				item.Detail = "密钥不可用：" + perr.Error()
			} else {
				client := scanner.NewDeepClient(10 * time.Second)
				probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
				_, probeErr := s.probeMemshellEndpoint(probeCtx, client, ms.URL, payload)
				cancel()
				if probeErr != nil {
					item.Detail = "当前无响应：" + probeErr.Error()
				} else {
					item.Detail = "仍存活；撤离时将先通过父 shell 反注册或端点自移除"
					rep.Residual = append(rep.Residual, fmt.Sprintf("内存马 #%d（%s %s）仍存活（预览未移除）", ms.ID, ms.Type, label))
				}
			}
			rep.Items = append(rep.Items, item)
			continue
		}
		removed, note, attempts := s.removeJavaMemshellRuntime(ctx, pg, ms)
		if !removed {
			item.Status = "failed"
			item.Detail = "移除未确认"
			if note != "" {
				item.Detail += "：" + note
			}
			rep.Memshells.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("内存马 #%d（%s %s）仍存活：%s",
				ms.ID, ms.Type, label, truncateIntranetOutput(strings.Join(attempts, "；"), 300)))
			blockMemshellParent(blocked, ms, "存在未清理的内存马")
			rep.Items = append(rep.Items, item)
			continue
		}
		s.releaseMemshellResource(ms.ID, "撤离自动移除内存马")
		if _, delErr := pg.DeleteJavaMemshell(ms.ID); delErr != nil {
			item.Status = "failed"
			item.Detail = "端点已移除但清理平台记录失败：" + delErr.Error()
			rep.Memshells.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("内存马 #%d（%s %s）端点已移除，但平台记录删除失败：%v",
				ms.ID, ms.Type, label, delErr))
			blockMemshellParent(blocked, ms, "内存马平台记录尚未清理")
			rep.Items = append(rep.Items, item)
			continue
		}
		item.Status = "removed"
		item.Detail = note
		rep.Memshells.Done++
		rep.Items = append(rep.Items, item)
	}
	return blocked
}

func blockMemshellParent(blocked map[int64]string, ms *db.JavaMemshell, reason string) {
	if ms.WebshellID == nil || *ms.WebshellID <= 0 {
		return
	}
	blocked[*ms.WebshellID] = fmt.Sprintf("内存马 #%d（%s）%s", ms.ID, displayOr(ms.Name, ms.Path), reason)
}

// intranetVerifyMarker classifies a verify-command result by its explicit
// marker; a non-zero exit code is ignored because some verify commands use
// `test ... && echo PRESENT || echo GONE` and still exit 0, while custom ones
// may exit 1 after printing GONE.
func intranetVerifyMarker(out intranetExecOutcome) string {
	switch {
	case strings.Contains(out.Output, intranetArtifactPresent):
		return "present"
	case strings.Contains(out.Output, intranetArtifactGone):
		return "gone"
	default:
		return "unknown"
	}
}

// intranetRescanArtifacts re-runs verify commands for the given artifacts and
// records present/unknown results as residuals.
func (s *Server) intranetRescanArtifacts(ctx context.Context, pg *db.DB, arts []*db.IntranetArtifact, rep *intranetEvacuationReport) {
	for _, art := range arts {
		rep.Scan.Checked++
		label := displayOr(art.Name, art.Path)
		verifyCmd := strings.TrimSpace(art.VerifyCommand)
		if verifyCmd == "" {
			rep.Scan.Unknown++
			rep.Residual = append(rep.Residual, fmt.Sprintf("落地物 #%d（%s）未配置验证命令，无法复核", art.ID, label))
			continue
		}
		ch, rerr := s.intranetArtifactRunner(ctx, pg, art, 0)
		if rerr != nil {
			if art.Status == db.IntranetArtifactRevoked && strings.Contains(art.Evidence, intranetArtifactGone) {
				// 半持久化落地物可能通过自己的 prepend 壳撤销：清理生效的那一刻这条
				// 通道就没了，事后无法再复核。但清理与复核是同一次执行完成的，证据里
				// 已带「痕迹已消失」，据此计为已清除，不能当成残留误报。
				rep.Scan.Gone++
				continue
			}
			rep.Scan.Unknown++
			rep.Residual = append(rep.Residual, fmt.Sprintf("落地物 #%d（%s）没有可用会话或 webshell，无法复核：%v", art.ID, label, rerr))
			continue
		}
		out := ch.Run(verifyCmd, intranetVerifyTimeout)
		switch intranetVerifyMarker(out) {
		case "present":
			rep.Scan.Present++
			rep.Residual = append(rep.Residual, fmt.Sprintf("落地物 #%d（%s %s）复核仍存在：%s",
				art.ID, art.Kind, label, truncateIntranetOutput(strings.TrimSpace(out.Output), 200)))
		case "gone":
			rep.Scan.Gone++
		default:
			rep.Scan.Unknown++
			detail := strings.TrimSpace(out.Output + "\n" + out.Note)
			rep.Residual = append(rep.Residual, fmt.Sprintf("落地物 #%d（%s %s）复核结果无法判定：%s",
				art.ID, art.Kind, label, truncateIntranetOutput(detail, 200)))
		}
	}
}

// intranetEvacuateWebshells probes every shell bound to a session of the task.
// With deleteShells it asks a v2 shell to unlink itself, then verifies the
// endpoint is really gone before deleting the platform record; any failure
// keeps the record and lands in the residual list. Parents in blockedShells
// still carry a memory shell and are never deleted. Shells referenced by an
// active PHP auto_prepend artifact are blocked until the artifact is revoked,
// and php_prepend shells are never self-deleted: their payload is wired in
// through .user.ini/.htaccess, so unlinking the file alone would break every
// request to the site.
func (s *Server) intranetEvacuateWebshells(ctx context.Context, pg *db.DB, taskID int64, rep *intranetEvacuationReport, dryRun, deleteShells bool, blockedShells map[int64]string) {
	shells, err := pg.ListWebshellsByIntranetTask(taskID)
	if err != nil {
		rep.Residual = append(rep.Residual, "读取任务 webshell 失败："+err.Error())
		return
	}
	for _, shell := range shells {
		rep.Webshells.Total++
		label := displayOr(shell.Name, shell.URL)
		item := intranetEvacuationItem{
			Type: "webshell", ID: shell.ID, Kind: "webshell", Name: label, Host: shell.Target,
		}
		if !dryRun && deleteShells {
			if reason, blocked := blockedShells[shell.ID]; blocked {
				item.Status = "blocked"
				item.Detail = "保留父 webshell：" + reason
				rep.Webshells.Failed++
				rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）暂不删除：%s", shell.ID, label, reason))
				rep.Items = append(rep.Items, item)
				continue
			}
			arts, aerr := pg.ListActivePHPPersistArtifactsByWebshell(shell.ID)
			if aerr != nil {
				item.Status = "failed"
				item.Detail = "查询 PHP 半持久化落地物失败：" + aerr.Error()
				rep.Webshells.Failed++
				rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）无法确认关联的 PHP 半持久化落地物：%v", shell.ID, label, aerr))
				rep.Items = append(rep.Items, item)
				continue
			}
			if len(arts) > 0 {
				ids := make([]string, 0, len(arts))
				for _, art := range arts {
					ids = append(ids, "#"+strconv.FormatInt(art.ID, 10))
				}
				item.Status = "blocked"
				item.Detail = "仍有 PHP 半持久化落地物引用，需先撤销：" + strings.Join(ids, "、")
				rep.Webshells.Failed++
				rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）暂不删除：仍有 %d 个 PHP 半持久化落地物（%s）引用，请先撤销落地物",
					shell.ID, label, len(arts), strings.Join(ids, "、")))
				rep.Items = append(rep.Items, item)
				continue
			}
		}
		if strings.TrimSpace(shell.URL) == "" {
			item.Status = "skipped"
			item.Detail = "webshell 没有可用地址，无法探活或删除"
			rep.Webshells.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）缺少地址，需人工确认是否已清除", shell.ID, label))
			rep.Items = append(rep.Items, item)
			continue
		}
		if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
			item.Status = "failed"
			item.Detail = "命中资产拦截规则：" + reason
			rep.Webshells.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）被拦截规则阻止探活/删除，需人工处理", shell.ID, label))
			rep.Items = append(rep.Items, item)
			continue
		}

		isPHPPersist := strings.EqualFold(shell.Source, "php_prepend")
		alive, aliveNote := s.intranetShellAliveAnyOS(ctx, shell)
		if dryRun {
			item.Status = "planned"
			if isPHPPersist {
				item.Detail = "PHP 半持久化通道，撤离时不会自删除"
				if alive {
					rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）为 PHP 半持久化通道（仍存活），撤离不会自删除，请先撤销落地物或手动清除 prepend 载荷", shell.ID, label))
				}
			} else if alive {
				item.Detail = "存活；启用自动删除将在撤离时自删除并复核"
				rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）仍存活（预览未删除）", shell.ID, label))
			} else {
				item.Detail = "未响应加密协议：" + aliveNote
			}
			rep.Items = append(rep.Items, item)
			continue
		}
		if !deleteShells {
			if alive {
				item.Status = "kept"
				item.Detail = "仍存活；未开启自动删除，需手工清除"
				rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）仍保留：未开启自动删除，请确认是否手动清除", shell.ID, label))
			} else {
				item.Status = "dead"
				item.Detail = "已无响应，平台记录保留：" + aliveNote
				rep.Webshells.Done++
			}
			rep.Items = append(rep.Items, item)
			continue
		}
		if isPHPPersist {
			if alive {
				item.Status = "kept"
				item.Detail = "半持久化通道仍在响应，不会执行自删除；请先撤销落地物或手动清除 prepend 载荷：" + aliveNote
				rep.Webshells.Failed++
				rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）为 PHP 半持久化通道，自动撤离不会自删除，需手动清除 prepend 载荷", shell.ID, label))
			} else {
				if _, delErr := pg.DeleteWebshell(shell.ID); delErr != nil {
					item.Status = "failed"
					item.Detail = "通道已无响应，但清理平台记录失败：" + delErr.Error()
					rep.Webshells.Failed++
					rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）通道已无响应，但平台记录删除失败：%v", shell.ID, label, delErr))
					rep.Items = append(rep.Items, item)
					continue
				}
				s.releaseWebshellResource(shell.ID, "撤离清理 PHP 半持久化记录")
				item.Status = "deleted"
				item.Detail = "半持久化通道路由已无响应，已清理平台记录：" + aliveNote
				rep.Webshells.Done++
			}
			rep.Items = append(rep.Items, item)
			continue
		}
		if shell.Protocol != scanner.ShellProtocolV2 {
			item.Status = "failed"
			item.Detail = "旧版 webshell 协议不支持自删除，需手工处理"
			rep.Webshells.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）为旧版协议，无法自动删除", shell.ID, label))
			rep.Items = append(rep.Items, item)
			continue
		}
		payload, perr := s.shellPayloadFor(shell)
		if perr != nil {
			item.Status = "failed"
			item.Detail = perr.Error()
			rep.Webshells.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）自删除失败：%s", shell.ID, label, perr.Error()))
			rep.Items = append(rep.Items, item)
			continue
		}
		client := scanner.NewDeepClient(20 * time.Second)
		ack, derr := scanner.DeleteShellSelf(ctx, client, shell.URL, payload)
		if derr != nil {
			item.Status = "failed"
			item.Detail = derr.Error()
			rep.Webshells.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）自删除失败：%s", shell.ID, label, derr.Error()))
			rep.Items = append(rep.Items, item)
			continue
		}
		gone, verifyNote := scanner.VerifyShellRemoved(ctx, client, shell.URL, payload)
		if !gone {
			hint := ""
			if kind := strings.ToLower(strings.TrimSpace(shell.ShellType)); kind != "" && !strings.Contains(kind, "php") {
				// JSP/ASPX 这类由容器解释执行的壳，删掉文件不等于删掉访问：servlet 已经加载
				// 进容器，文件消失后仍会照原样应答协议请求。不写清这一点，读者只会当成删除
				// 没成功而反复重试，真正要做的是重载应用或重启容器。
				hint = "（" + kind + " 壳由容器解释执行，文件已删除但 servlet 可能仍驻留，需重载应用或重启容器才能断开）"
			}
			item.Status = "failed"
			item.Detail = fmt.Sprintf("自删除回执 %q，但复核未通过：%s%s", ack, verifyNote, hint)
			rep.Webshells.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）自删除后仍可访问：%s%s", shell.ID, label, verifyNote, hint))
			rep.Items = append(rep.Items, item)
			continue
		}
		if _, delErr := pg.DeleteWebshell(shell.ID); delErr != nil {
			item.Status = "failed"
			item.Detail = "载荷已删除但清理平台记录失败：" + delErr.Error()
			rep.Webshells.Failed++
			rep.Residual = append(rep.Residual, fmt.Sprintf("webshell #%d（%s）载荷已删除，但平台记录删除失败：%v", shell.ID, label, delErr))
			rep.Items = append(rep.Items, item)
			continue
		}
		s.releaseWebshellResource(shell.ID, "撤离自动删除 webshell")
		item.Status = "deleted"
		item.Detail = fmt.Sprintf("自删除回执 %s；复核：%s", ack, verifyNote)
		rep.Webshells.Done++
		rep.Items = append(rep.Items, item)
	}
}

// intranetShellAliveAnyOS probes a shell directly with a command that works in
// both cmd.exe and POSIX shells.
func (s *Server) intranetShellAliveAnyOS(ctx context.Context, shell *db.Webshell) (bool, string) {
	payload, err := s.shellPayloadFor(shell)
	if err != nil {
		return false, err.Error()
	}
	client := scanner.NewDeepClient(20 * time.Second)
	out, err := scanner.RunShellCommand(ctx, client, shell.URL, payload, "echo "+intranetHeartbeatMark)
	if err != nil {
		return false, err.Error()
	}
	if !strings.Contains(out, intranetHeartbeatMark) {
		return false, "未返回心跳标记"
	}
	return true, "加密通道验证通过"
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

func (s *Server) evacuateIntranetTask(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		TaskID          int64  `json:"task_id"`
		DryRun          bool   `json:"dry_run"`
		CloseSessions   *bool  `json:"close_sessions"`
		DeleteWebshells bool   `json:"delete_webshells"`
		Scan            *bool  `json:"scan"`
		Note            string `json:"note"`
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
	opts := intranetEvacuationOptions{
		TaskID: req.TaskID, DryRun: req.DryRun, CloseSessions: true,
		DeleteWebshells: req.DeleteWebshells, SkipResidualScan: req.Scan != nil && !*req.Scan,
		Note: req.Note,
	}
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
		"撤离清理（任务收尾必做）：按落地物台账 id 逆序执行每条 revoke_command 并用 verify_command 验证痕迹消失，随后对已撤销项做一次残留复核、拆除本任务隧道、释放受管回调/监听资源、关闭会话，先移除本任务关联的 Java 内存马（优先经父 shell 反注册，失败则端点自移除，均需复核），最后处理 webshell，返回逐项撤离报告与残留清单。dry_run=true 只预览并做只读残留扫描，不执行撤销。delete_webshells=true 时会对本任务会话绑定的加密 v2 webshell 执行自删除，并以 HTTP 404/协议标记消失复核，成功后才删除平台记录；旧版 webshell 只能人工清理。内存马未确认移除时会保留其父 webshell 并列入残留。执行前确认该任务已不需要维持权限；有 failed/residual 时如实汇报，不要声称已清理干净。",
		objSchema(map[string]any{
			"task_id":          intranetIntParam("任务 ID（可选，默认当前任务）"),
			"dry_run":          map[string]any{"type": "boolean", "description": "true=只预览将撤销/拆除/关闭的对象并做只读残留扫描，不执行（默认 false）"},
			"close_sessions":   map[string]any{"type": "boolean", "description": "是否关闭本任务活跃会话，默认 true"},
			"delete_webshells": map[string]any{"type": "boolean", "description": "是否自删除本任务投放的 v2 webshell 并做 404/标记复核（默认 false）"},
			"scan":             map[string]any{"type": "boolean", "description": "撤离后是否重新执行验证命令做残留复核（默认 true）"},
			"note":             strParam("报告备注（可选）"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID          int64  `json:"task_id"`
				DryRun          bool   `json:"dry_run"`
				CloseSessions   *bool  `json:"close_sessions"`
				DeleteWebshells bool   `json:"delete_webshells"`
				Scan            *bool  `json:"scan"`
				Note            string `json:"note"`
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
			opts := intranetEvacuationOptions{
				TaskID: a.TaskID, DryRun: a.DryRun, CloseSessions: true,
				DeleteWebshells: a.DeleteWebshells, SkipResidualScan: a.Scan != nil && !*a.Scan,
				Note: a.Note,
			}
			if a.CloseSessions != nil {
				opts.CloseSessions = *a.CloseSessions
			}
			return jsonResult(s.intranetEvacuate(ctx, pg, opts))
		})
}
