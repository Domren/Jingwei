package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

const (
	intranetHeartbeatInterval   = time.Minute
	intranetHeartbeatStaleAfter = 5 * time.Minute
	intranetHeartbeatRetryAfter = 2 * time.Minute
	intranetHeartbeatTimeout    = 20 * time.Second
	intranetHeartbeatBatch      = 20
	intranetHealthLostAfter     = 3
)

func intranetHeartbeatCommand(osKind string) string {
	if osKind == intranetOSWindows {
		return "echo " + intranetHeartbeatMark
	}
	return "printf " + intranetHeartbeatMark
}

func intranetProbeLiveness(run intranetCommandRunner, osKind string, timeout time.Duration) (bool, time.Duration, intranetExecOutcome) {
	started := time.Now()
	out := run(intranetHeartbeatCommand(osKind), timeout)
	latency := time.Since(started)
	alive := !out.IsError && strings.Contains(out.Output, intranetHeartbeatMark)
	if !out.IsError && !alive {
		out.IsError, out.Note = true, "心跳标记缺失"
	}
	if !alive && strings.TrimSpace(out.Note) == "" {
		out.IsError = true
		out.Note = "目标不可达或未返回心跳标记"
	}
	return alive, latency, out
}

// intranetSessionHealth reads the health snapshot persisted in metadata.
func intranetSessionHealth(sess *db.IntranetSession) (string, int) {
	if sess == nil {
		return "", 0
	}
	health, _ := sess.Metadata["health"].(string)
	failures := 0
	switch v := sess.Metadata["health_failures"].(type) {
	case float64:
		failures = int(v)
	case int:
		failures = v
	}
	return health, failures
}

// intranetHeartbeatCheck probes one session, persists the result and records
// transition events. Manual checks always produce a heartbeat event; the
// background worker only emits on state changes so a dead target does not fill
// the event log once per minute.
func (s *Server) intranetHeartbeatCheck(ctx context.Context, pg *db.DB, sess *db.IntranetSession, manual bool) (bool, intranetExecOutcome, *db.IntranetSession) {
	// A turn already in flight is not a failed probe. Recording it as one lets a
	// long operator command (a build, a large transfer) age a healthy session into
	// lost, and the failure counter has no way to tell the two apart afterwards.
	mu := intranetTurnLock(sess.ID)
	if !mu.TryLock() {
		return false, intranetExecOutcome{ExitCode: -1, IsError: true, Note: "上一条命令仍在执行，本次心跳未探测，也未记为失败"}, sess
	}
	defer mu.Unlock()
	osKind := s.intranetOS(ctx, pg, sess)
	run := func(command string, timeout time.Duration) intranetExecOutcome {
		return s.intranetRunLocked(pg, ctx, sess, command, timeout)
	}
	alive, latency, out := intranetProbeLiveness(run, osKind, intranetHeartbeatTimeout)
	prevHealth, _ := intranetSessionHealth(sess)
	errMsg := ""
	if !alive {
		errMsg = truncateIntranetOutput(strings.TrimSpace(out.Note+"\n"+out.Output), 400)
	}
	updated, err := pg.RecordIntranetSessionHealth(sess.ID, alive, int(latency/time.Millisecond), errMsg, intranetHealthLostAfter)
	if err != nil {
		out.IsError = true
		if strings.TrimSpace(out.Note) == "" {
			out.Note = "记录心跳失败: " + err.Error()
		} else {
			out.Note += "；记录心跳失败: " + err.Error()
		}
		return alive, out, nil
	}
	health, failures := intranetSessionHealth(updated)
	if manual {
		msg := fmt.Sprintf("存活（%d ms）", latency/time.Millisecond)
		if !alive {
			msg = fmt.Sprintf("心跳失败 %d/%d：%s", failures, intranetHealthLostAfter, errMsg)
		}
		_ = pg.AddIntranetSessionEvent(sess.ID, "heartbeat", "心跳检测", truncateIntranetOutput(msg, 2000), !alive)
		return alive, out, updated
	}
	switch {
	case health == db.IntranetHealthOK && prevHealth != "" && prevHealth != db.IntranetHealthOK:
		_ = pg.AddIntranetSessionEvent(sess.ID, "health", "心跳恢复", fmt.Sprintf("会话恢复，延迟 %d ms", latency/time.Millisecond), false)
	case health == db.IntranetHealthDegraded && prevHealth == "":
		_ = pg.AddIntranetSessionEvent(sess.ID, "health", "心跳降级", truncateIntranetOutput(fmt.Sprintf("连续失败 %d/%d：%s", failures, intranetHealthLostAfter, errMsg), 2000), true)
	case health == db.IntranetHealthLost && prevHealth != db.IntranetHealthLost:
		_ = pg.AddIntranetSessionEvent(sess.ID, "health", "心跳丢失", truncateIntranetOutput(fmt.Sprintf("连续失败 %d/%d：%s", failures, intranetHealthLostAfter, errMsg), 2000), true)
	}
	return alive, out, updated
}

func (s *Server) runIntranetHeartbeat(ctx context.Context) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	lastProbe := map[int64]time.Time{}
	ticker := time.NewTicker(intranetHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.intranetHeartbeatSweep(ctx, lastProbe)
		}
	}
}

func (s *Server) intranetHeartbeatSweep(ctx context.Context, lastProbe map[int64]time.Time) {
	pg := s.m.pg
	if pg == nil {
		return
	}
	sessions, err := pg.ListIntranetSessionsForHeartbeat(time.Now().Add(-intranetHeartbeatStaleAfter), intranetHeartbeatBatch)
	if err != nil {
		log.Printf("[intranet][heartbeat] 扫描会话失败: %v", err)
		return
	}
	now := time.Now()
	for _, sess := range sessions {
		if ctx.Err() != nil {
			return
		}
		if last, ok := lastProbe[sess.ID]; ok && now.Sub(last) < intranetHeartbeatRetryAfter {
			continue
		}
		lastProbe[sess.ID] = now
		alive, _, _ := s.intranetHeartbeatCheck(ctx, pg, sess, false)
		if !alive {
			log.Printf("[intranet][heartbeat] 会话 #%d（%s）不可达", sess.ID, sess.Host)
		}
	}
	for id, at := range lastProbe {
		if now.Sub(at) > 24*time.Hour {
			delete(lastProbe, id)
		}
	}
}

func (s *Server) heartbeatIntranetSession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sess, err := s.intranetSession(pg, id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	alive, out, _ := s.intranetHeartbeatCheck(r.Context(), pg, sess, true)
	final, ferr := pg.GetIntranetSession(id)
	if ferr != nil {
		final = sess
	}
	writeJSON(w, 200, map[string]any{"alive": alive, "result": out, "session": final})
}

func intranetShellMatchesHost(host string, shell *db.Webshell) bool {
	host = intranetHost(host)
	if host == "" {
		return true
	}
	return intranetHost(shell.Target) == host || intranetHost(shell.URL) == host
}

// intranetFailoverCandidates filters shells down to verified same-host shells,
// preferring ones already marked alive. A session without a host never gets an
// automatic pick, because any shell could point at an unrelated target.
func intranetFailoverCandidates(sess *db.IntranetSession, shells []*db.Webshell) []*db.Webshell {
	if sess == nil || intranetHost(sess.Host) == "" {
		return nil
	}
	current := int64(0)
	if sess.WebshellID != nil {
		current = *sess.WebshellID
	}
	out := make([]*db.Webshell, 0, len(shells))
	for _, shell := range shells {
		if shell == nil || shell.ID == current || strings.TrimSpace(shell.URL) == "" {
			continue
		}
		if strings.EqualFold(shell.Status, "dead") {
			continue
		}
		if !intranetShellMatchesHost(sess.Host, shell) {
			continue
		}
		out = append(out, shell)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai := strings.EqualFold(out[i].Status, "alive")
		aj := strings.EqualFold(out[j].Status, "alive")
		if ai != aj {
			return ai
		}
		return out[i].ID > out[j].ID
	})
	return out
}

func (s *Server) intranetPingShell(ctx context.Context, shell *db.Webshell, osKind string) (bool, intranetExecOutcome, time.Duration) {
	out := intranetExecOutcome{ExitCode: -1}
	payload, err := s.shellPayloadFor(shell)
	if err != nil {
		out.IsError, out.Note = true, err.Error()
		return false, out, 0
	}
	client := scanner.NewDeepClient(intranetHeartbeatTimeout)
	cctx, cancel := context.WithTimeout(ctx, intranetHeartbeatTimeout+5*time.Second)
	defer cancel()
	started := time.Now()
	raw, err := scanner.RunShellCommand(cctx, client, shell.URL, payload, intranetHeartbeatCommand(osKind))
	latency := time.Since(started)
	if err != nil {
		out.IsError, out.Note, out.Output = true, err.Error(), raw
		return false, out, latency
	}
	if !strings.Contains(raw, intranetHeartbeatMark) {
		out.IsError, out.Note, out.Output = true, "备用 webshell 未返回心跳标记", raw
		return false, out, latency
	}
	out.ExitCode, out.Output = 0, raw
	return true, out, latency
}

func (s *Server) failoverIntranetSession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		WebshellID int64 `json:"webshell_id"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sess, err := s.intranetSession(pg, id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if intranetIsSSH(sess) {
		writeErr(w, 400, "SSH 会话不走 webshell，没有备用壳可切：口令失效请更新凭据台账后用 intranet_open_session transport=ssh 重开会话")
		return
	}
	current := int64(0)
	if sess.WebshellID != nil {
		current = *sess.WebshellID
	}
	var candidates []*db.Webshell
	if req.WebshellID > 0 {
		if req.WebshellID == current {
			writeErr(w, 400, "目标 webshell 与当前绑定相同")
			return
		}
		shell, serr := pg.GetWebshell(req.WebshellID)
		if serr != nil {
			writeErr(w, 400, "指定的 webshell 不存在")
			return
		}
		if !intranetShellMatchesHost(sess.Host, shell) {
			writeErr(w, 400, "指定的 webshell 不属于该会话主机")
			return
		}
		if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
			writeErr(w, 400, "指定的 webshell 命中资产拦截规则："+reason)
			return
		}
		candidates = []*db.Webshell{shell}
	} else {
		shells, _, lerr := pg.ListWebshells("", 200, 0)
		if lerr != nil {
			writeErr(w, 500, lerr.Error())
			return
		}
		candidates = intranetFailoverCandidates(sess, shells)
	}
	if len(candidates) == 0 {
		writeErr(w, 400, "没有可用的备用 webshell（需要同主机的其他存活 webshell）")
		return
	}

	osKind := intranetOSPosix
	if v, ok := sess.Metadata["os"].(string); ok && v == intranetOSWindows {
		osKind = intranetOSWindows
	}
	var last intranetExecOutcome
	for _, shell := range candidates {
		if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
			last.IsError, last.Note = true, "备用 webshell 命中资产拦截规则："+reason
			continue
		}
		alive, out, latency := s.intranetPingShell(r.Context(), shell, osKind)
		if !alive {
			last = out
			continue
		}
		if _, uerr := pg.SetIntranetSessionWebshell(sess.ID, shell.ID); uerr != nil {
			writeErr(w, 500, "切换 webshell 失败: "+uerr.Error())
			return
		}
		// The candidate just answered, so record health immediately instead of
		// waiting for the next background sweep.
		_, _ = pg.RecordIntranetSessionHealth(sess.ID, true, int(latency/time.Millisecond), "", intranetHealthLostAfter)
		_ = pg.AddIntranetSessionEvent(sess.ID, "failover",
			fmt.Sprintf("webshell #%d -> #%d", current, shell.ID),
			fmt.Sprintf("切换成功，心跳延迟 %d ms", latency/time.Millisecond), false)
		final, ferr := pg.GetIntranetSession(sess.ID)
		if ferr != nil {
			final = sess
		}
		writeJSON(w, 200, map[string]any{
			"session": final, "webshell": shell, "result": out,
			"switched": true, "latency_ms": latency / time.Millisecond,
		})
		return
	}
	msg := "候选 webshell 均未通过心跳检测"
	if strings.TrimSpace(last.Note) != "" {
		msg += "：" + truncateIntranetOutput(strings.TrimSpace(last.Note), 300)
	}
	_ = pg.AddIntranetSessionEvent(sess.ID, "failover", "自动切换失败", msg, true)
	writeErr(w, 400, msg)
}
