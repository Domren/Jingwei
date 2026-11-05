package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// 内网信息收集脚本库（F3）。每条脚本的 stdout 与**结构化提取结果**一起入库：
// 横向决策要用的是「开了哪些端口、哪些账号在、哪个计划任务可疑」，
// 而不是一大段要人肉阅读的终端输出。
//
// 脚本全部只读：不改配置、不下载外部内容、不做承诺之外的绕过。写操作归维持模块。

type intranetScriptDef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	OS      string `json:"os"` // linux / windows
	Command string `json:"command"`
	Parser  string `json:"-"`
	Note    string `json:"note,omitempty"`
}

var intranetScriptCatalog = []intranetScriptDef{
	{ID: "linux-os", Name: "系统与身份", OS: "linux", Parser: "os_info",
		Command: `cat /etc/os-release 2>/dev/null; uname -a; id`,
		Note:    "发行版/内核/当前身份"},
	{ID: "linux-users", Name: "本地账号", OS: "linux", Parser: "passwd",
		Command: `cat /etc/passwd`,
		Note:    "UID≥1000 与 root 账号"},
	{ID: "linux-sudo", Name: "sudo 权限", OS: "linux", Parser: "sudo",
		Command: `sudo -n -l 2>&1 || true`,
		Note:    "免密 sudo 条目高亮"},
	{ID: "linux-ports", Name: "监听端口", OS: "linux", Parser: "ports",
		Command: `ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null`,
		Note:    "协议/地址/端口/进程"},
	{ID: "linux-cron", Name: "计划任务", OS: "linux", Parser: "cron",
		Command: `crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null | head -120`,
		Note:    "当前用户 crontab 与 /etc/cron*"},
	{ID: "linux-suid", Name: "SUID 文件", OS: "linux", Parser: "lines",
		Command: `find / -xdev -perm -4000 -type f 2>/dev/null | head -100`,
		Note:    "常见的本地提权面"},
	{ID: "linux-sshkeys", Name: "SSH 公钥", OS: "linux", Parser: "ssh_keys",
		Command: `cat /root/.ssh/authorized_keys "$HOME/.ssh/authorized_keys" 2>/dev/null`,
		Note:    "已授权的公钥（可作维持痕迹）"},
	{ID: "linux-containers", Name: "容器", OS: "linux", Parser: "containers",
		Command: `docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}' 2>/dev/null; podman ps 2>/dev/null | head -50`,
		Note:    "运行中的容器与端口映射"},
	{ID: "win-systeminfo", Name: "系统信息", OS: "windows", Parser: "windows_systeminfo",
		Command: `systeminfo`,
		Note:    "OS 版本/补丁概况"},
	{ID: "win-users", Name: "本地用户", OS: "windows", Parser: "lines",
		Command: `net user`,
		Note:    "本机账号列表"},
	{ID: "win-admins", Name: "管理员组", OS: "windows", Parser: "lines",
		Command: `net localgroup administrators`,
		Note:    "本地管理员成员"},
	{ID: "win-ports", Name: "监听端口", OS: "windows", Parser: "windows_ports",
		Command: `netstat -ano`,
		Note:    "监听地址/端口/PID"},
	{ID: "win-patches", Name: "补丁", OS: "windows", Parser: "windows_patches",
		Command: `wmic qfe list brief`,
		Note:    "已安装补丁（缺失补丁需自行比对）"},
	{ID: "win-tasks", Name: "计划任务", OS: "windows", Parser: "windows_tasks",
		Command: `schtasks /query /fo LIST`,
		Note:    "任务名与状态"},
	{ID: "win-priv", Name: "令牌特权", OS: "windows", Parser: "lines",
		Command: `whoami /priv`,
		Note:    "当前令牌特权"},
}

func intranetScriptByID_(id string) (intranetScriptDef, bool) {
	for _, s := range intranetScriptCatalog {
		if s.ID == id {
			return s, true
		}
	}
	return intranetScriptDef{}, false
}

// ---- 结构化提取 -------------------------------------------------------------

func scriptLines(output string) []string {
	out := []string{}
	for _, line := range strings.Split(output, "\n") {
		if l := strings.TrimRight(line, "\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func parseIntranetScriptOutput(parser, output string) map[string]any {
	lines := scriptLines(output)
	items := []any{}
	switch parser {
	case "os_info":
		for _, l := range lines {
			if strings.HasPrefix(l, "PRETTY_NAME=") || strings.HasPrefix(l, "NAME=") ||
				strings.HasPrefix(l, "VERSION=") || strings.HasPrefix(l, "uid=") ||
				strings.Contains(l, "Linux ") {
				items = append(items, l)
			}
		}
	case "passwd":
		for _, l := range lines {
			f := strings.Split(l, ":")
			if len(f) < 7 {
				continue
			}
			uid, _ := strconv.Atoi(f[2])
			if uid == 0 || uid >= 1000 {
				items = append(items, map[string]any{"user": f[0], "uid": uid, "shell": f[6]})
			}
		}
	case "sudo":
		for _, l := range lines {
			if strings.Contains(strings.ToLower(l), "nopasswd") || strings.Contains(l, "may run") {
				items = append(items, strings.TrimSpace(l))
			}
		}
	case "ports":
		for _, l := range lines {
			if !strings.Contains(l, "LISTEN") {
				continue
			}
			f := strings.Fields(l)
			if len(f) < 4 {
				continue
			}
			// ss 与 netstat 的列布局不同：ss 是 Netid State Recv-Q Send-Q Local ...，
			// netstat 是 Proto Recv-Q Send-Q Local ...。按状态列的位置分辨。
			addr := f[3]
			if len(f) >= 5 && strings.EqualFold(f[1], "LISTEN") {
				addr = f[4]
			}
			host, port := addr, ""
			if i := strings.LastIndex(addr, ":"); i >= 0 {
				host, port = addr[:i], addr[i+1:]
			}
			proc := ""
			if i := strings.Index(l, "users:"); i >= 0 {
				proc = strings.TrimSpace(l[i:])
			}
			items = append(items, map[string]any{"proto": strings.ToLower(f[0]), "addr": host, "port": port, "process": proc})
		}
	case "cron":
		for _, l := range lines {
			trim := strings.TrimSpace(l)
			if strings.HasPrefix(trim, "#") || trim == "" {
				continue
			}
			items = append(items, trim)
		}
	case "ssh_keys":
		for _, l := range lines {
			trim := strings.TrimSpace(l)
			if strings.HasPrefix(trim, "ssh-") || strings.HasPrefix(trim, "ecdsa-") || strings.HasPrefix(trim, "sk-") {
				parts := strings.Fields(trim)
				kind, comment := parts[0], ""
				if len(parts) > 2 {
					comment = strings.Join(parts[2:], " ")
				}
				items = append(items, map[string]any{"type": kind, "comment": comment})
			}
		}
	case "containers":
		for _, l := range lines {
			if strings.Contains(l, "|") {
				parts := strings.SplitN(l, "|", 3)
				items = append(items, map[string]any{"name": parts[0], "image": parts[1], "ports": parts[2]})
			}
		}
	case "windows_systeminfo":
		for _, l := range lines {
			lower := strings.ToLower(l)
			if strings.Contains(lower, "os name") || strings.Contains(lower, "os version") ||
				strings.Contains(lower, "hotfix") || strings.Contains(lower, "system type") {
				items = append(items, strings.TrimSpace(l))
			}
		}
	case "windows_ports":
		for _, l := range lines {
			lower := strings.ToLower(l)
			if strings.Contains(lower, "listen") || strings.Contains(lower, "udp") {
				items = append(items, strings.Join(strings.Fields(l), " "))
			}
		}
	case "windows_patches":
		for _, l := range lines {
			if strings.Contains(strings.ToLower(l), "kb") {
				items = append(items, strings.Join(strings.Fields(l), " "))
			}
		}
	case "windows_tasks":
		for _, l := range lines {
			trim := strings.TrimSpace(l)
			if strings.HasPrefix(trim, "TaskName:") || strings.HasPrefix(trim, "Status:") {
				items = append(items, trim)
			}
		}
	default: // lines
		for _, l := range lines {
			items = append(items, strings.TrimSpace(l))
		}
	}
	return map[string]any{"kind": parser, "count": len(items), "items": items}
}

// ---- HTTP ----------------------------------------------------------------

func (s *Server) listIntranetScripts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"scripts": intranetScriptCatalog})
}

func (s *Server) listIntranetScriptRuns(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	runs, err := pg.ListIntranetScriptRuns(id, atoiDefault(r.URL.Query().Get("limit"), 50))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"runs": runs})
}

// runIntranetScript 执行一条目录里的脚本并把 stdout + 结构化结果一起落库。
func (s *Server) runIntranetScript(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "无效的会话 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		ScriptID string `json:"script_id"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	script, ok := intranetScriptByID_(strings.TrimSpace(req.ScriptID))
	if !ok {
		writeErr(w, 400, "脚本不存在："+req.ScriptID)
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
	sessOS, _ := sess.Metadata["os"].(string)
	if sessOS == intranetOSWindows && script.OS != "windows" {
		writeErr(w, 409, "该会话是 Windows，Linux 脚本无法执行")
		return
	}
	if sessOS == intranetOSPosix && script.OS != "linux" {
		writeErr(w, 409, "该会话是 Linux，Windows 脚本无法执行")
		return
	}
	out := s.intranetExec(r.Context(), pg, sess, script.Command, 45*time.Second)
	status := "done"
	if out.IsError || out.TimedOut {
		status = "failed"
	}
	taskID := int64(0)
	if v, ok := sess.Metadata["task_id"].(float64); ok {
		taskID = int64(v)
	}
	code := out.ExitCode
	run, err := pg.CreateIntranetScriptRun(db.IntranetScriptRunInput{
		SessionID: sess.ID, TaskID: taskID, ScriptID: script.ID, Name: script.Name,
		OS: script.OS, Command: script.Command, ExitCode: &code, Status: status,
		Output: truncateIntranetOutput(out.Output, 64<<10),
		Parsed: parseIntranetScriptOutput(script.Parser, out.Output),
	})
	if err != nil {
		writeErr(w, 500, "保存脚本结果失败："+err.Error())
		return
	}
	if out.Note != "" {
		run.Parsed["note"] = out.Note
	}
	writeJSON(w, 200, map[string]any{"run": run, "session": sess})
}

// scriptCatalogForOS 给测试与前端筛选用。
func scriptCatalogForOS(os string) []intranetScriptDef {
	out := []intranetScriptDef{}
	for _, s := range intranetScriptCatalog {
		if os == "" || s.OS == os {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
