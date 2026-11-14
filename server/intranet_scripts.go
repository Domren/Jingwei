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
	ID        string `json:"id"`
	Name      string `json:"name"`
	OS        string `json:"os"` // linux / windows
	Command   string `json:"command"`
	PShellCmd string `json:"-"` // PowerShell 会话下的等价命令；空则 fallback 到 Command
	Parser    string `json:"-"`
	Note      string `json:"note,omitempty"`
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
		// 没有 authorized_keys 是正常答案，不该记成「脚本失败」：逐文件判断存在再 cat，
		// 整个 for 的退出码就是 0。同时把来源文件标出来，维持痕迹要能指到具体路径。
		Command: `for f in /root/.ssh/authorized_keys "$HOME/.ssh/authorized_keys"; do if [ -s "$f" ]; then echo "# $f"; cat "$f"; fi; done`,
		Note:    "已授权的公钥（可作维持痕迹）"},
	{ID: "linux-containers", Name: "容器", OS: "linux", Parser: "containers",
		Command: `docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}' 2>/dev/null; podman ps 2>/dev/null | head -50`,
		Note:    "运行中的容器与端口映射"},
	{ID: "win-systeminfo", Name: "系统信息与补丁基线", OS: "windows", Parser: "patches",
		Command:   `systeminfo`,
		PShellCmd: `Get-CimInstance Win32_OperatingSystem | Select Caption,Version,BuildNumber,LastBootUpTime | Format-List; Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 15 HotFixID,InstalledOn,Description | Format-Table -AutoSize`,
		Note:      "OS 版本与 build + 已安装补丁（systeminfo 慢，约 30–60 秒；PS 版更快）"},
	{ID: "win-users", Name: "本地用户", OS: "windows", Parser: "lines",
		Command:   `net user`,
		PShellCmd: `Get-LocalUser | Select Name,Enabled,Description,LastLogon | Format-Table -AutoSize`,
		Note:      "本机账号列表"},
	{ID: "win-admins", Name: "管理员组", OS: "windows", Parser: "lines",
		Command:   `net localgroup administrators`,
		PShellCmd: `Get-LocalGroupMember -Group Administrators | Select Name,ObjectClass | Format-Table -AutoSize`,
		Note:      "本地管理员成员"},
	{ID: "win-ports", Name: "监听端口", OS: "windows", Parser: "windows_ports",
		Command:   `netstat -ano`,
		PShellCmd: `Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize; Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize`,
		Note:      "监听地址/端口/PID"},
	{ID: "win-patches", Name: "补丁（wmic）", OS: "windows", Parser: "patches",
		Command:   `wmic qfe list brief`,
		PShellCmd: `Get-HotFix | Select HotFixID,InstalledOn,Description | Format-Table -AutoSize`,
		Note:      "已安装补丁与基线比对；wmic 在新版本上可能已移除，PS 版更稳"},
	{ID: "win-hotfixes", Name: "补丁（PowerShell 直跑）", OS: "windows", Parser: "patches",
		Command:   `powershell -NoProfile -Command "Get-HotFix | Select-Object HotFixID,InstalledOn | ConvertTo-Csv -NoTypeInformation"`,
		PShellCmd: `Get-HotFix | Select HotFixID,InstalledOn,Description | Format-Table -AutoSize`,
		Note:      "cmd 会话通过 powershell.exe 调用；纯 PS 会话直接执行"},
	{ID: "win-endpoint", Name: "终端防护进程与服务", OS: "windows", Parser: "endpoint",
		Command:   `tasklist /fo csv /nh 2>nul & sc query type= service state= all 2>nul | findstr /i "SERVICE_NAME"`,
		PShellCmd: `Get-Process | Select Id,ProcessName | Format-Table -AutoSize; Get-Service | Where StartType -ne Disabled | Select Name,DisplayName,Status | Format-Table -AutoSize`,
		Note:      "按进程名/服务名识别杀软与 EDR；只登记有公开文档支撑的条目，认不出的列入待确认"},
	{ID: "linux-endpoint", Name: "终端防护进程", OS: "linux", Parser: "endpoint",
		Command: `ps -eo pid=,comm=,args= 2>/dev/null | head -200`,
		Note:    "同上，Linux 侧；主机上通常没有终端防护，读不到列表时不做判断"},
	{ID: "win-tasks", Name: "计划任务", OS: "windows", Parser: "windows_tasks",
		Command:   `schtasks /query /fo LIST`,
		PShellCmd: `Get-ScheduledTask | Select TaskName,TaskPath,State | Format-Table -AutoSize`,
		Note:      "任务名与状态"},
	{ID: "win-priv", Name: "令牌特权", OS: "windows", Parser: "lines",
		Command:   `whoami /priv`,
		PShellCmd: `whoami /priv`,
		Note:      "当前令牌特权（PS/cmd 语法一致，复用同一条）"},
}

// endpointOSKind 把脚本侧的 linux/windows 归到识别函数认的说法。
func endpointOSKind(os string) string {
	if strings.EqualFold(strings.TrimSpace(os), "windows") {
		return "windows"
	}
	return "linux"
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

func parseIntranetScriptOutput(parser, osKind, output string) map[string]any {
	switch parser {
	case "endpoint":
		return parseEndpointScript(endpointOSKind(osKind), output)
	case "patches":
		return parsePatchScript(output)
	}
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
		file := ""
		for _, l := range lines {
			trim := strings.TrimSpace(l)
			// 脚本用「# <路径>」标出每条公钥来自哪个 authorized_keys：维持痕迹
			// 要能指到具体文件，光有公钥内容不够。
			if strings.HasPrefix(trim, "# ") {
				file = strings.TrimSpace(trim[2:])
				continue
			}
			if strings.HasPrefix(trim, "ssh-") || strings.HasPrefix(trim, "ecdsa-") || strings.HasPrefix(trim, "sk-") {
				parts := strings.Fields(trim)
				kind, comment := parts[0], ""
				if len(parts) > 2 {
					comment = strings.Join(parts[2:], " ")
				}
				items = append(items, map[string]any{"type": kind, "comment": comment, "file": file})
			}
		}
	case "containers":
		for _, l := range lines {
			if strings.Contains(l, "|") {
				parts := strings.SplitN(l, "|", 3)
				items = append(items, map[string]any{"name": parts[0], "image": parts[1], "ports": parts[2]})
			}
		}
	case "windows_ports":
		for _, l := range lines {
			lower := strings.ToLower(l)
			if strings.Contains(lower, "listen") || strings.Contains(lower, "udp") {
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
	if sessShell(sess) == intranetShellPowerShell && strings.TrimSpace(script.PShellCmd) != "" {
		out = s.intranetExec(r.Context(), pg, sess, script.PShellCmd, 45*time.Second)
	}
	status := "done"
	if out.IsError || out.TimedOut {
		status = "failed"
	}
	taskID := int64(0)
	if v, ok := sess.Metadata["task_id"].(float64); ok {
		taskID = int64(v)
	}
	// 中文 Windows 的工具在 chcp 65001 下仍可能按 OEM 代码页输出中文段，
	// 直接入库会被 PostgreSQL 拒收（SQLSTATE 22021）：先清洗再截断/解析。
	cleanOutput := intranetValidUTF8Text(out.Output)
	code := out.ExitCode
	run, err := pg.CreateIntranetScriptRun(db.IntranetScriptRunInput{
		SessionID: sess.ID, TaskID: taskID, ScriptID: script.ID, Name: script.Name,
		OS: script.OS, Command: script.Command, ExitCode: &code, Status: status,
		Output: truncateIntranetOutput(cleanOutput, 64<<10),
		Parsed: parseIntranetScriptOutput(script.Parser, script.OS, cleanOutput),
	})
	if err != nil {
		writeErr(w, 500, "保存脚本结果失败："+err.Error())
		return
	}
	if out.Note != "" {
		run.Parsed["note"] = out.Note
	}
	// 终端侧识别不只留在运行记录里：它要进发现台账（可筛选、可交付），
	// 也要在后续动作前被看见。读不到列表时这里只会给一句「不做判断」。
	if note := s.recordEndpointFindings(pg, sess, taskID, script.ID, run.Parsed); note != "" {
		run.Parsed["finding_note"] = note
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
