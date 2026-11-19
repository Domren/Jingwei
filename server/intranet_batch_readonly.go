package server

import (
	"path/filepath"
	"strings"
	"time"
)

// 批量执行只对「明确只读」的命令放行。写操作一律拒绝，绝不因为其中夹了一条
// 只读命令就静默放行（A5 规则：含只读动作不能掩盖同一调用里的删改）。
// 这是一份默认拒绝白名单：解释器、包管理、重定向、命令替换等都不在表内。
var intranetBatchReadOnlyCommands = map[string]bool{
	// POSIX 只读命令
	"whoami": true, "id": true, "hostname": true, "uname": true, "pwd": true,
	"ls": true, "cat": true, "head": true, "tail": true, "less": true, "more": true,
	"echo": true, "printf": true, "date": true, "uptime": true, "ps": true,
	"df": true, "du": true, "free": true, "top": true, "ip": true,
	"ifconfig": true, "route": true, "netstat": true, "ss": true, "arp": true,
	"env": true, "printenv": true, "which": true, "whereis": true, "type": true,
	"grep": true, "egrep": true, "fgrep": true, "wc": true, "sort": true,
	"uniq": true, "cut": true, "tr": true, "stat": true, "file": true,
	"readlink": true, "realpath": true, "basename": true, "dirname": true,
	"getent": true, "nslookup": true, "dig": true, "host": true,
	"test": true, "[": true, "true": true, "false": true,
	// Windows 只读命令（与 POSIX 同名的只列一次）
	"dir": true, "ver": true, "tasklist": true, "systeminfo": true,
	"quser": true, "findstr": true, "ipconfig": true,
}

// batchReadOnlyRejectReason 判定批量命令是否被守卫拒绝。空串表示放行。
func batchReadOnlyRejectReason(command string) string {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return "命令不能为空"
	}
	// 输出重定向、命令替换、进程替换都能把一条看似只读的命令变成写操作；
	// 不尝试解析它们的语义，一律按写处理。
	if strings.ContainsAny(cmd, ">`") {
		return "批量执行禁止输出重定向与命令替换（写操作请逐条审批）"
	}
	if strings.Contains(cmd, "<(") || strings.Contains(cmd, ">(") {
		return "批量执行禁止进程替换（写操作请逐条审批）"
	}
	// 管道、&&、||、;、换行连接的每一段都必须只读：只读段不能掩盖后面的删改。
	segments := strings.FieldsFunc(cmd, func(r rune) bool {
		switch r {
		case ';', '|', '&', '\n', '\r':
			return true
		}
		return false
	})
	if len(segments) == 0 {
		return "命令无法解析，批量执行已拒绝"
	}
	for _, segment := range segments {
		if reason := batchReadOnlySegmentReason(segment); reason != "" {
			return reason
		}
	}
	return ""
}

func batchReadOnlySegmentReason(segment string) string {
	fields := strings.Fields(strings.TrimSpace(segment))
	if len(fields) == 0 {
		return ""
	}
	i := 0
	// 前置环境变量赋值不改变目标状态，跳过。
	for i < len(fields) && batchIsAssignment(fields[i]) {
		i++
	}
	// 常见包装器（sudo/env/command...）透传真实命令，逐层剥到命令名。
	for i < len(fields) {
		name := strings.ToLower(strings.Trim(fields[i], `"'`))
		switch name {
		case "sudo", "env", "command", "builtin", "nohup", "time", "exec":
			i++
			for i < len(fields) && strings.HasPrefix(fields[i], "-") && !batchIsAssignment(fields[i]) {
				i++
			}
			continue
		}
		break
	}
	if i >= len(fields) {
		return "未能识别要执行的命令，批量执行已拒绝"
	}
	base := strings.ToLower(filepath.Base(strings.Trim(fields[i], `"'`)))
	if !intranetBatchReadOnlyCommands[base] {
		return "命令「" + base + "」不在只读白名单内，批量执行已拒绝（写操作请逐条审批）"
	}
	args := fields[i+1:]
	// 白名单命令的写选项：find 的删除/执行、sed 的原地写、curl/wget 的落盘与提交。
	switch base {
	case "find":
		if batchHasFlag(args, "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fls") {
			return "find 的写入/执行选项被批量守卫拒绝"
		}
	case "sed":
		if batchHasFlag(args, "-i", "--in-place") {
			return "sed 的原地写入选项被批量守卫拒绝"
		}
	case "curl":
		if batchHasFlag(args, "-o", "-O", "-d", "--data", "-X", "--request", "-T", "--upload-file", "-F", "--form") {
			return "curl 的提交/落盘选项被批量守卫拒绝"
		}
	case "wget":
		if batchHasFlag(args, "-O", "-o", "--output-document", "--output-file", "--post-data", "--post-file") {
			return "wget 的落盘/提交选项被批量守卫拒绝"
		}
	}
	return ""
}

func batchIsAssignment(token string) bool {
	t := strings.Trim(token, `"'`)
	i := strings.Index(t, "=")
	if i <= 0 {
		return false
	}
	for _, r := range t[:i] {
		if !(r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func batchHasFlag(args []string, flags ...string) bool {
	for _, arg := range args {
		v := strings.ToLower(strings.Trim(arg, `"'`))
		for _, flag := range flags {
			f := strings.ToLower(flag)
			if v == f || strings.HasPrefix(v, f+"=") {
				return true
			}
		}
	}
	return false
}

// batchTarget 是一条批量执行目标。ID/Name 来自会话记录，执行器由调用方注入。
type batchTarget struct {
	ID   int64
	Name string
}

// batchReadOnlyRun 在守卫放行后对目标逐个执行只读命令，返回汇总条目。
// run 由调用方注入（真实路径走 intranetExec，测试用本地假执行器），因此本函数
// 不依赖数据库或网络，一个 10 台会话组的汇总可以在单测里跑全。
func batchReadOnlyRun(targets []batchTarget, command string, timeout time.Duration, run func(batchTarget, string, time.Duration) intranetExecOutcome) ([]intranetBatchItem, string) {
	if reason := batchReadOnlyRejectReason(command); reason != "" {
		return nil, reason
	}
	if len(targets) == 0 {
		return nil, "需要 session_ids、labels 或 task_id"
	}
	if len(targets) > intranetBatchLimit {
		targets = targets[:intranetBatchLimit]
	}
	if timeout <= 0 {
		timeout = intranetExecTimeout
	}
	out := make([]intranetBatchItem, 0, len(targets))
	for _, target := range targets {
		item := intranetBatchItem{SessionID: target.ID, Name: target.Name}
		item.Result = run(target, command, timeout)
		if item.Result.IsError {
			item.Error = item.Result.Note
		}
		out = append(out, item)
	}
	return out, ""
}
