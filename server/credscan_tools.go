package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
	actool "github.com/Autumn-27/norma/tool"
)

// 弱口令检测的 LLM 工具：发起与查询。
//
// 这里刻意分成两个工具、并且不起「复用」工具：credscan_start 只产出事实
// （哪些端点的哪组凭据可用），复用凭据走内网横向那组显式工具，由模型单独决定、
// 由拦截策略把关。发起与复用是两件事，合成一个工具就等于让检测偷偷触发动作。

type credToolInput struct {
	Targets       []string `json:"targets"`
	Protocols     []string `json:"protocols"`
	Name          string   `json:"name"`
	DictProfile   string   `json:"dict_profile"`
	Concurrency   int      `json:"concurrency"`
	RateLimit     int      `json:"rate_limit"`
	BudgetSeconds int      `json:"budget_seconds"`
	WaitSeconds   int      `json:"wait_seconds"`
	QueueOnly     bool     `json:"queue_only"`
	TaskID        int64    `json:"task_id"`
}

func (s *Server) credscanTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolCredscanStart(), s.toolCredscanStatus()}
}

func (s *Server) toolCredscanStart() actool.CoreTool {
	return wrTool("credscan_start",
		"对已授权目标发起弱口令检测（独立模块，异步排队）：按协议逐组验证口令，产出六态事实（命中 / 明确拒绝 / 连不上 / 账号锁定 / 不可判定 / 暂不支持），命中的凭据会写入凭据库、发现与资产，**但不会自动登录、不会自动复用凭据**。返回值包含任务 ID 与各态计数；命中的账号口令在结果里可见，是否拿去做后续动作由你显式调用相应工具决定。慢任务可传 queue_only=true 先排队，再用 credscan_status 查看。",
		objSchema(map[string]any{
			"targets":        strArrayParam("目标列表（IPv4 或域名；可带 host:port 指定端口，例如 10.0.0.5:2222）"),
			"protocols":      strArrayParam("要检测的协议：ssh、mysql、postgresql、redis、mongodb、ftp、telnet、socks5"),
			"name":           strParam("任务名（可选）"),
			"dict_profile":   strParam("字典档，默认 builtin"),
			"concurrency":    intArgSchema("并发端点数，默认 16，上限 128"),
			"rate_limit":     intArgSchema("每秒尝试数，默认 20，0=不限速"),
			"budget_seconds": intArgSchema("任务预算秒数，默认 600"),
			"wait_seconds":   intArgSchema("等待任务完成的秒数，默认 300，最大 900"),
			"queue_only":     map[string]any{"type": "boolean", "description": "true=只排队不等结果，立即返回任务 ID"},
		}, "targets", "protocols"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a credToolInput
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("参数解析失败: %v", err)), nil
			}
			pg := s.m.pg
			if pg == nil {
				return actool.Errorf("数据库未连接，无法创建弱口令检测任务"), nil
			}
			targets := make([]string, 0, len(a.Targets))
			for _, t := range a.Targets {
				if t = strings.TrimSpace(t); t != "" {
					targets = append(targets, t)
				}
			}
			if len(targets) == 0 {
				return actool.Errorf("至少需要一个目标"), nil
			}
			if len(targets) > credMaxTargets {
				return actool.Errorf(fmt.Sprintf("目标过多（%d），单次最多 %d 个", len(targets), credMaxTargets)), nil
			}
			if len(a.Protocols) == 0 {
				return actool.Errorf("至少指定一个协议"), nil
			}
			for _, p := range a.Protocols {
				name := strings.ToLower(strings.TrimSpace(p))
				if !scanner.CredProtocolSupported(name) || scanner.CredAdapterFor(name) == nil {
					msg := "该协议暂不支持：" + name
					if r := scanner.CredUnsupportedReason(name); r != "" {
						msg += "（" + r + "）"
					} else if !scanner.CredProtocolKnown(name) {
						msg += "（本平台不测该协议，未发起连接）"
					}
					return actool.Errorf(msg + "（未发起任何连接）"), nil
				}
			}
			if err := s.credDictExists(pg, a.DictProfile); err != nil {
				return actool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			parsed, err := scanner.ParseTargets(targets)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			if _, err := scanner.CredPlan(parsed, nil, a.Protocols); err != nil {
				return actool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			opts := map[string]any{
				"concurrency":    a.Concurrency,
				"rate_limit":     a.RateLimit,
				"budget_seconds": a.BudgetSeconds,
			}
			task, err := pg.CreateCredTask(db.CredTaskInput{
				Name: a.Name, Targets: targets, Protocols: a.Protocols,
				Options: opts, DictProfile: a.DictProfile,
			})
			if err != nil {
				return actool.Errorf(fmt.Sprintf("创建任务失败: %v", err)), nil
			}
			if s.credMgr != nil {
				s.credMgr.wakeup()
			}
			if a.QueueOnly || a.WaitSeconds <= 0 {
				return actool.Text(fmt.Sprintf(
					"已排队：弱口令检测任务 #%d（目标 %d 个 · 协议 %s）。本次不等待结果；用 credscan_status(task_id=%d) 查看进度与结论。",
					task.ID, len(targets), strings.Join(a.Protocols, ", "), task.ID)), nil
			}
			finished := s.waitCredTask(ctx, task.ID, time.Duration(a.WaitSeconds)*time.Second)
			return s.credTaskToolResult(task.ID, !finished)
		})
}

func (s *Server) toolCredscanStatus() actool.CoreTool {
	return wrTool("credscan_status",
		"查看弱口令检测任务的状态与结论（只读）：返回终态、各态计数与命中明细（端点 / 协议 / 账号 / 口令 / TLS）。任务仍在运行时如实返回 running 与当前计数。",
		objSchema(map[string]any{
			"task_id": intArgSchema("credscan_start 返回的任务 ID"),
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a credToolInput
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("参数解析失败: %v", err)), nil
			}
			if a.TaskID <= 0 {
				return actool.Errorf("需要 task_id"), nil
			}
			if s.m.pg == nil {
				return actool.Errorf("数据库未连接"), nil
			}
			finished := s.waitCredTask(ctx, a.TaskID, 0) // 只查一次，不等待
			return s.credTaskToolResult(a.TaskID, !finished)
		})
}

// waitCredTask 轮询到终态或超时。d<=0 表示只看一眼当前状态。
func (s *Server) waitCredTask(ctx context.Context, id int64, d time.Duration) bool {
	check := func() (bool, bool) {
		t, err := s.m.pg.GetCredTask(id)
		if err != nil {
			return false, false
		}
		switch t.Status {
		case db.CredTaskDone, db.CredTaskFailed, db.CredTaskCanceled:
			return true, true
		default:
			return false, true
		}
	}
	if done, _ := check(); done {
		return true
	}
	if d <= 0 {
		return false
	}
	deadline := time.Now().Add(d)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if done, _ := check(); done {
				return true
			}
		}
	}
}

func (s *Server) credTaskToolResult(id int64, timedOut bool) (actool.Result, error) {
	task, err := s.m.pg.GetCredTask(id)
	if err != nil {
		return actool.Errorf(fmt.Sprintf("读取任务 #%d 失败: %v", id, err)), nil
	}
	counts, err := s.m.pg.CredTaskOutcomeCounts(id)
	if err != nil {
		return actool.Errorf(fmt.Sprintf("读取任务 #%d 统计失败: %v", id, err)), nil
	}
	hits, _, err := s.m.pg.ListCredResults(id, db.CredResultFilter{Outcome: "hit", Limit: 50})
	if err != nil {
		return actool.Errorf(fmt.Sprintf("读取任务 #%d 命中失败: %v", id, err)), nil
	}

	statusLabel := map[string]string{
		db.CredTaskQueued: "排队中", db.CredTaskRunning: "运行中",
		db.CredTaskDone: "已完成", db.CredTaskFailed: "失败", db.CredTaskCanceled: "已取消",
	}[task.Status]
	var b strings.Builder
	fmt.Fprintf(&b, "弱口令检测任务 #%d（%s）：%s", task.ID, task.Name, statusLabel)
	if task.Stage != "" && task.Status == db.CredTaskRunning {
		fmt.Fprintf(&b, " · 阶段 %s", task.Stage)
	}
	b.WriteString("\n各态计数：")
	if len(counts) == 0 {
		b.WriteString("尚无结果行")
	} else {
		parts := make([]string, 0, len(counts))
		for _, k := range db.CredTaskOutcomes {
			if n := counts[k]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", k, n))
			}
		}
		b.WriteString(strings.Join(parts, " · "))
	}
	if task.Error != "" {
		fmt.Fprintf(&b, "\n错误：%s", task.Error)
	}
	if len(hits) > 0 {
		b.WriteString("\n命中（口令属于发现内容，是否复用由你显式决定）：")
		for i, h := range hits {
			if i >= 20 {
				fmt.Fprintf(&b, "\n  …其余 %d 条见任务详情页", len(hits)-20)
				break
			}
			tls := ""
			if h.TLS {
				tls = " · TLS"
			}
			fmt.Fprintf(&b, "\n  %s:%d %s %s/%s%s", h.Host, h.Port, h.Protocol,
				h.Username, h.Password, tls)
		}
	}
	b.WriteString("\n说明：命中已写入发现与凭据库，但平台没有自动登录或复用任何凭据。")
	if timedOut {
		b.WriteString("\n任务仍在后台运行；稍后用 credscan_status(task_id) 查看终态。")
	}
	return actool.Text(b.String()), nil
}
