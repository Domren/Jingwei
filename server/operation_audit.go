package server

// P1 · 操作端反溯源：操作审计一键导出。
//
// 回答三个问题：测了什么（任务描述 + 工具调用流水）、谁批的（授权书引用 + 授权
// 清单条目）、谁在操作（操作者）。导出是纯函数，不依赖实时 DB/网络，便于在无
// 环境的 CI 里写夹具验证；HTTP handler 只负责把 Manager 里的现状装进输入结构。
//
// 安全口径：命令/代理 URL 里可能带 user:pass@ 形式的凭据，导出前统一脱敏，
// 绝不把明文密钥或代理口令写进报告与响应。

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Domren/jingwei/db"
	"github.com/Domren/jingwei/guard"
)

// OperationAuditTask 是一项任务的操作审计来源。
type OperationAuditTask struct {
	ID           string
	Description  string
	Entries      []guard.AuditEntry
	Attributions map[string]int
}

// OperationAuditInput 是导出报告的纯数据输入。
type OperationAuditInput struct {
	Operator                 string
	AuthorizationRef         string // 授权书编号/引用（审计员指定的那份）
	Authorizations           []*db.Authorization
	Tasks                    []OperationAuditTask
	OperationProxyChain      string // 操作会话代理链（导出时脱敏）
	OperatorSessionIsolation bool
	GeneratedAt              time.Time
}

// OperationAuditReport 是可被 JSON/Markdown 消费者共用的结构化结果。
type OperationAuditReport struct {
	Operator                 string                   `json:"operator"`
	AuthorizationRef         string                   `json:"authorization_ref"`
	GeneratedAt              string                   `json:"generated_at"`
	OperationProxyChain      string                   `json:"operation_proxy_chain"` // 已脱敏
	OperatorSessionIsolation bool                     `json:"operator_session_isolation"`
	Authorizations           []OperationAuditAuthRef  `json:"authorizations"`
	Tasks                    []OperationAuditTaskView `json:"tasks"`
	EntryCount               int                      `json:"entry_count"`
}

// OperationAuditAuthRef 是授权书引用的精简视图（不导出目标明细之外的敏感字段）。
type OperationAuditAuthRef struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	Targets  []string `json:"targets"`
	Enabled  bool     `json:"enabled"`
	StartsAt string   `json:"starts_at,omitempty"`
	EndsAt   string   `json:"ends_at,omitempty"`
	Note     string   `json:"note,omitempty"`
}

// OperationAuditTaskView 是单项任务在报告里的视图。
type OperationAuditTaskView struct {
	ID           string             `json:"id"`
	Description  string             `json:"description"`
	Entries      []guard.AuditEntry `json:"entries"` // command 已脱敏
	Attributions map[string]int     `json:"attributions"`
}

// BuildOperationAuditReport 把现状装配成结构化报告。纯函数：不改入参、不查库。
func BuildOperationAuditReport(in OperationAuditInput) OperationAuditReport {
	auths := make([]OperationAuditAuthRef, 0, len(in.Authorizations))
	for _, a := range in.Authorizations {
		if a == nil {
			continue
		}
		ref := OperationAuditAuthRef{
			ID: a.ID, Name: a.Name, Targets: append([]string{}, a.Targets...),
			Enabled: a.Enabled, Note: RedactSecretsInText(a.Note),
		}
		if a.StartsAt != nil {
			ref.StartsAt = a.StartsAt.UTC().Format(time.RFC3339)
		}
		if a.EndsAt != nil {
			ref.EndsAt = a.EndsAt.UTC().Format(time.RFC3339)
		}
		auths = append(auths, ref)
	}
	tasks := make([]OperationAuditTaskView, 0, len(in.Tasks))
	entryCount := 0
	for _, t := range in.Tasks {
		entries := make([]guard.AuditEntry, 0, len(t.Entries))
		for _, e := range t.Entries {
			e.Command = RedactSecretsInText(e.Command)
			e.Reason = RedactSecretsInText(e.Reason)
			entries = append(entries, e)
		}
		entryCount += len(entries)
		attrs := make(map[string]int, len(t.Attributions))
		for k, v := range t.Attributions {
			attrs[k] = v
		}
		tasks = append(tasks, OperationAuditTaskView{
			ID: t.ID, Description: t.Description, Entries: entries, Attributions: attrs,
		})
	}
	gen := in.GeneratedAt
	if gen.IsZero() {
		gen = time.Now()
	}
	return OperationAuditReport{
		Operator:                 in.Operator,
		AuthorizationRef:         in.AuthorizationRef,
		GeneratedAt:              gen.UTC().Format(time.RFC3339),
		OperationProxyChain:      RedactSecretsInText(in.OperationProxyChain),
		OperatorSessionIsolation: in.OperatorSessionIsolation,
		Authorizations:           auths,
		Tasks:                    tasks,
		EntryCount:               entryCount,
	}
}

// RedactSecretsInText 把文本里的 URL userinfo（user:pass@host）脱敏成 ***:***@host。
// 同时兜住独立的 key=value / token=value 片段，避免代理口令随报告外泄。
var (
	reURLCred  = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)([^/@\s:]+):([^/@\s]+)@`)
	reKVSecret = regexp.MustCompile(`(?i)\b(api[_-]?key|token|password|passwd|secret|authorization)\s*[:=]\s*((?:bearer|basic)\s+[^\s,;}]+|"[^"]*"|'[^']*'|[^\s,;}]+)`)
)

func RedactSecretsInText(s string) string {
	if s == "" {
		return s
	}
	s = reURLCred.ReplaceAllString(s, "${1}***:***@")
	s = reKVSecret.ReplaceAllString(s, "$1=***")
	return s
}

// RedactProxyURL 是 RedactSecretsInText 的 URL 专用包装：解析失败时退化为整串脱敏。
func RedactProxyURL(raw string) string {
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		if _, hasPass := u.User.Password(); hasPass {
			u.User = url.UserPassword("***", "***")
			return u.String()
		}
		u.User = url.User("***")
		return u.String()
	}
	return RedactSecretsInText(raw)
}

// OperationAuditMarkdown 把结构化报告渲染成可归档的 Markdown。
func OperationAuditMarkdown(rep OperationAuditReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 操作审计导出\n\n")
	fmt.Fprintf(&b, "- 操作者：**%s**\n", nz(rep.Operator, "未记录"))
	fmt.Fprintf(&b, "- 授权书引用：**%s**\n", nz(rep.AuthorizationRef, "未指定"))
	fmt.Fprintf(&b, "- 生成时间：%s\n", rep.GeneratedAt)
	fmt.Fprintf(&b, "- 操作会话代理链：%s\n", nz(rep.OperationProxyChain, "直连"))
	fmt.Fprintf(&b, "- 操作会话与任务执行环境隔离：%t\n\n", rep.OperatorSessionIsolation)

	b.WriteString("## 授权依据（谁批的）\n\n")
	if len(rep.Authorizations) == 0 {
		b.WriteString("（无授权清单条目）\n\n")
	} else {
		b.WriteString("| ID | 名称 | 目标范围 | 状态 | 有效期 |\n|---|---|---|---|---|\n")
		for _, a := range rep.Authorizations {
			state := "停用"
			if a.Enabled {
				state = "启用"
			}
			window := a.StartsAt + " ~ " + a.EndsAt
			if a.StartsAt == "" && a.EndsAt == "" {
				window = "不限"
			}
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n",
				a.ID, mdCell(a.Name), mdCell(strings.Join(a.Targets, ", ")), state, mdCell(window))
		}
		b.WriteString("\n")
	}

	b.WriteString("## 操作流水（测了什么）\n\n")
	if len(rep.Tasks) == 0 {
		b.WriteString("（无任务记录）\n")
	}
	for _, t := range rep.Tasks {
		fmt.Fprintf(&b, "### 任务 #%s — %s\n\n", nz(t.ID, "?"), nz(t.Description, "未命名"))
		if len(t.Entries) == 0 {
			b.WriteString("（无闸门流水）\n\n")
			continue
		}
		b.WriteString("| 时间(ts) | 工具 | 动作 | 原因 | 命令(已脱敏) |\n|---|---|---|---|---|\n")
		for _, e := range t.Entries {
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n",
				e.TS, mdCell(e.Tool), mdCell(e.Action), mdCell(e.Reason), mdCell(e.Command))
		}
		b.WriteString("\n")
	}
	if len(rep.Tasks) > 0 {
		b.WriteString(fmt.Sprintf("审计条目合计：%d\n", rep.EntryCount))
	}
	return b.String()
}

func mdCell(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s)
}

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// exportOperationAudit 是「操作审计一键导出」端点。授权书引用来自设置，授权清单
// 来自 DB，操作流水来自各任务的 Guard；?task=<id> 可只看单项，?format=md 出 Markdown。
func (s *Server) exportOperationAudit(w http.ResponseWriter, r *http.Request) {
	authz, err := s.m.PG().ListAuthorizations(200)
	if err != nil {
		authz = nil // 授权清单读失败不阻断导出，报告里会标注空清单
	}
	in := OperationAuditInput{
		Operator:                 authUsername, // 操作者：平台唯一操作员账号（见 auth.go）
		AuthorizationRef:         s.m.AuditAuthorizationRef(),
		Authorizations:           authz,
		OperationProxyChain:      s.m.OperationProxyChain(),
		OperatorSessionIsolation: s.m.OperatorSessionIsolation(),
		GeneratedAt:              time.Now(),
	}
	only := strings.TrimSpace(r.URL.Query().Get("task"))
	s.m.mu.RLock()
	ids := make([]string, 0, len(s.m.tasks))
	for id := range s.m.tasks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if only != "" && id != only {
			continue
		}
		t := s.m.tasks[id]
		view := OperationAuditTask{ID: id, Description: t.Description}
		if t.Guard != nil {
			view.Entries = t.Guard.Audit()
			view.Attributions = t.Guard.Attributions()
		}
		in.Tasks = append(in.Tasks, view)
	}
	s.m.mu.RUnlock()

	rep := BuildOperationAuditReport(in)
	if strings.EqualFold(r.URL.Query().Get("format"), "md") {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(OperationAuditMarkdown(rep)))
		return
	}
	writeJSON(w, 200, map[string]any{"report": rep, "markdown": OperationAuditMarkdown(rep)})
}
