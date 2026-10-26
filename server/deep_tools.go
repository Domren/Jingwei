package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// deepTools exposes the automatic verification/exploitation capabilities to
// LLM agents. Each tool queues a real deep task (so progress/evidence are
// persisted exactly like the scan pipeline) and waits for its result.
func (s *Server) deepTools() []actool.CoreTool {
	return append([]actool.CoreTool{
		s.toolVerifyVulnerability(),
		s.toolExploitVulnerability(),
		s.toolVerifySQLI(),
		s.toolVerifyXSS(),
		s.toolWAFBypass(),
		s.toolInjectWebshell(),
		s.toolGetDeepTask(),
	}, append(s.intranetTools(), s.resourceTools()...)...)
}

type deepToolInput struct {
	Target      string   `json:"target"`
	TemplateIDs []string `json:"template_ids"`
	POCIDs      []int64  `json:"poc_ids"`
	FindingIDs  []int64  `json:"finding_ids"`
	Repeats     int      `json:"repeats"`
	WriteFind   *bool    `json:"write_finding"`
	JavaChains  string   `json:"java_chains"`
	JavaCmd     string   `json:"java_cmd"`
	WaitSeconds int      `json:"wait_seconds"`
	QueueOnly   bool     `json:"queue_only"`

	URLs       []string `json:"urls"`
	Params     []string `json:"params"`
	Cookie     string   `json:"cookie"`
	Headers    []string `json:"headers"`
	MaxPoint   int      `json:"max_points"`
	Level      int      `json:"level"`
	Risk       int      `json:"risk"`
	Techniques string   `json:"techniques"`
	DBMS       string   `json:"dbms"`
	Workers    int      `json:"workers"`
	RateLimit  int      `json:"rate_limit"`
	Stored     bool     `json:"stored"`
	StoredURL  string   `json:"stored_url"`
	Points     []struct {
		URL        string   `json:"url"`
		Method     string   `json:"method"`
		Data       string   `json:"data"`
		TemplateID string   `json:"template_id"`
		Params     []string `json:"params"`
		FindingIDs []int64  `json:"finding_ids"`
	} `json:"points"`

	Path     string   `json:"path"`
	Param    string   `json:"param"`
	Payload  string   `json:"payload"`
	Keywords []string `json:"keywords"`

	UploadURL string `json:"upload_url"`
	LandURL   string `json:"land_url"`
	ShellType string `json:"shell_type"`
	Password  string `json:"password"`
	FieldName string `json:"field_name"`

	TaskID int64 `json:"task_id"`
}

func (s *Server) toolVerifyVulnerability() actool.CoreTool {
	return wrTool("verify_vulnerability",
		"对已授权目标做漏洞验证：用指定 POC 模板（或按目标指纹自动匹配）重放，并自动调用 java-chains 处理 Java 反序列化。命中会按反证规则判定为 confirmed 或 needs_review（证据不足）；若传入 finding_ids，confirmed 会把对应发现置为已确认并追加证据。任务串行执行，工具会等待结果；命中与证据写入深度任务记录。",
		objSchema(map[string]any{
			"target":       strParam("目标 URL，例如 https://example.com"),
			"template_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "nuclei 模板 ID 列表（可选；来自 POC 库或漏扫结果）"},
			"poc_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "POC 库记录 ID 列表（可选）"},
			"finding_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "要回写确认的发现 ID 列表（可选；确认命中后置为 confirmed）"},
			"repeats":      map[string]any{"type": "integer", "description": "复现次数，1-3，默认 1"},
			"java_chains":  strParam("Java 反序列化时是否自动调用 java-chains：auto（默认）或 off"),
			"java_cmd":     strParam("java-chains 验证命令，默认 id"),
			"wait_seconds": map[string]any{"type": "integer", "description": "等待任务完成的秒数，默认 180，最大 600"},
		}, "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.runDeepTool(ctx, in, db.DeepTaskVerify)
		})
}

func (s *Server) toolExploitVulnerability() actool.CoreTool {
	return wrTool("exploit_vulnerability",
		"对已授权目标做漏洞利用验证：重放 POC 或按指纹自动选模板，保留请求/响应证据，自动调用 java-chains 验证 Java 反序列化；命中会按反证规则判定为 confirmed 或 needs_review。默认把 confirmed 命中写入「发现」；若传入 finding_ids，则改为确认并回写这些既有发现。任务串行执行并等待结果。",
		objSchema(map[string]any{
			"target":        strParam("目标 URL"),
			"template_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "nuclei 模板 ID 列表（可选）"},
			"poc_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "POC 库记录 ID 列表（可选）"},
			"finding_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "要回写确认的发现 ID 列表（可选；提供后不再新建发现）"},
			"write_finding": map[string]any{"type": "boolean", "description": "confirmed 命中后写入发现，默认 true"},
			"java_chains":   strParam("auto（默认）或 off"),
			"java_cmd":      strParam("java-chains 验证命令，默认 id"),
			"wait_seconds":  map[string]any{"type": "integer", "description": "等待秒数，默认 180，最大 600"},
		}, "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.runDeepTool(ctx, in, db.DeepTaskExploit)
		})
}

// toolVerifySQLI and toolVerifyXSS expose the specialized injection verifiers.
// A POC template only proves a response looked interesting; these queue sqlmap /
// dalfox, which prove or reject that the parameter really is an injection point,
// then replay the proved payload so the finding carries raw packets.
func (s *Server) toolVerifySQLI() actool.CoreTool {
	return wrTool("verify_sqli",
		"用 sqlmap 对已授权目标做 SQL 注入专项验证，代替 POC 模板判定：传入带参数的 URL 或注入点列表，sqlmap 仅做检测（不取数、不枚举库表）；确认后原样复放证明 payload，并保存未注入的对照请求，两侧原始 HTTP 报文写入证据；提供 finding_ids 时把对应发现置为已确认。登录站点必须传 cookie（如 PHPSESSID=…）。level 上限 3、risk 上限 2。宽字节（GBK 等多字节字符集）注入不在 sqlmap 的 payload 范围内：这类点改由对照复放判定，payload 仍能改变响应则确认，否则记为未复现。",
		objSchema(map[string]any{
			"urls":         strArrayParam("注入点完整 URL 列表（含参数），例如 http://host/sqli_str.php?name=1&submit=%E6%9F%A5%E8%AF%A2"),
			"points":       probePointSchema(),
			"target":       strParam("任务归属目标 URL（可选，默认取第一个注入点）"),
			"params":       strArrayParam("只测试这些参数名（可选，缩小检测范围）"),
			"cookie":       strParam("会话 Cookie，例如 PHPSESSID=…（登录站点必填）"),
			"headers":      strArrayParam("附加请求头，形如 X-Forwarded-For: 127.0.0.1（可选）"),
			"level":        intArgSchema("sqlmap 检测等级 1-3，默认 3"),
			"risk":         intArgSchema("sqlmap 风险等级 1-2，默认 2"),
			"techniques":   strParam("限定注入技术，BEUSQT 的子集，如 BEU（可选）"),
			"dbms":         strParam("后端数据库提示，如 mysql（可选）"),
			"max_points":   intArgSchema("最多验证的注入点数，默认 8，最大 50"),
			"finding_ids":  intArrayParam("要回写确认的发现 ID 列表（可选）"),
			"wait_seconds": intArgSchema("等待任务完成的秒数，默认 300，最大 600"),
			"queue_only":   map[string]any{"type": "boolean", "description": "true=只排队不等结果，工具立刻返回深度任务 ID，结论与原始报文跑完后自动回写 finding_ids；本意图剩余时间不足以等完时使用（默认省略=等待）"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.runDeepTool(ctx, in, db.DeepTaskSQLiProbe)
		})
}

func (s *Server) toolVerifyXSS() actool.CoreTool {
	return wrTool("verify_xss",
		"用 dalfox 对已授权目标做 XSS 专项验证，代替 POC 模板判定：传入带参数的 URL 或注入点列表（POST 用 points 携带原始请求体）。只有可执行的 verified 结论才算确认，仅反射时记为 needs_review；确认后复放证明请求，把原始 HTTP 报文写入证据，并按 finding_ids 回写发现。参数值不在响应中回显的点（盲打、存储型、需浏览器交互的 DOM 输出）超出 dalfox 的判定范围，其阴性结论不撤销原判定，记为 tool_uncovered。",
		objSchema(map[string]any{
			"urls":         strArrayParam("注入点完整 URL 列表（含参数），例如 http://host/xss_reflected_get.php?message=test&submit=submit"),
			"points":       probePointSchema(),
			"target":       strParam("任务归属目标 URL（可选，默认取第一个注入点）"),
			"params":       strArrayParam("只测试这些参数名（可选）"),
			"cookie":       strParam("会话 Cookie（登录站点必填）"),
			"headers":      strArrayParam("附加请求头（可选）"),
			"workers":      intArgSchema("dalfox 并发 1-20，默认 8"),
			"rate_limit":   intArgSchema("每秒请求数 1-200，默认 20"),
			"stored":       map[string]any{"type": "boolean", "description": "存储型 XSS：先提交再访问展示页，默认 false"},
			"stored_url":   strParam("存储型 XSS 的展示页 URL（stored=true 时使用）"),
			"max_points":   intArgSchema("最多验证的注入点数，默认 8，最大 20"),
			"finding_ids":  intArrayParam("要回写确认的发现 ID 列表（可选）"),
			"wait_seconds": intArgSchema("等待任务完成的秒数，默认 300，最大 600"),
			"queue_only":   map[string]any{"type": "boolean", "description": "true=只排队不等结果，工具立刻返回深度任务 ID，结论与原始报文跑完后自动回写 finding_ids；本意图剩余时间不足以等完时使用（默认省略=等待）"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.runDeepTool(ctx, in, db.DeepTaskXSSProbe)
		})
}

func probePointSchema() map[string]any {
	return map[string]any{
		"type":        "array",
		"description": "注入点列表（可选，比 urls 更精确：支持 POST 报文、参数名与逐点发现 ID）",
		"items": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":         map[string]any{"type": "string", "description": "注入点完整 URL（含参数）"},
				"method":      map[string]any{"type": "string", "description": "GET 或 POST，默认 GET"},
				"data":        map[string]any{"type": "string", "description": "POST 原始请求体，例如 name=1&submit=%E6%9F%A5%E8%AF%A2"},
				"template_id": map[string]any{"type": "string", "description": "关联的 POC 模板 ID（可选）"},
				"params":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "该点只测这些参数名（可选）"},
				"finding_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "该点对应的发现 ID（可选）"},
			},
		},
	}
}

func strArrayParam(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

func intArrayParam(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": desc}
}

func intArgSchema(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func (s *Server) toolWAFBypass() actool.CoreTool {
	return wrTool("test_waf_bypass",
		"对已授权目标识别 WAF 并测试多种绕过变形（编码、大小写、路径、请求头等），逐条记录是否绕过。适合在 POC 被拦截或需要确认 WAF 防护时调用。",
		objSchema(map[string]any{
			"target":       strParam("目标 URL（base_url）"),
			"path":         strParam("探测路径，默认 /"),
			"param":        strParam("参数名（可选）"),
			"payload":      strParam("攻击载荷，默认 SQL 注入串"),
			"keywords":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "判断绕过成功的响应关键词（可选）"},
			"wait_seconds": map[string]any{"type": "integer", "description": "等待秒数，默认 120，最大 600"},
		}, "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.runDeepTool(ctx, in, db.DeepTaskWAFBypass)
		})
}

func (s *Server) toolInjectWebshell() actool.CoreTool {
	return wrTool("inject_webshell",
		"向已授权目标的上传接口尝试投放 webshell，并在提供落地地址时验证存活；成功后会登记到 Webshell 管理。仅在明确授权且可控的测试环境使用。",
		objSchema(map[string]any{
			"upload_url":   strParam("上传接口完整 URL"),
			"land_url":     strParam("webshell 落地 URL（可选，用于存活验证）"),
			"target":       strParam("任务归属目标（可选，默认上传地址）"),
			"shell_type":   strParam("php / jsp / aspx，默认 php"),
			"password":     strParam("连接密码（可选，留空自动生成）"),
			"field_name":   strParam("上传表单字段名，默认 file"),
			"wait_seconds": map[string]any{"type": "integer", "description": "等待秒数，默认 120，最大 600"},
		}, "upload_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.runDeepTool(ctx, in, db.DeepTaskWebshellInject)
		})
}

func (s *Server) toolGetDeepTask() actool.CoreTool {
	return roTool("get_deep_task",
		"查询深度任务（验证/利用/WAF/Webshell）的状态、摘要与证据。当之前的工具等待超时或任务仍在队列时使用。",
		objSchema(map[string]any{
			"task_id": map[string]any{"type": "integer", "description": "深度任务 ID"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a deepToolInput
			_ = json.Unmarshal(in, &a)
			if a.TaskID <= 0 {
				return actool.Errorf("task_id 必填"), nil
			}
			return s.deepTaskToolResult(a.TaskID, false)
		})
}

func (s *Server) runDeepTool(ctx context.Context, in json.RawMessage, kind string) (actool.Result, error) {
	var a deepToolInput
	if err := json.Unmarshal(in, &a); err != nil {
		return actool.Errorf("参数格式错误"), nil
	}
	wait := a.WaitSeconds
	if wait <= 0 {
		wait = 180
	}
	if wait < 10 {
		wait = 10
	}
	if wait > 600 {
		wait = 600
	}
	params := map[string]any{"source": "llm"}
	target := strings.TrimSpace(a.Target)
	switch kind {
	case db.DeepTaskVerify, db.DeepTaskExploit:
		if target == "" {
			return actool.Errorf("target 必填"), nil
		}
		if len(a.TemplateIDs) > 0 {
			params["matched_template_ids"] = a.TemplateIDs
		}
		if len(a.POCIDs) > 0 {
			params["template_ids"] = a.POCIDs
		}
		if len(a.FindingIDs) > 0 {
			params["finding_ids"] = a.FindingIDs
		}
		if a.Repeats > 0 {
			params["repeats"] = a.Repeats
		}
		params["java_chains"] = displayOr(strings.TrimSpace(a.JavaChains), "auto")
		params["java_cmd"] = displayOr(strings.TrimSpace(a.JavaCmd), "id")
		if kind == db.DeepTaskExploit {
			writeFinding := true
			if a.WriteFind != nil {
				writeFinding = *a.WriteFind
			}
			params["write_finding"] = writeFinding
		}
	case db.DeepTaskSQLiProbe, db.DeepTaskXSSProbe:
		if a.WaitSeconds <= 0 {
			wait = 300
		}
		pts := a.probePoints()
		if target == "" && len(pts) > 0 {
			target = stringFromMap(pts[0], "url")
		}
		if target == "" {
			return actool.Errorf("请提供 urls、points 或 target"), nil
		}
		if len(pts) > 0 {
			params["points"] = pts
		}
		if c := strings.TrimSpace(a.Cookie); c != "" {
			params["cookie"] = c
		}
		if hs := cleanArgList(a.Headers, 16); len(hs) > 0 {
			params["headers"] = hs
		}
		if n := clampToolInt(a.MaxPoint, 1, 50); n > 0 {
			params["max_points"] = n
		}
		if len(a.FindingIDs) > 0 {
			params["finding_ids"] = a.FindingIDs
		}
		if kind == db.DeepTaskSQLiProbe {
			if l := clampToolInt(a.Level, 1, 3); l > 0 {
				params["level"] = l
			}
			if rk := clampToolInt(a.Risk, 1, 2); rk > 0 {
				params["risk"] = rk
			}
			if t := strings.TrimSpace(a.Techniques); t != "" {
				params["techniques"] = t
			}
			if d := strings.TrimSpace(a.DBMS); d != "" {
				params["dbms"] = d
			}
		} else {
			if w := clampToolInt(a.Workers, 1, 20); w > 0 {
				params["workers"] = w
			}
			if rl := clampToolInt(a.RateLimit, 1, 200); rl > 0 {
				params["rate_limit"] = rl
			}
			params["stored"] = a.Stored
			if u := strings.TrimSpace(a.StoredURL); u != "" {
				params["stored_url"] = u
			}
		}
	case db.DeepTaskWAFBypass:
		if target == "" {
			return actool.Errorf("target 必填"), nil
		}
		params["base_url"] = target
		if p := strings.TrimSpace(a.Path); p != "" {
			params["path"] = p
		}
		if p := strings.TrimSpace(a.Param); p != "" {
			params["param"] = p
		}
		if p := strings.TrimSpace(a.Payload); p != "" {
			params["payload"] = p
		}
		if len(a.Keywords) > 0 {
			params["keywords"] = a.Keywords
		}
	case db.DeepTaskWebshellInject:
		upload := strings.TrimSpace(a.UploadURL)
		if upload == "" {
			return actool.Errorf("upload_url 必填"), nil
		}
		if target == "" {
			target = upload
		}
		shellType := strings.ToLower(strings.TrimSpace(a.ShellType))
		if shellType == "" {
			shellType = "php"
		}
		password := strings.TrimSpace(a.Password)
		if password == "" {
			password = randomShellPassword()
		}
		params["upload_url"] = upload
		params["land_url"] = strings.TrimSpace(a.LandURL)
		params["shell_type"] = shellType
		params["password"] = password
		params["field_name"] = displayOr(strings.TrimSpace(a.FieldName), "file")
	default:
		return actool.Errorf("未知的深度任务类型"), nil
	}

	name := deepTaskLabel(kind) + " · " + target
	task, err := s.queueDeepToolTask(db.DeepTaskInput{
		Name:    name,
		Kind:    kind,
		Target:  target,
		Params:  params,
		AutoRun: false,
	})
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	if a.QueueOnly {
		return actool.Text(queuedProbeNote(kind, task.ID, a)), nil
	}
	finished := s.waitDeepTask(ctx, task.ID, time.Duration(wait)*time.Second)
	return s.deepTaskToolResult(task.ID, !finished)
}

// queuedProbeNote is the queue_only answer: the specialized tool runs in the
// background and its verdict lands on the linked findings when it finishes, so an
// agent under a wall-clock deadline still gets sqlmap/dalfox coverage instead of
// abandoning the verifier because waiting would eat its remaining turns. Pointing
// out a missing link here is cheaper than letting the probe prove an injection
// that nothing reads (see probeWriteBackNote).
func queuedProbeNote(kind string, id int64, a deepToolInput) string {
	note := fmt.Sprintf("已排队：%s（深度任务 #%d），本次调用不等待结果。工具跑完后结论与原始报文会自动写入该任务记录；进度用 get_deep_task(task_id=%d) 查看。同一批注入点不要重复排队。",
		deepTaskLabel(kind), id, id)
	if kind != db.DeepTaskSQLiProbe && kind != db.DeepTaskXSSProbe {
		return note
	}
	linked := len(a.FindingIDs) > 0
	for _, p := range a.Points {
		if len(p.FindingIDs) > 0 {
			linked = true
		}
	}
	if !linked {
		note += "注意：本次没有传 finding_ids，工具结论不会回写到任何发现——请在这批注入点各自 report_finding 之后，用 finding_ids=<发现 ID> 复跑，或在排队前先登记发现。"
	}
	return note
}

// probeWriteBackNote catches the case where a specialized verifier proved an
// injection but nothing in the platform changed: with no finding linked and none
// written, the verdict only lives in the deep task's own records, so the report
// and the finding list keep whatever the POC asserted. The agent is told to re-run
// with finding_ids or register the proved packets itself.
func probeWriteBackNote(task *db.DeepTask) string {
	if task.Kind != db.DeepTaskSQLiProbe && task.Kind != db.DeepTaskXSSProbe {
		return ""
	}
	if intParam(task.Summary, "confirmed", 0) <= 0 || intParam(task.Summary, "findings_confirmed", 0) > 0 {
		return ""
	}
	if boolParam(task.Params, "write_finding") {
		return ""
	}
	return "工具确认了注入点，但本次没有任何发现被回写：既没传 finding_ids，也没有可关联的模板发现，结论只留在深度任务记录里。请用 finding_ids=<已有发现 ID> 重新调用本工具，或先 report_finding 登记该注入点（PoC 用工具证明报文）再复测。"
}

// probePoints normalises the tool's urls/points args into the point list the
// deep task stores, so an agent can describe a POST injection as well as a GET
// one. Top-level params and finding ids fill in any point that left them out.
func (a deepToolInput) probePoints() []map[string]any {
	pts := []map[string]any{}
	seen := map[string]bool{}
	add := func(rawURL, method, body, templateID string, names []string, ids []int64) {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" || seen[rawURL] {
			return
		}
		seen[rawURL] = true
		if method == "" {
			method = "GET"
		}
		item := map[string]any{
			"url":         rawURL,
			"method":      strings.ToUpper(method),
			"template_id": strings.TrimSpace(templateID),
			"source":      "llm",
		}
		if body != "" {
			item["data"] = body
		}
		if len(names) > 0 {
			item["params"] = names
		}
		if len(ids) > 0 {
			item["finding_ids"] = ids
		}
		pts = append(pts, item)
	}
	for _, p := range a.Points {
		names := cleanArgList(p.Params, 10)
		if len(names) == 0 {
			names = cleanArgList(a.Params, 10)
		}
		ids := p.FindingIDs
		if len(ids) == 0 {
			ids = a.FindingIDs
		}
		add(p.URL, p.Method, p.Data, p.TemplateID, names, ids)
	}
	for _, u := range a.URLs {
		add(u, "", "", "", cleanArgList(a.Params, 10), a.FindingIDs)
	}
	if len(pts) > maxLLMProbePoints {
		pts = pts[:maxLLMProbePoints]
	}
	return pts
}

const maxLLMProbePoints = 20

func cleanArgList(items []string, max int) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || strings.ContainsAny(item, "\r\n") || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
		if len(out) >= max {
			break
		}
	}
	return out
}

// clampToolInt bounds an agent-supplied value; non-positive means "not given".
func clampToolInt(value, min, max int) int {
	if value <= 0 {
		return 0
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// queueDeepToolTask applies the same asset blocklist as the HTTP API before
// queueing a task for the deep manager.
func (s *Server) queueDeepToolTask(req db.DeepTaskInput) (*db.DeepTask, error) {
	pg := s.m.pg
	if pg == nil {
		return nil, errors.New("数据库未初始化")
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	rules, err := pg.ListAssetInterceptRules()
	if err != nil {
		return nil, errors.New("加载资产拦截规则失败: " + err.Error())
	}
	probe := &deepRun{s: s, pg: pg, task: &db.DeepTask{Kind: req.Kind, Target: req.Target, Params: req.Params}}
	if reason, blocked := scanTargetBlockReason(rules, probe.targets()); blocked {
		return nil, errors.New("目标命中资产拦截规则，已拒绝执行：" + reason)
	}
	task, err := pg.CreateDeepTask(req)
	if err != nil {
		return nil, err
	}
	if s.deepMgr != nil {
		s.deepMgr.wakeup()
	}
	return task, nil
}

// waitDeepTask polls until the task reaches a terminal state or the deadline
// expires. Cancellation returns false but leaves the task running.
func (s *Server) waitDeepTask(ctx context.Context, id int64, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if task, err := s.m.pg.GetDeepTask(id); err == nil {
			switch task.Status {
			case "done", "failed", "canceled":
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func (s *Server) deepTaskToolResult(id int64, timedOut bool) (actool.Result, error) {
	task, err := s.m.pg.GetDeepTask(id)
	if err != nil {
		return actool.Errorf("读取任务失败: " + err.Error()), nil
	}
	task.Log = ""
	out := map[string]any{"task": task}
	if timedOut {
		out["timed_out"] = true
		out["note"] = "任务仍在队列或执行中，可稍后用 get_deep_task 查询"
	}
	if records, err := s.m.pg.ListExploitRecords(id); err == nil {
		brief := make([]map[string]any, 0, len(records))
		review := 0
		for i, rec := range records {
			if i >= 50 {
				break
			}
			if rec.Verdict == "needs_review" {
				review++
			}
			item := map[string]any{
				"template_id": rec.TemplateID,
				"name":        rec.Name,
				"severity":    rec.Severity,
				"target":      rec.Target,
				"verdict":     rec.Verdict,
				"evidence":    truncateText(rec.Evidence, 600),
			}
			if rec.StatusCode != nil {
				item["status_code"] = *rec.StatusCode
			}
			if rec.Curl != "" {
				item["curl"] = rec.Curl
			}
			brief = append(brief, item)
		}
		out["records"] = brief
		if review > 0 {
			out["needs_review"] = review
			out["review_note"] = "部分命中证据不足。请按记录 evidence 中的复核清单补一次差分/对照验证后再下结论；不要仅凭状态码或通用关键词判定漏洞存在。"
		}
	}
	if note := probeWriteBackNote(task); note != "" {
		out["write_back_note"] = note
	}
	if results, err := s.m.pg.ListWAFBypassResults(id); err == nil {
		brief := make([]map[string]any, 0, len(results))
		for i, res := range results {
			if i >= 50 {
				break
			}
			brief = append(brief, map[string]any{
				"target":    res.Target,
				"vendor":    res.WAFVendor,
				"variant":   res.Variant,
				"verdict":   res.Verdict,
				"status":    res.StatusCode,
				"note":      res.Note,
				"resp_size": res.RespLength,
			})
		}
		out["waf_results"] = brief
	}
	if task.Kind == db.DeepTaskWebshellInject {
		switch v := task.Summary["webshell_id"].(type) {
		case float64:
			if v > 0 {
				out["webshell_id"] = int64(v)
			}
		case int64:
			if v > 0 {
				out["webshell_id"] = v
			}
		}
	}
	return jsonResult(out)
}

// deepToolBindings are the agents that receive the deep capabilities by
// default. Skill-gated MCP tools use the same set.
var deepToolBindings = []string{"auto", "pentest", "worker"}

func (s *Server) seedDeepTools() {
	bindings, _ := json.Marshal(deepToolBindings)
	for _, t := range s.deepTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			// seeding is best-effort; the tool still works if no row exists
			continue
		}
	}
}
