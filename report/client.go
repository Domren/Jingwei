package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/jingwei/db"
)

// 客户交付版报告（H1）：内部全量报告的对面——只含已确认项、中英双语标签、
// 按责任方（受影响资产）分组给出修复建议，并在附录里保留可复现的原始报文。
//
// 刻意做成确定性的模板而不是让模型现写：交付件的措辞与结构要每次一致，
// 客户对比两轮报告时才看得出「修了什么」。英文只覆盖标题与字段标签，正文内容
// 保留原文（自动翻译会把技术细节译出歧义，那比不译更糟），交付时如需全文英文
// 由人翻译。

type ClientReportInput struct {
	Findings    []*db.DBFinding
	Assets      map[int64]string
	GeneratedAt time.Time
	// ScopeNote 是授权与范围声明，由操作员在导出时填写（可空）。
	ScopeNote string
}

var clientStatusAllowed = map[string]bool{
	"confirmed": true, "fixed": true, "resolved": true, "risk_accepted": true,
}

func clientAssetName(f *db.DBFinding, assets map[int64]string) string {
	for _, id := range f.AssetIDs {
		if name := strings.TrimSpace(assets[id]); name != "" {
			return name
		}
	}
	return "未关联资产 / Unassociated"
}

func clientTitle(f *db.DBFinding) string {
	if strings.TrimSpace(f.Name) != "" {
		return f.Name
	}
	if strings.TrimSpace(f.VulnClass) != "" {
		return f.VulnClass
	}
	return "未命名漏洞 / Unnamed finding"
}

// ClientMarkdown 渲染客户交付版。已确认以外的状态在这里再过滤一次：调用方
// 忘了传 audience=external 也不能把未确认项写进交付件。
func ClientMarkdown(in ClientReportInput) string {
	if in.GeneratedAt.IsZero() {
		in.GeneratedAt = time.Now()
	}
	fs := make([]*db.DBFinding, 0, len(in.Findings))
	for _, f := range in.Findings {
		if clientStatusAllowed[f.Status] {
			fs = append(fs, f)
		}
	}
	sortFindingsForExport(fs)

	var b strings.Builder
	b.WriteString("# 安全测试报告 / Security Assessment Report\n\n")
	fmt.Fprintf(&b, "**生成时间 / Generated**: %s\n\n", in.GeneratedAt.Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, "**已确认漏洞 / Confirmed findings**: %d\n\n", len(fs))
	b.WriteString("> 本报告仅涵盖已确认并复核的漏洞；测试范围以双方签署的授权清单为准。\n")
	b.WriteString("> This report covers confirmed and retested findings only. Scope is defined by the signed authorization.\n\n")
	if strings.TrimSpace(in.ScopeNote) != "" {
		fmt.Fprintf(&b, "**授权与范围 / Scope**: %s\n\n", strings.TrimSpace(in.ScopeNote))
	}

	// 概览：按严重级别
	bySeverity := map[string]int{}
	for _, f := range fs {
		bySeverity[strings.ToLower(nz(f.Severity, "info"))]++
	}
	b.WriteString("## 风险概览 / Risk Overview\n\n")
	b.WriteString("| 级别 / Severity | 数量 / Count |\n| :-- | --: |\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if bySeverity[sev] > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", sev, bySeverity[sev])
		}
	}
	b.WriteString("\n")

	// 按责任方（资产）分组
	groups := map[string][]*db.DBFinding{}
	order := []string{}
	for _, f := range fs {
		name := clientAssetName(f, in.Assets)
		if _, ok := groups[name]; !ok {
			order = append(order, name)
		}
		groups[name] = append(groups[name], f)
	}
	sort.Strings(order)

	b.WriteString("## 漏洞明细 / Findings\n\n")
	for _, asset := range order {
		fmt.Fprintf(&b, "### 受影响资产 / Affected asset: %s\n\n", asset)
		for i, f := range groups[asset] {
			fmt.Fprintf(&b, "#### %d. %s\n\n", i+1, clientTitle(f))
			fmt.Fprintf(&b, "- **类别 / Category**: %s\n", nz(f.VulnClass, "—"))
			fmt.Fprintf(&b, "- **级别 / Severity**: %s\n", nz(f.Severity, "info"))
			if f.CVSS != nil {
				fmt.Fprintf(&b, "- **CVSS v3.1**: %.1f\n", *f.CVSS)
			}
			fmt.Fprintf(&b, "- **状态 / Status**: %s\n", nz(f.Status, "pending"))
			if s := strings.TrimSpace(f.Summary); s != "" {
				fmt.Fprintf(&b, "\n**摘要 / Summary**\n\n%s\n", s)
			}
			if advice := clientRemediation(f); advice != "" {
				fmt.Fprintf(&b, "\n**修复建议 / Remediation**\n\n%s\n", advice)
			}
			b.WriteString("\n")
		}
	}

	// 修复建议汇总（按资产），方便客户按责任分发。
	b.WriteString("## 修复建议汇总 / Remediation Summary\n\n")
	for _, asset := range order {
		fmt.Fprintf(&b, "- **%s**：\n", asset)
		for _, f := range groups[asset] {
			advice := clientRemediation(f)
			if advice == "" {
				advice = "按同类漏洞的通用修复方案处理。"
			}
			// 只取第一句，汇总保持一行。
			line := strings.SplitN(strings.TrimSpace(advice), "\n", 2)[0]
			fmt.Fprintf(&b, "  - %s — %s\n", clientTitle(f), line)
		}
	}
	b.WriteString("\n")

	// 附录：原始报文，保证客户/复测方可以照着复现。
	b.WriteString("## 附录：原始报文 / Appendix: Raw Packets\n\n")
	for _, f := range fs {
		if strings.TrimSpace(f.HTTPRequest) == "" && strings.TrimSpace(f.HTTPResponse) == "" && len(f.EvidencePackets) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### #%d %s\n\n", f.ID, clientTitle(f))
		if len(f.EvidencePackets) > 0 {
			for _, p := range f.EvidencePackets {
				fmt.Fprintf(&b, "**%s**\n\n```http\n%s\n\n%s\n```\n\n", nz(p.Note, "原始交互"),
					strings.TrimRight(p.HTTPRequest, "\n"), strings.TrimRight(p.HTTPResponse, "\n"))
			}
			continue
		}
		// 被动读取型证据（端口横幅之类）没有请求字节。留一个空的代码块在客户
		// 报告里看起来像导出坏了，写清楚「没发过请求」才是可信的表述。
		req := strings.TrimRight(f.HTTPRequest, "\n")
		if strings.TrimSpace(req) == "" {
			req = "（无请求字节：被动读取 / No request bytes: passive read）"
		}
		resp := strings.TrimRight(f.HTTPResponse, "\n")
		if strings.TrimSpace(resp) == "" {
			resp = "（无响应正文 / No response body captured）"
		}
		b.WriteString("**请求 / Request**\n\n```http\n" + req + "\n```\n\n")
		b.WriteString("**响应 / Response**\n\n```http\n" + resp + "\n```\n\n")
	}
	return b.String()
}

// clientRemediation 按漏洞类别给出确定性的修复建议（中英双语要点）。
// 关键词匹配刻意宽：宁可给一条通用但正确的建议，也不要把类别说错。
func clientRemediation(f *db.DBFinding) string {
	key := strings.ToLower(f.VulnClass + " " + f.Name)
	switch {
	case strings.Contains(key, "sqli") || strings.Contains(key, "sql 注入") || strings.Contains(key, "sql injection"):
		return "使用参数化查询/预编译语句，禁止拼接 SQL；对输入做类型与长度校验；最小权限运行数据库账号。/ Use parameterized queries, validate input, and run the DB account with least privilege."
	case strings.Contains(key, "xss"):
		return "对输出按上下文做编码，启用内容安全策略（CSP）；对富文本使用白名单过滤。/ Encode output per context and enforce a Content Security Policy."
	case strings.Contains(key, "weak") || strings.Contains(key, "弱口令") || strings.Contains(key, "credential"):
		return "立即更换为该主机独立的高强度口令，禁用或限制默认账号，并启用登录失败锁定与来源限制。/ Rotate to a unique strong password, disable default accounts, and enable lockout/rate limits."
	case strings.Contains(key, "upload") || strings.Contains(key, "上传"):
		return "限制可上传类型与大小，上传目录禁止脚本执行，文件重命名并落在 Web 根之外。/ Restrict file types, disable script execution in upload paths, and store files outside the web root."
	case strings.Contains(key, "rce") || strings.Contains(key, "命令执行") || strings.Contains(key, "deserial") || strings.Contains(key, "反序列化"):
		return "升级受影响的组件到修复版本，禁止不可信数据的反序列化/命令拼接，按最小权限运行服务。/ Patch the affected component and avoid deserializing untrusted data."
	case strings.Contains(key, "traversal") || strings.Contains(key, "文件包含") || strings.Contains(key, "lfi") || strings.Contains(key, "目录遍历"):
		return "对文件路径做白名单校验并规范化，禁止将用户输入直接拼入包含/读取路径。/ Validate paths against an allowlist and canonicalize before use."
	case strings.Contains(key, "ssrf"):
		return "对出站请求做目标白名单与内网地址拦截，禁止跟随重定向到非授权目标。/ Enforce an egress allowlist and block private/metadata ranges."
	case strings.Contains(key, "exposed") || strings.Contains(key, "unauthorized") ||
		strings.Contains(key, "对外暴露") || strings.Contains(key, "未授权") ||
		strings.Contains(key, "redis") || strings.Contains(key, "mongodb") || strings.Contains(key, "memcached") ||
		strings.Contains(key, "elasticsearch") || strings.Contains(key, "zookeeper"):
		return "把服务绑定到内网或回环地址，用防火墙限制可访问来源，启用认证（支持时再开 TLS）并关闭危险命令；这类服务不应以默认配置对外网开放。/ Bind the service to internal/loopback interfaces, restrict sources by firewall, enable authentication (and TLS where supported), and disable dangerous commands; do not expose such services to the internet with default settings."
	case strings.Contains(key, "info") || strings.Contains(key, "泄露") || strings.Contains(key, "disclosure"):
		return "关闭生产环境的调试与目录列举，移除响应中的版本与内部路径信息。/ Disable debug endpoints and remove version/path details from responses."
	default:
		return "按该漏洞类别的标准修复方案处理，并在修复后使用本报告附录中的报文复测。/ Apply the standard fix for this class and retest with the packets in the appendix."
	}
}
