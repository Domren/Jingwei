// Package chains 蒸馏「反问思维链」：遇到 X 就先问自己 Y。
//
// 设计原则（来自 artex-ymh CHAINS-INTEGRATION-DESIGN）：
//   - 不靠模型自觉：该出现时必须出现（L3 由代码路由注入）
//   - 在对的时刻出现：SQLi 的链只在打 SQLi 时出现
//   - 成本固定：每轮开销有硬顶，不随语料增长
//
// 三层已实现：
//   - L1 监测（代码判据）→ honeydetect/ + guard/
//   - L2 纪律（meta 铁律）→ Discipline() 常驻 system
//   - L3 场景（技术链骨架）→ Skeleton() 按意图条件注入
//
// 原设计的 L4「全书参考文件」（skills/chains/）没有移植进本仓库。L3 骨架已把每条链
// 的必问项固化进注入内容，缺 L4 不改变行为；保留一条指向不存在目录的说明只会让人
// 以为还有一层待接入，故删除。
package chains

import (
	"strings"
)

// Discipline returns the L2 meta-discipline block for planner/worker system prompts.
// 这些是「元认知铁律」——不分场景永远适用的反问。
func Discipline() string {
	return `
**反问纪律（chains L2）**——执行前/写回前对照自检，不靠自觉：
1. **回显阴性 ≠ 漏洞阴性**：没报错不代表没注入，盲注/时间盲注/带外都需要专门测。
2. **版本 ≠ 漏洞**：指纹匹配到 CVE 不等于可利用，必须实际触发拿到证据才算。
3. **异常 ≠ 漏洞**：超时、500、慢响应可能是网络问题、也可能是蜜罐——先排除环境因素。
4. **同质响应 → 转向**：连续 15+ 次类似响应（同长度/同状态码），说明这条路走不通，换向。
5. **完美的漏洞是陷阱**：无条件注入、无认证 RCE、一步到位——太顺利要警惕蜜罐。
6. **卡住 ≠ 探透**：一次失败不代表这个面没有洞，换参数/换方法/换编码再试。
7. **证据不足不登记**：没有请求/响应或命令输出，就用 record_fact 记疑点，别硬报 finding。
8. **误报写 fact，真漏洞才落图**：拿不准的写 inferred 事实交规划者判断，别污染漏洞库。
9. **每个结论都要能自证**：报告里每一句话都要有对应的报文/输出支撑，否则删掉。
10. **你是来测漏洞的，不是来跑工具的**：工具报「found」不等于真有，自己看响应。`
}

// Skeleton returns the L3 scenario chain skeleton for a given vulnclass/intent.
// 代码路由：根据意图文本/vulnclass 匹配，不靠模型判断"我现在需要哪条链"。
func Skeleton(intentText, vulnclass string) string {
	text := strings.ToLower(intentText + " " + vulnclass)

	switch {
	case containsAny(text, "sql", "sqli", "注入", "injection", "database"):
		return skeletonSQLi()
	case containsAny(text, "xss", "cross-site", "跨站", "script"):
		return skeletonXSS()
	case containsAny(text, "rce", "命令执行", "command", "exec", "代码执行", "code"):
		return skeletonRCE()
	case containsAny(text, "lfi", "rfi", "文件包含", "path", "traversal", "目录遍历", "file"):
		return skeletonFile()
	case containsAny(text, "ssrf", "服务端请求", "request.forgery"):
		return skeletonSSRF()
	case containsAny(text, "auth", "认证", "bypass", "绕过", "越权", "authz", "权限"):
		return skeletonAuth()
	case containsAny(text, "recon", "信息收集", "指纹", "fingerprint", "枚举", "enum"):
		return skeletonRecon()
	case containsAny(text, "deserialization", "反序列化", "java", "php", "pickle"):
		return skeletonDeser()
	case containsAny(text, "upload", "上传", "file.upload"):
		return skeletonUpload()
	case containsAny(text, "xxe", "xml"):
		return skeletonXXE()
	default:
		return skeletonGeneric()
	}
}

func containsAny(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func skeletonSQLi() string {
	return `
【SQLi 反问链】
Q: 注入点在哪？GET/POST/Cookie/Header/Body？有几层参数？
Q: 数据库类型？报错信息/时间差异/版本头能判断吗？
Q: 回显型还是盲注？联合查询/报错/布尔/时间/带外？
Q: WAF/过滤怎么绕？大小写/注释/双写/编码/分块？
Q: 有没有用 sqlmap 复测？verify_sqli 传了吗？
Q: 权限有多大？能不能读文件/写文件/执行命令？
→ 判据：报错回显 ≠ 只有报错型；盲注也要测到底。误报写 fact，真漏洞才落图。`
}

func skeletonXSS() string {
	return `
【XSS 反问链】
Q: 反射/存储/DOM？在哪回显？编码/过滤怎么绕？
Q: 有没有用 dalfox 复测？verify_xss 传了吗？
Q: 能不能拿到 Cookie/执行 JS？危害有多大？
Q: CSP/HttpOnly 有没有？能绕吗？
→ 判据：alert(1) 只是证明，要给出可复现的 payload 和危害场景。`
}

func skeletonRCE() string {
	return `
【RCE 反问链】
Q: 命令注入还是代码执行？参数在哪？有哪些过滤？
Q: 有回显吗？没有就用外带（dnslog/collaborator）或写文件。
Q: 有哪些编码/截断/分隔符绕过？| ; $() 反引号 单引号 双引号？
Q: 权限多大？能读写哪些文件？
→ 判据：id/uname 不是终点，拿到可复现的完整请求+响应才算。`
}

func skeletonFile() string {
	return `
【文件操作 反问链】
Q: 路径遍历还是文件包含？读还是写？能穿越几层？
Q: 有哪些过滤？../ 还是 %2e%2e/ 还是双写？
Q: 能读到什么敏感文件？/etc/passwd、源码、配置、密钥？
Q: 能不能写文件？写到哪？能不能变成 webshell？
→ 判据：读到文件≠漏洞，给出实际读到的内容和完整请求才算。`
}

func skeletonSSRF() string {
	return `
【SSRF 反问链】
Q: 能访问内网吗？127.0.0.1/169.254.169.254/内网段？
Q: 协议支持？http/https/file/gopher/dict？
Q: 有回显吗？没回显用外带或时间盲注。
Q: 有没有解析限制/白名单？怎么绕？
→ 判据：能访问到内网服务/元数据才算，请求 URL+响应内容是证据。`
}

func skeletonAuth() string {
	return `
【认证/越权 反问链】
Q: 认证绕过还是权限提升？水平越权还是垂直越权？
Q: 能不能改其他用户的数据？改 id 参数/改 session？
Q: 有没有多步验证/二次确认？能跳过吗？
Q: JWT/Session/Cookie 有没有弱点？可伪造/可爆破？
→ 判据：拿到其他用户数据/管理员权限才算，给出完整请求+敏感响应。`
}

func skeletonRecon() string {
	return `
【信息收集 反问链】
Q: 端口/服务/版本/指纹都收集全了吗？有没有遗漏的端口/子域？
Q: 有没有敏感文件/目录？robots.txt、.git、.svn、备份文件？
Q: 技术栈确定了？框架/中间件/数据库/操作系统？
Q: 有没有蜜罐特征？太完美的服务要警惕。
→ 判据：信息本身不是漏洞，但它是攻击面地图——收得全才能打得准。`
}

func skeletonDeser() string {
	return `
【反序列化 反问链】
Q: 序列化格式？Java/PHP/Pickle/JSON/Protobuf？
Q: 有没有现成 gadget chain？Java Chains 工具链？
Q: 能执行到什么程度？弹计算器/读文件/反弹 shell？
→ 判据：序列化对象能控制=高危，给出完整 payload 和实际效果。`
}

func skeletonUpload() string {
	return `
【文件上传 反问链】
Q: 前端/后端校验？Content-Type/扩展名/文件头/大小？
Q: 能传什么类型？图片马/解析漏洞/双写/截断？
Q: 上传后能访问吗？能执行吗？
→ 判据：传上去≠能利用，要给出访问 URL+执行效果。`
}

func skeletonXXE() string {
	return `
【XXE 反问链】
Q: XML 解析器支持外部实体吗？有没有回显？
Q: 能读文件吗？能内网探测吗？能 SSRF 吗？
Q: 有 WAF/过滤？怎么绕？
→ 判据：读到文件/探测到内网才算，给出完整 XML payload 和响应。`
}

func skeletonGeneric() string {
	return `
【通用反问链】
Q: 这条路走通了吗？同质响应 15+ 次就换向。
Q: 有没有测完整？GET/POST/Header/Cookie/Body 都试了吗？
Q: 绕过手段试完了吗？编码/大小写/双写/分块？
Q: 证据够吗？没有请求/响应就用 record_fact 记疑点。
→ 判据：能复现+有证据才算漏洞，否则写 fact 交规划者。`
}
