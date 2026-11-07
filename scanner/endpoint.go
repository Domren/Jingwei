package scanner

// 终端防护识别与补丁基线（F5）。
//
// 这一层只回答两句事实：这台机器上跑着什么终端安全产品、已安装的补丁里有没有基线关注的条目。
// 它**不判断能不能绕过、不提供任何规避做法**——把「检测到 Defender」写成「怎么关掉 Defender」
// 是把一个信息事实变成一份攻击建议，而那份建议既不可靠（版本与策略差异极大）也不该由平台给出。
//
// 两条口径决定结果能不能进报告：
//
//  1. **识别按证据说话**。每条命中都带着它依据的进程名/服务名，读的人可以自己核对；
//     认不出的可疑名字进「待人工确认」一栏，不静默丢掉，也不硬安一个产品名上去。
//     签名表是人工整理的子集，命中不了不等于没有防护——这句会写在结论里。
//  2. **补丁基线不是补丁比对**。基线只放少数高信号通告（永恒之蓝、BlueKeep、Zerlogon、
//     PrintNightmare 一类），每条列的是「该通告在各版本上出现过的 KB 号集合」而不是
//     「哪个系统该装哪个 KB」——因为累计更新会取代早期 KB 编号，一台完全打满补丁的机器
//     也可能一个基线号都不出现。所以「集合里一个都没命中」的结论是**待确认**，
//     不是「存在漏洞」；反过来命中了就是这一条不构成缺口。

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// 终端安全产品的类别。
const (
	EndpointKindAV    = "av"   // 传统反病毒
	EndpointKindEDR   = "edr"  // 端点检测与响应
	EndpointKindHIPS  = "hips" // 主机入侵防护/行为防护
	EndpointKindOther = "other"
)

// EndpointSignature 是一个已登记的终端安全产品。
//
// Tokens 是**进程名或服务名**（小写、不带 .exe/.sys）。用精确匹配而不是子串：
// 子串匹配会让 "guard" 命中 Jenkins 的某个服务，误报一次「有杀软」比漏报一次
// 更糟——后续动作会围着一个不存在的防护做决策。
type EndpointSignature struct {
	Product string
	Vendor  string
	Kind    string
	Tokens  []string
}

// endpointSignatures 是人工整理的签名表。只收有公开文档支撑的名字；
// 没把握的产品宁可留给「待人工确认」，也不猜。
var endpointSignatures = []EndpointSignature{
	{Product: "Microsoft Defender 防病毒", Vendor: "Microsoft", Kind: EndpointKindAV,
		Tokens: []string{"msmpeng", "windefend", "nissrv", "securityhealthservice", "mpdefendercoreservice", "defender", "wdfilter"}},
	{Product: "Microsoft Defender for Endpoint", Vendor: "Microsoft", Kind: EndpointKindEDR,
		Tokens: []string{"mssense", "sense-cncproxy", "mdsensorrun", "mdecore", "msbt", "msensor", "miaudit", "wdai"}},
	{Product: "火绒安全软件", Vendor: "火绒", Kind: EndpointKindHIPS,
		Tokens: []string{"hipstray", "hipsdaemon", "sysdiag", "usnsvc", "hwsd", "huorong"}},
	{Product: "360 安全卫士 / 主动防御", Vendor: "三六零", Kind: EndpointKindHIPS,
		Tokens: []string{"zhuodongfangyu", "360tray", "360sd", "360safe", "qhwatchdog", "qhsafe", "360rp"}},
	{Product: "奇安信天擎", Vendor: "奇安信", Kind: EndpointKindEDR,
		Tokens: []string{"qaxtray", "tqdefender", "tqclient", "qhtqtray", "tianqing", "360qax"}},
	{Product: "Symantec Endpoint Protection", Vendor: "Broadcom/Symantec", Kind: EndpointKindAV,
		Tokens: []string{"ccsvchst", "smc", "rtvscan", "symcorsec", "savsmcservice"}},
	{Product: "McAfee Endpoint Security", Vendor: "McAfee", Kind: EndpointKindAV,
		Tokens: []string{"mcshield", "mfeopenfile", "mfefire", "mfeann", "macompatsvc", "mfeevtmgr"}},
	{Product: "Kaspersky Endpoint Security", Vendor: "Kaspersky", Kind: EndpointKindAV,
		Tokens: []string{"avp", "avpworker", "avpserver", "klnagent", "kavfltr"}},
	{Product: "ESET Endpoint Security", Vendor: "ESET", Kind: EndpointKindAV,
		Tokens: []string{"ekrn", "egui", "eset_raclsrv", "setup向导"}},
	{Product: "Trend Micro OfficeScan / Apex One", Vendor: "Trend Micro", Kind: EndpointKindAV,
		Tokens: []string{"ntrtscan", "tmlisten", "ofcscan", "ccproxy", "tmsmartscanagent"}},
	{Product: "Sophos Endpoint", Vendor: "Sophos", Kind: EndpointKindAV,
		Tokens: []string{"saveservice", "sophossavi", "sophoscleaner", "intelappservice", "savservice"}},
	{Product: "Avast / AVG", Vendor: "Gen", Kind: EndpointKindAV,
		Tokens: []string{"aswserv", "avastsvc", "avastui", "aswtools", "avgsvc", "avgidsagent"}},
	{Product: "Bitdefender", Vendor: "Bitdefender", Kind: EndpointKindAV,
		Tokens: []string{"bdagent", "vsservice", "epintegration", "productagent", "bdredline"}},
	{Product: "CrowdStrike Falcon", Vendor: "CrowdStrike", Kind: EndpointKindEDR,
		Tokens: []string{"csfalconservice", "csagentruntime", "csfalconcontinst"}},
	{Product: "SentinelOne", Vendor: "SentinelOne", Kind: EndpointKindEDR,
		Tokens: []string{"sentinelagent", "sentinelhelperservice", "sentinelui"}},
	{Product: "VMware Carbon Black", Vendor: "VMware", Kind: EndpointKindEDR,
		Tokens: []string{"cbsensor", "cbdaemon", "carbonblack"}},
	{Product: "Cylance / BlackBerry Protect", Vendor: "BlackBerry", Kind: EndpointKindEDR,
		Tokens: []string{"cylancesvc", "cylanceui", "cylancepolicy"}},
	{Product: "ClamAV", Vendor: "Cisco", Kind: EndpointKindAV,
		Tokens: []string{"clamd", "freshclam", "clamav-daemon", "clamonacc"}},
	{Product: "Dr.Web", Vendor: "Doctor Web", Kind: EndpointKindAV,
		Tokens: []string{"dwservice", "spIDER", "drweb32", "drwebcs"}},
	{Product: "安天智甲 / 其它国产终端防护", Vendor: "安天", Kind: EndpointKindAV,
		Tokens: []string{"antiy_tray", "shenjiav", "avkwatch"}},
}

// endpointHintTokens 是「看着像安全产品但没登记过」的线索词。命中它们只进待确认栏。
var endpointHintTokens = []string{
	"guard", "defend", "defense", "fangyu", "protect", "antiv", "avsvc", "hips", "sandbox",
	"edr", "xdr", "security", "safe", "trust", "scan", "qu", "360", "qax", "sangfor",
	"topsec", "nsfocus", "dbapp", "ahnlab", "venustech", "uniaccess", "secunify",
}

// EndpointMatch 是一条识别命中。
type EndpointMatch struct {
	Product string `json:"product"`
	Vendor  string `json:"vendor"`
	Kind    string `json:"kind"`
	Token   string `json:"token"` // 依据的进程名/服务名
	Line    string `json:"line"`  // 原始那一行，供人工核对
}

// EndpointReport 是一次识别的全部产出。
type EndpointReport struct {
	Matches []EndpointMatch `json:"matches"`
	// Unidentified 是「像安全产品但签名表里没有」的名字。它们既不算识别成功，
	// 也不该被丢掉：漏一个没登记的产品，比多列一条待确认要危险得多。
	Unidentified []string `json:"unidentified,omitempty"`
	ScannedLines int      `json:"scanned_lines"`
	// Empty 为真表示输入里一条进程/服务行都没读到（命令没跑成、输出被截断、
	// 权限不足），这时**不能**说「没有终端防护」。
	Empty bool `json:"empty"`
}

// Summary 是给日志与报告的一句话，含「签名表是子集」这句免责。
func (r EndpointReport) Summary() string {
	if r.Empty {
		return "没有读到进程/服务列表（命令失败、输出为空或权限不足），无法判断终端防护情况"
	}
	parts := make([]string, 0, 3)
	if len(r.Matches) > 0 {
		names := make([]string, 0, len(r.Matches))
		for _, m := range r.Matches {
			names = append(names, m.Product)
		}
		parts = append(parts, "识别到终端安全产品 "+strings.Join(dedupeSortedStrings(names), "、"))
	}
	if len(r.Unidentified) > 0 {
		parts = append(parts, "另有 "+strconv.Itoa(len(r.Unidentified))+" 个进程名像安全产品但未登记，需人工确认")
	}
	if len(parts) == 0 {
		parts = append(parts, "签名表内没有命中（表是人工整理的子集，未命中不等于没有防护）")
	}
	return strings.Join(parts, "；")
}

// IdentifyEndpointSecurity 从一段进程/服务列表文本里识别终端安全产品。
// osKind 只影响行的切分方式（tasklist 的 CSV 与 ps 的定宽列），判定逻辑同一套。
func IdentifyEndpointSecurity(osKind, output string) EndpointReport {
	rep := EndpointReport{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		name := processNameFromLine(osKind, line)
		if name == "" || isEndpointNonProcessLine(name, line) {
			continue
		}
		rep.ScannedLines++
		token := normalizeProcessToken(name)
		if token == "" {
			continue
		}
		hit := false
		for _, sig := range endpointSignatures {
			for _, t := range sig.Tokens {
				if token == strings.ToLower(t) {
					rep.Matches = append(rep.Matches, EndpointMatch{
						Product: sig.Product, Vendor: sig.Vendor, Kind: sig.Kind, Token: token, Line: line,
					})
					hit = true
					break
				}
			}
			if hit {
				break
			}
		}
		if hit {
			continue
		}
		for _, hint := range endpointHintTokens {
			if strings.Contains(token, hint) {
				rep.Unidentified = append(rep.Unidentified, name)
				break
			}
		}
	}
	rep.Matches = dedupeMatches(rep.Matches)
	sort.Slice(rep.Matches, func(i, j int) bool { return rep.Matches[i].Product < rep.Matches[j].Product })
	rep.Unidentified = dedupeSortedStrings(rep.Unidentified)
	rep.Empty = rep.ScannedLines == 0
	return rep
}

var (
	csvQuotedRE    = regexp.MustCompile(`^\s*"([^"]+)"`)
	psArgsRE       = regexp.MustCompile(`^\s*\d+\s+\S+\s+(\S+)`)
	serviceStateRE = regexp.MustCompile(`SERVICE_NAME:\s*(\S+)`)
)

// endpointNonProcessTokens 是表头与标签列：把它们当进程行计数，会让「只有表头的输出」
// 被读成「读到过进程、只是没命中」，而这两种情况在报告里是完全不同的话。
var endpointNonProcessTokens = map[string]bool{
	"image name": true, "pid": true, "session name": true, "session#": true, "mem usage": true,
	"service_name": true, "description": true, "hotfixid": true, "installedon": true,
	"name": true, "command": true, "usage": true, "error": true,
}

var endpointErrorLineRE = regexp.MustCompile(`(?i)^(error|fatal|usage)[:：]|access is denied|cannot \b|not found|no such|command not found`)

// isEndpointNonProcessLine 判断这一行是不是「进程/服务列表里的一条」。
// 命令失败、权限不足、只有表头，都要落到空输入那一档，而不是「读到过但没命中」。
func isEndpointNonProcessLine(name, line string) bool {
	if endpointNonProcessTokens[normalizeProcessToken(name)] || endpointNonProcessTokens[strings.ToLower(strings.TrimSpace(name))] {
		return true
	}
	return endpointErrorLineRE.MatchString(strings.TrimSpace(line))
}

// processNameFromLine 从一行输出里取出进程名/服务名。支持四种常见格式，
// 取不出来就返回空——不猜。
func processNameFromLine(osKind, line string) string {
	trim := strings.TrimSpace(line)
	if m := serviceStateRE.FindStringSubmatch(trim); m != nil {
		return m[1]
	}
	if strings.HasPrefix(trim, `"`) {
		if m := csvQuotedRE.FindStringSubmatch(trim); m != nil {
			return m[1]
		}
	}
	if osKind == "windows" {
		// tasklist /fo csv 之外还有 wmic 的逗号分隔：第一列是名字
		if parts := strings.FieldsFunc(trim, func(r rune) bool { return r == ',' || r == ' ' }); len(parts) > 0 {
			return parts[0]
		}
		return ""
	}
	if m := psArgsRE.FindStringSubmatch(trim); m != nil {
		return m[1]
	}
	fields := strings.Fields(trim)
	if len(fields) == 0 {
		return ""
	}
	if _, err := strconv.Atoi(fields[0]); err == nil {
		return "" // 只有 PID 开头的残行，没有名字
	}
	return fields[0]
}

// normalizeProcessToken 去掉扩展名、路径与括号，转小写。
func normalizeProcessToken(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.Trim(n, "()\"'")
	if i := strings.LastIndexAny(n, `/\`); i >= 0 {
		n = n[i+1:]
	}
	for _, ext := range []string{".exe", ".sys", ".dll", ".bin"} {
		n = strings.TrimSuffix(n, ext)
	}
	return strings.TrimSpace(n)
}

func dedupeMatches(in []EndpointMatch) []EndpointMatch {
	seen := map[string]bool{}
	out := make([]EndpointMatch, 0, len(in))
	for _, m := range in {
		key := m.Product + "|" + m.Token
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	return out
}

// ── 补丁基线 ────────────────────────────────────────────────────────────────

// PatchAdvisory 是一条基线通告：一组可能出现在「已安装补丁」里的 KB 号。
//
// 集合而不是「哪个系统该装哪个 KB」，是因为累计更新会取代早期编号；只要集合里
// 有一个出现在安装列表，就认为这一条不构成缺口。
type PatchAdvisory struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	KBs      []string `json:"kbs"`
	Note     string   `json:"note"`
	Severity string   `json:"severity"`
}

// patchBaseline 是人工挑选的高信号子集，不是完整补丁比对。
// 完整比对请用 WSUS/SCCM/DISM/psexport 的补丁清单。
var patchBaseline = []PatchAdvisory{
	{ID: "MS17-010", Title: "服务器消息块远程执行代码（永恒之蓝）", Severity: "high",
		KBs: []string{"KB4012212", "KB4012213", "KB4012214", "KB4012215", "KB4012216", "KB4012217",
			"KB4012218", "KB4012598", "KB4012606", "KB4015217", "KB4015438", "KB4015439", "KB4015546"},
		Note: "SMBv1 远程执行；集合覆盖 7/8.1/10/2008R2/2012/2012R2/2016 各版本出现过的编号"},
	{ID: "CVE-2019-0708", Title: "远程桌面服务远程执行代码（BlueKeep）", Severity: "high",
		KBs: []string{"KB4493446", "KB4493465", "KB4493472", "KB4499148", "KB4499175", "KB4500323",
			"KB4500327", "KB4500331", "KB4503260", "KB4503262", "KB4503272"},
		Note: "RDP 预认证远程执行；仅对开着 3389 的老版本有意义"},
	{ID: "CVE-2020-1472", Title: "Netlogon 特权提升（Zerlogon）", Severity: "high",
		KBs:  []string{"KB4566424", "KB4566454", "KB4566466", "KB4567523", "KB4570999", "KB4571756", "KB4574727"},
		Note: "域控相关；成员服务器与域控的补丁批次不同，集合按 2020-08 那轮列"},
	{ID: "CVE-2021-34527", Title: "打印后台处理程序远程执行代码（PrintNightmare）", Severity: "high",
		KBs: []string{"KB5004945", "KB5004953", "KB5004956", "KB5004958", "KB5005565", "KB5005567",
			"KB5005568", "KB5005569", "KB5005611", "KB5005625"},
		Note: "2021-07/08 两轮累计更新都带相关修复，集合按这两轮列"},
}

// PatchAdvisoryIDs 给界面与文档用，避免别处再抄一份编号。
func PatchAdvisoryIDs() []string {
	out := make([]string, 0, len(patchBaseline))
	for _, a := range patchBaseline {
		out = append(out, a.ID)
	}
	return out
}

// PatchItem 是一条通告的比对结果。
type PatchItem struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	State   string   `json:"state"` // installed | not_seen | unknown
	Matched string   `json:"matched,omitempty"`
	KBs     []string `json:"kbs"`
	Note    string   `json:"note"`
}

// PatchReport 是一次补丁基线比对。
type PatchReport struct {
	OSName    string      `json:"os_name,omitempty"`
	OSBuild   string      `json:"os_build,omitempty"`
	Installed []string    `json:"installed"`
	Items     []PatchItem `json:"items"`
	// Truncated / Missing 说的是输入本身不完整（systeminfo 被截断、命令没跑成、
	// 权限不足拿不到列表）。这时候**任何**一条基线都不能下结论，只能报未判定。
	Incomplete bool   `json:"incomplete"`
	Reason     string `json:"reason,omitempty"`
}

// Summary 一句人话，把「未命中不等于存在漏洞」写进去。
func (r PatchReport) Summary() string {
	if r.Incomplete {
		return "补丁列表不完整（" + firstNonEmptyString(r.Reason, "输出被截断或命令失败") + "），本轮不做缺失判断"
	}
	if len(r.Installed) == 0 {
		return "没有读到任何已安装补丁条目，无法做基线比对（不等于没打补丁）"
	}
	var hit, miss []string
	for _, it := range r.Items {
		switch it.State {
		case "installed":
			hit = append(hit, it.ID)
		default:
			miss = append(miss, it.ID)
		}
	}
	parts := []string{"已安装补丁 " + strconv.Itoa(len(r.Installed)) + " 条"}
	if len(hit) > 0 {
		parts = append(parts, "基线命中 "+strings.Join(hit, "、"))
	}
	if len(miss) > 0 {
		parts = append(parts, "基线未命中 "+strings.Join(miss, "、")+
			"（待确认：累计更新可能已取代基线里的 KB 编号，未命中不等于存在漏洞）")
	}
	return strings.Join(parts, "；")
}

// AnalyzeWindowsPatches 从 systeminfo / wmic qfe / Get-HotFix 的输出里取已安装 KB 集合，
// 与基线比对。输入可以是三种格式混合，取不出来就报未判定。
func AnalyzeWindowsPatches(output string) PatchReport {
	rep := PatchReport{Installed: []string{}}
	seen := map[string]bool{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		lower := strings.ToLower(line)
		if rep.OSName == "" && strings.Contains(lower, "os name") {
			rep.OSName = trimAfterColon(line)
		}
		if rep.OSBuild == "" && (strings.Contains(lower, "os version") || strings.Contains(lower, "os 版本")) {
			v := trimAfterColon(line)
			if fields := strings.Fields(v); len(fields) > 0 {
				rep.OSBuild = fields[0]
			}
		}
		for _, kb := range kbNumbers(line) {
			if !seen[kb] {
				seen[kb] = true
				rep.Installed = append(rep.Installed, kb)
			}
		}
	}
	sort.Strings(rep.Installed)
	if len(rep.Installed) == 0 {
		rep.Incomplete = true
		if strings.TrimSpace(output) == "" {
			rep.Reason = "输出为空"
		} else {
			rep.Reason = "输出里没有 KB 编号"
		}
		return rep
	}
	for _, a := range patchBaseline {
		item := PatchItem{ID: a.ID, Title: a.Title, KBs: a.KBs, Note: a.Note}
		for _, kb := range a.KBs {
			if seen[strings.ToUpper(kb)] {
				item.State = "installed"
				item.Matched = strings.ToUpper(kb)
				break
			}
		}
		if item.State == "" {
			item.State = "not_seen"
		}
		rep.Items = append(rep.Items, item)
	}
	return rep
}

var kbRE = regexp.MustCompile(`(?i)\b(kb\d{5,8})\b`)

func kbNumbers(line string) []string {
	out := make([]string, 0, 2)
	for _, m := range kbRE.FindAllStringSubmatch(line, -1) {
		out = append(out, strings.ToUpper(m[1]))
	}
	return out
}

func trimAfterColon(line string) string {
	if i := strings.Index(line, ":"); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	if i := strings.Index(line, "："); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	return strings.TrimSpace(line)
}

func firstNonEmptyString(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
