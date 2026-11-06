package db

// 痕迹矩阵（G4）：每种维持手段在目标上留下什么、怎么证明清掉了、清掉之后还剩什么。
//
// 为什么要有这张表：撤销命令跑成功只说明「我们执行了删除」，不说明「 defender 看不到痕迹」。
// 报告里如果只写「已清理」，读者会把它当成「目标恢复原状」，而实际留下的认证日志、事件日志、
// 任务计划程序记录、mtime 与访问日志一条都没少。这两件事必须分开写，而且要靠经验之外的东西
// ——也就是这张表——写出来。
//
// 这里只描述**平台自己做的事**留下的后果，不构成对任何具体检测产品的规避建议；
// 表里「清不掉的残留」一栏的目的恰恰是把残留说清楚，让操作者据此决定还要不要继续维持。
//
// 单一来源：kind 常量在 intranet_artifacts.go，计划命令在 server/intranet_persist.go，
// 而「痕迹/验证/残留」的口径在这里。新增 kind 时如果没在这里补档案，
// TestArtifactTraceProfilesCoverEveryKind 会失败。

// ArtifactTraceProfile 是一种维持手段的痕迹档案。
type ArtifactTraceProfile struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Traces 是部署后在目标上留下的可观察痕迹（文件、键值、任务对象、日志条目）。
	Traces []string `json:"traces"`
	// Verify 是平台用来判定「已清除」的方式；注意判定只看验证命令的输出，不看撤销命令的退出码。
	Verify string `json:"verify"`
	// Residue 是撤销之后仍然存在的痕迹——这些不是「没清干净」，而是当前权限与技术上清不掉或
	// 不该动的东西，必须原样写进报告。
	Residue []string `json:"residue"`
}

// 非台账来源的两类维持手段：内存马活在 JVM 里、隧道活在进程与出站连接里，
// 都不进 intranet_artifacts，但同样是「本次留下了什么」的一部分。
const (
	ArtifactTraceMemshell = "memshell"
	ArtifactTraceTunnel   = "tunnel"
)

var artifactTraceProfiles = map[string]ArtifactTraceProfile{
	IntranetArtifactFile: {
		Kind: IntranetArtifactFile, Name: "上传的文件",
		Traces: []string{
			"落地文件本身：内容、大小、属主与权限、创建与修改时间",
			"配套的 sidecar 文件（密钥覆盖 / 重放保护等），与被执行文件同目录",
			"写入过程在 Web 服务器访问日志里留下的那条请求",
		},
		Verify: "对同一路径再取一次：文件不存在才算清掉（撤销命令退出码不算证据）",
		Residue: []string{
			"父目录的 mtime 变化；删除本身不写时间戳，但目录条目变化可查",
			"访问日志 / 容器日志里的上传与请求记录",
			"主机侧文件创建审计（auditd、EDR）记录的事件",
		},
	},
	IntranetArtifactCron: {
		Kind: IntranetArtifactCron, Name: "cron 计划任务",
		Traces: []string{
			"一条 crontab 行，末尾带 `# jw:<token>` 注释——注释里的 token 是稳定可关联的标记",
			"root 用户可见时落在 /var/spool/cron/crontabs/ 或 /etc/cron.d/",
			"每次执行产生的输出与子进程",
		},
		Verify: "`crontab -l` 输出里不再出现该 token（按 token 精确匹配，绝不整表覆盖）",
		Residue: []string{
			"cron 的执行日志（/var/log/cron、journalctl -u cron）里已经发生的那些次执行",
			"cron 产生的本地邮件或输出文件",
			"执行过的那个文件自身的痕迹（见「上传的文件」）",
		},
	},
	IntranetArtifactSystemd: {
		Kind: IntranetArtifactSystemd, Name: "systemd 系统级服务",
		Traces: []string{
			"/etc/systemd/system/jingwei-<token>.service 单元文件",
			"配套脚本 /etc/jingwei-<token>.sh",
			"`systemctl enable` 在 /etc/systemd/system/*.wants/ 下建立的符号链接",
		},
		Verify: "单元文件、脚本与 wants 符号链接都不存在，且 `systemctl list-unit-files` 不再列出该名字",
		Residue: []string{
			"journald 里该单元已经产生的启动/退出记录",
			"删除单元文件这一动作本身（有文件创建审计时可见）",
		},
	},
	IntranetArtifactUserSystemd: {
		Kind: IntranetArtifactUserSystemd, Name: "systemd 用户级服务",
		Traces: []string{
			"~/.config/systemd/user/jingwei-<token>.service",
			"~/.config/jingwei-<token>.sh",
			"用户级 wants 目录里的符号链接（WantedBy=default.target）",
		},
		Verify: "上述三项都不存在；用户级 `systemctl --user list-unit-files` 不再列出该名字",
		Residue: []string{
			"用户会话 journald 记录",
			"该用户已登录会话里仍在跑的进程（撤销单元不会杀掉已启动的进程）",
		},
	},
	IntranetArtifactAt: {
		Kind: IntranetArtifactAt, Name: "at 一次性任务",
		Traces: []string{
			"~/.jingwei-at-<token>.sh 脚本与同名 .id sidecar",
			"atd 队列（/var/spool/cron/atjobs/）里的那个作业",
		},
		Verify: "`atq` 里不再出现该作业号，脚本与 sidecar 都不存在",
		Residue: []string{
			"作业执行时产生的输出邮件（/var/mail/）",
			"atd 日志与 spool 目录的历史条目",
		},
	},
	IntranetArtifactProfile: {
		Kind: IntranetArtifactProfile, Name: "shell 启动文件追加行",
		Traces: []string{
			".profile / .bashrc 末尾追加的一行，带 `# jw:<token>` 标记",
			"该文件被 source 时启动的子进程",
		},
		Verify: "文件内容里不再包含该标记（只删自己那一行，不动别人的配置）",
		Residue: []string{
			"文件本身被修改的时间戳与历史版本差异",
			"该用户 shell 的 history 文件",
			"已经由它启动过的会话留下的进程记录",
		},
	},
	IntranetArtifactSSHKey: {
		Kind: IntranetArtifactSSHKey, Name: "SSH 授权公钥",
		Traces: []string{
			"authorized_keys 里一行带 `jw:<token>` 注释的公钥；公钥本身就是可跨主机关联的标识",
			"每次用该 key 登录都会在认证日志里留下来源地址与密钥指纹",
		},
		Verify: "按注释 token 精确匹配，该行不再存在（绝不重写整个 authorized_keys）",
		Residue: []string{
			"/var/log/auth.log 或 secure 里已经发生的那些次登录",
			"`last` / wtmp 的登录记录",
			"私钥若已被复制到别处，删除公钥不等于撤销访问能力",
		},
	},
	IntranetArtifactSchtasks: {
		Kind: IntranetArtifactSchtasks, Name: "Windows 计划任务",
		Traces: []string{
			"任务名 <base>-<token>，触发器为登录 / 开机 / 每 N 分钟",
			"C:\\Windows\\System32\\Tasks\\ 下对应的任务 XML 文件",
			"任务指向的脚本或可执行文件路径",
		},
		Verify: "`schtasks /query /tn <name>` 找不到该任务，且 Tasks 目录下没有对应 XML",
		Residue: []string{
			"TaskScheduler 操作日志里任务注册与每次运行的事件",
			"运行产生的 Prefetch 与 SRUM 记录",
		},
	},
	IntranetArtifactRegistry: {
		Kind: IntranetArtifactRegistry, Name: "注册表自启动项",
		Traces: []string{
			"HKCU\\...\\CurrentVersion\\Run 下名为 <base>-<token> 的字符串值（值名与数据都是可关联标记）",
			"值数据指向的可执行文件路径",
		},
		Verify: "`reg query` 该键不再返回这个值名",
		Residue: []string{
			"NTUSER.DAT 的修改时间与注册表事务日志",
			"开启 Sysmon 时的注册表事件记录",
		},
	},
	IntranetArtifactService: {
		Kind: IntranetArtifactService, Name: "Windows 服务",
		Traces: []string{
			"服务名 <base>-<token>，启动类型 auto，指向的二进制路径写在服务配置里",
			"HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name> 键",
		},
		Verify: "`sc query <name>` 报服务不存在（1060）",
		Residue: []string{
			"System 事件日志里的服务安装与启停事件（7045 / 7036 一类）",
			"服务进程运行期间的进程创建事件",
		},
	},
	IntranetArtifactWMI: {
		Kind: IntranetArtifactWMI, Name: "WMI 事件订阅",
		Traces: []string{
			"root\\subscription 下的 __EventFilter、CommandLineEventConsumer 与二者绑定，三个对象都以 jingwei-<token> 命名",
			"消费者指向的脚本或命令行",
		},
		Verify: "三个对象名都不再出现——只删绑定而留下筛选器与消费者，等于把重新绑定的能力留在原地",
		Residue: []string{
			"WMI-Activity 操作日志里的注册与触发记录",
			"WMI 存储库文件（OBJECTS2.DATA 等）里的历史对象",
		},
	},
	IntranetArtifactStartup: {
		Kind: IntranetArtifactStartup, Name: "启动目录脚本",
		Traces: []string{
			"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\<base>-<token>.cmd",
			"文件内容里的命令行与被调用的目标",
		},
		Verify: "该文件不存在",
		Residue: []string{
			"每次登录执行产生的进程创建事件与 Prefetch",
			"启动目录的枚举缓存（Explorer 的 BagMRU / ShellBags）",
		},
	},
	IntranetArtifactPHPUserINI: {
		Kind: IntranetArtifactPHPUserINI, Name: "PHP .user.ini 半持久化",
		Traces: []string{
			".user.ini 里一段带 `# jw:<token>` 标记的块，声明 auto_prepend_file 指向同目录的 .jw<token>.php",
			"那个 prepend 载荷文件本身",
			".user.ini 的修改时间；PHP 对它有默认 5 分钟的缓存，撤销后短时间内仍可能生效",
		},
		Verify: "标记块与 prepend 载荷文件都不存在——两项都要验，只删一项等于留下悬空引用或留下可重新指向的块",
		Residue: []string{
			"Web 服务器访问日志里对该目录的请求",
			"已开启 opcache / 审计扩展时的脚本记录",
		},
	},
	IntranetArtifactPHPHtaccess: {
		Kind: IntranetArtifactPHPHtaccess, Name: ".htaccess 半持久化",
		Traces: []string{
			".htaccess 里带 `# jw:<token>` 标记的块，声明 php_value auto_prepend_file",
			"prepend 载荷文件本身",
		},
		Verify: "标记块与载荷文件都不存在",
		Residue: []string{
			"访问日志中的请求记录",
			"若服务器配置禁止 .htaccess 覆盖，撤销前那段配置本身已经生效过的那些次请求",
		},
	},
	IntranetArtifactOther: {
		Kind: IntranetArtifactOther, Name: "人工登记的落地物",
		Traces:  []string{"由操作者在描述与路径里写明；平台不能凭空知道"},
		Verify:  "只有登记了验证命令才能复核；没有验证命令时报告会写「未配置验证命令，无法复核」",
		Residue: []string{"未知——报告里对应位置留空，不做猜测"},
	},
	ArtifactTraceMemshell: {
		Kind: ArtifactTraceMemshell, Name: "Java 内存马",
		Traces: []string{
			"JVM 内新注册的 filter / servlet / listener / valve，或 agent 型额外监听的端口",
			"一个随机化的访问路径（形如 /static/<8 位十六进制>.js）——它本身就是可关联标记",
			"不落盘：重启容器即消失，这既是清理手段也是失效原因",
		},
		Verify: "探针不再报告该类型存在，且该 URL 不再按协议应答；两者都过才算清掉",
		Residue: []string{
			"Web 容器访问日志里对该路径的每一次请求",
			"堆内存里的类加载与注册痕迹（dump 可见）",
			"catalina.out 一类运行日志里可能的加载记录",
		},
	},
	ArtifactTraceTunnel: {
		Kind: ArtifactTraceTunnel, Name: "内网隧道（chisel / ssh 转发）",
		Traces: []string{
			"目标上的后台进程，以及 <tag>.pid / <tag>.log 两个 sidecar 文件",
			"目标到控制端的出站连接与本地监听端口",
		},
		Verify: "进程不存在、sidecar 文件不存在、控制端不再收到该连接",
		Residue: []string{
			"两端连接日志与已经转发过的流量记录",
			"任何一次 netstat/ss 快照里出现过的端口",
			"启动隧道那条命令的 shell history",
		},
	},
}

// ArtifactTraceProfileFor 取一种手段的痕迹档案。ok=false 表示这个 kind 没有档案
// ——调用方必须把它当成缺陷暴露出来，而不是给一个空壳继续往下写。
func ArtifactTraceProfileFor(kind string) (ArtifactTraceProfile, bool) {
	p, ok := artifactTraceProfiles[kind]
	return p, ok
}

// ArtifactTraceKinds 列出所有有痕迹档案的 kind，供「新增 kind 必须有档案」那条用例使用。
func ArtifactTraceKinds() []string {
	out := make([]string, 0, len(artifactTraceProfiles))
	for k := range artifactTraceProfiles {
		out = append(out, k)
	}
	return out
}
