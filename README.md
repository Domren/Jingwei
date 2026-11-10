<div align="center">

# Jingwei（精卫）

自动化红队渗透平台 · 不配 LLM 也能扫描与验证，配上 LLM 则全链自动规划与深挖 · Docker 分发版

[![Release](https://img.shields.io/github/v/release/Domren/Jingwei?label=release)](https://github.com/Domren/Jingwei/releases)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Docker](https://img.shields.io/badge/ghcr.io-domren%2Fjingwei-2496ED?logo=docker&logoColor=white)](https://github.com/Domren/Jingwei/pkgs/container/jingwei)

> 本项目基于 **Autumn-27/ARTEX** 二次开发，保留原始提交历史、版权声明与 AGPL-3.0 许可证；
> 上游现由 [RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX) 持续维护，完整署名见 [NOTICE](NOTICE)。

</div>

---

## Jingwei 1.6.1

> 1.6.1 是补账版本：修三台真机回归揪出的两处缺陷（扫描增量对比面板在空增量时白屏、对外交付
> 导出被丢失的 0 字节证据 blob 拖垮），并收掉 WAF 绕过模块两条已知欠账——**空参数名不再拼出
> `?=<载荷>` 的假注入点**（变形标「未发起」、不发包不占预算，堵死「绕过成功」的假信号来源），
> 重试模式/请求预算/止损阈值进入表单「高级选项」与 API 收口（预算硬上限 64）。另做了一轮
> `staticcheck` 清零。无数据库迁移、无行为开关变化，原地升级即可。
>
> 此前版本摘要：1.6.0 是深度版本：弱口令检测从 21 协议扩到 **31 个协议且全部有真实服务端用例**——补齐 MSSQL / SMB /
> Jenkins / JBoss / RouterOS / SVN / SNMP / smtp-ssl 等并在真服务上走命中与拒绝双路径，RDP 如实落
> 「不可判定」；拿不到可复现真服务的 Oracle / WebLogic / WinRM / CobaltStrike 整条删除，**「只靠桩的支持」
> 不算支持**。长跑可靠性成环：**断点续扫**（计划钉住模板与目标，中断只补剩下的，布局对不上就拒绝续扫而不是
> 拼半旧半新）、隔离容器里重建的**扫描性能基线**（带环境指纹，不符拒比）、**隧道并发预算**（超预算排队，
> 而不是把唯一通道挤死后误报「这一片没问题」）。判定口径再收：**XSS 交给镜像内 Chromium 真执行**（反射与
> 执行分开记，跑不起来判「待复核」而不是「没执行」）、**WAF 自适应重试**（基线被拦才按拦截形态重排变形，
> 预算封顶、四种停止原因逐发留痕，绕过结论强制人工复核）。侦察面新增**子域名枚举任务**（字典 + 泛解析判据 +
> 解析 IP 直接进端口探测，第三方公开接口默认关）与**终端防护识别 / 补丁基线**（进程名精确匹配签名表，
> 未命中补丁只记「待确认」，报告全程不给规避建议）。横向的副作用进了台账：**凭据跨主机复用**每批可整体
> 撤销、「**维持痕迹矩阵**」自动列出每种手段留下什么与验证到什么程度、根密钥轮换后按条给出可执行补救。
> 目标解析补上 IPv6（裸地址与 `[ipv6]:port`），一条坏目标不再拖垮整批。界面视觉验证与平台自检成为发版必过门。
>
> 此前版本摘要：1.5.0 把「弱口令检测」做成可用模块（21 协议、六态结论、原始报文、内外两份报告），
> 把「客户授权清单」做成目标策略的一等输入，新增客户交付版报告与两次扫描的增量视图，并计入 1.4.x 清账项。
> 1.4.2 是部署侧修复——`docker-compose.yml` 按白名单注入环境变量，
> 导致代码里在读的 10 个运行时开关在容器里根本配不上——包括内网隧道的控制端地址
> （`JINGWEI_PIVOT_SERVER`，缺它时 chisel 与 ssh 隧道的自动部署命令整体不可用）、
> 范围管控强度 `JINGWEI_GUARD_ENFORCEMENT`、两类落地物的 TTL 与模型调用墙钟。现在这些开关都进了
> 两份 compose 与 `.env.example`，并新增一项审计测试锁住「代码读了但部署配不上」这一类缺陷；
> 根 compose 的监听端口与 DSN 覆盖也与 Release 用的那份对齐（此前 DEPLOY 让改的端口变量不生效）。
> 1.4.1 是一版纯安全加固：会话 cookie 只允许同站的变更请求
> （显式 Bearer 不受影响）、目标范围与资产禁令在读取失败时改为**失败关闭**、工作区文件操作改用
> `os.Root` 固定根目录（挡住软链越界与「检查后被替换」的竞态），另修掉代理地址重复拼协议头、
> Skill 覆盖安装失败会丢旧版、演示站发现页崩溃三处。
> 1.4.0 把 WebShell 与内网这条线做成可用工具：加密 v2 协议（密钥不出现在流量里、AEAD、时间戳 + nonce
> 防重放、随机载体、Windows 壳）、大马文件管理、Java 内存马五类注入、PHP 半持久化，以及一条壳一个对话框的
> WebShell 工作台（虚拟终端 / 文件管理 / 系统信息），内网 SSH 会话复用同一个终端组件。同时把签名根密钥与
> 内网口令、模型 API 密钥一律密封进数据库——容器重建不再让已投放的壳变成砖，库里也不再有明文可顺手一览。
> 1.3.x 修复登录入口的验证码/限速/请求边界与 JWT 不可撤销问题，并在 1.3.0 补齐利用闭环：
> 影响升级与弱口令自动链、内网横向、可撤销的权限维持台账、按台账逆序撤离。

- **弱口令检测**：31 个协议、全部有真实服务端用例（SSH / MySQL / PostgreSQL / Redis / MongoDB / FTP /
  Telnet / Socks5 / Web Basic / WebDAV / Tomcat 与 JBoss 管理台 / Elasticsearch / Memcached / Zookeeper /
  SMTP / POP3 / IMAP（含隐式 TLS 变体）/ LDAP / LDAPS / VNC，以及本批补的 MSSQL / SMB / RouterOS /
  Jenkins / SVN / SNMP）；RDP 如实落「不可判定」，4 个拿不到真服务的协议整条删除——「只靠桩的支持」不算支持。
  六态结论区分「验证过不存在」与「没测出来」，每条结论带逐字节的原始报文；只产出事实，**不自动登录、不复用**。
- **断点续扫与性能基线**：POC 阶段按「模板段 × 目标组」分片、逐片落库，超时/打断后只补剩下的；模板或目标
  变了就拒绝续扫而不是拼半旧半新。性能基线在一次性隔离容器里重建，带环境指纹、不符拒比。
- **子域名枚举**：字典爆破 + A/AAAA/CNAME 解析做成一条任务，确认的名字与 IP 直接进资产图与端口探测；
  泛解析、未判定、查询预算三条判据决定结果可不可信；第三方公开接口默认关（查它会把你给的根域名发给第三方）。
- **WAF 自适应重试**：基线恒先发、被拦才按拦截形态重排变形（限速/验证码类优先改头、特征类优先编码、
  规则类优先路径）；预算默认 8 发、硬上限 64，四种停止原因逐发留痕；绕过结论一律强制人工复核。
- **浏览器真实执行验证 XSS**：镜像内 Chromium 逐条执行判定，反射与执行分开记；执行环境不可用落
  「待复核」而不是「没执行」。
- **凭据复用批次台账**：操作员主动发起的跨主机复用逐次入账（五类计数 + 每次尝试的证据 + 本批新建凭据），
  可整体撤销——撤销只删本批新建的，历史尝试不抹。
- **维持痕迹矩阵与密钥轮换补救**：17 种维持手段每种登记「留下什么、怎么验证清除、撤销后仍剩什么」，
  撤离报告自动成表；换根密钥后按条给出可执行补救（重投载荷/标注残留/指明重填位置，不猜旧值）。
- **终端防护识别与补丁基线**：进程/服务名精确匹配约 20 家杀软/EDR 签名，认不出的进「待人工确认」；
  补丁按高信号通告的 KB 集合比对，未命中只记「待确认」；报告对这两类全程不给规避建议。
- **隧道并发预算**：经隧道/代理的扫描按端点定并发口径，超预算的任务排队并写明等待原因，而不是把唯一
  通道挤死后误报「这一片没问题」。
- **客户授权清单**：IP/CIDR/域名 + 排除项 + 有效期。存在有效授权时，任何任务（含界面直接建的扫描与弱口令）
  的目标都必须落在授权内，拒绝原因点名是哪条授权不管用。
- **客户交付版报告**：中英双语标签、授权与范围声明、按受影响资产分组的明细与修复建议汇总、CVSS、原始报文附录，
  只含已确认项；发现页另有「对外交付版」导出（排除未确认/误报/重复/忽略）。
- **加密 v2 WebShell**：握手派生会话密钥，密钥离流量；AEAD 加密 + 时间戳/nonce 防重放 + 随机载体，
  同一密钥可生成不同外观载荷（填充、注释、函数名随机化）并带 SHA-256 载荷指纹与自检。
- **大马与内存马**：v2 通道上的文件管理（目录列表、分块读写、重命名、删除、改权限，PHP/JSP/ASPX 三套）；
  经 JSP 父壳注入 Filter/Servlet/Listener/Valve/Agent 五类内存马并可撤销；PHP `auto_prepend_file`
  半持久化透传原页面，不改站点行为。
- **WebShell 工作台**：一条壳一个对话框，虚拟终端有当前目录、退出码、耗时、stderr 着色、`cd` 续用、
  历史翻阅与可选超时档位；系统信息一次往返采集 12 个分区。内网 SSH 会话与它共用同一个终端组件。
- **密钥与静态数据**：签名根密钥存进数据库单行表，容器重建不再重新铸钥匙；内网凭据口令与模型 API 密钥
  按用途派生密钥密封入库，接口不再回显明文，换过根密钥后启动自检并按类别提示补救动作。
- **SSH 承载的内网会话**：只有 22 端口、没有 web 服务的主机也能纳入受管会话；目标上已有的文件可登记成
  受管壳，凭据台账可视化，隧道台账区分监听开在哪一侧。
- **应用层发现**：同一服务下按路径字典、robots/sitemap、页面链接与 SPA 路由识别子路径系统，
  随机路径 soft-404 过滤后作为系统级资产入库并关联。
- **固定渗透基线**：弱口令（内置 WebCrack 引擎跑登录页 admin 字典）与 SQL/XSS 参数位置枚举
  作为扫描必跑步骤，不依赖 nuclei 是否命中；参数位置交给镜像内 sqlmap / dalfox 专项判定，
  同一位置只付一次工具成本。登录页带 AJ-Captcha 滑块时，WebCrack 在纯 HTTP 内自动取图、
  求解、提交校验并把凭据注入表单，失败换图重试；同源限制，不调用外部识别服务。
- **滑块验证码求解**：内置通用求解器（轮廓 + 内容匹配，可生成拟人拖动轨迹），提供
  `POST /api/captcha/slider`、agent 工具 `solve_slider_captcha`、`jingwei captcha-solve`
  子命令与 Go 包多种入口，不依赖浏览器或外部识别服务；自定义滑块协议可用 JSON profile
  描述，极验/易盾等商业协议明确报不支持。
- **先探测后渗透**：LLM 任务在 planner 首轮前完成端口/指纹/应用层发现与 POC 初筛，结果落
  资产与发现；`chains` 的反问纪律与场景链由代码按意图注入，不靠提示词自觉。
- **可复现证据**：上报即固化结构化复现过程（入口/前置/真实步骤/来源），报告逐步绑定流量
  快照；证据质量校验拦截「见截图」式占位；发现可用 Chromium 头less 渲染取证截图。
- **深度利用扩展**：请求重发（原始报文重放）、跨任务凭据库、内网拓扑页、AES-256-CBC 加密
  WebShell 会话；「资产同步」页退役。
- **品牌化**：控制台、登录/初始化页、侧栏、报告、通知、页脚与后端服务名统一为「精卫 Jingwei」。
- **POC 模板库**：nuclei 模板的搜索、筛选、统计、详情、上传、启停与批量执行；镜像内置 nuclei 3.11.1。
- **自动化漏扫**：不配置 LLM 也能跑——端口探测 + 25,136 条 FLUX 指纹 + nuclei 命中直接生成漏洞发现，
  SQL 注入与 XSS 由镜像内置的 sqlmap / dalfox 专项验证器复核。
- **可复现报文**：每条发现绑定完整原始请求/响应报文，多步 POC 保存整条报文链；非 HTTP 协议
  （Redis RESP、MySQL 握手、SSH banner）按协议本身出十六进制字节，可直接复现验证。
- **深度利用**：exploit / verify / waf-bypass / webshell / resources / intranet 六个子页，
  Java 反序列化走可选 java-chains sidecar + MCP。
- **安全边界**：工具调用统一经 Guard 做目标范围与出站限制、密钥脱敏与痕迹清理，判定结果带反证去重。
- **全链自动化**：planner / worker / main-agent 协作，探索图 + 资产图双图驱动任务推进。
- **完整工作台**：任务与计划任务、发现与报告（DOCX/HTML 导出）、资产与内网拓扑、流量录制、工具执行、LLM 记录。
- **人在环路**：拦截规则、审批记录、旁路问答与通知推送。
- **Docker 分发**：`linux/amd64` / `linux/arm64` 多架构镜像，Compose 一键部署，升级只换镜像。

> 未配置 LLM 时，POC 库、资产、流量、发现/报告查看、系统管理等仍可使用；
> 对话、任务执行与 Agent 自动规划需要先在「系统 → LLM」配置模型。

## 版本历史

### 1.6.1 — 2026-11-10

- **补账版本**：修复扫描增量对比在空增量时前端白屏（差集列表恒序列化为 `[]`）、对外交付导出被
  丢失的 0 字节证据 blob 拖垮（空正文无损还原、非空缺失仍报错）。
- **WAF 绕过两条欠账收口**：空参数名不再产生 `?=<载荷>` 假注入点（变形标「未发起」，不发包、
  不占预算、不留假痕迹）；重试模式/预算/止损阈值进表单高级选项与 API 收口（硬上限 64）。
- **工程**：`staticcheck` 17 项死代码与 4 项废弃 API 逐项核对清零；发版 checklist 补 tag 形态与
  门禁提交两条。无数据库迁移，原地升级。

### 1.6.0 — 2026-11-09

- **弱口令检测 21→31 个协议，全部有真实服务端用例**：补 MSSQL / SMB / RouterOS / Jenkins / JBoss(WildFly) /
  SVN / SNMP / smtp-ssl 并在真服务上走命中与拒绝双路径；RDP 如实「不可判定」；Oracle / WebLogic / WinRM /
  CobaltStrike 因验不了整条删除。内置字典拆 core/vendor 两档（内容版本 `2026.11`）并按协议重排条目顺序。
- **长跑可靠性**：断点续扫（分片计划钉住、布局不符拒绝续、打断只补剩下）、隔离容器性能基线（带环境指纹拒比）、
  隧道并发预算（超限排队而不是把通道挤死）。
- **判定口径**：XSS 由镜像内 Chromium 真执行判定（反射/执行分记，跑不起来判「待复核」）；WAF 自适应重试
  （基线先探、按拦截形态重排、预算封顶与四种停止原因逐发留痕、绕过强制人工复核）；exec() 语境命令编码助手
  （shell/argv/单串三种语境真实进程等价验证）。
- **侦察与横向**：子域名枚举成任务（泛解析判据 + 解析 IP 直接进端口探测，公开接口默认关）；终端防护识别与
  补丁基线进发现台账并作决策输入；凭据跨主机复用批次台账可整体撤销；维持痕迹矩阵与密钥轮换批量补救。
- **工程**：IPv6 目标（裸地址与 `[ipv6]:port`，一条坏目标不拖垮整批）；界面视觉验证与平台自检进发版必过门；
  CHANGELOG↔README 一致性自动校验；`tools/envaudit` 继续钉住「代码读了但部署配不上」。
- **验证**：四组合全量测试全绿；31 协议真机用例（credscan-lab / six-pack / smtps-lab，SQL Server 2022、
  Samba 4.24、WildFly 25、RouterOS CHR、Jenkins LTS、xrdp、snmpd、svnserve 等真实服务）。

### 1.5.0 — 2026-11-05

- **弱口令检测**（深度利用 → 弱口令检测）：21 协议、六态、原始报文；任务/字典/进度/报告/LLM 工具齐全；
  真机验证台 27 条用例 / 21 个协议全过，真机逼出 12 条线上缺陷并逐条修掉；SNMP 与二档 8 个协议如实标「暂不支持」。
- **客户授权清单与目标策略**：授权清单 + 排除项 + 时间窗；范围外目标在创建与执行两处都被拒（不建任务、不发包）；
  拒绝按任务与成因计数，拦截页可见。
- **客户交付版报告与对外导出**：`format=client-md` 与 `audience=external`，只含已确认项，口令打码或省略报文。
- **增量视图与复测**：两次扫描对比区分「已修复」与「目标不可达」；复测结论追加进漏洞报告并联动状态。
- **内网与通知**：信息收集脚本库（15 条只读脚本、结构化入库）、撤离后台账外残留扫描、落地物到期/复测/残留事件通知。
- **修复**：隧道自动选型、非精卫载荷的措辞、构建换源；统一测试暴露的 14 条缺陷全部修复
  （路由未注册、提交漏文件、数组列读不回、CORS 通配等）。
- **验证**：四组合全量测试全绿；浏览器端到端；平台自身安全回归 20 项全 PASS。

### 1.4.2 — 2026-11-04

- **部署侧修复（无新功能，可原地升级；不需要重建数据库）**：`docker-compose.yml` 用白名单注入环境变量，
  代码里 `os.Getenv` 读的 10 个运行时开关从来没被传进容器，在 `.env` 里写了也不生效：
  `JINGWEI_PIVOT_SERVER`（内网隧道控制端地址）、`JINGWEI_GUARD_ENFORCEMENT`（范围管控强度）、
  `JINGWEI_WEBSHELL_TTL_HOURS` / `JINGWEI_MEMSHELL_TTL_HOURS`（落地物过期）、`JINGWEI_LLM_STREAM`、
  `JINGWEI_LLM_CALL_TIMEOUT`（根 compose 漏配）、`JINGWEI_BTW_MAX_OUTPUT_TOKENS`、
  `JINGWEI_WEBCRACK_BRIDGE` / `JINGWEI_WEBCRACK_PYTHON`、`JINGWEI_CONFIG` / `JINGWEI_SKILL_DIR`。
  其中控制端地址缺失会让隧道自动选型直接返回「未配置」，chisel 与 ssh 两条自动生成
  部署命令的路在按文档部署的实例上整体不可用。
- **端口与 DSN 覆盖对齐**：根 compose 的监听端口此前写死 `9790/9791`，文档让改的
  `JINGWEI_WEB_PORT` / `JINGWEI_PROXY_PORT` 不起作用；`JINGWEI_PG_DSN` 也只能在 Release 那份里覆盖。
  现在两份 compose 行为一致。
- **新增审计测试**：`go test ./tools/envaudit/` 要求源码（非测试文件）里读的每个环境变量，
  要么在两份 compose 与 `.env.example` 里都有落点，要么在豁免表里写明理由——防止这类缺陷复发。
- **文档**：DEPLOY §4 补齐控制端地址与各开关的语义、默认值与安全含义（`JINGWEI_GUARD_ENFORCEMENT`
  放宽等于主动降低越界拦截）；§10.2 新增「拉取失败通常是 dockerd 的代理进程没在监听」的判读方法。

### 1.4.1 — 2026-11-04

- **安全加固（无新功能，可原地升级）**：
  - 会话 cookie 的写操作（`POST`/`PUT`/`PATCH`/`DELETE`）必须同站：优先按 `Sec-Fetch-Site` 判定，
    头缺失时校验 `Origin` 的协议 + 主机 + 有效端口，两者都没有就拒绝；显式 `Authorization` 请求豁免。
  - 目标范围与资产禁令改为**失败关闭**：读平台禁令、任务范围、公司资产展开任一失败即拒绝工具调用，
    不再「记一行日志然后放行」；数据库抖动会表现为工具调用失败并提示稍后重试，这是设计行为。
  - 工作区七个文件接口统一改用 `os.Root` 固定根目录，软链跟不出去，也挡住「检查通过后目录被换成
    软链」的竞态；下载不再按路径二次解析。
- **修复**：自定义 HTTP 工具的代理地址重复拼协议头（`http://http://…`）导致工具请求全挂；
  Skill 覆盖安装先删旧版、新版装失败就两头落空——改为先备份再换，失败回滚，回滚也失败时告知备份路径；
  演示数据模式（`NEXT_PUBLIC_MOCK=1`）下「发现」页按任务/系统分组时崩溃。
- **验证**：新增 4 个测试文件 9 个测试（跨站 cookie、策略失败关闭、软链替换竞态、上传不跟软链、
  skill 回滚、代理地址不重复拼）；全量测试 URI 与 keyword 两种 DSN 写法各一轮无失败；
  演示站发现页四个页签逐个点开确认渲染正常，不只是「不报错」。

### 1.4.0 — 2026-11-03

- **加密 v2 WebShell 协议**：握手派生会话密钥（密钥不出现在流量里）、AEAD 加密、时间戳 + nonce 防重放、
  随机请求载体，支持 PHP / JSP / ASPX 与 Windows `cmd` / `powershell` 壳；载荷多态混淆（填充、注释、
  函数名随机化）与 SHA-256 载荷指纹、部署后自检。
- **大马、内存马与半持久化**：v2 通道上的文件管理（目录列表、分块读写、重命名、删除、改权限）；经 JSP
  父壳注入 Filter / Servlet / Listener / Valve / Agent 五类内存马并可撤销；PHP `auto_prepend_file`
  前置载荷透传原页面、不改站点行为。
- **WebShell 工作台**：一条壳一个对话框——虚拟终端（当前目录、退出码、耗时、stderr 着色、`cd` 续用、
  历史翻阅、超时档位 15/30/60/120/300 秒）、文件管理、系统信息（12 个分区 + PHP 解释器自述）；
  内网 SSH 会话与它共用同一个终端组件。
- **内网**：只有 22 端口、没有 web 服务的主机也能建受管会话；目标上已有的文件可登记成受管壳；
  新增凭据台账页签与隧道台账的 `listen_side`（监听开在目标侧还是控制侧）。
- **密钥与静态数据**：签名根密钥改存数据库单行表，容器重建不再重新铸钥匙（升级既不用重新登录，
  也不用重投 webshell）；内网口令与模型 API 密钥按用途派生密钥密封入库，接口不再回显明文。
- **修复**：等不到回包不再报成「shell 坏了」（九处传输错误不再被压平成字符串）；系统族探测没答时不再
  被猜测永久钉死；同一内网会话改为轮次互斥；系统信息不再被一次根目录遍历拖死整面板；不带 `type` 的
  资产查询不再被兜底成 `root_domain`（内网拓扑图此前对没有根域名的目标永远空白）。
- **文档**：README 截图换成 Jingwei 自己的界面（演示数据 + 1.4.0 实机实例两组，共 20 张）。
- **维持与撤离**：落地物台账增加指纹、TTL 与幂等判定；撤离支持 dry-run 预览、残留扫描、可选自动删壳，
  失败项保持可重试。
- **工程**：测试并行隔离（每包独立 schema + 套件锁）、浏览器端到端脚本随仓库提供于 `tools/e2e/`、
  仓库根 `Dockerfile` 可直接构建。

### 1.3.1 — 2026-11-01

安全修复版本，针对 1.3.0 自测发现的登录面问题：

- 登录与首次初始化必须完成服务端生成的一次性滑块验证码（绑定客户端 IP、3 分钟过期、单次使用、
  容差 ±6px，并按 IP 限制签发频率）。
- 同一 IP 15 分钟内失败 5 次锁定 15 分钟，返回 `429` 与 `Retry-After`；锁定期间即使密码正确也不下发会话。
- 认证接口请求体上限 16 KiB（超出 `413`）、认证读取超时 10 秒；HTTP 服务补 `ReadHeaderTimeout` /
  `ReadTimeout` / `IdleTimeout` / `MaxHeaderBytes`（不设 `WriteTimeout`，避免截断 SSE）。
- 会话改为可撤销的 `HttpOnly` Cookie（`SameSite=Strict`，HTTPS 下带 `Secure`，24 小时）；JWT 增加版本
  声明并与库中值比对，修改密码立即吊销全部旧会话；不再接受 `?token=`，前端不再把令牌写入 localStorage。
- 兼容性：从 1.3.0 升级需重新登录；HTTPS 反向代理需传递 `X-Forwarded-Proto: https`。

### 1.3.0 — 2026-11-01

- **利用闭环**：sqlmap 确认注入后按账户与 DBA 权限评估升级严重级；弱口令确认后自动排队 Webshell 注入，
  同一主机不重复上传。
- **内网横向**：`intranet_recon` 收集网卡、路由、ARP、监听端口；凭据台账记录来源与原始证据，跨主机
  复用前先验证；隧道支持 SOCKS5 与端口转发两阶段生命周期；目标扫描、弱口令、深度利用均可经隧道出站。
- **权限维持**：可撤销落地物台账，每条带部署、验证、撤销命令与执行证据；Linux 标准模块 cron / systemd /
  ssh_key，Windows 标准模块计划任务与注册表启动项。
- **撤离清理**：按台账 id 倒序撤销并逐条验证，随后拆隧道、释放受管回调与监听、关闭会话；失败项保持
  active 供重试，提供撤离预览与撤离报告。
- **通用滑块验证码求解**：纯 Go 图像匹配（轮廓 + 内容匹配，可生成拟人轨迹），提供 API、agent 工具、
  CLI 子命令与 Go 包多种入口；弱口令引擎内嵌纯 HTTP 滑块自动化，识别被拒自动换图重试。
- **修复**：nuclei DAST 与旧式 payload 模板互斥加载导致一半模板被静默跳过；软 404 / 403 路径误登记为
  系统；预扫 POC 误报；Windows 会话命令静默假成功；证据报文丢失 Host 与重定向后的会话 Cookie。

### 1.2.2 — 2026-10-30

文档补丁，功能与 1.2.1 相同：README 增加交流二维码，部署文档、Compose 默认镜像标签与前端包版本同步。

### 1.2.1 — 2026-10-30

发布包清理补丁，功能与 1.2.0 相同：移除工具说明中的真实公网地址示例，改用文档保留地址，
源码包与镜像不再包含该地址。

### 1.2.0 — 2026-10-30

把「扫到什么报什么」推进到「固定流程必跑基础漏洞」：

- **应用层发现与登录页发现**：按内置路径字典、robots/sitemap、页面链接与 SPA 路由识别子路径系统，
  随机路径 soft-404 基线过滤「全路径同响应」，结果作为系统级资产入库。
- **固定渗透基线**：弱口令（镜像内置 WebCrack 引擎跑 admin 字典）与 SQL/XSS 注入点枚举作为必跑步骤，
  不依赖 nuclei 是否命中；参数位置交给内置 sqlmap / dalfox 专项判定，同一位置只付一次工具成本。
- **LLM 任务先探测后渗透**：规划前完成端口、指纹、应用层发现与 POC 初筛；场景链由代码按意图路由注入，
  不靠模型自觉；新增蜜罐评分、每任务固定 UA、审批「一键放行」、会话自动标题。
- **证据与复现**：证据质量校验拦截「见截图」式占位；原始报文取证截图、报告分页、请求重发、
  跨任务凭据库、内网拓扑页。
- 工程标识从 ARTEX 全面切换为 **Jingwei**。

### 1.1.0 — 2026-10-26

- **不依赖 LLM 的自动化漏扫引擎**：端口探测 + 25,136 条 FLUX 指纹 + nuclei 模板并发执行，命中直接生成
  漏洞发现；扫描完成后自动串联复核、深度利用、WAF 绕过与可选 WebShell 注入。
- 注入类判定改由 sqlmap / dalfox 专项验证器自证；时间盲注按响应预算止损，不再误报或挂死。
- **可复现报文**：每条发现绑定完整原始请求/响应，多步 POC 保存整条报文链；非 HTTP 协议（Redis RESP、
  MySQL 握手、SSH banner）按协议本身出十六进制字节；报告支持 DOCX / HTML 导出。
- 反证判定区分确认/误报并回写状态，同一漏洞跨轮次去重；漏洞列表按任务、按系统分组。
- 新增「深度利用」一级栏与六个子页、java-chains 可选 sidecar 与 MCP 链路、内网两阶段能力与
  受管资源台账 / 端口审计。
- **安全边界**：工具调用统一经 Guard 做目标范围、出站控制、不可信内容标记与密钥脱敏；worker 利用结束
  清理痕迹，不在目标遗留测试文件。
- LLM 稳定性：连接池健康重试、单次调用超时、任务停滞检测自动暂停、按模型实时计量。
- 发现 / 任务 / 资产 / 公司四类列表批量删除；测试进程强制使用独立测试库，不再接管生产任务。

### 1.0.0 — 2026-10-22

- **品牌化**为「精卫 Jingwei」：控制台、登录/初始化页、侧栏、报告、通知、后端 Banner 与健康检查服务名；
  新增《使用须知》、首次启动密码初始化与管理员改密流程。
- **POC 模板库**：nuclei YAML 的搜索、筛选、统计、详情、上传、启停、删除与批量执行；内置 nuclei 3.11.1，
  首版导入 13,058 条模板；修复 YAML 转义 NUL 导致写库失败，补齐 `tcp` / `udp` / `workflows` 协议识别。
- **发布方式改为 Docker-only**：GitHub Actions 构建 AMD64 / ARM64 镜像，原生 runner 冒烟测试后推送 GHCR；
  Release 自动附带 `docker-compose.yml`、`DEPLOY.md` 与镜像 digest；新增 `deploy/docker-compose.yml`
  与 `deploy/.env.example`，支持独立卷、健康检查与端口覆盖。

## 截图

> 标注「演示数据」的页面取自内置演示数据集（`NEXT_PUBLIC_MOCK=1`：域名 `acme.com`、地址为 RFC 5737
> 文档保留段）；其余取自 1.4.0 实机实例，目标是本地 Docker 隔离靶机，地址均为内网段。

### 平台与 LLM 协同（演示数据）

| 仪表盘：Token 消耗、活动流、发现概览 | 任务列表：目标进度与漏洞分级 |
| :---: | :---: |
| ![仪表盘](screenshots/dashboard.png) | ![任务](screenshots/tasks.png) |

| 人在环路对话：注入 hint、旁路提问 | LLM 录制：逐轮请求与工具调用回放 |
| :---: | :---: |
| ![对话](screenshots/chat.png) | ![LLM 录制](screenshots/llm.png) |

### 无 LLM 扫描与可复现证据（实机）

| 自动化漏扫：端口探测 + 指纹 + POC 命中 | 发现：按任务与系统分组，可批量整理 |
| :---: | :---: |
| ![自动化漏扫](screenshots/scans.png) | ![发现](screenshots/findings.png) |

| POC 库：内置 1.3 万条 nuclei 模板 | 资产：企业 / IP / 子域 / 服务 / 应用 / 接口分层 |
| :---: | :---: |
| ![POC 库](screenshots/pocs.png) | ![资产](screenshots/assets.png) |

### 流量、拦截与拓扑

| 流量（演示数据）：全局录制代理 | 命令拦截（演示数据）：规则 + 模型兜底 |
| :---: | :---: |
| ![流量](screenshots/traffic.png) | ![拦截规则](screenshots/intercept.png) |

| 内网拓扑（演示数据）：按资产类型分层 | 请求重发（实机）：原始报文重放，时钟块可左右拖拽 |
| :---: | :---: |
| ![内网拓扑](screenshots/topology.png) | ![请求重发](screenshots/repeater.png) |

### 深度利用（实机）

| WebShell 管理：存活检测与加密 v2 协议 | 工作台 · 虚拟终端：当前目录、退出码、耗时 |
| :---: | :---: |
| ![WebShell 管理](screenshots/webshells.png) | ![工作台终端](screenshots/workbench-terminal.png) |

| 工作台 · 文件管理（大马） | 工作台 · 系统信息：一次往返采集 12 个分区 |
| :---: | :---: |
| ![文件管理](screenshots/workbench-files.png) | ![系统信息](screenshots/workbench-info.png) |

| 内网渗透：会话 / 隧道 / 凭据 / 落地物 | 会话终端：与工作台共用同一组件 |
| :---: | :---: |
| ![内网渗透](screenshots/intranet-sessions.png) | ![内网会话终端](screenshots/intranet-terminal.png) |

| 凭据台账：口令只写不读 | 受管资源与端口审计：到期自动回收 |
| :---: | :---: |
| ![凭据台账](screenshots/intranet-credentials.png) | ![受管资源](screenshots/resources.png) |

---

## 快速开始（Docker）

> 自 1.0.0 起仅通过 Docker 镜像分发，不再提供预编译二进制或页面一键换装。
> 完整参数、备份恢复与故障排查见 [DEPLOY.md](DEPLOY.md)。

**环境要求**：Docker Engine 24+、Docker Compose v2，`linux/amd64` 或 `linux/arm64`，
建议 2 核 CPU / 4 GB 内存 / 10 GB 磁盘。

### 方式一：使用仓库内 Compose（推荐）

```bash
git clone --depth 1 --branch v1.6.1 https://github.com/Domren/Jingwei.git
cd Jingwei/deploy
cp .env.example .env
# 编辑 .env：至少修改 POSTGRES_PASSWORD
docker compose pull
docker compose up -d
```

### 方式二：只下载 Release 部署文件

```bash
mkdir jingwei && cd jingwei
curl -fsSLO https://github.com/Domren/Jingwei/releases/download/v1.6.1/docker-compose.yml
curl -fsSLo .env https://raw.githubusercontent.com/Domren/Jingwei/v1.6.1/deploy/.env.example
# 编辑 .env 后启动
docker compose pull
docker compose up -d
```

启动后访问 `http://<服务器IP>:9790`。首次进入会跳转到初始化页，设置管理员密码；
用户名固定为 `Jingwei`。流量录制代理只监听宿主机 `127.0.0.1:9791`。

### 镜像访问

镜像发布在 GitHub Container Registry：

```bash
docker pull ghcr.io/domren/jingwei:1.6.1
```

仓库维护者将 Package 设为公开后可直接拉取。若镜像仍为私有，请使用具备
`read:packages` 权限的 GitHub Token 登录（Token 不要写入 `.env` 或提交到仓库）：

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u Domren --password-stdin
```

### 配置

部署目录的 `.env` 由 Docker Compose 自动读取：

| 变量 | 必填 | 说明 |
| --- | :---: | --- |
| `POSTGRES_PASSWORD` | 是 | 数据库密码，建议使用字母数字强随机值 |
| `POSTGRES_USER` / `POSTGRES_DB` | 否 | 默认均为 `jingwei` |
| `JINGWEI_IMAGE` | 否 | 默认 `ghcr.io/domren/jingwei:1.6.1` |
| `JINGWEI_WEB_PORT` | 否 | Web/API 宿主端口，默认 `9790` |
| `JINGWEI_PROXY_PORT` | 否 | 流量代理宿主端口，默认 `9791`，仅绑定 `127.0.0.1` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | 否 | 也可启动后在 UI 配置 |
| `JINGWEI_LLM_PROVIDER` / `JINGWEI_LLM_MODEL` / `JINGWEI_LLM_BASE_URL` / `JINGWEI_LLM_PROXY` | 否 | 自定义 OpenAI 兼容端点或代理 |

密码含 `@`、`:`、`/` 等特殊字符时会被直接拼入 DSN，请改用 URL 编码后的
`JINGWEI_PG_DSN` 覆盖完整连接串，或使用字母数字密码。

### 升级

```bash
# 先备份数据库与 data 卷
docker compose pull
docker compose up -d
```

数据库结构在应用启动时幂等迁移，无需手动执行 SQL。回滚时把 `.env` 中的
`JINGWEI_IMAGE` 改回旧 tag 再 `docker compose up -d`；数据库迁移不会自动回退，
重要升级前请先备份。

### 数据持久化

| 卷 | 内容 |
| --- | --- |
| `jingwei_pgdata` | PostgreSQL 全量数据（任务、配置、POC 模板等） |
| `jingwei_jingwei_data` | `/app/data`：JWT 签名密钥、流量录制等运行数据 |

默认不暴露 PostgreSQL 端口；请勿把 `9791` 代理端口开放到公网。

---

## 反向代理（HTTPS）

前端、API 与 SSE 活动流由同一个后端端口提供。公网部署建议只开放 443，
将 `127.0.0.1:9790` 留在内网。SSE 是长连接，反代必须关闭缓冲：

```nginx
server {
    listen 443 ssl;
    server_name jingwei.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass http://127.0.0.1:9790;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

可在「系统配置 → HTTP Basic Auth」再加一层访问验证。健康检查接口为
`GET /api/health`，保持公开且不返回敏感信息。

---

## 从源码构建镜像

发布镜像由 GitHub Actions 在原生 AMD64 / ARM64 runner 上构建并验证，流程见
[`.github/workflows/release.yml`](.github/workflows/release.yml)。本地构建需要
Go 1.26+、Node.js 22+ 与 Docker：

```bash
# 1. 构建前端静态产物
cd web && npm ci && npm run build:static && cd ..

# 2. 嵌入前端并编译 Linux 二进制
rm -rf server/webui/dist && cp -r web/out server/webui/dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embedui -trimpath \
  -ldflags "-s -w -X main.version=1.6.1" -o dist/amd64/jingwei ./cmd/jingwei

# 3. 构建运行镜像
docker build --network=host --build-arg TARGETARCH=amd64 \
  -t jingwei:1.6.1 .
```

本地开发运行后端与前端的方法见 [DEPLOY.md](DEPLOY.md#从源码开发)。

## 技术架构（摘要）

- **后端**：Go 单二进制，内嵌 Next.js 静态前端；PostgreSQL 16 持久化；JWT 鉴权。
- **调度**：planner 负责拆解与排序意图，worker 执行具体动作，main-agent 维护主链路；
  事件驱动、无状态会话，支持多 worker 过程级信息交换。
- **双图**：探索图记录攻击路径与事实，资产图归并域名/IP/端口/站点/端点；
  已测节点高亮，支持覆盖图查看与折叠。
- **工具链**：镜像内置 nmap、curl、nuclei、Playwright Chromium 等常用组件；
  工具与 MCP/Skills 可在系统页扩展。
- **流量**：内置 MITM 代理录制请求/响应，供发现证据与报告引用。

更细的引擎生命周期、意图状态机与多轮规划说明见上游 ARTEX 仓库
（[RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX)，即 Autumn-27/ARTEX 的持续维护版）。

## 发布流程

1. 更新版本号与 `CHANGELOG.md`，提交到 `main`。
2. 创建并推送 `vX.Y.Z` 标签。
3. GitHub Actions 自动构建前端与双架构二进制，在原生 runner 上启动容器做健康检查，
   推送 GHCR 镜像，并创建 GitHub Release（附带 `docker-compose.yml`、部署文档与镜像 digest）。

发布只使用仓库内置 `GITHUB_TOKEN`，无需配置 Docker Hub 凭据。

## 交流

扫码关注微信公众号 **网安智界**，在公众号后台私信即可入群交流。

<div align="center">

<img src="screenshots/wechat-qr.jpg" alt="微信公众号 网安智界" width="240" />

</div>

## 许可与免责声明

### 开源协议

本项目采用 **GNU Affero General Public License v3.0（AGPL-3.0）**，完整条款见
[LICENSE](LICENSE)。任何人都可以自由使用、修改和分发本项目，但衍生作品必须同样以
AGPL-3.0 开源；若修改后通过网络向用户提供服务，必须向这些用户公开对应的完整源码。
原始版权、许可与署名信息不得移除，详见 [NOTICE](NOTICE)。

本项目基于 ARTEX 二次开发：

- 上游作者与源头：**Autumn-27/ARTEX**（AGPL-3.0）
- 现由 [RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX) 持续维护
- Jingwei 新增与修改：Copyright (C) 2026 Jingwei contributors

### 允许使用范围

- 仅可用于**阅读、学习与研究源码**，以及在**本地隔离环境**中进行技术原理验证；
- 适用于个人学习、学术研究、代码审阅等非攻击性用途。

### 禁止事项

- **严禁使用本工具对任何网站、线上服务或联网系统发起扫描、探测、利用或攻击**
  （无论是否获得授权、是否为自有资产）；
- 严禁用于任何实际的渗透测试、攻防对抗或生产环境；
- 严禁用于非法入侵、数据窃取、勒索、拒绝服务或任何破坏性、犯罪性活动；
- 严禁利用本工具从事违反所在国家/地区法律法规的行为。

### 合规责任与免责

使用者须自行遵守所在国家/地区关于网络安全、数据保护与计算机犯罪的全部法律法规
（在中国大陆包括但不限于《网络安全法》《数据安全法》《个人信息保护法》及相关司法解释）。
**因使用本工具产生的一切法律责任与后果，均由使用者自行承担。**

本项目按“现状（AS IS）”提供，不附带任何明示或默示的担保。作者及贡献者不对使用本工具
（无论使用方式是否得当）所导致的任何直接或间接损失、数据丢失、系统损坏或法律纠纷承担责任。
**下载、安装或使用本项目，即表示你已阅读、理解并同意上述全部条款。**
