# 更新日志

本项目的重要变更记录在此文件中，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

### 新增

- **弱口令检测的引擎层就位（1.5.0 的第一块地基）**：新增 `scanner/credscan.go`。
  这个模块的边界写死在代码里——**只测出并记下「某资产的某协议存在某组可用凭据」这条事实**，
  不编排别的模块、不自动触发任何动作、不自动复用凭据；用不用由人决定。
  端口按三级优先决定：输入带端口就只用那个端口 → 没有则用端口探测/指纹判过的 `host:port` →
  两者都没有才用协议默认端口表。**默认端口表只回答「去测哪个端口」，绝不回答「那个端口是什么协议」**：
  2222 上跑的 HTTP 如果被当成 SSH 打了字典，那份证据从生成起就是假的，比不测更坏。这条硬约束有两处
  代码保证——指纹说这端口是 HTTP 而任务勾了 SSH 就直接不产出端点；按默认表挑出来的端口必须先经过
  握手确认，认不出来就一条字典都不发。
  结果分六态：`命中 / 明确拒绝 / 连不上 / 账号锁定 / 不可判定 / 不支持`。后三态存在的唯一理由是
  报告必须能区分「验证过不存在弱口令」与「没测出来」：**没实现＝没测过**，落「不支持」而不是「拒绝」。
  运行边界同样为报告的可信度服务：并发（默认 16、上限 128）、限速、墙钟预算（默认 10 分钟）、
  同一端点连续 3 次传输层失败即放弃、一旦观察到锁定提示立刻停手——**每种收尾都逐行留下记录**，
  少一行就等于在报告里宣称「这个端口测过了」。命中与拒绝都带原始请求/响应字节（新增
  `ProtocolExchangePacket`）：发过请求的尝试不能套 banner 那套格式，那句「扫描器未发送任何应用层
  请求字节」会变成假记录，复现命令也发不出同一串字节。
  单测 12 项（不含真实网络，靠适配器调用次数断言「有没有偷偷多试」）。写测试时抓到并修掉一个真缺陷：
  主循环用 `select` 等预算定时器，于是每次迭代都卡在 select 上——默认预算 10 分钟等于
  **什么都不测、干等 10 分钟**；改成「派生 context + 到点非阻塞检查」后同样的测试 0.06 秒跑完且
  真的产生了预算行。

- **弱口令检测接入一档 8 个高频协议，每个都在真实服务上验过命中与拒绝**：新增
  `scanner/credscan_{redis,postgres,mysql,mongodb,ssh,socks5,ftp,telnet}.go`，
  覆盖 Redis（含「未开认证」）、PostgreSQL（scram-sha-256 / md5 / trust）、MySQL
  （`caching_sha2_password` 的快速与完整认证通道、`mysql_native_password`、认证切换）、
  MongoDB（scram-sha-256 / scram-sha-1）、SSH（口令）、Socks5（无认证与 username 子协商）、
  FTP、Telnet。PostgreSQL 与 MySQL 支持先升 TLS 再认证，且**记录的是 TLS 通道内的明文**并把它标出来
  ——不标出来，复现命令就写成了一条裸 socket，照着发必然拿不到同样的响应。
  公共层另加三份：`credscan_wire.go`（带字节记录的裸连接：每段请求/响应都留档，
  `writeLine` **拒绝用户名或口令里含 CR/LF**——那是往服务端塞第二条命令）、`scram.go`
  （SCRAM 客户端，校验服务端 nonce 必须延长、迭代数异常即拒）、`bson_min.go`（Mongo 用的最小 BSON，
  未知类型**报错而不是跳过**：静默跳过的结果是一个看起来合法的握手包，而字段其实丢了）。
  认证形态按协议证据判定而非按端口：把 8 个适配器逐个按在真实 HTTP 端口上，**无一确认成功**，
  各自给出「没有该协议的证据」——这是「默认端口表只决定测哪个端口」那条硬约束的真机版。
  **为什么自己实现而不引第三方驱动**：① 引擎的证据要求是**每一段请求与响应字节**都能逐字节复现，
  驱动内部自己拨号自己丢包，报告里就没有可复现的字节；② 「明确拒绝」「传输层失败」「没测出来」
  三种意思必须分别落到不同结果态，而驱动只给一句「登录失败」时只能靠猜，猜错就是把「没测出来」
  写成「已排除」；③ 本模块的边界是「一条事实进、一条事实出」，不该把扫描器的生命周期交给一个
  自带连接池、重试与超时的库。
  **验证口径**：`tools/e2e/credscan-lab/`（含 README 与 `down.sh`）在宿主机与边界靶机上摆出真守护进程，
  `JW_CRED_LAB=1` 的用例逐个用被测代码去打——**14 个协议用例全过，每个都走命中与拒绝两条路径**；
  另有一条守卫验「空凭据不得判成命中」。口令全部现场生成、只存 600 权限的临时清单，
  `down.sh` 删临时容器与临时用户并恢复被改过的系统配置。只验命中等于没验「拒绝长什么样」，
  而 deny 是报告里唯一能说「这组口令被排除」的态。
  这一批真正的产出是 **12 条只有在线上才暴露的缺陷**（包序号、SASL 长度含不含 NUL、Mongo 的
  `$db` 必须排在文档末尾、SCRAM-SHA-1 的口令要先过一遍 `md5(user:mongo:password)`、
  vsftpd 的 banner 因为服务端反查 DNS 而迟迟不到、`421 too many connections` 曾被误判成
  「账号锁定」……），逐条与根因记在开发文档的缺陷台账里；自写靶子和自写适配器可能错得一模一样，
  这类问题只有真库能撞出来。

- **弱口令检测成为可用模块（深度利用 → 弱口令检测）**：任务创建 / 列表 / 详情 / 取消 / 删除、
  2 秒级进度与日志、结果按六态筛选，每条命中都能展开看原始协议报文；详情页可导出**内部版**
  （全部六态 + 报文附录）与**对外版**（只含已确认命中、口令打码，未测与不支持的协议显式列出）报告。
  任务落 `cred_tasks` / `cred_results`，重启后中断的任务标记为失败，不会留下永远「运行中」的假状态；
  结果分批写库，写失败会把行放回缓冲重试，最终仍失败就判任务失败——**结果少一行等于报告里多一句假话**。
  命中自动落三条事实：资产服务行、`weak-credential` 发现、凭据库记录（状态 `untested`），
  **不登录、不复用、不触发任何动作**。字典默认只用 25 组内置精简字典；可在页面导入
  「用户:口令」字典档（上限 5000 组），任务日志与报告都记档名，结论可追溯。
  LLM 侧新增 `credscan_start` / `credscan_status`（支持 `queue_only`）：模型能主动发起检测并读取结论，
  但没有「自动复用」工具——发起与复用是两件事。
  防锁定：同一账号连续 5 次被明确拒绝后停止再试该账号（余下口令组记「不可判定」并写明原因），
  其他账号照常；收到服务端锁定提示则整个端点立即停手。这里刻意不把「主动停手」写成 `locked`，
  「账号已被锁」必须是服务端说过的话。
  真机验证：14 个协议用例（命中 + 拒绝两条路径）、8 个适配器按在 HTTP 端口上无一确认成功、
  空凭据不判命中；服务端 API 与任务链另由 4 个集成测试覆盖（任务生命周期、字典导入与选用、
  工具调用、事实落库与「未自动复用」）。

### 修复

- **「目标上的文件不是精卫生成的载荷」不再被说成密钥问题**（E2 真机验证抓到）：登记一个地址后
  平台会做一次 v2 存活验证；如果那个文件是别人放的普通 PHP（存在、能执行、返回 200，但回显
  根本不是 v2 信封），旧措辞是「令牌版本不匹配（可能被 WAF 拦截、shell 已失效或密钥不匹配）」，
  把操作员支去给一把不存在的壳轮换密钥。现在先判断回显是否可能是协议报文（base64url 且长度够），
  不是就直说「目标回显的不是加密 v2 协议报文（N 字节：前 48 字符）」并指向正确做法：
  用 `webshell_register` 带 `session_id` + `deploy_path` 让平台把载荷写上去。真的信封解不开时
  仍按原样报协议错误——两种成因不能共用一句话。
  真机复核（Ubuntu-1 上 Apache 里的真实 PHP 文件）：登记 → 判 `dead` 并给出上述原因；
  经会话写入正确载荷 → 复查 `alive`、加密通道验证通过。验证文件与记录随后删除，台账零残留。

### 变更

- **镜像里的 `@playwright/*` 不再装 `@latest`**：`@playwright/mcp`、`@playwright/cli`、`playwright`
  此前每次构建都拉当时最新版，于是同一个提交重建两次可能得到两套浏览器工具——镜像内容与代码
  提交对不上，上游接口一变就只在某次重建后炸，而且没有回退路径。现在由三个构建参数钉住
  （`PLAYWRIGHT_MCP_VERSION` / `PLAYWRIGHT_CLI_VERSION` / `PLAYWRIGHT_VERSION`，默认值即
  2026-11-05 实测可用的一组：0.0.84 / 0.1.23 / 1.64.1），要升级时改这三行，CI 无需改动。

### 新增

- **失败关闭的目标策略现在按任务与成因计数**（可观测性清账项）：1.4.1 把「读不到授权范围 /
  读不到平台禁令 / 展不开公司资产」从「记一行日志然后放行」改成「拒绝调用」之后，操作员看到的
  只有一句「工具被拒」——数据库抖动、范围没登记、目标真的越界，三种完全不同的成因长得一模一样。
  现在每一次拒绝都落一行 `guard_denials`（任务、成因类别、当时的强制模式、最近一次原因与时间），
  新增 `GET /api/intercept/guard/denials?hours=`，并在「系统 → 拦截规则」页的目标防护卡片下方
  加一张近 7 天的分组统计表：拒绝总数、涉及任务数、当前模式，以及按任务×成因的明细。
  类别分开计数：`超出登记范围`、`命中资产禁令`、`读不到任务范围`、`展不开公司资产`、
  `读不到禁令`、`策略数据源不可用`。`warn` 模式同样计数（只是放行），这样从 `warn` 切回
  `strict` 之前就能先看到会误伤多少。统计写入是尽力而为：计数失败绝不改变裁决，
  安全边界不能依赖一块可能正在抖的数据库。

### 新增

- **SSH 承载会话现在认得 PowerShell**（Windows 横向的清账项）：目标上的登录 shell 是
  PowerShell 时（Windows OpenSSH 可以把它设成默认 shell），此前的唯一探测脚本
  `echo __JW_OS__%OS% & uname -s` 在 PowerShell 里是一句语法错误——`&` 是调用运算符，
  整行不执行、没有任何回显，于是这台机器被判成「不是预期的 shell」，会话刚建好就 closed，
  哪怕口令是真的、机器完全能打。现在选型按 sh / cmd / PowerShell **依次**试：前两种在
  链式探测里就能区分（`%OS%` 会不会被展开），只有 PowerShell 需要那条不带 `&` 的探测，
  解释器认出来后写进会话台账 `metadata.shell`。配套新增 PowerShell 形态的命令包装
  （`;` 分隔、`$LASTEXITCODE` 取退出码、`(Get-Location).Path` 报当前目录，路径只接受
  盘符绝对形式并做单引号转义）与环境探测、内网信息收集脚本；终端与执行结果多回一个
  `shell_kind`。
- **SSH 登录通了但账号跑不了命令时，说清原因**：以前只留一句「未解析到命令结束标记」。
  现在区分 nologin/shell 占位账号、sshd 配了 ForceCommand、连接被提前关闭与目标完全没回显
  四种情况并点名原因，操作员知道该改账号 shell 还是换思路。同时这条凭据仍记为**有效**并写明
  「登录成功但无执行通道」——口令本身是真的，横向台账不该把它当未验证丢掉；但会话照旧关闭，
  不假装能用。

### 已知限制（本版未覆盖，如实记下）

- 会话落在 PowerShell 时，**文件上传/下载与权限维持脚本仍是 cmd 形态**（certutil 链、
  `%SystemRoot%` 变量等），发过去会失败并报「未解析到命令结束标记」——是明确的失败，
  不是静默成功。要让它们可用需要逐段改成 PowerShell 形态或经 `cmd /c` 桥接。

### 修复

- **ssh 变体的隧道方向也是反的，改判为 `ssh -R`**（A1 真机验证抓到）：目标上没有 chisel 时，
  此前生成 `ssh -N -D <端口>`（SOCKS5）与 `ssh -N -L <端口>:<内网主机>:<端口>`（端口转发）。
  这两个形态的监听确实开在目标上，但**目的地一律由远端——也就是控制端——发起**，
  于是它只是把控制端的网络借给目标用，对「穿透到只有目标可达的内网段」这个唯一目的毫无作用。
  真机对照：同一台只有 OpenSSH 的目标，`-D` 打仅内网段的服务超时，`-R` 同一目的地拿到 200。
  现在 SOCKS5 生成 `ssh -N -R <监听地址>:<端口>`（不带目的地的 `-R` 会让控制端 sshd 监听，
  连接转回目标上的 ssh 客户端由它拨目的地），端口转发生成 `ssh -N -R <监听地址>:<端口>:<主机>:<端口>`，
  两者的 `listen_side` 都是 pivot，验证与拆除复核按控制端一侧做。前提是控制端有一个目标能连进来的
  sshd，且它的 `GatewayPorts` 为 `clientspecified`/`yes`——不满足时 ssh 进程照跑、控制端却没有监听，
  verify 会以「端口不可达」失败而不是假装成功（DEPLOY §4 已写）。
- **ssh 隧道新增 `JINGWEI_PIVOT_SSH_USER`**：`-R` 命令是下发到目标上执行的，留空时 ssh 沿用
  **目标侧**的登录名，控制端账号不同名就直接认证失败；而命令带 `BatchMode=yes`，失败是秒挂而不是
  停在口令提示，操作员很容易误判成网络问题。现在可以钉住用户名（非法值拒绝生成命令并点名变量）。
- **`intranet_tunnel` 工具说明里 listen_side 与 chisel 形态的对应关系是错的**：它写着
  「target（socat、ssh -D/-L、chisel R:）/ pivot（chisel client 不带 R:）」，与实测正好相反，
  照它手写 `deploy_command` 会把复核指到错误的一侧。已按实测重写，并补上「要打只有目标可达的网段，
  出口必须在目标侧（chisel `R:` / `ssh -R`）」这条判据；`listen_host` 参数说明原先谎称默认
  `127.0.0.1`（实际留空即绑全接口），照着填反而会把控制端监听锁死在回环上，一并改正。

### 修复

- **chisel 隧道的两条命令此前一条都不对**（A1 真机验证抓到）：
  1. 生成的 `chisel client --fingerprint auto …` 在 chisel 1.13.0 上不成立——`auto` 不是合法值，
     客户端把整串当 SHA-256 指纹校验，报 `ssh: handshake failed: Invalid fingerprint` 并无限重试，
     这条路从来没通过。现在默认**不带** `--fingerprint`，需要固定控制端密钥时再配
     `JINGWEI_PIVOT_CHISEL_FINGERPRINT`（只接受 43–44 位 base64 真指纹；填错直接拒绝生成命令，
     不下发一条连不上的隧道）。
  2. 方向与监听侧标反了。真机实测：`R:<port>:socks` 与 `R:<port>:<host>:<port>` 的监听开在
     **控制端**（chisel server 持有），拨号目的地由目标发起，因此能打到只有目标可达的内网服务
     （实测 200）；不带 `R:` 的形态才是目标监听、控制端拨号。此前 SOCKS5 用的是不带 `R:` 的形态
     却把 `listen_side` 标成 pivot——隧道建不起来还能理解，更糟的是它把「验证/拆除该看哪一侧」
     也指错了。现已按实测改正，并把 `R:` 的监听侧从此前误标的 target 改成 pivot。
  3. `port_forward`（目标侧监听且由目标拨目的地，等价 socat）这个方向 chisel 表达不了，
     现在明确拒绝自动生成并指向 socat / 手写 `deploy_command`，不再下发一条反向的假成功命令。
  用 chisel 时控制端需以 `chisel server --reverse` 运行，否则这些 `R:` 请求会被服务端拒绝（DEPLOY §4 已写）。

### 修复

- **隧道自动选型里 ssh 与 chisel 共用一个端口**：`JINGWEI_PIVOT_SERVER` 的端口既被 chisel client 用来拨控制端，
  又被生成的 `ssh -D` / `ssh -L` 当成 sshd 端口，而现实中 chisel 常在 8788、sshd 在 22 —— 只有一个值时
  必然有一条路是错的（目标会去 ssh 登录 chisel 端口）。新增 `JINGWEI_PIVOT_SSH_PORT`（留空＝22）只作用于
  ssh 变体，chisel 仍用 `JINGWEI_PIVOT_SERVER` 自带端口；该值非法时拒绝生成命令并点名变量，
  不退回 22 假装成功。

### 修复

- **镜像构建可以在无代理网络下完成**：Dockerfile 新增 `NPM_REGISTRY` 构建参数，
  预装 `@playwright/*` 那一步原来只能直连 `registry.npmjs.org`，在国内网络下报
  `npm error network … behind a proxy` 导致构建失败；留空时行为与之前完全一致（CI 不受影响），
  本机构建传 `--build-arg NPM_REGISTRY=https://registry.npmmirror.com` 即可。与已有的
  `PLAYWRIGHT_DOWNLOAD_HOST`、Node 二进制换源保持同一套思路。

### 新增

- **弱口令检测地基**：`scanner/target.go` 的目标解析支持显式端口——`ip:port`、`[ipv6]:port`、
  `domain:port` 与带端口的 URL 都能解析，新增 `Target.Port`（只在输入写明端口时非零），
  作为弱口令检测三级端口决策的第一级；端口写错（0 / 65536 / 非数字 / 结尾裸冒号）明确报
  「端口无效」而不是退化成猜主机名，`host:port` 带路径、网段带端口都被拒绝，去重键纳入端口
  （`10.0.0.1` 与 `10.0.0.1:2222` 不再互相吞掉）。IPv6 仍统一报「仅支持 IPv4」，与后续 IPv6 支持一并规划。

## [1.4.2] - 2026-11-04（部署侧修复：环境变量注入面与端口覆盖）

### 新增

- **部署期可注入的运行时开关补齐**：`JINGWEI_PIVOT_SERVER`（内网隧道的控制端地址）、
  `JINGWEI_GUARD_ENFORCEMENT`、`JINGWEI_WEBSHELL_TTL_HOURS` / `JINGWEI_MEMSHELL_TTL_HOURS`、
  `JINGWEI_LLM_STREAM`、`JINGWEI_BTW_MAX_OUTPUT_TOKENS`、`JINGWEI_WEBCRACK_BRIDGE` /
  `JINGWEI_WEBCRACK_PYTHON`、`JINGWEI_CONFIG` / `JINGWEI_SKILL_DIR` 现在都能从 `.env` 进容器。
  此前 compose 是白名单式注入，这些变量代码在读、部署却配不上——其中
  `JINGWEI_PIVOT_SERVER` 缺失会让 chisel / `ssh -D` / `ssh -L` 的隧道自动选型在真实实例上整体不可用
  （`plan` 只会返回「未配置」），而它连 `.env.example` 都没进过。
- **`tools/envaudit` 审计测试**：源码（非测试文件）里读的每一个环境变量，必须在两份 compose 与
  `.env.example` 里都有落点，或在豁免表里写明理由；漏掉任何一个就测试失败。这道锁是为了让
  「配置了也没用」这类缺陷不再复发。

### 修复

- 根目录 `docker-compose.yml` 的监听端口此前写死为 `9790/9791`，DEPLOY §10.3 让操作员改
  `JINGWEI_WEB_PORT` / `JINGWEI_PROXY_PORT` 其实不起作用；现在与 `deploy/docker-compose.yml` 一致。
- 根 compose 支持 `JINGWEI_PG_DSN` 覆盖（口令含需转义字符或数据库不在本 compose 里时的逃生口），
  与 deploy compose 对齐。

### 文档

- DEPLOY §4 补充控制端地址与运行时开关的语义和默认值；§10.2 补充「拉取镜像失败往往是 dockerd 的
  代理进程没在监听」的判读方法，并说明它只影响拉取、不影响本地构建与运行。

## [1.4.1] - 2026-11-04（安全加固：cookie 同站门、策略失败关闭、工作区固定根）

本版没有新功能，是 1.4.0 之后的一批安全与健壮性修复。功能面与 1.4.0 完全一致，可直接原地升级。

### 安全

- **会话 cookie 只允许同站的变更请求**：`requireAuth` 之前对所有写操作只看「有没有有效会话」，
  不区分这个 cookie 是不是被别的站点借来发的——本地部署时 `127.0.0.1:9790` 上没有 CSRF 防护，
  任意恶意网页都能让浏览器替操作员改配置、删数据、投放载荷。现在带会话 cookie 的
  `POST`/`PUT`/`PATCH`/`DELETE` 必须先过同站判定：优先看 `Sec-Fetch-Site`（`same-origin`/`same-site` 放行，
  `cross-site` 直接拒），头缺失时才比 `Origin` 的 scheme + host + 有效端口（含 http↔80、https↔443 的
  默认端口等价）；**两个头都没有就拒绝**，不做「看起来无害就放过」。显式带 `Authorization` 的请求
  不属于浏览器的附带凭据，保持豁免，CLI 与脚本不受影响。
- **目标范围与资产禁令改为失败关闭**：`guardTargetPolicy` 原先在数据库读失败时打一行日志然后**放行**
  （理由是「瞬时抖动不该让所有工具调用失败」），代价是抖动期间平台资产禁令和任务授权范围同时消失，
  agent 可以打到范围外的主机而只留下一条日志。现在读全局资产禁令、任务禁令、任务测试范围、
  公司资产展开任一失败，都返回 `ScopeOut` 并给出中文原因（「无法读取任务授权范围，请稍后重试」）；
  策略数据源整个不可用（`pg == nil`）同样拒绝。**行为变化要预期**：数据库抖动现在会让工具调用直接失败，
  而不是悄悄放开范围——对红队工具这是正确的取向。
- **工作区文件操作固定到根目录内**：原来靠「先 `filepath.Clean` 拼绝对路径、再 `os.Stat` 检查前缀」
  挡越界，两个问题都在：软链本身合法但跟进去就出了根；检查和真正读写之间目录被换成软链（TOCTOU）
  也挡不住。现在七个接口（list / read / write / mkdir / delete / download / upload）统一改用
  `os.OpenRoot` 拿到的 `*os.Root` 做全部 I/O——约束由内核按目录 fd 强制，路径换了也不出这个根；
  `wsResolve` 额外逐级 `Lstat` 拒绝已存在的软链；`download` 从按路径二次解析的 `http.ServeFile`
  换成 `http.ServeContent`（直接喂 root 内打开的文件）。工作区没有重命名接口，无遗漏面。

### 修复

- **自定义 HTTP 工具的代理地址被重复拼协议头**：录制代理地址本身带 `http://` 时，代码又补一次前缀，
  拼出 `http://http://127.0.0.1:8788`，工具请求全部走不通。现在只在没有 scheme 时才补。
- **Skill 覆盖安装失败会把旧版一起丢掉**：`overwrite` 分支先 `os.RemoveAll(旧目录)` 再装新目录，
  新目录安装失败时旧版已经没了——用户既没有新版也回不去旧版。改成先把旧目录 `rename` 成
  `.backup-*`，装成功才清理备份；装失败就 `rename` 回来；连回滚也失败时**把备份目录路径报给用户**，
  而不是留一句「安装失败」。
- **演示数据模式下「发现」页崩溃**：mock 数据集没有实现 `/exploration/findings/systems` 与 `/ids`，
  页面按任务/系统分组时读到 `undefined.length` 直接抛运行时错误。现在补齐两个端点，并按后端的
  「主系统」选择口径归属（`service` > `endpoint` > `app` > `subdomain` > `ip` > `root_domain`，
  带 host:port 与路径后缀），分页参数非法时退回默认值。

### 验证

- 新增 4 个测试文件、9 个测试：`auth_csrf_test.go`（跨站 cookie 写被拒 / bearer 豁免）、
  `guard_policy_failclosed_test.go`（读失败与无库都返回 `ScopeOut`）、
  `workspace_root_test.go` 与 `workspace_test.go`（软链替换竞态、上传不跟软链、越界拒绝）、
  `skill_upload_test.go` 补覆盖安装失败保旧版、`customtool_test.go` 补代理地址不重复拼。
  全部通过；`gofmt` 与 `go vet ./server/...` 干净。
- 全量测试两种 DSN 写法各一轮：`go test ./...`（URI）与 `go test ./db/... ./server/... ./agent/...`
  （keyword/value）均无失败。
- mock 发现页做了视觉核对（不只是「不报错」）：起 `NEXT_PUBLIC_MOCK=1` 的站点，四个页签逐个点开并
  展开任务分组，无脚本报错、无错误浮层，分组正常显示 3 个任务 / 9 个系统与各级严重度计数。
- 确认 CSRF 门不会挡现有前端：全站没有 `<form method=post>`，也没有 `sendBeacon`，写操作一律走
  同源 `fetch`（浏览器必带 `Origin`）。CORS 侧仍是「只有 loopback 同源才允许带凭据」，
  `Access-Control-Allow-Origin: *` 不构成跨源读取敏感数据的路径。

### 升级

- 原地升级即可：`docker compose pull && docker compose up -d`。数据库结构无变更，
  不需要重新登录，也不需要重投 webshell。
- 若你的部署依赖「用 cookie 但从别的源发写请求」（例如自己写的浏览器插件跨源调用），
  这类调用在本版会被 `403 跨站 cookie 请求不允许执行变更操作` 拒绝；改用显式 `Authorization` 即可。
- 若数据库不稳定，现在会看到工具调用被拒绝并提示「请稍后重试」，这是设计行为，不是回归。

## [1.4.0] - 2026-11-03（WebShell 与内网能力强化）

### 新增

- **加密 v2 WebShell 协议**：握手派生会话密钥（密钥不出现在流量中）、AEAD 加密、时间戳 + nonce
  防重放、随机请求载体头、失败静默；支持 PHP / JSP / ASPX 与 Windows `cmd`/`powershell` 壳。
- **载荷多态与自检**：同一密钥可生成不同外观载荷（填充、注释、函数名随机化）、载荷 SHA-256 指纹、
  部署后自检；`GET /api/deep/webshells/{id}/payload` 导出与库中记录一致。
- **平台签名密钥入库**：签名根密钥（`/app/jwt.key`）改存数据库单行表 `platform_secret`，启动时「库优先 → 旧文件迁移入库
  后删除 → 都没有才生成并写库」。它同时是三样东西的根：会话 JWT 的 HS256 签名、webshell/内存马/半持久化密钥密封的派生
  （`HMAC(jwt.key, 用途)`）、HTTP Basic 认证门 cookie 的派生。读取口刻意收窄成 `platformSecretStore` 两个方法，只在
  `server.New` 调用一次；它不是一条 `settings`——`settings` 被到处按 key 读取并经 `GET /api/settings` 白名单回显给浏览器，
  而这把钥匙绝不能出现在任何 API、报告或工具出口里。写入用 `INSERT … ON CONFLICT (id) DO NOTHING` 再读回，判定落在主键
  约束上，两个实例同时首启因此会收敛到同一把而不是各自铸一把。
- **内网凭据口令与模型 API 密钥同样密封入库**：密封内核从 webshell 一处抽成 `db/seal.go`，按用途派生
  （`jingwei/webshell-secret/v1`、`jingwei/intranet-credential/v1`、`jingwei/llm-api-key/v1`，一处泄露解不开另一处），
  并把它装进数据库层唯一的读写口：`UpsertIntranetCredential` 写入前密封、`scanIntranetCredential` 读出时解回，
  `SaveProfile` 密封 `api_key`（`api_key_hint` 仍取明文末四位，界面照旧认得出是哪个 key），
  `ActiveProfile`/`ProfileByID`/`PoolProfiles`/`ProfileAPIKeys` 解回明文。选择在库里收口而不是在每个调用点解封，
  是因为漏掉一个点的表现是拿密文去拨 SSH 或去发 `Authorization` 头——看着像口令错了或 key 失效，排查方向完全错。
  凭据口令用**确定性**密封（nonce 由明文派生）：`intranet_credentials` 上有 `UNIQUE (host, username, password)`，
  随机 nonce 会让每次重登记都变成新的一行，台账重复报同一个凭据，绑在旧 `credential_id` 上的 SSH 会话也就指向
  错误的行。解封失败不降级成「没有口令」：凭据行标记 `SealBroken`、列表照常返回（一行读不出不能让整张表空白），
  而拨号与复用直接拒绝并写明「平台签名密钥已更换，请重新登记该凭据」；模型 key 解不开则清空该 profile 的 key，
  让上层报「这个配置没有可用密钥」而不是带着一串密文去请求。存量明文由一次性启动迁移收敛（`secret_seal_v1` 标记，
  只有整轮零失败才写标记，否则下次继续）。
- **大马（文件管理）**：在 v2 通道上以单个操作字节实现目录列表、分块读/写、重命名、删除、
  mkdir、chmod；分块 256 KiB、单次读取上限 512 KiB、列表上限 3000 条。载荷内部自我保护，
  拒绝改写/删除自身与密钥缓存文件、拒绝删除 `/`。后端 `GET .../files`、`GET|POST .../file`、
  `POST .../files/action`（仅 v2、必须有地址、受资产拦截规则约束、拒绝 NUL 路径、请求体上限 2 MiB），
  前端「文件管理（大马）」面板支持浏览、上传、下载、在线编辑、重命名、权限与递归删除。
- **Java 内存马**：经 JSP 父壳注入 Filter / Servlet / Listener / Valve / Agent 五类内存马，
  支持类型探测、存活检查、命令执行与验证式移除；`java_memshells` 数据表与受管资源台账联动。
- **PHP 半持久化**：`auto_prepend_file` 前置载荷（透传原页面、不改变站点行为），部署/撤销/验证
  命令与台账记录，撤离时逆序清理。
- **会话与传输**：WebShell 心跳与失效告警、分块上传下载、压缩传输。
- **SSH 承载的内网会话**：内网里大量主机只有 22 端口、没有 web 服务，webshell 永远落不下去，凭据复用换来的
  立足点就停在一条凭据记录上——不能执行、收集不到信息，也进不了维持与撤离台账。会话现在支持
  `transport=ssh`（`intranet_open_session` 与内网页「承载方式」）：口令取自凭据台账的 `credential_id`，
  每次执行都重新读取该行，凭据删掉会话立即拒绝再跑；命令仍走与 webshell 同一套 `__JW_CWD__`/`__JW_EC__`
  标记协议，cwd 续用、OS 探测缓存、执行事件与探测记录全部一致。登录身份（`host` + `ssh_port`）与实际接入
  地址（`dial_host`/`dial_port`）分开登记，经隧道映射的 SSH 因此不会把平台自己写成目标资产。登录通了却
  跑不出标记协议的会话直接置为 closed 并写明「目标上的 shell 不是预期的那种」，不留 active 让后面每条命令
  都撞同一句错；SSH 会话不参与 webshell 故障转移（400 拒收）。
- **把目标上已有的文件登记成受管壳**：`webshell_register` 覆盖 `inject_webshell` 之外的投放途径——worker
  自己写的文件、其他漏洞链的落地物、目标上本来就存在的壳。过去这些文件不进任何台账，撤离枚举不到。工具会
  封存密钥、绑定任务、写资源台账，默认加密 v2 并立即做一次存活验证；若目标上的文件不是精卫生成的载荷
  （v2 验证必然失败），可带 `session_id` + `deploy_path` 先经该会话把正确载荷写到对应路径再登记，载荷与
  密钥不经过对话上下文。
- **内网凭据台账可视化**：内网页新增「凭据台账」页签——弱口令命中、横向复用与手工登记的账号都列在同一张表里，
  可按 待验证/已验证/已失效 过滤，逐条看来源、依据与最近使用时间，并可一键「复用验证」（只拿这一组账号口令打
  登记过的登录页，不走字典）。过去这张表只有 `intranet_credentials` 工具看得到，人工想核对「这台只开 22 的主机
  到底登记过哪些账号」只能进数据库查。新增「登记凭据」对话框把字典之外拿到的口令入账（泄露页面读出的、会话里
  cat 配置文件得到的、情报给的）。新建 SSH 会话的「凭据 ID」手填框换成凭据选择器，选中即自动带上主机、账号与
  SSH 端口——之前要人先查 ID 再手敲，填错只会得到「凭据不存在」。
- **权限维持**：扩展标准维持模块，落地物台账增加指纹、TTL 与幂等判定。
- **撤离清理**：dry-run 预览、残留扫描、可选自动删除 WebShell，失败项保持可重试。
- **WebShell 工作台**：一条壳一个对话框，三个页签——虚拟终端、文件管理（大马）、系统信息。虚拟终端照内网会话
  那套 `__JW_CWD__`/`__JW_EC__` 标记协议做逐条回传：当前目录、退出码、耗时、stderr 原样着色，`cd` 与「粘贴目录
  跳转」都续用到下一轮，↑/↓ 翻历史，超时档位可选 15/30/60/120/300 秒，滚动区在切去别的页签时不清空
  （只有终端页签常驻挂载）。系统信息一次往返采集 12 个分区（主机、身份、时间、网络、CPU、内存、磁盘、当前
  目录、提权线索、可用工具、Web 服务与进程、端口），PHP v2 壳额外附带解释器自述。列表页与对话框的入口按钮
  都带 title 说明它们走的是同一条命令通道。
- **内网会话终端与 webshell 终端合成一个组件**：内网会话（SSH 承载、或绑定 webshell 的那两种）原来自己写了一套
  终端——只有命令、输出、时间，没有目录、退出码、耗时，超时和「目标没回话」在界面上长得一样。现在它和工作台用
  同一个 `ShellTerminal`：服务端把 `intranetExecOutcome` 改成 `shellExecResult` 的别名（`output/cwd/exit_code` 之外
  多出 `os_kind/duration_ms/timed_out/marker_ok`，对老的读取方是纯增量），`intranetRun` 改为把会话传输包成
  `shellSender` 后交给 `shellExec`，两种承载方式因此共用同一套 `__JW_CWD__`/`__JW_EC__` 语义与同一个超时判定。
  目录仍然由服务端在会话行上记账，所以同一个目标的 webshell 终端与内网终端不会各拿一份状态互相打架；一条不返回
  的命令也不再推进 `last_seen`，否则失效会话扫描会把挂住的目标当成健康的。对话框另开「执行记录」页签装台账
  事件（含 worker 在别处跑的命令）——事件里没有退出码与结束标记，所以不并进终端滚动缓冲，切过去时重新读一次。
  `intranet_exec` 工具出口也补上 `timed_out`/`marker_ok`，worker 不再把「这条命令不返回」误读成「这个 shell 坏了」。
- **请求重发页的时钟块**：报文上方一个带边框的整块，显示当前公历时间到秒（`2026年11月03日 14:49:26`），每秒走字。
  默认居中，按住可以左右拖到不挡字的地方，拖不出正文区边缘；位置只记一个「相对中心的偏移像素」，写进浏览器
  localStorage，刷新与下次进来都保持。没有按钮、没有箭头、没有档位——挪这件事交给拖拽本身。时钟走的是浏览器
  本地时间，且只在客户端渲染：静态导出的首屏没有服务端时刻，也就不会比对不上。

### 变更

- **隧道台账新增 `listen_side`**：监听端口开在哪一侧要写清楚——socat、`ssh -D`/`-L`、带 `R:` 的 chisel 开在
  目标（`target`），`chisel client` 不带 `R:` 时监听开在控制端（`pivot`）。`verify` 与拆除复核都按这一侧做：
  过去在控制端复核一条目标侧的 socat（或反过来）会把好隧道判成失败，也会让隧道明明拆掉了、台账却仍在
  `deployed`。`plan` 自动选型时改写该字段，手写 `deploy_command` 时由操作员用 `listen_side` 纠正；部署成功后
  返回的 `access` 也按侧给出真正能连的入口。未配置 `JINGWEI_PIVOT_SERVER` 时，plan 直接说明需要手动提供
  `deploy_command`，不再生成一条拨不通的控制端命令。
- WebShell 密钥在数据库中密封存储（`server/shell_secret.go`），接口不再回显明文密钥。
- 删除测试代码中硬编码的数据库口令，测试统一使用隔离库与环境变量。

### 修复

- **探测失败会把目标永久钉在 POSIX**：系统族探测不到（chroot、受限 shell、目标当时没答）时 `shellOSKindOf` 回退
  POSIX，这本身是对的——总得选一个 wrapper；错的是 `execWebshellCommand` 把这个回退值当事实写进 `webshells.os_kind`。
  一旦写入，后续每一轮都读缓存、不再重探，一台只是当时没答的 Windows 壳就永久按 POSIX 语法执行，界面上也没有任何
  地方可以纠正。现在 `shellExec` 只在探测真的答了时才报告系统族（未证实时 `os_kind` 留空，`UpdateWebshellTerminal`
  的空值语义就是「不动这一列」），终端的系统族徽章换成可选择的下拉：自动探测 / POSIX sh / Windows cmd。人工指定是
  决定而不是猜测，会照常写进台账；内网会话同样接受该字段并写进会话 metadata（唯一的系统族来源，避免上传、下载、
  维持、撤离各步各用一套判断）。
- **同一内网会话上的命令会互相踩目录**：会话的当前目录记在会话行上，两个标签页（或一个标签页与后台心跳）
  同时执行时读到同一个旧值、并发跑完、后写的赢——终端下一轮从谁都没要过的目录继续，操作员在错误的位置读输出。
  现在一个会话一轮：`intranetRun` 拿会话级互斥锁，`intranetHeartbeatCheck` 用 `TryLock`，拿不到就报
  「上一条命令仍在执行，本次心跳未探测，也未记为失败」——一次五分钟的大文件传输不该把健康会话熬成「丢失」。
- **「未确认」看起来像卡住的 bug**：一条超时的命令会把壳标成 `unknown`，而平台刻意不定时重连目标（按计划打客户
  主机是操作员的决定，不是后台默认），于是徽章可以长期停在未确认却不说明原因。现在四种状态都带悬浮说明，未确认
  那条写明「上一次等待超时或检测没通过……点『检测』确认」。
- **测试包之间互相删数据**：`go test ./...` 并行时 `db`/`server`/`agent` 共用同一张表空间，一个包的清理会抹掉
  另一个包正在断言的行（实测 `TestActivityPageSessions` 偶发失败，串行却永远通过）。这几个包的测试改用
  `db.OpenTestSchema` 各占一个 schema——连接串钉 `search_path`，`schema.sql` 里不带限定的建表因此落进各自的
  schema，每个包得到一份独立且完整播种的库。seal 测试的 schema 在套件结束时删除，不再留残渣。
- **测试隔离只在一种 DSN 写法下成立**：`OpenTestSchema` 把 `options=-csearch_path=…` 直接拼在连接串末尾。
  keyword/value 写法（配置文件生成的那种）这样是对的，但 URI 写法（`JINGWEI_PG_DSN=postgres://…?sslmode=disable`，
  文档里给的就是这一种）的参数属于 query string，拼上去的裸空格被读成第二个 `sslmode` 值，于是走隔离 schema 的
  测试整批死在「failed to configure TLS (sslmode is invalid)」。更要命的是各包 TestMain 把「打不开隔离句柄」当成
  「没配数据库」照常跑下去，只是不再持有套件锁——`NewManager` 那批仍写共享表的测试于是和 db 包并发，实测报出
  7 起 `deadlock detected (SQLSTATE 40P01)`。现在 `withSearchPath` 按 DSN 形态分别处理（URI 写进 query 参数并
  合并调用方已有的 `options`，keyword 写法保持追加，已带 `options` 的 keyword 写法直接拒绝而不是写出两个同名参数），
  TestMain 打不开隔离 schema 或拿不到锁时退出并说明原因，不再无声地降级到共享表；`db/test_schema_test.go` 钉住
  两种形态。上一轮「并行全量通过」的结论是在 keyword 写法下得到的，换 URI 写法就暴露了这条，记录在此。
- **重复保存同一份原始报文，去重看的是秒表**：快照 id 是内容指纹，而指纹把 `captured_at` 也算在内，
  `SaveRawExchanges` 又用 `time.Now().Unix()` 去填它——同一个 finding 把同样两条报文存两遍，只要两次调用跨了秒边界
  就落成 4 条快照而不是 2 条。`evidence` 里那条「want 2 deduplicated bindings」在负载下偶发失败就是这么来的（串行、
  第一轮并行都过，第二轮并行才炸，所以它看起来像 flake 而不是 bug）。现在 `RawExchange` 带 `CapturedAt`，为 0 才取
  「现在」：调用方知道报文是何时抓的就照实写，重试因此真的幂等；测试固定同一个瞬间。没有改指纹口径——快照 id 已经
  写进库也写进导出包，动它要同时处理历史 id 与 `InstallSnapshots` 的完整性复核，代价和这条 flake 不成比例。
- **夹具清理读数组的方式一直失败，只是被日志吞了**：`purgeEvidenceFixture` 用 `array_agg(…)::text[]` 读快照 id 再
  `Scan` 进 `*[]string`，database/sql 不接受驱动的 string 落到 `*[]string`（实测报 `unsupported Scan`），而这个
  helper 把错误记成 `t.Logf` 而非致命，于是清理静默半失效，全靠同一句 DELETE 里的 `created_at` 兜底才没留下可见残渣。
  改成按行读 id，不再依赖数组编解码。
- **仓库里的 Dockerfile 在开发机上构建不起来**：`# syntax=docker/dockerfile:1` 让 buildkit 去 Docker Hub 拉外部
  前端，而 dockerd 的 systemd drop-in 把 `HTTP(S)_PROXY` 指到一个没监听的端口，解析直接失败——本轮之前每次部署
  都靠一份删掉该行的 `/tmp/Dockerfile.1.4.0` 副本，等于部署不可复现。文件里只用到 `RUN --mount=type=cache`，
  Docker 28.5 的内置前端就支持，所以删掉该行并在原位写明原因与恢复条件；本轮部署已直接用仓库根目录的 Dockerfile。
- **端到端脚本只活在本机**：Playwright 验证脚本与签会话令牌的脚本散在仓库外，别人拿到仓库复现不了。移进
  `tools/e2e/`（含 README，实例地址、令牌文件、截图目录、会话名都可用环境变量覆盖），本轮两条 e2e 就是从仓库里
  跑通的。
- **文件管理与系统信息把「等不到」说成「失败了」**：上一轮只修了命令通道，`scanner` 里还有六处在压平传输错误
  （`shell_files.go`、`shell_info.go`、`shell_crypto.go` 两处、`memshell.go` 两处），`errors.New(resp.Error)` 把
  `*url.Error` 变成裸字符串，`errors.Is(err, context.DeadlineExceeded)` 自然永远不成立。现在统一走
  `resp.transportErr()` 保留原因，服务端新增 `shellChannelError`：期限到点回「等待超时：目标没有在期限内回答，
  本次操作已停止（载荷上可能仍在执行）」，其它错误保持原话——一次慢目录列表不再和「shell 挂了」长得一样。
- **内网对话框的上传/下载结果退化成文本**：命令页签升级后，这两个页签仍把 `note` 拼在输出里，看不到退出码、耗时与
  「超时」。改为共用终端那套徽章（`shellExitBadge`/`fmtDuration` 导出后复用），一条规则两处渲染，不各写一份。
- **旧协议壳的「文件管理」是灰的，但没说为什么**：禁用态只表达「不可用」，读者只会当成功能坏了。现在页签下方写明
  大马走加密 v2 的文件操作字节，并说明要用最新载荷重新投放。
- **签名密钥换过之后没有任何提示**：密封值对新密钥不可解，表现是每个 webshell 看着存活（存活检查过得去）而每条命令
  都解不开，读起来像目标出了问题。现在启动时自检一次，按类别打印解不开的条数与各自的补救动作（重投载荷 / 重新注入 /
  重新登记凭据 / 重填模型密钥），DEPLOY.md §7.4 写清两条恢复路径：从换密钥前的备份里把 `platform_secret` 那一行写回，
  或按台账逐条重做。
- **内网口令与模型 API 密钥明文躺在库里**：`intranet_credentials.password` 与 `llm_profiles.api_key` 都是明文列，
  而它们恰恰是一次行动里最值钱的两样——内网账号口令、能花钱的 key。任何一次误查表、任何一份被贴进聊天或工单
  的转储、任何一个把整行序列化出去的出口（日志导出、报告模板、将来新写的 handler）都会直接带走它们；
  webshell 密钥早就密封了，这两处却没有，密封因此是不对称的：拿到库的人照样接管整个内网。现在两者按用途派生的
  密钥密封入库（见「内网凭据口令与模型 API 密钥同样密封入库」）。要说清边界：签名根密钥也在同一个库里，所以这层
  挡的是误查表、按 key 读设置的代码路径与共享转储时的顺手一览，不是「拿到数据库也读不出凭据」；它消除的是「库里
  有明文」这件事本身。
- **容器重建把所有已投放的 webshell 变成砖**：签名根密钥写在 `/app/jwt.key`——镜像层之外的容器可写层，`config.BaseDir()`
  硬编码、不可配置。`docker compose up -d --force-recreate` 一次就重新铸一把，于是所有登录会话失效，更要命的是
  `webshells.secret` / `java_memshells.secret` / 半持久化密钥都是用这把钥匙的派生密钥 AES 密封的，解封直接失败：
  每条命令都回「webshell 密钥解封失败（JWT 密钥可能已更换，请重新投放载荷）」。目标上的文件还在、站点还在跑，但
  平台再也打不开它们，只能删记录重投。密钥现在入库（见「平台签名密钥入库」），备份口径与数据库合一；首次启动会把
  旧文件原样搬进库并删掉文件，因此升级那一次重建不轮换、壳不需要重投。写库失败时启动直接失败退出，不再抱着一个
  「这次能用、下次重建就蒸发」的临时密钥正常运行。
- **webshell 终端首条命令把目录钉在 `/`**：虚拟终端复用内网会话的脚本包装器，空 cwd 一律 `cd /`，于是登录后
  第一条 `id`/`pwd` 报的是文件系统根目录，而 web 服务器实际把进程放在脚本所在目录——操作员据此判断「壳能读
  网站目录吗」会得到错的答案，还得先手动 `cd`。现在 webshell 通道首轮用 `cd .`（保持目标自己的 `$PWD`，仍
  在取不到时退回 `/`），内网 SSH 会话的语义不变，因为那边续用的是会话自己记下的目录。
- **等不到回包被报成传输错误**：命令超过超时档位时，HTTP 发送端在自己的客户端超时上先断，交回的是
  `Post …: context deadline exceeded`，而超时判定只看外层 context（超时 + 宽限），因此 `timed_out=false`、
  备注是一句底层错误。操作员读到的是「这个壳坏了」，真实情况是「那条命令不返回」。现在客户端超时也判为
  停止等待，写 `timed_out=true` 并说明目标上的命令可能仍在继续。
- **错误原因在传输层被抹平，上面的判定在真实链路上根本不触发**：`DeepResponse.Error` 是字符串，
  `RunShellCommand` 又用 `fmt.Errorf("%s", …)`/`errors.New(…)` 重建错误，`errors.Is`/`errors.As` 拿不到
  `context.DeadlineExceeded` 与 `net.Error`。单元测试直接喂一个 `*url.Error` 所以照绿，真机复跑仍然误判。
  `DeepResponse` 现在额外保留 `Err`，命令通道返回带原因的错误（文案不变，字符串匹配的调用方不受影响），
  并在 `scanner` 侧加回归测试钉住「客户端超时的原因必须能被 `errors.Is` 读到」。
- **系统信息整面板被一次根目录遍历拖死**：12 个分区共用一次请求与 60 秒预算，提权线索里的
  `find / -perm -4000` 越过挂载点走进 `/mnt/c`，在实机上跑了几分钟——超时的不是那一个分区，而是整块信息
  面板。改为 `-xdev` 并截断到 20 条，实测同机 12 分区 150–190ms 返回。
- **协议徽章把密钥轮次写成协议版本**：列表页与工作台标题显示 `加密 v${key_version}`，v2 壳的密钥没轮换过时
  就写着「加密 v1」——而「是不是 v2」恰好决定文件管理页签可不可用，读起来像平台在跟一个旧协议壳说话。
  两处统一显示 `加密 v2`，密钥轮次留在悬浮说明里。
- **非 PHP 壳的系统信息少一块却没有解释**：解释器自述（php.ini、open_basedir、disable_functions）只有 PHP
  v2 壳能回答，JSP/ASPX 上过去只是安静地少一块，看起来像采集失败。现在这类壳明确标注该分区不可用及原因。
- **同一落地地址重复投放留下两条壳记录**：往一个已经登记过的路径再注入一次，上传已经把目标上的文件换掉了，
  旧记录描述的那个载荷不再存在——旧密钥打不开新文件，绑在旧 id 上的会话每条命令都撞 v2 MAC 校验失败，撤离时
  自删除的是「记录里的旧载荷」而不是真实文件，目标上反而留下没人认领的后门。现在按调用意图分流：`inject_webshell`
  与带 `session_id`+`deploy_path` 的 `webshell_register` 会覆盖投放，原地复用同一条记录（保留 id 让会话与台账仍然
  对得上，换掉载荷/密钥/指纹，状态退回 `unknown`，旧的 `managed_resources` 行以「被覆盖」为原因置为 released，
  同时只留一条 active，覆盖事实在 `summary`、壳备注与深度任务日志里各写一遍）；手工创建壳与不带投放参数的
  `webshell_register` 遇到已登记地址则拒绝并指明是哪一条记录 owns 该地址（`already_registered` 提示直接复用该 id），
  不再静默插第二行。
- **凭据台账接口把内网账号口令明文发给浏览器**：`GET|POST /api/intranet/credentials` 直接序列化 `password`
  字段，于是每条列表请求、每次登记的回显、前端状态缓存与反向代理访问日志里都留下一份内网口令副本——这些恰恰是
  横向移动换来的最有价值的东西。现在 `db.IntranetCredential.Password` 是 `json:"-"`，只回 `has_password`
  （与 webshell 密钥同一套「只写不读」规则）。界面本来也不需要明文：复用验证与 SSH 会话都由平台按
  `credential_id` 自己取。agent 侧仍拿得到口令，因为拼原始报文（Basic 头、POST 体、SSH 交互）没有
  `credential_id` 可携带，这一步在工具出口显式重新附加，只覆盖工具路径，REST 处理函数一律保持掩码。
- **平台自己的隧道监听被回流成「内网资产」**：代理扫描的返回里，`127.0.0.1:41320` 这类地址是平台侧隧道的入口，
  按原样落库就成了「精卫内网里有一台 127.0.0.1 的主机」——下一轮 scope 申请、开会话、批量执行都会去打自己的
  隧道，还把这些假资产带进报告。现在回环地址先查隧道台账（`LiveIntranetTunnelByListen`：`localhost` 与
  `127.0.0.1` 是同一只 socket，`0.0.0.0`/`::`/`*` 通配也算命中，只认 `deployed`/`verified`），命中就把这条发现
  改写成隧道对端的真实内网身份——ip、端口、服务 URL 与 `Host` 头一起换（`rewriteScanURL` 拒绝无 scheme 的裸串，
  不再拼出 `//10.253.77.14:80/not a url` 这种地址），查不到归属的本地监听直接丢弃；`intranet_request_scope`
  审批时拒绝把平台自身登记为资产并在响应里写明原因，但 `task_scope` 照常授权，不逼着人为了「127.0.0.1」再批一次。
  没有 `task.Proxy` 的普通扫描不参与改写，实验室里打到 loopback 的真实资产仍然按原样入库。
- **实例重启后隧道拆不掉、台账却说已释放**：受管资源的拆除动作是内存里的回调表，进程重启或任务移交后回调就没了，
  过期回收与释放只把台账改成 released，目标上的 socat / SOCKS 监听进程照旧听着。现在释放与过期回收都会按台账行
  （`metadata.tunnel_id`）重建拆除流程；撤离时不等回调，无条件再走一遍会话侧的 `teardown_command`，并在杀掉进程后用
  目标侧 `ss -lnt` 追加「【拆除复核】」证据。没有绑定会话、或没有拆除命令时，证据直接写明「拆除命令未执行，仅台账置为
  stopped」，不再留下看不见的假干净。
- **指向已删除任务的 `task_id` 把数据库报错直接吐给调用方**：创建内网会话、创建隧道、部署维持物时，Postgres 的
  `intranet_sessions_task_id_fkey` 报错原样出现在 API 响应里。改为 `intranetTaskGuard` 前置校验，返回 400 与
  「任务 #N 不存在或已删除，无法归入该任务的撤离台账」。
- **维持物部署失败时台账只剩一句无从复核的话**：维持模块的部署脚本都以 `set -e` 开头，旧的内层脚本一旦中途失败就
  打印不出结尾标记，退出码和已产生的输出一起丢失；且 web 壳通常只回传 stdout，目标侧的 `Permission denied` 全落在
  web 服务器错误日志里，取证时看不见。命令改放进子 shell、由 `EXIT` trap 打印 `__JW_CWD__`/`__JW_EC__` 并整体 `2>&1`，
  台账失败原因改为引用目标原话；对 `/usr/sbin/nologin` 一类无法落地维持物的账户新增 `JW_WARN_NOLOGIN_SHELL` 告警，
  不再记成成功。
- **JSP/ASPX 壳自删除后复核仍报可访问**：判定本身是对的（文件已删、servlet 仍在容器里驻留），撤离报告补充说明
  需重载应用或重启容器才能断开，避免误读成删除失败。
- **镜像里 webcrack 依赖装坏了也照样构建成功**：`Dockerfile` 的 webcrack 层以 `... || echo` 收尾，shell 里 `&&` 与 `||`
  同优先级左结合，前面任何一步失败都被这句 echo 吃掉、层退出码为 0，Docker 于是缓存住一个缺件的层（SOCKS5 隧道下的
  登录尝试要到运行时才报错）。核心依赖安装与其导入自检改用 `{ ...; }` 成组，失败即构建失败；`ddddocr` 仍保持可选。
- **经 SOCKS5 隧道跑 webcrack 缺依赖**：`requirements-core.txt` 补上 `requests[socks]`，核心自检同时导入 `socks`。
- **登录滑块偶尔发出自己解不开的题**：`TestGeneratedSliderPuzzleIsSolvable` 在全量测试里随机失败
  （实测 8 连抽约每 64 题错 1 题，`solver offset=234 want 184，confidence=0.00`）。背景是随机圆斑与折线，
  轮廓与内容两条打分通道都可能被别处的强边缘夺走。人眼看着含糊的题，合法用户也会拖错位置，而验证一次即作废、
  只能重新登录，等于把一次随机绘图变成锁门。现在 `newSliderPuzzle` 发题前先用平台自己的 `captcha.SolveSlider`
  核对缺口位置，落在登录容差外就重绘（上限 `sliderPuzzleAttempts=4`，四次都不合格就照旧发出，绝不因为
  画不出题而拒绝登录页）。新增 `TestRawSliderRenderAmbiguityRate` 盯原始单次绘制的歧义率（实测 2-5/200），
  绘图质量退化时先在这里报警，而不是让签发验证码慢下来。
- **nuclei 超时把已拿到的结果连同报错一起丢掉**：超时分支只报「扫描超时」，调用方无从知道引擎已经落了多少 POC
  命中与发现。改为在报错里带上保留条数，并说明其中含应用层探测、弱口令与服务暴露，不再把部分完成说成一无所获。
- **LLM 用裸 HTTP 上传的可执行文件不进任何台账，撤离扫不到**：实网一轮深挖经上传点写了 12 个 PHP/JSP 马，
  finding 里写「清理验证见 record_fact」，但既没登记、也没删除，`intranet_evacuate` 按落地物台账清理时报「未发现残留」，
  最后只能人工进目标逐个 `rm` 再复核 404。worker 收尾规约新增第 6 条：保留的落地文件必须进台账
  （webshell 由平台登记，其余用 `intranet_artifact_register` 带 `revoke_command`/`verify_command`），
  既不登记也不删除时只能在 finding 里如实写「未登记、未清理，需人工确认」，不许写「已清理」。
- **java-chains 的回调端口在容器里没有人在听**：`JAVA_CHAINS_CALLBACK_BIND` 一个变量被当成两件事用——它既是
  docker 在**宿主机**哪块网卡上发布 50389/58080 等回调端口，又被直接拿去当 sidecar 的 `bindHost`。sidecar 容器有
  自己的网络命名空间，docker-proxy 把连接转发到**容器的 eth0 IP**，所以按默认值 `127.0.0.1` 监听时，宿主机端口
  看着是开的（本机 `curl` 都通）、容器内后面却没有进程在 eth0 上听，于是**任何**目标——本机、同宿主机其他容器、
  远端主机——都永远回连不上：目标侧 JNDI lookup 直接失败，侧车日志停在 `anonymous bind failed` /
  `LDAP connection has been closed`，一条 `outcome=lookup` 都不会有，平台只能报「已投递未回连」。现在拆成两个变量：
  新增 `JAVA_CHAINS_LISTEN_BIND`（默认 `0.0.0.0`，只决定容器内的监听面，不改变暴露面）与
  `JAVA_CHAINS_CALLBACK_BIND`（仍默认 `127.0.0.1`，决定宿主机发布），`java_bind_host` 走前者、
  `java_callback_host` 走后者。
- **JNDI 服务已在运行时换绑被静默忽略**：`quick_jndi` 的语义是「没起就起、起了就用」，服务已经启动时它照旧发布
  成功并只在 `service.bound.host` 里报出**原来的**监听地址——要求 `0.0.0.0` 却拿到 `127.0.0.1` 也一样回 200，
  payload 于是投到一个没人监听的地址。现在 `publishJNDI` 比对返回的 `bound.host` 与要求的监听地址
  （`normalizeListenHost` 把 `0.0.0.0`/`::`/`*`/空视为同一只通配 socket，`localhost`/`127.0.0.1`/`::1` 视为 loopback），
  不一致时调 `java_chains_services_restart` 换绑再重新发布，并在任务日志里写明换过绑；重启失败不谎报成功，
  改为按当前监听投递并提示「回连结果需人工核对」。新增 `scanner.JavaChainsClient.JNDIService`/`RestartJNDI` 承载这两个动作。
- **不带 type 的资产查询被悄悄收窄成 root_domain，内网拓扑页因此画不出图**：`GET /api/assets` 在既没有 `company_id`
  也没有 `task_id`、且 `type` 为空时把 `type` 兜底成 `root_domain`，存储层再按 `type = $1` 过滤。拓扑页正是用
  `api.assets("", 500)` 一次取全量、再在前端按「公司 → 域名 → IP → 服务 → 端点」分层，于是只有登记过根域名的任务
  才可能出图；纯 IP / 服务资产（内网段扫描、单 IP 靶站）永远显示「暂无资产」，而接口回的是 200 加空数组，
  调用方看不出是被过滤还是真没有。现在空 `type` 在 `CountByType`/`QueryByType` 里就是不加类型条件，兜底删除。
  新增 `TestQueryByTypeEmptyReturnsAllTypes` 钉住「同一次查询里 root_domain 与 ip 两种类型都要能拿到」。

### 验证

- **内网拓扑修复的实机核对**：换上带修复的二进制后，同一实例的 `GET /api/assets?type=&limit=500` 从 `total 0`
  变成 `total 13`（12 条 service + 1 条 ip），`type=service` 与 `type=root_domain` 的过滤结果不变；拓扑页从
  「0 个节点 · 0 条关系」变成「3 个节点 · 12 条关系」。
- **README 截图换成 Jingwei 自己的界面**：20 张图分两组采集——仪表盘/任务/对话/LLM 录制/流量/拦截/拓扑取自内置
  演示数据（`NEXT_PUBLIC_MOCK=1`，域名 `acme.com`、地址为 RFC 5737 文档保留段），漏扫/发现/POC 库/资产/请求重发/
  WebShell 工作台/内网渗透/受管资源取自 1.4.0 实机实例（本地隔离靶机，内网地址）。上游 ARTEX 的
  `agents.png`/`logs.png`/`assets_test.png`/`sessions.png`/`graph.png` 一并删除。截图过程中发现两处不能用的画面，
  都是「看文字断言发现不了、只有看图才看得见」：演示数据下发现页直接抛 `Cannot read properties of undefined`，
  以及系统信息面板把宿主机名带到画面里——后者改用更矮的视口把该区块留在画面外，终端类截图也换成不含
  `uname -n` 的命令。
- **请求重发时钟块（本轮）**：`tools/e2e/verify-repeater-clock.js` 打真实实例 16 项全绿——到秒格式、每秒走字、
  位于「请求报文」上方、报文区整体下移、边框确实渲染出来、默认居中、页面上不再有左/中/右按钮与左右箭头、
  鼠标右拖 180px 落点准确、拖完偏移写进 localStorage、往两头的过头拖拽都夹在正文区内、刷新后位置不变且还能继续拖、
  无页面脚本报错。中途走过一段弯路值得留着：第一版是「三档 + 箭头」，时钟做成绝对定位层而控制钮留在文档流里且没写
  `ml-auto`，于是控制钮落在行首，与左对齐的时刻糊成一片——边缘位置全对、16 项全绿，是看截图才看出来的。改成整块
  可拖之后，重叠这一类问题从根上没有了，断言也随之从「不重叠」换成「拖得动、夹得住、记得住」。
  部署后 #9/#10 两套壳仍直接 `exec`（本轮只改前端与静态导出，密封未动）。
- **B/D 类缺陷（本轮）**：`TestIntranetHeartbeatSkipsBusySession` 用真 SSH 夹具起一条挂住的命令，断言心跳报
  「未探测」且失败计数不变；`db.OpenTestSchema` 之后连续两轮 `go test ./...`（并行、不加 `-p 1`）20 包全绿，
  此前偶发失败的 `TestActivityPageSessions` 不再复现；部署改用仓库根目录的 `Dockerfile`（不再需要 `/tmp` 副本），
  两条 e2e 从 `tools/e2e/` 运行：内网 SSH 终端 17 项、WebShell 工作台 24 项全绿。密钥扫描：本轮会话用到的
  签名根密钥、靶机口令、测试库口令在工作树里 0 命中，`postgres://` 形态的匹配全是占位符，唯一的公网 IP 匹配来自
  `web/node_modules/zod` 的测试夹具（已 gitignore）。
- **A1-A5 缺陷修复（本轮）**：单测侧新增 `TestShellExecReportsOnlyProbedFamily`（探测没答就不报告系统族，报告了才
  能被写入台账）、`TestShellOSKindOfFallsBackWithoutCachingFailure` 改为断言 `confirmed=false`（旧版只断言回退值是
  POSIX，正是它让调用方敢把猜测当事实写进去）、`TestShellChannelErrorWordsDeadlines`（期限到点说「等待超时」，其它
  错误保持原话）、`TestAuditSealedSecretsCountsUnreadable`（同一把密钥解得开的记录报 0，换一把后按类别报数，且那一行
  标 `SealBroken` 而不是把密文当口令返回）。浏览器侧：WebShell 工作台 24 项全绿（新增旧协议壳的禁用说明与「明文」徽章
  两项，夹具建完即删），内网 SSH 终端 17 项全绿（新增系统族下拉切到 Windows cmd 后快捷命令随之更换、切回自动仍可执行、
  上传结果显示 `exit 0` 徽章三项）。部署后实测：启动日志无 `[seal]` 告警（现存密钥都能解开），#9/#10 两套壳的
  `os_kind` 与探测结果一致，验证用的任务、凭据与会话已清理。
- **内网 SSH 会话终端（本轮，真机）**：在 Ubuntu-1 起 sshd（`172.23.0.1:2201`，`lab` 账号），登记凭据 →
  开 `transport=ssh` 会话 → 浏览器端到端 13 项全绿：对话框四页签（命令/上传/下载/执行记录）、`id; pwd` 回
  `uid=1000(lab)` 且徽章 `exit 0`、`ls` 不存在的目录红色 stderr + `exit 2`、跳到 `/tmp` 后下一轮 `pwd` 仍在
  `/tmp`、`sleep 30` 配 15 秒档位显示 `exit 超时` 而不是报错、切到「执行记录」时重新读台账并列出刚跑的命令、
  全程无页面 JS 错误。截图写在本地 `shots/`（不入库，可用 `tools/e2e/` 的脚本重生成）。后端另有
  `TestIntranetSSHExecReportsAbandonedWait` 钉住「超时不推进 `last_seen`」。
- **凭据与模型密钥密封（本轮）**：`db/seal_test.go` 四条用例在独立 schema 里跑真库——写入后列值是 `v1:` 且不含明文、
  `UNIQUE (host, username, password)` 在密封下仍然把重登记收敛成一行（这是最容易改坏的一条）、从库里读出的行再写回
  不会被二次封装、明文行由启动迁移收敛且重跑无害、换一把根密钥时列表仍返回该行并标记 `SealBroken` 而不是把密文当
  口令交出去、`api_key_hint` 仍是明文末四位、`ProfileAPIKeys`（出口指纹）拿到的是明文而不是密文、空 key 更新不丢
  原 key。生产侧实测：迁移日志「凭据 0 条、模型密钥 3 个已改为密封」，`GET /api/llm` 的 `key_set=true`
  （该值来自解回明文后的激活配置，解封失败会被清空），新登记的 SSH 凭据列值 `v1:` 且不含口令子串，而会话照常
  拨号成功。之后第三次 `--force-recreate`：#9/#10 两套壳与 SSH 会话 #1 全部无需重投直接可用。
- **签名密钥入库（本轮）**：先把运行中容器的 `/app/jwt.key` 备份出来，用同一把值建表并 seed `platform_secret`，
  再连续 `--force-recreate` **两次**——这正是过去会砖掉一切的操作用法。结果：旧会话令牌仍然通过认证（签名密钥没换），
  Ubuntu-1 上 #9 PHP / #10 JSP 两套壳**不重投**仍能 `exec`（密封密钥没换），新容器内已不存在 `/app/jwt.key`，
  日志没有「新 JWT key 已写入」。工作台端到端 21 项在此构建上复跑仍全绿。新增 `server/auth_jwt_key_test.go`
  覆盖库优先、旧文件迁移、工作区内旧位置迁移、重启复用、插入竞争失败方保留文件、写库失败拒绝启动六种情形；
  `db/platform_secret_test.go` 覆盖读写、`ON CONFLICT` 收敛、<32 字节拒绝，并断言这把钥匙没有同时躺在 `settings` 里。
  测试脚本 `mint-session.sh` 也随之改从库里取签名密钥——它读 `/app/jwt.key` 时立刻 `ENOENT`，正好是这次改动的旁证。
- **WebShell 工作台（本轮，Ubuntu-1 真机）**：在边界靶机上按 API 落两套加密 v2 壳——Apache :8080 的 PHP 壳与
  Tomcat9 :8081 的 JSP 壳，容器内经桥网关 `172.23.0.1` 访问目标。Playwright 无头端到端 21 项断言全绿：列表两行
  都「检测→存活」且协议徽章写 `加密 v2`；PHP 终端 `id` 回 `uid=33(www-data)`、退出码 0、当前目录是脚本目录
  `/var/www/html/assets`（不是 `/`）；`ls` 不存在的目录以红色 stderr + `exit 2` 呈现；目录跳到 `/etc` 后下一轮
  仍在那儿；`sleep 30` 配 15 秒档位显示 `exit 超时` 与「目标上的命令可能仍在继续」而不是报错；大马列出网站目录
  文件；系统信息 12 分区一次往返 188ms 并带 PHP 8.1 运行时自述（open_basedir / disable_functions 未限制）；
  JSP 走同一组件回 `uid=999(tomcat)`，其系统信息对缺少 PHP 自述给出解释；全程无页面 JS 错误。截图存于
  截图同样写在本地 `shots/`（不入库）。`go test -p 1 -count=1 ./...` 全绿（并行跑 `./...` 时 `db` 包会与
  `agent`/`intercept` 抢同一张隔离库偶发失败，串行稳定）。
- 全量 Go 测试 `go test -p 1 -count=1 ./...` 20 包 ok、0 FAIL（本轮实测于 2026-11-02，
  接隔离库 `jingwei_gotest`，`gofmt -l` 与 `go vet` 无输出）；
  java-chains 的两条真机用例另配 `JAVA_CHAINS_MCP_TOKEN`/`JAVA_CHAINS_LIVE_TARGET` 单独跑，同样全绿。
  新增 `scanner/shell_files_*`、
  `server/webshell_files_test.go`、`server/memshell_manual_test.go`、`scanner/shell_crypto_php_*` 等。
- **SSH 承载会话与自资产回流（本轮）**：`server/intranet_ssh_test.go` 起一个进程内 `x/crypto/ssh` 服务加一个认得
  包装脚本的假 POSIX shell，覆盖 SSH 会话的执行、cwd 续用、OS 探测缓存、凭据出证、登录通但无标记即关闭、拒绝把
  平台自身作为 SSH 目标、经隧道映射的接入地址与身份分离、SSH 会话拒绝 webshell 故障转移；
  `server/intranet_reflux_test.go` 覆盖 `LiveIntranetTunnelByListen`（`localhost` 拼写、`0.0.0.0` 通配、
  未部署/端口 0/远端监听都不算命中）、`rewriteScanURL`、审批拒绝把平台自身登记成资产（`task_scope` 仍授权）、
  隧道监听端口改写成真实内网身份，以及没有 `Proxy` 的普通扫描不参与改写。前端 `tsc --noEmit` 通过。
- **落地地址覆盖与凭据掩罩（本轮）**：`server/webshell_reinject_test.go` 覆盖同一 `url` 第二次投放不再插行、
  复用同一条记录（id 不变、载荷/密钥/指纹换掉、状态退回 `unknown`、备注写明覆盖了哪条旧载荷）、台账只留一条
  active 且旧行以「被覆盖」为原因 released、手工创建重复地址得到 400 且不落库、`webshell_register` 回
  `already_registered` 并指路 `deploy_path`；`server/intranet_credentials_mask_test.go` 覆盖列表与登记响应里
  没有 `password` 键也没有明文、`has_password` 为真，以及 `intranet_credentials` 工具仍然把口令交给 agent。
  新增页签「凭据台账」与 SSH 凭据选择器经 `tsc --noEmit` 通过，并已在生产实例（1.4.0）上补做浏览器视觉验证：
  页签渲染出两条凭据、整页 DOM 与库中真实口令逐条比对不含明文，「登记凭据」对话框字段齐全，承载方式选 SSH 后
  「凭据」是下拉选择器（选项为 `#id 账号@主机:端口 · 协议 · 来源`，同样不含口令）且带 SSH 端口 / 登录账号 /
  接入地址三段——见 `docs/进度与下一步.md`「浏览器视觉验证」。
- 真实 Tomcat 9 JSP 大马端到端通过；`php -S` 运行时文件管理与半持久化通过。
- 前端 `tsc --noEmit` 与静态导出构建通过；`build.sh --target linux/amd64`（embedui）通过。
- **三台 WSL Ubuntu 真机全能力回归**：边界机 Ubuntu-1 提供 PHP 漏洞站（:8080，file/search/upload/tools/backup）、
  Tomcat9 `/lab/`（:8081，deser.jsp + upload.jsp）、MySQL（:3306/:3307）与 sshd（:2201），另有仅经隧道可达的
  10.99.0.0/24 内网段；平台侧跑独立实例 `jingwei-lab`（`--network host -addr 127.0.0.1:9797 -proxy 127.0.0.1:9798`、
  独立库 `jingwei_lab`），生产实例与生产库全程不参与。
- **无 LLM 扫描 + 固定渗透基线**：3 个扫描任务 `done`——资产 6-10、开放端口 5-9、应用层系统 8、基线页面 12 与
  参数点 18、弱口令命中 1、服务暴露发现 1-2；full 模式（347 模板、nuclei 333s）得 8 条发现，并自动派发 6 个深度
  任务（4 条确认、19 条利用记录）。经 SOCKS5 隧道的内网扫描同样 `done`，内网资产按台账回流。
- **WebShell v2 / 大马 / PHP 半持久化 / 内存马**：PHP 与 JSP v2 壳在真实 Apache 与 Tomcat9 上握手、执行、
  轮换密钥与自删除全链路通过；大马文件管理（列表/分块读写/重命名/权限/递归删除）与半持久化 prepend 落到台账并可撤销；
  Filter / Servlet / Listener / Valve / Agent 五类内存马注入后按验证式移除复核。
- **权限维持与撤离**：落地物台账累计 14 条（cron / systemd / user_systemd / profile / at / ssh_key /
  php_htaccess），逐条部署验证后按 id 逆序撤销，终态全部 `revoked`，残留复核报「未发现残留」——这里的残留判定
  由目标侧验证命令实态给出，不是台账改状态。
- **有 LLM 深挖**：任务 4（钉住 profile 352、`seed_first_intent`、超时 1800s）终态 `done`，5 个目标全部 met、
  6 条确认发现（4 critical / 2 high），每条都带可复现的原始请求/响应报文；对 `search.php?host=` 给出的是
  「参数不进命令拼接」的反证并定位到真实 sink `tools/ping.php`，没有顺着任务描述硬凑成功；`llm_records` 抓到了
  worker 的调用与用量；`GET /api/report?task=4` 输出 15333 字节 Markdown。
- **超时收尾时序**（同一条任务实测）：`首次运行盖章 → 到点进入收尾 → drain 1m30s → 硬取消在跑 run → 终局一轮判定
  5/5 → 收尾完成,终态=done`；被打断的意图如实写回 `exhausted`，未谎称完成。
- **java-chains 只到降级路径**：本机拿不到 sidecar 镜像（Docker Hub 经代理不可达），MCP 探活报 `no such host`，
  深挖按约定把「该能力不可用」连同原因写进结论，不虚构反序列化利用成功；构造 payload 的正路径仍未验证
  （已于同日补验，见下条「java-chains 正路径端到端」）。
- **java-chains 正路径端到端（2026-11-02 补验）**：这一轮 sidecar 镜像能正常拉到，于是用真
  `javachains/javachains:2.0.0-beta7` + Ubuntu-1 Tomcat9/JDK17 上的 fastjson 型 JNDI sink
  （读 body 的 `dataSourceName` 后 `new InitialContext().lookup(...)`，`/root/lab-ubuntu/u1-java-jndi.sh`）
  跑通自动链路的真实入口 `runJavaChains`：预设 `java.fastjson.jndi` 被选中、
  JNDI 引用发布成功（`service.bound.host=0.0.0.0`、token 形如 `ed3d96ee…`）、
  把模板里的 `ldap://{{interactsh-url}}/jwlab` 改写成 `ldap://127.0.0.1:50389/<token>` 并投递原始报文，
  侧车 `runtime_logs` 出现该 token 的 `outcome=lookup` 与 `outcome=serve`，记录因此是
  `verdict=confirmed`（证据含请求/响应原文与 `outcome=`）而不是「已投递」；回调端口登记成受管资源，
  任务结束后 JNDI 发布数归零、服务停止、台账行 released。上述两条断言固化为
  `server/java_chains_deep_live_test.go`（缺 `JAVA_CHAINS_MCP_TOKEN`/`JAVA_CHAINS_LIVE_TARGET` 时 `t.Skip`，
  不会把真机依赖带进 `go test ./...`），另一条 `TestJavaChainsLiveRepairsStaleListenBind` 先把服务起在
  `127.0.0.1` 再要求 `0.0.0.0`，验证平台察觉 `bound.host` 不一致后重启并重新发布、仍然确认回连。
  JDK17 上 lookup 到达侧车后对象反序列化被 JDK 自己的 `trustSerialData` 默认值拒掉
  （`Object deserialization is not allowed`），这不影响「目标确实回连」的判定。也正是在这次实跑里暴露了
  【修复】的「回调端口在容器里没有人在听」与「已运行时换绑被静默忽略」两项——之前两轮回归都只跑到降级路径，
  没机会看见。
- **本轮修掉的两处假干净**：LLM 裸 HTTP 上传的 12 个可执行文件不在任何台账里（撤离报「未发现残留」，最后人工
  `rm` 后逐个复核 404，见【修复】「LLM 用裸 HTTP 上传的可执行文件不进任何台账」条）；nuclei 超时文案报
  「已保留 0 条结果」而同一行 summary 里写着 `results:2 / findings:2`（见【修复】「nuclei 超时把已拿到的结果
  连同报错一起丢掉」条）。
- **靶机残留核验**：验证结束后 Ubuntu-1 上 `/var/www/html/upload/` 与 `/var/lib/tomcat9/webapps/lab/upload/` 均空、
  无 `jingwei-*` systemd 单元、无 crontab / at 任务、无 `authorized_keys`、无 `.profile` 注入、无 chisel/socat 进程，
  监听端口只剩靶场自身服务。
- **靶机收摊（2026-11-02）**：按「停服务、保留软件包」处置——Ubuntu-1 `systemctl stop apache2 apache-htcacheclean
  tomcat9 mysql ssh`、Ubuntu-2 `systemctl stop lab-release ssh`、Ubuntu-3 `systemctl stop lab-panel mysql ssh`。
  四个 WSL 发行版共用 mirrored 网络，任一发行版内 `ss -lntp` 即可复核全部监听：2201/2202/2203/3306/3307/8080/8081/
  8090/8091 全部消失，只剩生产实例的 9790 / 9791 / 55432 与只监听回环的测试库 55433（跑 go test 时按需起停）。
  apt 包、`/var/www/html`、`webapps/lab`、`/opt/release`、
  `/opt/panel` 与弱口令账号原样保留（unit 仍 `enabled`，下次验证 `systemctl start` 即复用）；部署脚本留在
  `/root/lab-ubuntu`，其中本轮生成的口令已全部换成占位符，重建步骤见其 `README.md`。

### 升级

- **生产实例已切到 1.4.0（2026-11-02）**：`jingwei-jingwei-1` 从 `jingwei:1.3.1` 换成用当前工作树构建的
  `jingwei:1.4.0`，只重建应用容器（`docker compose up -d --no-deps jingwei`），PostgreSQL 未动。升级前留好回滚点：
  `pg_dump` 到 `/root/backups/jingwei-pre-1.4.0-*.dump`、`.env` 备份、旧镜像 tag `jingwei:1.3.1` 保留。
  核对项全部通过：`GET /api/health` 返回 `version=1.4.0`；9790/9791 正常监听、登录页 200；各表行数与升级前一致
  （scan_tasks 10、deep_tasks 17、webshells 3、managed_resources 6、findings 13、exploit_records 15、assets 52、
  intranet_credentials 2、poc_templates 13141、intranet_tunnels 0）；`intranet_tunnels.listen_side` 由启动迁移自动
  补上；容器环境里 `JAVA_CHAINS_LISTEN_BIND=0.0.0.0` 与 `JAVA_CHAINS_CALLBACK_BIND=127.0.0.1` 各司其职（远端目标要
  回连仍须按 `deploy/JAVA_CHAINS.md` 改回调发布地址）；镜像内 `import socks` 可用（1.7.1）；服务出的前端 chunk 与
  本地构建 md5 相同、含「凭据台账」与「登记凭据」，确认新 UI 真在跑而不是只有后端。
- **升级后不必再重新登录、也不必重投 webshell**：1.3.1 把签名密钥移出可浏览工作区落到 `/app`（不在持久卷内），
  此后每次容器重建都重新铸一把——所有人掉登录、所有已投放的壳解封失败要重投。本版把密钥移进数据库并在首次启动
  时把旧文件原样搬进去，因此从 1.3.1/1.4.0 早期镜像升级时**只要旧容器里的 `/app/jwt.key` 还在**就能无损过渡；容器
  已经被重建过、密钥已经换过的实例，则仍需重新投放一次载荷（此后不再轮换）。数据库本身仍是唯一需要备份的东西。
- **构建环境的一处障碍**：docker daemon 的 systemd drop-in 里 `HTTP(S)_PROXY=127.0.0.1:7890` 指向一个没在监听的代理，
  `# syntax=docker/dockerfile:1` 因此解析失败（也解释了此前几轮 sidecar 镜像拉不动）。本次不改系统配置，改用去掉
  `# syntax=` 行的 Dockerfile 副本构建（本 Dockerfile 不用 heredoc / `--link` / secret 挂载，Docker 28.5.2 内置前端够用）。
- 本版代码仍未提交（未获授权 commit/push），1.4.0 镜像由工作树直接构建。

## [1.3.1] - 2026-11-01

本版修复 1.3.0 自测发现的两项平台认证问题：登录入口缺少验证码、速率限制与请求超时；
JWT 长期有效且无法撤销，并可通过 URL 查询参数传递、由前端存入 localStorage。修复后
登录面具备一次性滑块验证码、按 IP 失败锁定与请求体/读取时限，会话改为可撤销的
HttpOnly Cookie，修改密码会立即吊销全部旧会话。

### 安全修复

- **登录防护**：登录与首次初始化必须完成服务端生成的一次性滑块验证码；挑战绑定客户端
  IP、3 分钟过期、单次使用、容差 ±6px，并按 IP 限制签发频率。
- **失败锁定**：同一 IP 在 15 分钟内失败 5 次后锁定 15 分钟，返回 `429` 与
  `Retry-After`；锁定期间不再校验密码或下发会话。
- **请求边界**：认证接口请求体上限 16 KiB（超出返回 `413`），认证读取超时 10 秒；
  HTTP 服务增加 `ReadHeaderTimeout` 10s、`ReadTimeout` 5m、`IdleTimeout` 2m、
  `MaxHeaderBytes` 1 MiB（不设 `WriteTimeout`，避免截断 SSE）。
- **会话可撤销**：JWT 增加 `ver` 声明并与数据库中的 token version 比对；token version
  与密码哈希在同一事务中轮换，修改密码后所有旧会话立即失效，当前会话换发新 Cookie。
  升级到 1.3.1 后，1.3.0 签发的无版本 token 全部失效。
- **凭据不再暴露给 JavaScript**：会话 Cookie 为 `HttpOnly`、`SameSite=Strict`，
  HTTPS 下带 `Secure`，有效期 24 小时；不再接受 `?token=`，前端不再把 JWT 写入
  localStorage，SSE 通过同站 Cookie 鉴权。
- 为兼容 CLI/自动化，继续接受 `Authorization: Bearer`，登录响应仍返回 token。

### 新增

- `/api/auth/session`、`/api/auth/logout`、`/api/auth/captcha` 端点。
- 登录与初始化页面加入滑块验证码；失败后自动换图，支持手动刷新。
- 侧栏退出登录改为调用服务端注销并清除 Cookie。
- 修改密码提示更新为“其他设备会话立即失效”。

### 兼容性

- 从 1.3.0 升级后需要重新登录（旧 token 没有版本声明）。
- HTTPS 反向代理需传递 `X-Forwarded-Proto: https`，否则不会设置 `Secure` Cookie；
  HTTP 部署不受影响。
- 登录锁定为进程内按 IP 计数，服务重启后清零；多副本部署不共享锁定状态。

## [1.3.0] - 2026-11-01

本版把利用闭环从「单点验证」扩展到「横向、维持、撤离」：SQL 注入确认后做权限影响评估，
弱口令确认后可自动接力 Webshell 上传；内网新增侦察、凭据台账、SOCKS5 / 端口转发隧道与
可撤销落地物台账，并提供 Linux（cron/systemd/ssh_key）与 Windows（计划任务/注册表）标准
维持模块；撤离按台账逆序撤销并验证。扫描引擎修复了 nuclei DAST 模板与旧式模板互斥加载
导致空模板组、整次扫描被判定失败的问题；并新增通用滑块验证码求解能力。

### 新增

- **利用闭环**：sqlmap 确认注入后评估账户与 DBA 权限，按影响升级严重级；弱口令确认
  后自动排队 Webshell 注入任务，避免同一主机重复上传。
- **内网横向**：`intranet_recon` 收集网卡、路由、ARP、监听端口；凭据台账记录来源与
  原始证据，跨主机精确复用前先验证；隧道支持 SOCKS5 与端口转发两阶段生命周期；目标扫描、
  弱口令、深度利用子任务均可经隧道代理出站；支持范围审批与任务交接；Windows 会话支持
  cmd 探测与执行。
- **权限维持**：`intranet_artifacts` 可撤销落地物台账，每条记录带部署、验证、撤销
  命令与执行证据；Linux 标准模块 cron、systemd、ssh_key，Windows 标准模块计划任务
  （schtasks）与注册表启动项；上传文件自动登记为待清理落地物。
- **撤离清理**：按台账 id 倒序撤销并逐条验证，随后拆除隧道、释放受管回调与监听、
  关闭会话；失败项保持 active 供重试，Webshell 作为残留明确列出；提供撤离预览、执行
  API、LLM 工具与撤离报告。
- **深挖与验证**：上传表单字段自动解析并复用到 Webshell 链；注入基线任务的结果通过
  `LinkScanTaskResult` 绑定回父扫描，扫描汇总同步深挖确认数与发现数。
- **WebCrack**：支持按 `user:password` 精确复用已确认凭据（经 stdin 传递，不出现在进程
  标题）；支持代理；识别验证码被拒并换图重试，分别统计重试与 OCR 失败次数。
- **WebCrack 滑块自动化**：弱口令引擎内嵌纯 HTTP 滑块处理，自动识别 AJ-Captcha
  blockPuzzle，逐次获取新挑战图并经 stdin 调用 `jingwei captcha-solve` 求解；用
  AES-128-ECB 生成 `pointJson` 与 `captchaVerification` 注入登录表单，校验失败自动换图
  重试。接口与图片限制在登录页同源；另支持 JSON profile 描述自定义滑块协议，极验/易盾
  等商业协议明确报不支持，求解器缺失或版本过旧时给出可操作的诊断。
- **通用滑块验证码**：新增 `captcha` 包与受 JWT 保护的 `POST /api/captcha/slider`，传入
  背景图与滑块图即可得到缺口坐标、拖动距离与置信度，可生成拟人拖动轨迹；纯 Go 图像匹配，
  不依赖浏览器或外部识别服务。LLM 通过 `solve_slider_captcha` 工具使用，弱口令、深度利用
  与脚本均可直接调用；支持 PNG/JPEG/GIF、data URL/base64，agent 工具还接受本机文件路径。
- **界面**：内网页新增落地物、凭据、撤离预览与报告；扫描列表展示自动深挖任务进度。

### 修复

- nuclei DAST fuzzing 模板与旧式 payload 模板在 `-dast` 下互斥加载：按模板类型分组执行，
  避免一半模板被静默跳过，以及只剩 headless 模板的空组导致整次扫描失败。
- 跳过 headless 浏览器模板并记录数量，不再交给 nuclei 触发 Chromium 下载或空模板报错。
- 应用层发现抑制软 404 / 403 路径，避免把同响应路径误登记为系统。
- 预扫 POC 命中收紧判定，证据统一为原始请求/响应。
- 在线文件上传靶场暴露的三项问题（表单字段、会话 Cookie 传递、证据报文）。
- Windows 会话命令静默假成功。
- WebCrack 证据报文补全 Host 与重定向后的会话 Cookie，凭据不再从证据中丢失。

### 验证

- Windows 目标 d54f：取权、内网横向、计划任务与注册表维持、按台账逆序撤离均实测通过。
- Linux 目标 jw-linux-p3（systemd 252 / Debian 12）：cron、systemd、ssh_key 三类模块的
  部署、验证、载荷执行与撤销全部通过，`crontab` 与文件确认清理。
- 无 LLM 扫描 #11：nuclei 55 条模板分三组正常执行，基线枚举 `?id=1` 并排队 sqlmap，
  确认 boolean/error/time/UNION 注入与 DBA 权限，critical 发现回写扫描（结果 1 / 发现 1）。
- WebCrack 滑块（本机 mock AJ-Captcha）：admin/123456 自动换图求解命中，证据请求含
  `captchaVerification`，会话 Cookie 保留；错误口令未被误报为成功；求解器缺失与旧版
  二进制分别给出明确错误。Python 17 项单测与 `go test -p 1 ./...` 全绿。

### 升级

- 新增 `intranet_credentials`、`intranet_artifacts` 表，服务启动时自动建表，无需手工迁移。
- 从 v1.2.2 升级只需替换镜像标签；原有配置与数据继续可用。

## [1.2.2] - 2026-10-30

文档补丁，功能与 1.2.1 相同。

### 文档

- README 增加微信公众号「网安智界」交流二维码，删除未引用的旧二维码图片。
- 部署文档、Compose 默认镜像标签与前端包版本同步更新到 1.2.2。

### 升级

- 从 1.2.1 升级只需替换镜像标签，无需数据库迁移或配置变更。

## [1.2.1] - 2026-10-30

发布包清理补丁，功能与 1.2.0 相同。

### 修复

- 移除 `traffic_search` 工具说明中的真实公网地址示例，改用 TEST-NET-3 文档地址；
  源码包与镜像不再包含该地址。

### 变更

- 部署文档、Compose 默认镜像标签与前端包版本同步更新到 1.2.1。

### 升级

- 从 1.2.0 升级只需替换镜像标签，无需数据库迁移或配置变更。

## [1.2.0] - 2026-10-30

本版把「扫到什么报什么」推进到「固定流程必跑基础漏洞」：新增应用层发现、弱口令与
SQL/XSS 注入基线；LLM 任务在规划前先做资产探测与 POC 初筛；同时补齐证据截图、结构化
复现、请求重发、凭据库与内网拓扑，并把工程标识从 ARTEX 全面切换为 Jingwei。
相对 v1.1.0 共变更 334 个文件（266 个已跟踪文件，其中 4 个删除；68 个新增），
新增约 14.5k 行、删除 2.2k 行。

### 应用层发现与固定渗透基线

- 新增应用层发现（`scanner/appdiscover.go`）：同一服务下按内置路径字典、robots.txt/sitemap、
  页面链接与脚本、SPA 路由串识别子路径系统；随机路径 soft-404 基线过滤「全路径同响应」；
  识别结果作为系统级资产入库并关联（`db/finding_systems.go`）。
- 新增登录页发现（`scanner/loginform.go`）：相对链接解析、两级爬取、静态资源跳过，以
  `<input type="password">` 判定表单，供弱口令基线选点。
- 固定基线 · 弱口令（`server/scan_baseline.go` + `scanner/webcrack.go`）：镜像内置 vendored
  WebCrack 引擎（`tools/webcrack/`），按评分取前 8 个登录页跑 admin 字典，命中直接落
  finding 并带原始请求/响应。默认只装核心依赖；带验证码的页面需
  `--build-arg WEBCRACK_OCR=true` 构建，缺 OCR 时跳过该页并记录原因，不再整页放弃。
- 固定基线 · 注入点（`scanner/injection_harvest.go`）：只读枚举页面链接查询串与表单字段
  （跳过 password/token/csrf 等字段、不提交表单、跨主机丢弃，24 页 / 80 点 / 8 秒上限），
  参数位置排队给 sqlmap / dalfox 专项任务判定；同一 `METHOD|host+path|参数集` 只付一次
  工具成本，已被 POC 阶段覆盖的位置不再重复排队。
- 基线在扫描的四个出口都会执行（含「无模板命中」「无 nuclei 目标」两条早退路径），
  nuclei 全灰也照样枚举参数并交给专项验证器。
- 扫描详情前端新增「应用层发现 / 弱口令检测 / 注入基线」阶段与对应徽标。

### LLM 任务：先探测后渗透

- 规划前置（`server/task_prescan.go`）：planner 首轮前完成端口/指纹/应用层发现与 POC 初筛，
  结果落资产与发现并写入摘要事实节点；预扫描失败不影响任务继续。
- 新增 `chains` 包：L2 反问纪律常驻 planner/worker system prompt，L3 场景链按意图与
  vulnclass 由代码路由注入，不靠模型自觉。
- 新增 `honeydetect`：按服务 banner、HTTP 头、响应体与协议怪癖给输出打蜜罐评分，接入
  Guard 的不可信内容标记。
- 每任务固定 UA（`guard/ua_pool.go`，由 task id 派生），避免跨任务被 UA 关联。
- 审批「一键放行」：放行 2/4/8 小时，同类调用自动通过；指纹对数字/UUID 归一，deny 永不豁免。
- 会话/任务自动标题：首段用户输入压成一行标题，模型输出经清洗，输入按不可信数据处理。

### 证据、复现与报告

- 证据质量校验（`agent/evidence_quality.go`）：拦截「见截图」「详见报告」式占位文案，
  要求证据本身包含结论与具体片段。
- 结构化复现（`db/finding_reproduction.go` + `report/reproduction.go`）：上报瞬间记录真实
  步骤与报文，报告按步绑定流量快照；每步紧跟自己的报文与「对应流量证据 #N」，响应按
  命中片段裁剪，避免整页噪音。
- 取证截图（`evidence/shot.go`）：用镜像内 Chromium headless 把真实收发报文渲染成 PNG
  取证面板（高亮命中片段 + 采集时间），发现详情可自动/手动生成、查看与删除。
- 发现复核时间线（`db/finding_review.go`）：记录每次人工改状态的时间与前后值，便于审计。

### 深度利用扩展

- 新增「请求重发」：原始报文直接重发，可走录制代理、跳过 TLS 校验、自定义超时；回显完整
  响应与耗时；本机/链路本地地址默认拒绝（`JINGWEI_REPEATER_ALLOW_LOCAL=1` 放行）。
- 新增「凭据库」：跨任务汇总已获取凭据与来源，便于一个口令打多个服务。
- 新增「内网拓扑」页；侧栏移除「资产同步」页。
- 加密 WebShell 会话（`scanner/shell_crypto.go`）：AES-256-CBC，密钥由口令派生，
  流量中不出现明文命令。

### 漏扫引擎改进

- 指纹无命中时回退到 `dast` 标签模板，避免「指纹识别失败 = 全量跳过」。
- 补强 Python/Node 指纹（gunicorn、uWSGI、Jinja2、Tornado、Twisted、Express 等）。
- nuclei 输出上限 8 MiB → 64 MiB，避免大量 info 命中截断尾部高危结果。
- 修复 curl 命令解析：`-x`/`--proxy` 以前被当成方法（`-x http://…` 解析出 method
  `HTTP://…`，真实 POST 丢失）；现支持 `-XPOST`、`-xhttp://…`、`--proxy=` 等写法，
  `-h` 不再吞掉 URL，代理单独保存为 `Proxy` 字段。

### 工程与构建

- 模块与产物更名：`github.com/Autumn-27/artex` → `github.com/Autumn-27/jingwei`；
  二进制 `artex` → `jingwei`（`cmd/jingwei`），镜像入口 `/app/jingwei`。
- 环境变量统一为 `JINGWEI_*`（`JINGWEI_PG_DSN` / `JINGWEI_CONFIG` / `JINGWEI_SKILL_DIR` /
  `JINGWEI_LLM_*` / `JINGWEI_NOTIFY_ALLOW_LOCAL` / `JINGWEI_REPEATER_ALLOW_LOCAL`）；
  旧 `ARTEX_*` 不再读取，升级时必须同步修改 `.env` 与 compose。
- Dockerfile：Node 改从 npmmirror 下载、nuclei 增加 gh-proxy 回退、pip 使用 cache mount、
  WebCrack 依赖分核心/OCR 两档。
- 新增单元测试：重定向策略（同主机放行、≤3 跳、跨主机拦截）、nuclei/sqlmap/dalfox
  执行层（假二进制记录 argv 与产出、超时强杀）；删除 chains 包文档中指向未移植
  `skills/chains/` 的 L4 悬空引用。

### 修复

- 预扫端口范围收敛（`server/task_prescan.go`）：显式指定非标准端口（如 `:10800`）时只探测
  该端口，不再扩成 80/443/8000/8080 等整套 Web 端口；只给主机名或 80/443 时仍按 Web 端口集探测。
- 存量安装的 `report_finding` 工具 Schema 自动升级（`finding_workflow_tools_v4_report_finding_defaults`）：
  补齐 `reproduction` / `cvss` / `traffic_refs` / `evidence_hint_id` 并把 `cvss` 设为必填，
  修复旧库升级后上报因旧 Schema 被拒绝的问题。

## [1.1.0] - 2026-10-26

### 自动化漏扫引擎（不依赖 LLM）

- 新增 `scanner` 扫描内核与 `/api/scans` 任务体系：端口探测（top100/自定义范围）、Web 指纹识别、nuclei 模板并发执行、结果直接落为漏洞发现。
- 集成 FLUX 指纹库 25,136 条规则（`scanner/fpdata`，含 `NOTICE.md` 署名），指纹识别与 nuclei 标签联动筛选模板。
- 新增「自动化漏扫」前端页面：任务创建、实时进度、发现列表与报告导出。
- 扫描完成后自动串联后续动作：漏洞复核、深度利用、WAF 绕过、可选 WebShell 注入（`server/scan_auto.go`）。
- 注入类判定改为专项验证器自证：集成 sqlmap（SQL 注入）与 dalfox（XSS）替代 POC  matcher 的启发式判定。
- 时间盲注增加止损：目标被慢查询拖住时按响应预算中止并给出「不可判定」结论，不再误报为漏洞或超时挂死。
- 修复全量模式静默截断模板的覆盖缺陷：模板库超过 10,000 条启用 POC 时，旧实现按 id 截断，恰好丢弃后期补测导入的靶场专用模板（含 DVWA 全部 13 条认证 POC），且日志无任何痕迹；现改为按危险等级优先加载并显式记录被舍弃数量（`db.ListEnabledPOCContents`）。

### 原始报文与可复现性

- 新增流量采集层（`db/finding_traffic.go`、`traffic`）：每条漏洞发现绑定完整原始请求/响应报文，多步 POC 记录整条报文链而非最后一步。
- 非 HTTP 协议按协议本身出证：MySQL/Redis/SSH 等给出原始字节交互（`scanner/protocol_packet.go`），带十六进制视图与可直接复现的监听/连接方式，不再包装成 HTTP 请求。
- PoC 展示改为纯原始报文，移除 curl 命令形式。
- 报告新增 DOCX / HTML 导出（`report/findings_docx.go`、`findings_html.go`），按发现分页、内嵌验证步骤与报文。

### 判定、去重与分组

- 新增 `verdict` 反证判定：对命中结果做二次反证，区分确认/误报并回写发现状态。
- 新增 `dedupe_key` 去重，同一漏洞在多轮扫描/多模板命中不再重复堆积。
- 漏洞列表支持按任务、按系统（资产主体）分组展示。

### 深度利用

- 新增一级栏目「深度利用」及 exploit / verify / waf-bypass / webshell / resources / intranet 六个二级页面。
- 新增深度利用 HTTP 内核（`scanner/deepuse.go`）、数据表与任务框架，并把深度能力作为工具暴露给 LLM 探索路径。

### Java 反序列化（java-chains）

- 新增 java-chains 可选 sidecar 与 MCP 注册链路：`scanner/javachains.go`、`server/java_chains.go`、`server/java_chains_deep.go`。
- 深度任务自动识别反序列化入口并调用 java-chains 回写证据；新增 `skills/java-chains/SKILL.md`、`deploy/JAVA_CHAINS.md` 与 `deploy/java-chains-setup.sh`。

### 内网测绘与资源台账

- 新增内网两阶段能力（`db/intranet.go`、`server/intranet*.go`）与会话/隧道入口。
- 新增受管资源台账与端口审计（`db/managed_resources.go`、`server/resources.go`、`server/resource_tools.go`）。

### Guard 与安全边界

- 新增工具调用 Guard：目标范围限制（`guard/scope.go`）、出站控制（`guard/egress.go`）、内容抽取与不可信标记（`guard/extract.go`、`agent/untrusted.go`）、密钥脱敏（`server/guard_secrets.go`）。
- 新增 worker 痕迹清理规约（`agent/cleanup.go`），利用结束后不在目标上遗留测试文件/WebShell。

### LLM 稳定性

- LLM 连接池健康重试（`llmpool`）、单次调用超时（`agent/calltimeout.go`）、任务停滞检测与自动暂停（`server/stagnation.go`）。
- 每轮 LLM 调用按模型计量并实时可查（`/api/llm/records/by-model`），便于判断任务是否仍在推进。

### 批量操作与测试隔离

- 发现、任务、资产、公司（资产主体）四类列表补齐批量删除，后端改为单次请求的批量接口。
- 测试进程强制使用独立测试库（`ARTEX_PG_DSN`），不再接管生产任务；清理测试夹具泄漏与全局状态污染。
- 新增 `tools/audit_docx.py`（校验导出报告的报文绑定完整度）与 `tools/coverage.py`（漏洞覆盖对账）。

## [1.0.0] - 2026-10-22

### 品牌与界面

- 品牌化为「精卫 Jingwei」：控制台、登录/初始化页、侧栏、报告、通知、后端 Banner 与健康检查服务名。
- 登录页、初始化页与主界面底部恢复老版页脚文案，并补充 ARTEX / AGPL-3.0 署名。
- 新增《使用须知》完整条款、首次启动密码初始化与管理员密码修改流程。

### POC 模板库

- 新增 POC 模板库：nuclei YAML 的搜索筛选、统计、详情、上传、启停、删除与批量执行。
- 内置 nuclei 3.11.1；执行支持最多 50 个目标、200 个模板，超时 10–600 秒，关闭 interactsh 与自动更新。
- 新增旧版 POC 数据迁移工具 `cmd/pocimport`，本次已导入 13,058 条模板（22 条非模板配置跳过）。
- 修复 YAML 转义 NUL 导致 PostgreSQL 写入失败；补齐 `tcp`/`udp`/`workflows` 协议识别。

### Docker 与发布

- 版本号统一为 `1.0.0`；前端包版本与 Release 镜像版本一致。
- 新增 `deploy/docker-compose.yml` 与 `deploy/.env.example`，支持独立卷、健康检查与端口覆盖。
- 发布方式改为 Docker-only：GitHub Actions 构建 AMD64 / ARM64 镜像，原生 runner 冒烟测试后推送 GHCR。
- 新增 Release 自动化：创建带 `docker-compose.yml`、`DEPLOY.md` 与镜像 digest 的 GitHub Release。
- 在线更新源切换为 `Domren/Jingwei`；Docker 部署通过拉取新镜像升级。
- 移除上游 Vercel Demo 工作流与二进制发布流程，新增 [DEPLOY.md](DEPLOY.md) 部署指南。

## [0.3.18] - 2026-10-12

### 审批审查

- 新增脚本审查快照，向审查模型提供直接引用脚本的路径、大小、SHA-256 和源码；快照不完整时强制转人工审批。
- 新增审批旁路问答会话，支持基于审批上下文连续追问，且旁路模型不能执行工具或改变审批状态。
- 新增审批记录全文检索、审批编号精确定位、日期范围筛选及状态、判定来源组合筛选。
- 修复审批详情脚本区域裁切、脚本展开状态显示和旁路面板关闭后的聊天布局问题。

## [0.3.17] - 2026-10-10

### 计划任务

- 新增日历式计划任务，支持按时间规则创建、编辑、启停和删除任务。
- 任务列表支持查看计划状态与下一次运行时间，并补充计划任务管理页面。
- 支持按日期范围筛选计划任务、日历式运行时间线和批量选择操作。
- 优化立即运行、暂停来源与状态颜色展示，并在计划状态变化后刷新时间线。

## [0.3.16] - 2026-10-09

### 访问控制

- 新增可选的 HTTP Basic Auth 访问控制，可在系统设置中配置，并修复配置持久化占用请求锁的问题。

### 同一漏洞的重复上报归并

- Reporter 在生成独立报告后按同任务候选证据判断同一实际缺陷，明确重复时归并，证据不足时提交人工确认建议。
- 新增可展开漏洞文件夹、统一报告、原始等级分布、独立漏洞/上报记录统计及归并历史；每条原报告、证据和流量继续保留。
- 支持手动整理所选历史记录、移出成员与防止自动再次归并，继承任务保持只读。
- 统一报告采用证据版本校验；导出默认统一报告，可包含原始子报告，未生成或过期时明确提示并保留原材料。

## [0.3.15] - 2026-10-07

### 部署与发布维护

- 迁移至独立的 `RuoJi6/ARTEX` 仓库，保留原提交历史与分支。
- 页面在线更新源为 `RuoJi6/ARTEX`；GitHub Actions 构建五个平台程序包和 SHA256 校验文件。
- 在原生 AMD64、ARM64 runner 上构建 Docker Hub 镜像，并验证程序启动、数据库连接和内嵌前端。
- 两种架构验证通过后，发布 `v0.3.15`、`latest` 镜像及对应程序包。
- Compose 和部署说明使用本仓库的镜像，补充已有部署保留数据的迁移方式。

### 拦截

#### 新增的功能

- **新增内置拦截规则「删除类接口路径」**：此前内置的 HTTP 破坏性规则只认 DELETE **方法**，而多数应用的删除接口用 GET/POST 就能触发，`curl 'http://t/api/user/delete?id=1'` 这类调用会真实删掉目标数据。现补一条 `deny` 规则覆盖 `/delete /del /remove /unlink /erase /destroy`（动词后必须跟分隔符，`/delivery`、`/details`、`/delta` 不会误拦）。已有实例升级后也会拿到，可在「系统 → 命令拦截」里停用或删除。
- **模型兜底审批的 token 消耗可单独查看**：审批调用此前没有独立的计量归属，花了多少只能靠猜。现在它单独计量，「系统 → 命令拦截」的「模型兜底审批」开关下方新增用量卡片——调用次数、输入、输出、缓存读写五项累计统计，加一张近 30 天每日消耗的迷你柱图。

### 漏洞推送

#### 新增的功能

- **漏洞发现支持推送到 IM**：新增「系统 → 通知推送」页，可把扫描发现推送到**钉钉、飞书、企业微信、通用 Webhook、Telegram、邮件**六种渠道。同一类型可配任意多个实例，每个实例独立设启停、限流与过滤规则。
- **推送时机分实时与汇总两种模式**：实时模式命中即逐条发送；汇总模式按全局周期（默认 30 分钟）合并成一条消息，开头给出新增数量与级别分布。想做「高危实时、其余汇总」就建两个渠道分别配置。
- **过滤规则支持四个维度**：最低严重级别、限定任务 / 资产范围、漏洞类型关键词包含与排除（排除优先）、是否接收处置状态变更（默认关）。消息带「查看详情」按钮，目标地址由全局「回链地址」配置，留空则不带按钮。
- **投递历史与手动重发**：列出每条投递的状态、尝试次数、失败原因与所属渠道，可按渠道与状态筛选；失败项可一键重发（重发会清零重试计数）。
- **渠道凭据掩码回显**：Webhook 地址、加签密钥、Bot Token、SMTP 密码等只回显带尾号提示的掩码值；提交时原样回传表示「不修改」，清空输入框则删除该字段。

#### 修复的问题

> 本节是功能初版完成后一轮安全审计的结论，每条都先复现、再修、再补回归测试。

- **修复掩码可被「改目标地址、保留凭据」绕过（严重）**：配置合并对「未提及的键」一律保留库中原值，于是只改地址、对凭据避而不谈，就能让服务端把库里的真凭据发到任意地址，且完全静默。现规定目标地址一旦变化，每个凭据字段都必须显式表态——给新值，或显式留空表示不再需要。
- **修复 markdown 系渠道对不可信内容零转义**：漏洞标题与摘要来自模型输出、资产 URL 来自扫描结果，构造的标题会在钉钉 / 企业微信 / 飞书里渲染成可点击外链，图片语法则会在渲染时被客户端拉取并泄露阅读者 IP。现统一做单行化 + markdown 元字符转义，且转义发生在各渠道的渲染出口而非共用的标题函数。
- **修复投递地址的 SSRF 面**：此前环回、内网与云元数据地址一律可投递，而失败响应体前 200 字节会进 `last_error` 并被投递历史回显，构成一条半盲读原语。现改在**拨号阶段**设防，覆盖 DNS 重绑定，并拒绝跨主机重定向；环回与链路本地地址需显式设置 `ARTEX_NOTIFY_ALLOW_LOCAL=1`，RFC1918 私网仍放行（内网自建 SMTP 中继很常见）。
- **修复推送凭据经错误信息外泄**：钉钉的 `access_token`、企业微信的 `key`、Telegram 的 bot token 都在 URL 里，而投递失败时完整 URL 会流入 `last_error`、投递历史、服务端日志与前端提示四处。现统一脱敏，只保留 `scheme://host` 与底层原因。
- **修复汇总消息被截断后整批标记已送达导致的静默丢失**：被截掉的漏洞既不在消息里、也不在失败列表里，投递历史却显示成功。现改为按**整条**打包，只标记装进本条的那些，其余回队列等下一条续发且不消耗重试次数，消息头部也写明还有多少条将在下一条继续。
- **修复最低级别门槛打错字会让过滤器静默失效**：`min_severity` 写成 `hgih` 这类笔误时未知级别序数为 0，判定退化成恒真，用户以为只收高危、实际全部漏洞都被灌进群里。现于写入路径校验取值并列出可选值。
- **修复 `rate_per_min = 0`（不限流）不可达**：写库这一层把显式 0 悄悄改成了默认值，操作者以为放开了限流、实际仍被卡着。默认值改到接口层在字段缺省时填。
- **修复汇总渠道完全绕过令牌桶**：`rate_per_min` 对 digest 模式此前没有任何作用。现在领取条数同时受本轮额度与内存上界两个约束。
- **修复失败处置按整批最大尝试次数判断，让老投递连坐新投递**：一个已重试两次的老投递会把同批里全新的投递一起拖进 failed，新漏洞一次重试都没用上就永久丢失。现改为逐条决定。
- **修复汇总批次中快照无法解析的投递被静默标记成功**：这类条目会被渲染阶段跳过，却随整批一起算作成功。现在显式判失败并给出原因。
- **修复单渠道每轮投递条数可能超出租约时长**：多实例部署下，租约过期的行会被重新领走、重复发送并双份递增尝试次数。现按「租约 / 单次超时」倒推每轮上限，并有断言把这几个常量的关系钉死。
- **修复 Telegram 截断可能切断 HTML 实体**：截断只避开了半截标签，没避开 `&amp` 这类实体残片，而解析器可能因此拒收**整条**消息。现在两者都回避。
- **修复邮件渠道把临时性 SMTP 失败判成永久失败**：灰名单 `450` 这类 4xx 是临时拒绝、本该稍后重试，此前一律判死，启用灰名单的服务器会让每条推送都在首次尝试后失败。现按应答码首位区分，4xx 可重试、5xx 永久失败。
- **修复提交嵌套结构时会真的把掩码字面量写进库**：像 `webhook.headers` 这种对象字段只能整体掩码或整体提交，把掩码哨兵塞进对象内部会被当真实值存下来、导致鉴权静默失效。现在这种提交被显式拒绝。

#### 设计说明

- **写漏洞的事务只做一次盲 INSERT**：`notification_events` 与漏洞在同一事务内写入，提交即保证两者原子一致。这条 INSERT 刻意不读渠道表、不跑用户的过滤规则，并由 `SAVEPOINT` 包住——否则一条配错的过滤条件就能中止事务，让高危漏洞存不进库。
- **投递用租约领取而非长事务**：`FOR UPDATE SKIP LOCKED` 领取后把行置为 `sending` 并把 `next_attempt_at` 推到未来作为租约，投递期间不持有数据库锁；进程崩溃留下的行会在租约到期后被重新领取，自愈且不会无限重试。
- **限流不消耗重试预算**：先按令牌桶算出本轮额度，再按这个数量去领取。顺序反过来会让被限流挡下的投递白计一次尝试次数，三次预算被纯等待耗光后落入失败。

### 测试基础设施

#### 修复的问题

- **修复公司 ICP 归属用例的清理顺序导致的资产永久残留**：`defer d.Close()` 在函数返回时先执行、`t.Cleanup` 在其后，于是清理语句全部落在已关闭的连接上，错误又被丢弃，测试资产与公司永久残留在库里，还会让其他按资产计数断言的用例莫名失败。现改为关闭连接也走 `t.Cleanup` 并注册在前，同时让清理失败显形。

### 流量

#### 新增的功能

- **流量列表支持内容检索、路径 / 状态码 / 长度筛选与列排序**：筛选行支持按**响应内容**（走全文索引）、**路径**、**状态码**（精确值或 `2xx` 这类分桶）、**响应长度范围**过滤，表头可按时间、状态码、响应长度排序，排序偏好记在本地。新增两个索引，已有实例升级后自动生效；Agent 工具的 query 契约未改动。
- **流量列表新增「清空全部」**：一次删除全部流量记录（忽略当前筛选），并清理索引已不再记录的历史 host 目录，清空后顺带做一次全量压实并提示实际释放了多少空间。已绑定到漏洞的流量证据存在独立的证据库中，不受影响。

#### 修复的问题

- **修复删除流量后磁盘空间不被释放**：索引库建库时没有启用 `auto_vacuum`，文件永不收缩；全文索引又是 `contentless_delete`，`DELETE` 只写 tombstone 而不回收原 postings——删流量反而让索引变大（实测抓 6MB 正文 → 索引 16MB，删光后仍是 16MB）。现在新建索引库启用 `auto_vacuum=incremental`，每次删除后在后台分块执行全文索引合并与增量回收，逐步把空间还给系统（同一场景回落到 104KB）；回收在块间释放写锁，不阻塞流量录制。

> 升级说明：`auto_vacuum` 只能在建库时设定，因此**已有实例的索引库仍是旧模式**，增量回收在其上是空操作（启动时会打印一行提示）。这类库升级后 tombstone 的增长已经止住，而已占用的体积用「清空全部」回收一次即可——那一步会把库转成增量回收模式，此后日常删除自行生效。

### LLM

#### 修复的问题

- **修复自定义会话头在「一次性 LLM 调用」路径上不生效**：目标拆解（第 0 轮）与冷节点压缩都是不挂 transcript store 的一次性调用，context 上没有 session id，网关侧因此读不到该头——对 opencode zen 这类缺头直接 400 的端点，表现为「第 0 轮失败、后续 planner 轮次却完全正常」。现为这两条路径显式挂上按探索稳定的 session id，顺带让 token 用量能正确归因到对应探索（此前完全记不到）。

### 工具

#### 修复的问题

- **修复 MCP 与自定义工具的输出截断不生效，大结果整段灌爆上下文**：MCP 工具的返回此前完全不经截断，HTTP 类自定义工具则因传入空的工具上下文，一直用写死的 6000 字符而非会话配置的上限。现两条路径统一走 `actool.Capture`：按会话 `MaxOutputChars`（默认 30000）截断，配了 `ToolOutputDir` 时把全量输出溢写到磁盘、消息里只留开头片段与文件指针。
- **升级 norma 到 v0.4.3**：harness 层统一执行 `CaptureOnce`，任何工具（含今后新增的）都不会再因为漏接截断而溢爆上下文。

### 部署

#### 修复的问题

- **修复反向代理部署下活动流连不上**：SSE 地址此前无条件拼成 `${hostname}:8787`，反代到 443 的部署里页面从 `https://域名/` 加载、SSE 却被指向未对公网开放的 8787 端口，表现为活动流反复重连。现按 `NODE_ENV` 区分：生产默认同源，仅 `next dev` 保留 `:8787` 以绕过 Next.js 对 SSE 的缓冲；`NEXT_PUBLIC_SSE_BASE` 覆盖口保留。README 补充了反向代理部署说明。

### 发现

#### 修复的问题

- **修复「按资产」视图资产列表溢出后没有滚动条**：外层卡片只给了 `max-height` 而没有确定高度，滚动视口的百分比高度解析不出来，于是资产多时列表要么撑破卡片、要么被截断且无法滚动。现把高度上限直接落到资产树的原生滚动容器上，随窗口高度自适应。

### 数据库

#### 修复的问题

- **为连接池设置上限**：`database/sql` 默认不限制应用自身可打开的连接数，池里没有空闲连接时会无条件新建，一路顶到 PostgreSQL 的 `max_connections`（默认 100）才被拒。现封顶 32 条，超额查询改为等待空闲连接，同样的负载下表现为变慢而不是报错；若 `max_connections` 调低过需同步下调。
- **提升连接复用率**：`MaxIdleConns` 的默认值是 2，并发超过 2 的连接用完即关、下次请求要重做 TCP 与 PostgreSQL 认证握手。现将空闲上限提到与总上限一致，并补上 30 分钟连接寿命与 5 分钟空闲淘汰，让池能自然换掉长期存活的坏连接。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.14] - 2026-09-24

### 任务列表

#### 新增的功能

- **任务列表新增「漏洞」列**：按严重度分档显示 严 / 高 / 中 / 低 的数量，非零档位按严重度着色，一眼看清每个任务的漏洞规模与分布。

#### 修改的功能

- **「描述 / 目标」两列宽度收窄**：超长内容省略显示，鼠标悬浮可查看全文，减少长文本挤占列表横向空间。

### 探索图与规划态势概览

#### 修改的功能

- **精简规划态势概览（graph_overview）并为各列表设定数量上限**：最近事实、已结束意图、待办意图、冷区摘要与确认漏洞明细均改为「最新一窗 + 计数兜底」，未展示的可按需查询；显著降低每轮 LLM 上下文体积、避免长任务上下文膨胀（关联任务概览的冷区一并限流）。

#### 修复的问题

- **折叠冷节点后消除探索图中 digest 与 finding 之间的反向重复边**。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.13] - 2026-09-19

### 资产拦截

#### 新增的功能

- **新增全局资产拦截规则（黑名单）**：支持录入全等与模糊匹配的域名 / IP / URL 以及 CIDR 网段，提供规则的增删改查与启用/停用，管理页位于「系统 → 资产拦截」；默认内置模糊拦截政府（`.gov` / `.gov.cn`）与教育（`.edu` / `.edu.cn`）网站。
- **资产拦截接入执行链**：Agent 在下发意图（`add_intent`）与插入资产（`insert_assets`）前先对目标资产做拦截判定——命中拦截的意图不下发、命中拦截的资产不插入，并向 Agent 返回资产信息与拦截原因。
- **新增任务级拦截 / 允许（白名单）规则**：独立于全局规则、仅对本任务生效，判定顺序为「先拦截后允许」——命中拦截即禁止；未命中拦截但本任务配置了允许规则且都不命中，则「不允许测试」；未配置允许规则时不启用白名单。可在创建任务时录入，也可在任务详情「总览」中增删改与启用/停用。
- **任务模板支持预设分类与任务级拦截/允许规则**：模板可保存任务分类与一组任务级规则，应用模板时一并带入新任务表单。

### 操作审查

#### 修复的问题

- **收紧模型裁判输出协议，减少截断导致的误放行**：将裁决说明（comment）上限由 500 汉字下调至 120 汉字并强制「只输出 JSON、不带前言或代码块」，避免裁决被 `MaxTokens` 截断后无法解析、进而按模型失败策略放行（fail-open）。

### 任务归档

#### 修复的问题

- **归档遇到符号链接时跳过而非整包失败**：归档格式端到端仅支持普通文件与目录，此前工作目录中出现任意符号链接都会导致整个任务归档失败；现改为跳过该符号链接并记录日志，其余文件正常归档（不跟随链接、不越出目录树）。

### 账户与合规

#### 新增的功能

- **登录前新增「使用须知与免责声明」弹窗**：需勾选同意后方可登录。

### 许可与依赖

#### 修改的功能

- **项目采用 AGPL-3.0 开源协议**，并完善 README 的许可与免责声明说明。
- **升级 norma 至 v0.4.1**。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.12] - 2026-09-17

### 探索链路播报板

#### 新增的功能

- **任务详情页新增「探索链路播报板」**（#144）：以时间轴流水视角呈现任务的探索节点（起点/目标/意图/事实/漏洞/提示/压缩），支持按类型筛选、关键字搜索、正序/倒序、分页与自动刷新；处于「最新在前的第一页」时为直播位、每轮刷新，离开该位时只累计未读计数、不打扰当前阅读，并以「N 条新播报 · 回到最新」一键返回。按天分组，长任务翻页也能认出「这是哪天的事」。
- **播报板每行显示节点 id**（#145），便于对照探索链路图与定位具体节点。
- **播报板节点详情展开显示上下游与锚定资产**（#147）：展开一条播报可见该节点的上游（由此而来）/下游（由此产生）关系，鼠标悬停关联条目弹出对应节点的名片（类型/状态/来源/时间/摘要/payload 片段）；并顺带列出该节点锚定的资产（类型标签 + 可辨识文本）。相关数据随播报页一并下发，展开不额外发请求。
- **播报板搜索支持按节点 id 筛选**（#150）：搜索框在「内容 / 来源」之外新增节点 id 匹配，输入纯数字或界面展示的「#41」形式即可精确定位对应节点。

### 意图管理

#### 新增的功能

- **意图删除支持「假删除 / 真删除」两种模式**（#149）：待领、运行中、已暂停的意图均可删除，删除需填写原因；删除模式在确认弹窗中选择。
  - **假删除（默认）**：意图置为「已删除」并把原因记入独立字段，保留意图节点与其全部产出、血缘。
  - **真删除**：物理移除该意图，以及「仅由它支撑」的独占子孙节点（沿产出 / 意图链级联到叶子），避免留下孤立数据；被删意图的 Token 计量按原始日期归档保留；共享节点（还被其它意图引用）、目标与任务根事实一律保留，真删除弹窗会展示预计级联影响的节点数。

  两种模式都会通知规划者「该意图由用户删除 + 原因」并据此重新规划。

### 操作审查

#### 新增的功能

- **审批记录支持按状态与判定来源筛选**（#139）：可按审批状态、判定来源过滤审批记录，快速定位目标记录。

#### 修复的问题

- **待处理审批请求独立于历史分页加载**（#133）：待处理请求不再受历史列表分页影响，翻阅历史记录时仍完整可见。

### Agent

#### 修改的功能

- **Worker 角色描述改为通用网络安全平台表述**（#138）。

#### 修复的问题

- **修复冷节点压缩从不触发**：给按任务运行的规划器接上 Compactor，冷节点压缩（cold-digest）此前因未接入而从不执行，现已恢复。

### 聊天

#### 新增的功能

- **聊天支持多类型记录的 @ 引用及滚动分页**（#135）：可在聊天中 @ 引用多种类型的记录，引用候选支持滚动分页加载。

#### 修复的问题

- **长消息气泡约束在会话面板内**（#137）：过长的消息气泡不再溢出会话区域。
- **修复新对话未创建时上传文件报「缺少上传文件」**：Composer 的文件选择在清空 input 之前先把 `FileList` 快照为数组再回调；此前草稿态需先异步创建会话，恢复执行时与 input 活绑定的 `FileList` 已被清空，导致上传缺少文件字段、后端返回 400。

### 流量

#### 修复的问题

- **流量录制代理默认只监听 127.0.0.1**（#129、#130）：避免默认配置下开放代理暴露在其它网络接口。

### Web

#### 修复的问题

- **修复静态导出版任务列表页丢失全局头部**。
- **补齐 demo 漏洞详情页关联流量 mock，修复白屏**。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)
- [@dingpotian](https://github.com/dingpotian)

## [0.3.11] - 2026-09-15

### 操作审查

#### 新增的功能

- **审批记录支持来源定位**（#125）：点审批记录的「来源」可跳回触发该次审批的那一次工具执行——打开原始完整会话、自动分页加载到目标位置、就地展开命令与结果并在滚动区居中高亮，前后消息保持可读；用户手动滚动时停止自动校正。跨普通对话、任务 Worker、规划器与主 Agent 分段会话，均通过持久化的 `tool_use_id` 与任务映射精确定位（新增作用域内调用 ID 索引），缺失、重复或关联不明确时显式提示而非跳到其他执行。会话被删除或任务归档/记录缺失时给出明确提示。
- **审批记录支持翻页**（#115）。

#### 修改的功能

- **精简模型审查输入**（#124、#125）：模型审查（规则未命中后的 LLM 裁判）输入收敛为「当前这一次完整工具调用 + 明确选定的简短背景 + 本机工作目录」的版本化 JSON。背景只取真实用户消息（聊天/任务主 Agent 的当前用户消息），Worker 不再附带意图摘要、也清除从上级 Agent 继承的背景；规划器与自动触发会话不补造用户消息。不再附带任务描述、目标、操作约束、全局探索态势、历史调用或 Worker 完整意图——这些仍按原逻辑用于 Agent 执行与独立会话审计，只是不进入操作审查。所有裁决要求输出 JSON 的 `decision`/`comment`，说明必须包含「实际操作、成功后的后果、命中规则」；参数或背景中的指令不能改变审查策略。保存实际发送给模型的输入快照及指纹，旧版快照保留并标注版本，不用当前数据补造旧输入。

#### 修复的问题

- **模型裁决被代码块包裹时不再静默放行**（#126）：模型返回的裁决 JSON 若被 ``` 代码块包裹，此前解析失败会经模型失败策略被静默放行；现在先剥离代码块围栏再解析，解析仍失败才按已配置的失败策略处理。

### Agent

#### 新增的功能

- **新增实验性 noa 上下文压缩**（norma 升级至 v0.4.0）：系统设置中可开启的实验功能，默认关闭。开启后由 noa（模型驱动的上下文压缩）接管主 Agent、规划器、Worker、聊天四类 Agent 的上下文压缩，替代内置压缩；压缩原文持久化归档，集中落在 `<workDir>/noa/<会话ID>/` 下（不分散在各任务目录内），按会话 ID 全局唯一分目录。接入失败自动回退内置压缩，不中断真实任务；开关每次运行读取一次，切换只影响之后启动的运行。

#### 修复的问题

- **探索图工具在无任务上下文时拒绝而非 nil 崩溃**：非任务上下文调用探索图相关工具时返回明确错误，不再因空存储解引用崩溃。

### MCP

#### 新增的功能

- **支持旧版 SSE MCP 服务**（#117）：兼容仅提供旧式 SSE 传输的 MCP 服务端。

### 流量

#### 修复的问题

- **流量检索按端口感知匹配记录的主机**（#114）：`traffic_search` 的主机匹配纳入端口，避免不同端口的同主机记录相互串扰。
- **`traffic_search` 描述迁移出错不再中断后续 reporter 迁移**：单条迁移失败被隔离，不影响后续迁移执行。

### Web

#### 修改的功能

- **任务复测漏洞选项增加分割线**（#122）：复测漏洞选择项之间增加分隔，视觉更清晰。

#### 修复的问题

- **修复 demo 任务详情页整页崩溃**：mock 模式下任务详情「会话」标签会去拉 `GET /api/tasks/<id>/side-questions`（旁路提问历史），但 mock handler 没有这条路由，被读兜底按“路径以 s 结尾即集合”返回了 `[]`，导致 `data.items` 为 `undefined`，旁路 hook 的 `merge()` 对其迭代抛 `TypeError: t is not iterable`；该异常发生在 `setItems` 的 updater 里、被 React 推迟到 render 阶段重抛，调用方 `catch` 接不住，整页被错误边界接管显示 “This page couldn't load”。现在 mock handler 显式返回空的旁路历史，`sideAPI.history` 也对返回值做归一化（`items` 非数组一律兜成 `[]`）作为防御纵深。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)

## [0.3.10] - 2026-09-13

### 网络

#### 新增的功能

- **网络搜索新增 DeepSeek 官方来源**：直接复用当前激活的 LLM 配置。它与其余三个来源性质不同——DeepSeek 没有可直接调用的搜索接口，搜索只存在于其 Anthropic 兼容接口内部（`web_search_20250305` 服务端工具），由 DeepSeek 服务端执行。因此它**仅支持 DeepSeek 官方端点 + anthropic 协议**（OpenAI 协议端点会直接拒绝服务端工具），且每次搜索会**额外消耗一次模型调用**、请求**不经过搜索出口代理**、也**不计入流量留痕**，返回结果**只有标题与链接**（无摘要，需正文时由 WebFetch 抓取）。设置页说明上述限制但**不做校验拦截**，是否满足由用户自行确认，可用「测试搜索」按钮实跑一次验证。

### Agent

#### 新增的功能

- **worker 获得跨 work 回看能力**：新增 `search_all_worker_traces`（不必先知道 intent_id，按关键字在本任务所有 work 的执行过程里全局检索命中步骤）与 `get_worker_trace`（锁定某条 work 后列步骤流、就地按关键字搜、按 step_id 取完整内容），用于复用别的 work 见过却没写进 fact 的观察、避免重复劳动。
- **`node_detail` 下放给 worker**：配合上面的回看工具，worker 拿到 intent_id / 节点 id 后可直接查该节点的完整详情。
- **`add_hint` 触发的规划轮会被显式播报**：此前新增提示只把 hint 折进态势总览、让规划者自己发现；现在一次 `add_hint` 会给规划者记一条「人新增了 N 条战略提示：…」触发（批量算一条，不逐条刷屏），规划者被明确告知“本轮由新增 hint 触发”并直接看到提示内容。

#### 修改的功能

- **全局态势提示改为“松绑”口吻**：鼓励探索发散、跨意图线索及时上报，而非过早收敛。
- **精简 worker 边界措辞**：初次受阻不代表探透，聚焦“把本意图内的绕过手段走完再下结论”。
- `insert_assets` 移除每条资产的 `related` 入参：它唯一的作用是决定要不要把这条资产加进本任务范围，值又不落库（同一资产被再次登记就作废、界面上也看不出谁被判为无关），实际只是让模型多做一次留不住的判断。
- **测试范围(`task_scope`)不再受资产覆盖度开关影响**：`insert_assets` 的自动入范围(`source='auto'`)无论覆盖度开启与否都执行，`add_task_scope` 也始终提供给 planner / 任务内主 Agent / 目标拆解 Agent。范围是任务的授权边界、资产查询的过滤基准，覆盖度开关只决定要不要拿它当分母算指标，不该决定要不要累积范围本身。此前关闭覆盖度会让 `auto`/`agent` 两条写入路径同时失效，`task_scope` 只剩界面手工添加的行。`list_untested_assets` 仍随覆盖度关闭而隐藏（它本身就是纯覆盖度视角）。

#### 修复的问题

- **修复任务间资产互串**（#59）：`list_assets` 此前把任务 id 写死为 0、裸查整个共享资产库，模型又无从写出范围过滤条件，于是把别的任务的资产（尤其 IP）当成本任务目标，测试方向被带偏。现在它只返回落在【本任务及直接关联任务】测试范围(`task_scope`)内的资产，按**归属**匹配而非字面值：范围里有某根域即可查到其名下全部子域/服务/接口，有某网段即可查到段内主机及服务；按 id 直取范围外资产同样取不到。非任务上下文(Auto/pentest)无范围可依，仍回退全库。顺带修复 IP 直连主机(如 `http://1.2.3.4/api`)无法被网段范围命中的归属盲区。UI 的「测试资产」视图（按任务生产者过滤）不受影响。
- **修复 worker 跨 work 回看工具被误删**：`search_all_worker_traces` / `get_worker_trace`（以及 `node_detail`）加进 worker 默认工具集后，被一段“收敛 worker 工具面”的旧迁移在启动时又解绑掉，导致 worker 实际拿不到这些工具。已把它们移出该解绑清单，并对已跑过旧迁移的库一次性补绑回 worker。
- **修复 `/btw` 旁路提问偶发入库失败**：side_question checkpoint 落库前剥除 JSONB 不支持的 NUL(`\u0000`) 转义，避免含该字符的内容写入报错。

### 触发器

#### 修复的问题

- **合并触发会话按任务去重任务描述/目标**：多任务合并触发时，同一任务的任务描述/目标不再重复拼进消息，避免长目标反复堆叠把上下文撑爆。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.9] - 2026-09-11

### Agent

#### 新增的功能

- 任务内主 Agent 支持**多会话**：可新建、切换、独立重置上下文，每个会话都能交互。
- 支持持久化的 `/btw` **旁路提问**：不打断主线追问，问答落库，重启后仍在。
- `spawn_task` 新增 `source_task_ids`，新任务可**只读继承**来源任务的资产与发现。

#### 修改的功能

- 关闭 worker 的跨 engagement 记忆并收敛其默认工具面：读上下文、跨 work 复盘属规划职责，worker 只管单条意图的执行与写回。
- 精简 worker 默认提示词；`get_worker_output` 移除 `terminated` 与 `worker_name` 字段；精简 `insert_assets` / `list_assets` 的描述。

#### 修复的问题

- 修复 work 因**空转回合**提前中断的问题：模型有时会用一整轮只输出思考，既不给正文也不调工具，此时 harness 看到的是一次自然结束（`end_turn` 且无 `tool_use`），直接以 `completed` + 空总结收场——一条还没做完的意图就断在半路，表现为「任务正常结束但没有任何文字总结」。五层 LLM 重试一层都够不着它：它不是错误，同 provider 安全窗口重试的入口是"流失败"，熔断在 `err == nil` 时直接判成功，意图重跑只认 `model_error`；SDK 的空响应重试也够不着，因为那层以"有没有 yield 过事件"判空，而思考增量本身就是事件。现在 work 的 Stop 钩子会识别这种回合并注入一条续跑指令，让模型带着已经产出的思考继续执行下一步——刻意不选"原样重发"，因为这类空转通常由提示词与上下文形状决定，是稳定行为而非随机抽风，重发只会让模型再想一遍。
- 次数复用 LLM 页「重试与退避」里的**空响应重试次数**（两者都在回答"模型完成了却没产出实质内容"，只是判据与手段不同），默认 2 次，填 `-1` 即关掉、退回原先"空转即收场"的行为。它是一条意图的**总量**上限而非连续次数：harness 自身已限死连续空转只推一次，只有真正发生过工具回合配额才刷新，所以这个数挡的是「工具 → 空转 → 推 → 工具 → 空转」这类循环把意图预算耗光。触发时日志记 `[work <worker> · #<意图>] 空转回合…注入续跑指令 (n/N)`。设计见 `docs/LLM重试设计.md` §1.1。
- 修复长对话下 `/btw` 的上下文预算与输入布局；非安全上下文（非 HTTPS 访问）降级生成旁路请求 ID。

### 流量

#### 新增的功能

- 漏洞支持**关联多条流量证据**，可排序、加备注、按角色区分（请求/响应/佐证）。
- 报告 Agent 会在写报告前**自动关联**相关流量证据。
- 新增 Agent **流量绑定开关**，并补齐证据在 Agent 之间的交接。

### 任务

#### 新增的功能

- 支持**会话级漏洞复测**：复测跑在独立 Agent 会话里，列表与详情显示运行状态。

### 拦截

#### 新增的功能

- 审批记录新增**详情与执行审计**：可查看工具请求上下文、模型/规则初判、执行输出与参数指纹。

### 资产

#### 新增的功能

- 任务测试资产支持 **DSL 搜索**。

### LLM

#### 修复的问题

- 修复测试连接未补发自定义会话头，导致 opencode zen 返回 400 的问题。

### 网络

#### 新增的功能

- MCP 的 HTTP 传输支持**跳过 TLS 证书校验**，便于接入自签证书的服务。

### UI

#### 新增的功能

- 会话列表按 Agent 分组，支持展开收起与独立置顶；对话支持按 Agent 筛选。
- 攻击链路图渲染压缩（digest）节点，并收缩其成员。

#### 修复的问题

- 修复登录凭据不同步导致的白屏。
- 拦截提示文案改为明确标示「平台管控」，避免被误读成目标侧的防御。

### 部署与更新

#### 新增的功能

- 支持**页面一键更新**：系统配置页新增「版本与更新」卡片，顶栏在有新版时亮出提示。流程为下载发布包 → 校验 `SHA256SUMS` → 冒烟测试 → 暂存 → 退出由守护脚本重新拉起完成换装，页面自动刷新。
- 新增守护启动脚本 `start.sh` / `start.bat` 作为正式启动入口（发布包与 Docker 镜像均已带上，`install.sh` 不变），按退出码决定是否重新拉起，并负责把 SIGTERM 转发给 artex。校验与换装逻辑都在 Go 里，脚本保持傻瓜化。
- 失败自动兜底：校验或冒烟不通过就丢弃、继续跑当前版本；新版连续 3 次启动失败则回滚上一版本。设置页另有手动回滚（注意数据库结构不会回退）。
- 更新只认 GitHub 域名且强制 HTTPS，发布源不可配置；开发构建禁用一键更新。GitHub 查询结果缓存 30 分钟，避免顶栏提示耗尽 API 配额。

#### 已知限制

- Docker 下只换程序、不换镜像：工具链不会跟着升级，且重建容器会退回镜像自带版本，需要时仍用 `docker compose pull artex`。
- 不同步发布包里的 `skills/`，新版新增的内置 skill 不会自动生效。
- 更新即重启，会中断正在运行的任务。

### 依赖

#### 修改的功能

- 升级 norma 至 v0.3.7。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)

## [0.3.8] - 2026-09-09

### LLM

#### 新增的功能

- LLM 页新增「重试与退避」标签页：五层重试的**次数**与**间隔**都可以配。一次模型调用的失败由内到外经过建连重试（SDK，流开始前的连接重置 / 超时 / 429 / 5xx）、空响应重试（SDK，正常结束却没有任何内容，仅 openai 格式）、同 provider 安全窗口重试（未向调用方交付任何输出前的断流重放）、轮询熔断（连续失败到阈值就冷却跳过）、意图重跑（worker 以 model_error 收场后整条意图重跑）五层，内层用尽才轮到外层。每层两个旋钮，语义统一：留空 = 用原本的默认次数与指数退避；填次数就用该次数；填间隔就把指数退避换成固定间隔；填 -1 = 关掉这层重试。前三层跟着端点走，可在每个模型配置里逐字段覆盖全局默认（只钉间隔的仍继承全局次数）；熔断与意图重跑是进程级语义，只有全局一份。保存后热生效，不需要重启。全部留空即当前行为，旧库升级后逐字节不变（新列默认 0、settings 键不存在即全默认）。连接测试刻意不带这些参数——它有 30s 硬超时，叠上用户配的重试只会把能用的端点测成超时失败。设计见 `docs/LLM重试设计.md`。
- 每个 LLM 配置支持自定义**会话头**（`session_header_key`）：非空时每次 LLM 请求都会带上该 HTTP 头，头值为当前运行的 session id（chat 会话为 `conv-<id>`、worker 为 `exp<x>-worker-i<intent>` 等），用于某些按 session-id 头做提示缓存 / 粘性路由的网关。实现上从请求 context 里读取 session id 注入，无需改 norma，同一共享 provider 也能按会话发出不同头值。旧库带迁移，前端 LLM 配置弹窗新增输入框。

#### 修复的问题

- 修复保存 LLM 配置时因会话头字段为空直接报 `23502` 的问题：该列是 `NOT NULL DEFAULT ''`，此前误套 `NULLIF($n,'')` 把未填写的会话头写成 NULL 触发非空约束，现按空串语义直接传参。

### Agent

#### 新增的功能

- 墙钟超时改为**就地收尾**：依赖 norma v0.3.6，`MaxDuration` 到点会打断正在跑的工具并在活 ctx 上按收尾轮数续跑（写回已识别内容 + 总结，终态为 timeout），不再依赖 worker/planner 各自的 `maxDur+90s` 外部硬 ctx 把卡住的 run 直接杀成 `aborted_tools`。chat 走同一 harness 自动获得同样行为，mainagent 无 `MaxDuration` 不受影响。
- 停摆兜底：planner 在心跳 / 无变动唤醒且全图已无任何 open 或 running 意图时，开场白改为停摆告警，明确告知无 worker 在跑、无排队方向，本轮必须产出一个或多个互不重复的新意图（不得产出 0 意图）。

#### 修改的功能

- worker 提示词重构：意图 / 启动指令 / 锚定资产原始 JSON 移入 system prompt，每轮重拼、绝不被 compaction 压掉，续跑也不依赖 transcript 首消息留存；启动 user 消息瘦身为仅全局态势 overview（可降级、容忍 stale）。代价是 system 混入 per-intent 数据、失去跨意图缓存复用，是「不丢意图」的刻意取舍。
- 精简 planner / worker 默认正文并修正若干实战问题：planner 对 `recent_done` 按状态区分（blocked/exhausted 先查 trace 再决定，不当死路也不无脑重跑）、否定结论改为「观察 / 存疑、非定论」且采信前看 evidence、目标未达成且无 open/running 意图必须产出（硬底线）、深度优先于覆盖度；worker 否定类结论只写「观察 + 试探性读法」、判决权归 planner，跨意图线索写进 fact 的 summary 交规划者、不自己追。reseed 会把新默认作为新版本追加并切过去，用户自定义 / 旧版本保留在历史可回滚。
- 收敛 work agent 默认工具集与资产写回提示：worker 只负责单条意图的执行与写回，读上下文 / 跨 work 复盘属规划职责，故从其默认工具移除 `list_facts` / `node_detail` / `list_companies` 及跨 work 检索（`search_all_worker_traces` / `list_worker_traces` / `get_worker_trace`），只留 `list_findings`（报漏洞前查重）+ `add_finding` / `record_fact` + `insert_assets` / `list_assets`；提示词删掉与 `insert_assets` schema 冲突的陈旧字段说明（`type=tech`/`on_url`/`props`）。旧库带一次性迁移剥离对应绑定，planner/main 的同名绑定不动。

### 探索图

#### 新增的功能

- **探索图冷节点压缩（cold-digest）**：把老且长期不活跃的意图 / 事实折叠成 digest 节点在 `graph_overview` 里展示，原始节点永久保留、按 id 可完整还原（存储无损、只压呈现、折叠可逆）。冷热判定按逆向可达 + 任一活分支即热，配 R=6 轮防抖与连通分量分组；后台压缩（minor 折未覆盖冷块、major 回源重压合并碎片）带活跃度复核与冷却互斥，绝不上热路径也绝不覆盖已复活节点。概览侧提供 `cold_digests` 与按资产索引的 `cold_index`，`expand_digest` / `expand_index` 负责还原。关联 / 继承任务的概览同样复用其自身折叠视图，`expand_digest` 支持跨任务只读还原。`expand_digest` / `expand_index` 只给 planner 与 main agent，不给 worker。均带旧库迁移。
- `graph_overview` 全量输出 `finding_list`：findings 是任务最高价值产物且单任务通常不多，改为在概览里全量带出（不像 facts 只给最近窗口），planner/worker 每轮即可一眼看全所有确认漏洞，无需再调 `list_findings`。每条精简为 `{id, summary, evidence?, from_intent?, assets?}`，其中受影响资产直接给可读内容（url / 域名 / ip:port）而非裸 id。

#### 修改的功能

- `graph_overview` 不再平铺 `hosts`：coverage 块移除 host 列表（大范围任务里每轮最多携带 500 个 host 字符串，对规划决策价值有限），只保留 `host_count`，具体主机按需 `list_assets` 查。新增顶层 `done_intents_total`（已结束意图总数），与被截断到 ≤15 的 `recent_done_intents` 平行，让 planner 去重时知道有无被截。

### 工具

#### 修改的功能

- `add_company_scope` 默认绑定由 worker 改为 planner：定义企业资产范围属规划 / 主控 / Auto 的职责，worker 只执行探索。新库 seed 默认绑定为 mainagent/planner/auto，老库带一次性迁移。
- planner 默认绑定 `list_assets`：现同时具备 `list_assets`（DSL 全库检索）与 `list_untested_assets`（范围内未测），老库一次性回填、不覆盖用户解绑。

### 任务

#### 新增的功能

- 任务列表新增「运行中 Worker」列：统计该任务下 `state='running'` 的意图节点数，口径与任务详情页概览的「运行中 Worker」完全一致，无运行中 Worker 时显示 0。

### 网络

#### 新增的功能

- 新增**全局出口代理**配置：所有目标流量可经统一的全局代理出网（http/https/socks5，支持 `user:pass`）。开启流量捕获时作为 MITM 记录代理的上游（流量照录再经代理出网，拦截与透传两条路径都走上游、不泄露源 IP）；关闭捕获时直接注入 agent 的 bash 环境与 WebFetch（`proxyEnv` 增加 `ALL_PROXY` 支持 socks5）。配置存于 settings KV 表（无需迁移），前端系统配置页新增「全局代理」卡片，与网络搜索代理、LLM 代理相互独立。

### UI

#### 修复的问题

- 修正意图状态标签的语义错误：`exhausted`「已穷尽」→「预算耗尽」（实为达步数 / 时间预算被中途掐断、只写回部分结果，并非该方向已探尽）、`blocked`「被拦截」→「执行出错」（实为模型 / API / 网络故障重试用尽、意图基本没真正探成，并非目标 / WAF 拦截），并补上此前缺失的 `stopped`「已停止」（用户手动停止的 work）。

### 依赖

#### 修改的功能

- 升级 norma 至 v0.3.4：MCP 工具输出增加截断与落盘（见 `651b961`），后续 v0.3.6 支撑墙钟就地收尾。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.7] - 2026-08-31

### LLM

#### 新增的功能

- 模型配置新增「输出上限」，并可选择上限用哪个请求字段名：上限限制单次回复最多生成多少 token，随每次请求发出，0（默认）= 不发送该字段、由服务端默认值决定；它与「上下文窗口」是两回事——后者是模型总容量，只在本地用来算压缩阈值，不出现在请求里。字段名开关仅对 `openai`（Chat Completions）格式有意义：空（默认）发 `max_tokens`，绝大多数兼容网关只认它；OpenAI 官方推理模型（o 系列 / GPT-5）反过来只认 `max_completion_tokens`，收到 `max_tokens` 会直接报 `unsupported_parameter`，这类端点需手动切到新字段。两种格式各自定死了字段名（Anthropic 为 `max_tokens`、Responses API 为 `max_output_tokens`），故非 openai 格式该开关置灰并在保存时清空。同时补上一条此前从未接通的链路：planner / worker / chat / 主 Agent / 目标拆解五处都没设过输出上限，openai 系压根不发、Anthropic 走 SDK 的 8192 兜底，光加配置项而不接这条线，填了数字也不会生效；现在取值与「流式输出」一样按配置每轮解析，故障转移切换后下一轮即生效。旧库升级后行为完全不变（新列默认 0 与空字段名）。
- 后台点「测试」时把每次 HTTP 尝试的状态码与网关原始响应体打进服务端日志（响应体裁到 4K），便于诊断 401、额度文案、空帧、返回 HTML 页面等情况，不再只能看到 UI 折叠后的 ok / err。该日志不依赖「LLM 记录」开关。

#### 修改的功能

- 任务 LLM 配置链改为任何状态都可修改，不再限制「运行中 / 暂停 / 配置链耗尽」：任务结束（done / failed / timeout）后主 Agent 对话仍走这条链，链上模型出问题时原先既不能改也就没法继续交互。后端 HTTP 与 DB 事务两处终态拦截一并去掉，前端弹窗对终态任务也开放编辑与保存。终态任务保存时不再重开额度阻塞意图（那些意图会被挪到 open，既没有 worker 执行、也不再满足「重跑意图」的条件），想继续跑仍走重跑意图 / 新增目标，由它们把任务重新拉回运行态。

### Agent

#### 修改的功能

- 「给运行中的 Worker 发消息调方向」改为复用已有的暂停 / 恢复 + transcript resume 机制，行为与主 Agent 对话一致：此前走的是一套自建的介入持久化协议，牵动调度屏障、恢复流程与十余处活动查询过滤。现在消息经下一轮输入注入，意图在专属 goroutine 里直接跑，不受 3 槽 worker 池限制、随发随跑；前端保留消息框并恢复「直接继续」按钮，发送改由 SSE 承载。无 DB schema 改动。取舍：消息仅存内存、不做崩溃恢复，且发消息时该任务可能瞬时超并发一个 worker（低频场景，可接受）。

### 任务

#### 修复的问题

- 修复归档大型任务时内存耗尽（OOM）崩溃的问题：归档改为流式写入快照，不再把整个任务一次性读进内存；同时补齐冷归档路径上的三处恢复缺口——现代安装的流量只存在 SQLite 里，此前在 PostgreSQL 提交与 SQLite 提交之间崩溃会让已归档任务的流量滞留在热存储且无从恢复，现在无论有无历史目录都会写暂存日志，缺失的 `journal.json` 也按可丢弃处理。
- 修复任务较多时系统卡顿的问题：加载对话与加载界面存在明显延迟。任务列表、任务上下文与探索记录的查询一并优化，前端的仪表盘、对话页与任务详情页同步减少了重复请求。

### 资产

#### 修改的功能

- 去掉企业资产范围「最多 256 条规则」的限制：逐个 IP / 域名录入范围的企业很容易撞上这个上限，撞上之后只能拆成多个企业，而范围本身并不因为条数多就更慢。前后端与 demo mock 三处上限一并移除，单条规则仍限 1024 字符，请求正文 2 MiB 的上限保留作兜底（约合四五万条规则）。

### 技能

#### 修复的问题

- 修复上传技能压缩包报「上传失败：zip: unsupported compression」的问题：Go 标准库只内置 Store / Deflate 两种解压器，压缩软件在非默认档位下写出的 bzip2、Zstandard 包一律解不开。现在补上这两种解压器（纯 Go 实现，不引新的外部依赖）；Deflate64 / LZMA / XZ / PPMd 等确实解不了的方式，以及加密压缩包，改为在解压前就报出中文提示，直接点名是哪个文件用了哪种压缩方式、该怎么重新打包，不再把底层英文错误甩给用户。
- 修复技能内文件名校验把中文文件名判为非法的问题：路径校验原先是 `[A-Za-z0-9-_./]` 的 ASCII 白名单，压缩包里只要有一个中文命名的文件（`参考/说明.md` 之类），整包上传就会以「压缩包含非法路径」失败。改为 Unicode 黑名单：允许各种语言的文件名与空格，仍然拒绝控制字符、非法 UTF-8、零宽与双向控制字符（RLO 文件名伪装）、`\ % # ? * : " < > |` 以及 `..` / 绝对路径 / 空路径段，防目录穿越的行为不变。技能名同样放开——ASCII 仍限小写字母、数字与连字符（agentskills.io 规范），中文等非 ASCII 字母可直接作技能名，但不接受空格、点和路径分隔符。
- 修复 Windows 压缩软件打出的中文包解压后文件名乱码或整包被拒的问题：这类 zip 不置 UTF-8 标志位、按 GBK 写文件名，现在按 GBK 兜底解码后再做路径校验。同时 `name: "中文技能"` 这种带引号的 frontmatter 也能正确取到技能名。

### UI

#### 新增的功能

- 发现页新增「全部发现」平铺视图并设为默认，与原「按任务分组」视图通过页头 Tab 切换：分组视图要逐个任务展开才看得到漏洞，只想跨任务扫一眼列表时反而绕路。平铺视图是一张跨任务大表（每页 10/20/50/100 条），行为与分组视图完全一致——勾选导出、行内展开看证据与详细报告、行内改名称/类别/严重度、改处置状态、深入、删除。两个视图共用统计卡片与筛选条，切换不丢筛选，当前视图与筛选项一并记在本地；轮询只打当前视图，行内改动会同步写两边缓存，切过去不会看到过期数据。
- 发现页新增「按资产」视图：左侧资产树（企业 → 根域名 / IP → 子域名 → 服务 → 接口，企业层只在资产确实有归属时才出现），右侧是选中节点整棵子树下的发现，与另外两个视图共用同一张表和同一批筛选条件。树只收有发现的资产，祖先链按需补齐（发现只挂在最深的接口上时，上面几层照样能拼出来），节点上的计数是子树聚合并按发现去重的；资产已删除或本就没关联资产的发现进「未关联资产」桶。与另外两个视图不同，资产视图不轮询——进入视图、改筛选、页内增删改发现、或点树上的刷新按钮时才查询，左树是导航结构，没必要每 5 秒重算。树上每层只显示相对上一层的增量（子域名去掉根域名后缀、服务显示 `https :443`、接口只显示路径），完整值在悬停提示与面包屑里；节点过多时整层丢弃接口/服务层级并给出提示，计数仍计入上层。

#### 修复的问题

- 修复手机端会话详情里会话记录被挤压看不全的问题：窄屏下折叠会话列表，把宽度让给记录本身。

### 依赖

#### 修改的功能

- 升级 norma v0.3.2 → v0.3.3：新增 `Config.MaxTokensField`，让 OpenAI Chat Completions 的输出上限可以改发 `max_completion_tokens`（推理模型只认这个键）。两个键互斥、只发其中一个，默认仍是 `max_tokens`。
- 升级 `golang.org/x/mod` v0.37.0 → v0.40.0，修复两处依赖安全告警。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)
- [@begininvoke](https://github.com/begininvoke)

## [0.3.6] - 2026-08-27

### LLM

#### 修复的问题

- 修复「非流式」开关保存后重新打开又变回「流式」的问题（#69）：配置列表接口的 DTO 漏了 `streaming` 字段，响应从不返回它，前端读到 `undefined` 后一律回落成默认流式；实际写入与 DB 存储本无问题，只是读不回来。DTO 补回该字段（不加 `omitempty`，`false` 也必须出现在响应里）。
- 测试连接改为校验模型确有回复、并按该配置真实的收发模式来测（#65）：此前只判 HTTP 是否成功，请求通但模型零回复（思考烧光预算 / 正文被安全策略吞掉 / 兼容层丢 `content`）也报「连接成功」，与会话里「不回话」的表现割裂；且测试恒走流式，非流式配置测的其实是另一条通道。现在空回复直接判失败、成功时在提示里展示模型回复，并把当前流式开关一并带入测试，让「测试通过」与「会话跑得通」保持一致。

### Agent

#### 修改的功能

- `list_facts` 改为分页 + 关键词过滤，避免事实多时单次调用撑爆上下文（#74）：默认返回最新 20 条，支持 `limit`（上限 100）/ `before` 游标 / `q` 摘要关键词，返回 `{facts, total, has_more, next_before}`；单条 summary 过长按字数截断（全文仍走 `node_detail`）。worker / planner 提示词同步为分页语义。旧库通过一次性迁移把新参数 schema 刷进工具目录表（`SeedTool` 首插入only，否则工具管理页显示「无参数」）。

### 工具

#### 新增的功能

- 「工具执行」页新增工具调用次数统计（#72）：工具栏「统计」按钮打开弹窗，按工具展示调用次数、占比与失败次数（次数降序）；沿用列表的任务 / 关键词筛选，统计整个结果集而非当前页，弹窗打开时才拉取。

### 依赖

#### 修改的功能

- 升级 norma v0.3.1 → v0.3.2：修复 OpenAI 系响应里被静默丢弃的 reasoning/refusal（Responses 补 `reasoning_text`）、reasoning 字段三名去重、空响应（零内容块）有界重试、压缩边界切断工具配对导致的网关 400（同时修复已烤进 transcript 的存量孤儿）。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.5] - 2026-08-25

### LLM

#### 新增的功能

- 每个 LLM 配置支持流式/非流式切换（默认流式）：开走流式 SSE；关走真·非流式（`stream:false`、一次性返回完整 JSON），可绕开部分网关糟糕的 SSE 实现（空帧、思考字段丢帧），代价是失去运行中的实时进度与实时 Token 计数。worker / planner / mainagent / chat / goals 均按当前激活配置动态取值；`llmpool` / `llmrec` / 任务运行时三层 Provider 包装均兼容非流式；`llm_profiles` 新增 `streaming` 列并 `ALTER` 补旧库（默认 `true`，旧配置无感）。
- 支持 OpenAI Responses API 格式的 LLM 配置：每个配置新增第三种格式 `openai-responses`（打 `POST /v1/responses`），与 Chat Completions / Anthropic 并列；`BaseURL` 归一化、默认模型 `gpt-5`；`llm_profiles` 的 `format` 约束加入 `openai-responses` 并幂等迁移补旧库；前端格式下拉新增「OpenAI (Responses API)」。依赖升级 norma v0.3.1（含 `reasoning_content` 回传修复）。
- 录制 LLM 请求/响应 HTTP 原文：在 HTTP transport 层捕获真实 wire body，保留归一化视图看不到的工具 schema、`tool_use` 块与原始 SSE 帧；norma 内部重试的多次尝试逐次保留；`llm_records` 新增 `raw_request` / `raw_response` 两列并 `ALTER` 补旧库；录制页详情面板增加「原文」视图切换与请求/响应复制按钮（兼容非安全上下文的 `execCommand` 回退）。

### 对话

#### 修改的功能

- 会话列表多选改为「多选」模式开关：默认列表不再常驻每行勾选框（观感更干净），表头改为「共 N 个 + 多选」按钮；点「多选」进入选择模式（勾选框、全选、批量删除），「完成」退出并清空选择，批量删除全部成功后自动退出（有失败则留在选择模式便于重试）；单条重命名 / 置顶 / 删除仍走每行 ⋯ 菜单。

### UI

#### 修改的功能

- 任务管理、会话操作与流量查看体验增强（#57）：任务列表列排序偏好可持久化记忆、行内重命名改用图标直接触发（不再经菜单）、抽屉（sheet）交互与流量查看细节优化。

#### 修复的问题

- Worker 资产标签只显示域名与 IP，并正确处理空标签的场景。

### Agent

#### 新增的功能

- planner 判目标时新增「量化验收核对」：目标含可量化验收条件（资产测试覆盖度达到 X%、拿到 N 个 flag、获得某权限）时，`prove_goal` 前必须核对 `graph_overview` 的实测值（`coverage.pct`、findings 计数等），实测未达标则禁止 `prove_goal`、改为派意图补足差距，不得以「主要部分已完成/大体达成」为由提前标 met。修复了目标要求覆盖度 100%、实测仅 40% 却被判完成的问题。

#### 修改的功能

- 重写 planner 提示词中「本轮 0 意图」的判定依据：原文将 0 意图描述为「最常见、最重要的原则」，会让规划者在目标未达成、范围内仍有未测面时过早收手。现改为只在两种具体情况下才应产出 0 意图——① 想到的方向都已被 open/running/recent_done 意图覆盖；② 下一步依赖当前正在运行的 work 的产出、而产出尚未出现（应等其跑完、图更新后的下一次唤醒再规划）。并补充反向约束：确有未被覆盖且不依赖在跑 work 的新方向、或目标未达成且仍有未测面时，不要因「0 意图常见」而收手。
- 强化 worker 提示词中「否定结论的证据门槛」：对「不可注入/端口关闭/无登录入口」等可能让规划者放弃一整条方向的否定结论，要求下结论前先穷尽该意图内的合理手段（换编码/参数/路径/方法）；手段未走完或证据偏弱一律标 `confidence=inferred`，避免用轻率的 `observed` 否定把整条路线焊死（任务早期的错误否定尤其会把方向带偏且难以自愈）。
- 上述 planner / worker 默认提示词变更通过一次性迁移（`reseedPlannerPrompt` / `reseedWorkerPrompt`，各带 settings flag 守卫）追加为新版本并切为当前版本；旧版本保留在版本历史中，自定义过提示词的用户可在版本记录里恢复。

### 运维

#### 新增的功能

- 新增 `reset-password.sh` 重置管理员（用户名固定 `ARTEX`）密码：支持 local / docker 两种部署，连接信息可显式指定或自动从 `--dsn`/`$ARTEX_PG_DSN`/`config.json` 读取；在库内用 `pgcrypto` 生成与后端登录兼容的 bcrypt 哈希并写回 `settings.auth.password_hash`，重置后无需重启服务。密码经环境变量传入、不进入进程 argv，并做转义防注入。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)

## [0.3.4] - 2026-08-24

### UI

#### 新增的功能

- 任务列表勾选多个任务后可批量修改分类，目标分类支持「未分类」以将任务移出当前分类；整批写入在一个事务内完成，失败项只会是勾选后已被删除的任务。

#### 修改的功能

- 新建任务的「任务分类」由下拉选择改为可搜索输入框：输入即过滤已有分类，库里没有的名称回车（或点下拉里的「创建」）即时新建并选中，选中项以可移除的 tag 展示；仍限单个分类。

### 对话

#### 修复的问题

- 修复会话已选定 LLM 配置、但全局无激活配置时，发送消息被「LLM 未配置，无法对话」拦截的问题。发送前的检查原本只看全局激活配置，而实际执行会优先用会话所选配置，两处解析逻辑不一致；现统一为同一套（会话/Agent 绑定优先，全局兜底）。
- 无法对话时的提示按状态细分：完全没有配置提示「添加配置」，有配置但未激活提示「激活或为本会话指定一个配置」，不再一律显示「未配置」，便于定位。

### Agent

#### 新增的功能

- 目标已全部达成的任务，主 Agent 经 `add_intent` 下发的意图可被 Worker 直接领取执行、跑完即止：此时 Planner 不再运行（任务无 open 目标即不进规划），避免其重判目标达成而取消刚下发的意图；frontier 抽干后任务回到已完成。主 Agent 下发意图前会依据意图内容反问用户是否将其登记为正式目标，登记则任务恢复常规自主规划。

#### 修改的功能

- `get_worker_trace` / `get_task_worker_trace` 的 `step_ids` 超过一次上限（5 个）时不再直接报错，改为返回前 5 步的完整内容，并在结果中通过 `returned_step_ids` / `omitted_step_ids` / `notice` 告知本次取了哪些、还有哪些未取，并提示「若已足够则无需再取」。传入的重复与非法 id 会先去重、剔除后再计数。

#### 修复的问题

- 任务列表改为按任务 id 降序（最新创建在最前），替换原先的按创建时间排序。同一时刻创建的多个任务时间戳相同、排序不稳定，配合每 10 秒轮询和内存 map 的随机遍历，会导致它们在列表里频繁互换位置。

### 资产

#### 修复的问题

- 修复企业归属重算被单行脏数据打挂：`assets.ip` 存了主机名（Agent 或资产 API 写入）时，`a.ip::inet` 会抛 `22P02`，导致新增/修改企业资产范围和删除企业全部失败并回滚。改用安全转换 `try_inet()`，非法值跳过而不是中断整条语句。
- 无法解析的 `ip` 不再静默跳过：企业范围保存后会明确提示有多少条资产的 `ip` 不是合法 IP（含具体 id 和取值），提醒这些资产不会被 IP/CIDR 规则归属；同一信息也写入服务端日志，覆盖没有前端响应的路径（删除企业、scopesentry 同步、Agent 写入）。
- 任务测试范围的 IP/CIDR 匹配同步改用 `try_inet()`，替换原先只检查字符集的正则守卫（`abc.def` 这类全 hex 字母的主机名此前仍会漏过并触发同样的报错）。

#### 修改的功能

- `ip`、`service`、`endpoint` 资产的 `ip` 字段不再接受主机名：`insert_assets` 和资产 API 会逐条返回带 `index` 的错误，并直接给出改正方法（改用 `type=subdomain` 填 `domain`，或先解析 A/AAAA 记录），Agent 可据此自行修正后重插。同批次中的其他资产不受影响，照常入库。

### 贡献者

- [@neouks](https://github.com/neouks)

## [0.3.3] - 2026-08-23

### Worker

#### 新增的功能

- 运行中的 Worker 支持单项暂停、恢复和取消；暂停保留意图、事实与漏洞，取消会在执行退出后事务性清理当前意图及其直接产物。
- 增加 `paused` 意图状态、执行栅栏和具名终止原因，防止暂停、取消或任务删除后出现迟到黑板写入。
- 增加可选任务并发上限；新建、恢复、漏洞深入和队列补位统一通过持久化 FIFO 准入路径。

#### 修改的功能

- Worker 单次运行墙钟默认时长由 600 秒调整为 1200 秒；超时任务复活后在下一次真实执行时重新计时。
- Worker、Planner 和主 Agent 的真实执行状态统一驱动任务状态徽标，修复 Worker 运行时仍显示“空闲”的问题。
- Worker 会话保留单项控制和当前会话 Token 汇总，模型名称移动到当前会话标题右侧展示。

#### 删除的功能

- 删除 Worker 多选、全选及批量暂停/继续界面，同时移除 Worker 批量控制 API 和 Mock 契约。
- 删除 Worker 列表行中的 Token 徽标与 Tooltip，底层完整 Token 账本和任务聚合接口继续保留。

### LLM

#### 新增的功能

- 任务支持有序 LLM 配置链；明确识别供应商额度不足时自动切换下一配置，并持久化当前配置、耗尽状态和错误摘要。
- 运行中和暂停任务支持编辑完整配置链、调整顺序和手动切换当前配置，从下一次 LLM 调用生效。
- 自动切换、手动切换和全链耗尽写入结构化系统活动，并通过任务活动流弹出可去重提醒。
- 增加任务角色模型解析接口，统一解析 Main Agent、Planner 和 Worker 下一次调用使用的配置与模型。
- 增加可选的全局 LLM Pool，支持配置调用顺序、指定模型失败兜底、健康状态、冷却恢复和手动重置。
- 增加始终开启的 LLM 用量账本，按任务、会话、模型和配置聚合输入、输出及缓存 Token。

#### 修改的功能

- 目标拆解、Planner、Worker 和主 Agent 共享任务级 LLM runtime（解析优先级见下）。
- 故障转移只响应明确的额度、余额或账单错误；普通限流、鉴权、网络、服务端和上下文错误不会错误切换。
- LLM 配置页改为配置卡片列表和右侧抽屉编辑，并提供 Pool 轮询顺序、优先级、排除项、健康状态和恢复操作。
- 配置链耗尽信息支持窄屏换行；当前模型由会话列表图标改为当前会话标题旁的文字标签和完整 Tooltip。
- 任务内各角色解析 LLM 的顺序调整为「Agent 绑定 → 任务配置链 → 全局」：显式绑定模型的角色始终跑在该模型上，未绑定角色才落到任务链，任务链为空时再落到全局。
- 出站代理留空即直连，不再回退 `HTTP_PROXY`/`HTTPS_PROXY` 环境变量（显式 `ARTEX_LLM_PROXY` 不受影响）；代理输入支持带账号密码的 `socks5://user:pass@host:port`。

#### 修复的问题

- 提交前（尚未产出任何输出）的瞬时流式失败在同一 provider 上安全退避重试，显著减少「只跑了一两个工具就中断、无总结、终态 `model_error`」的情况；额度耗尽、上下文过长和 4xx 确定性错误不重试，仍分别交由故障转移与压缩恢复处理。

#### 删除的功能

- 删除会话列表中的 LLM 图标式标识，避免与 Worker 状态图标混淆。

### UI

#### 新增的功能

- 任务支持全局分类的创建、重命名、删除和筛选；新建任务可直接选择分类。
- 增加全局任务模板 CRUD 和右侧管理抽屉；新建任务可加载预设描述与目标，也可将当前内容另存为模板。
- 新建任务支持关联多个来源任务和多个企业资产范围；企业范围通过单个多行文本框自动识别域名、URL、IP、CIDR、ICP 和企业关键词。
- 任务测试资产支持实时新增和删除，记录人工、企业、继承或 Agent 发现等来源；Worker 会话标题旁显示当前测试资产及来源摘要。
- 发现页按任务分组并提供组内独立分页，支持为漏洞填写描述并创建高优先级深入意图。
- 对话支持重命名、置顶、取消置顶和删除；任务列表支持当前页批量暂停与继续。
- 流量详情和工具执行详情改为右侧抽屉；HTTP 报文补齐 `Host` 并高亮请求行、状态码、Header、JSON 和标记语言正文。
- 任务列表操作列新增「详情」与「暂停/继续」按钮；会话发送键位可在系统设置中配置（`Enter` / `Cmd+Enter` 等），Web 搜索区新增代理输入框。
- 会话标题右侧徽标改为显示 LLM 配置名称，模型 ID 移至 hover Tooltip；任务可设置可选名称，任务列表新增名称列与搜索（空则回退到描述）。
- 技能页增加使用次数、最近使用时间和缺失依赖统计，便于定位未生效或未安装的技能。

#### 修改的功能

- 任务标题改为可聚焦详情链接；任务资产、企业资产、发现任务组和组内漏洞使用服务端真实分页、稳定排序与精确总数。
- 新增企业改用右侧抽屉，范围录入统一为多行文本并提供实时识别、校验和类型预览。
- 主 Agent 输入框支持自动增长、`Enter` 发送、`Shift+Enter` 换行，并避免中文输入法组合态误发送。
- Agent 预览、任务报告和相关详情统一使用共享 Markdown 渲染；删除确认、长错误和移动端抽屉宽度统一修复。
- 任务模板选择框以模板名称显示和搜索、以模板 ID 提交；恢复系统原始字体尺寸，应用版本统一显示为 `0.3.3`。
- 任务总计和当前会话 Token 只高亮输入、缓存读取和输出数值；发送按钮使用更简洁的上箭头图标。
- 任务总览的测试范围显示企业名称而非 ID。

#### 修复的问题

- 含点号的普通文本不再被误判为 ICP 备案号。
- 修复变量目录中与全局运行时变量（如 `{{.Now}}`）撞名，导致 Agent 编辑器变量列表渲染出重复 key 的问题。

#### 删除的功能

- 删除任务卡片独立“进入”按钮，统一点击任务标题进入详情。
- 删除仪表盘“新建任务”按钮、新增企业的 Logo URL 输入项，以及发现页顶部和任务分组中的漏洞数量 Badge。
- 撤销全局字体增大 10% 的样式，并删除会话列表中的 Worker 选择框、模型图标和行级 Token 统计。

### Agent

#### 新增的功能

- 新任务可直接关联多个已有任务，实时只读继承直接来源任务的目标、事实、漏洞、已完成意图、资产范围和黑板上下文。
- 黑板读取工具支持按需查询来源任务节点、事实、漏洞和执行轨迹；继承节点带来源标记且所有写工具拒绝修改。
- 企业范围工具支持域名、URL、IP、CIDR、ICP 和企业关键词；关键词仅作为 Agent 范围提示，不参与资产自动归属。
- 漏洞深入操作会在原任务创建带资产锚点和 `derived_from` 边的高优先级人工 Worker 意图。
- 总览新增「目标管理」卡片，支持人工查看、新增、修改和删除目标；新增或修改会通知 Planner 并复活任务，删除硬删目标节点（级联删边与锚点）但不复活。
- 主 Agent 默认获得 `steer_work` 工具，可对运行中的 Worker 实时注入纠偏指令而不打断、不丢失进展（仍校验意图归属本任务）。

#### 修改的功能

- 来源任务意图不进入新任务 frontier，新任务继续使用独立 exploration、执行队列、工作目录和对话历史。
- 删除运行中的意图不再销毁数据：改为停到 `stopped`、要求填写删除原因、把原因作为事实挂到该意图并写入 payload，规划者按 `cancelled` 触发感知（保留意图内容与原因）。
- 主 Agent 对话改为服务端活动流驱动，发送失败可恢复输入；打开会话时自动贴底并在详情懒加载后保持最后回复可见。
- 任务暂停会终止当前 Main Agent、Planner 和 Worker 调用，但不阻止暂停期间用户主动发起新的主 Agent 编排会话。
- 取消、关闭和流式中断统一保留真实终止原因、已生成内容、运行轮数、耗时、Token 与未返回工具调用。

#### 删除的功能

- 删除主 Agent 客户端乐观消息回显，避免暂停、失败或并发活动下出现重复消息和跨会话串流。

### 约束

#### 新增的功能

- 目标拆解阶段先抽取操作约束（allow/deny）再拆目标，主 Agent 运行时可补充；约束按最高优先级注入 Planner 与 Worker 系统提示，去偏后多样性与拓面探索显式服从约束。
- 总览新增「约束管理」卡片与增删改接口；约束注入范围可按 Planner / Worker 分别开关（默认都开，每轮读取、即时生效）。新表 `task_constraints` 使用 `CREATE TABLE IF NOT EXISTS`，旧库自动补建。

### 拦截

#### 新增的功能

- 命令拦截在正则/字符串规则之外新增模型兜底审批：一条规则都未命中时由模型做 `ALLOW`/`ASK`/`DENY` 语义判定，失败回退动作与审批超时动作可配置；拦截页拆分「拦截规则 / 模型配置」两个 Tab，模型判定结果标注 `[模型]` 前缀与理由。

#### 修复的问题

- 加固裁判输出解析，避免正确的 `DENY` 判定被误当作放行。

### 流量

#### 修改的功能

- 流量录制改为整条 exchange 落 SQLite（大正文溢出到按 hash 去重的 blob 桶），文本正文建 trigram 全文索引，支持任意子串与中文搜索；删除退化为单条 SQL 事务，从数小时降到毫秒级且期间不再停摆录制。新增大 body 流式下载与 `traffic_search` 全文参数；旧文件树数据免迁移，仍可读、可搜、可删。

### 任务与资产

#### 新增的功能

- 创建任务新增「资产覆盖度功能」开关（默认开）：关闭后不计算与展示覆盖度、态势图只显示资产、不自动累积 `task_scope`，相关工具从 Planner / 主 Agent 剔除；企业关联不受此开关影响。
- `insert_assets` 每条资产新增 `related` 标记（默认 `true`）：仅在开启覆盖度时生效，`false` 只入共享资产库、不计入本任务覆盖度（如顺带发现的旁站或无关资产）。
- 企业范围和任务测试资产统一支持域名、URL、IP、CIDR、ICP 与关键词文本识别；域名/IP 可创建或复用全局资产，CIDR/ICP/关键词保留为任务范围上下文。

### 构建

- `build.sh --release` 支持一次构建 Linux amd64/arm64、macOS amd64/arm64 和 Windows amd64，并生成带 `skills/`、配置示例和 README 的 zip 发布包。
- 使用 Go linker 去除调试信息并生成 zip 发布包；UPX 改为显式可选，避免其自解压 ELF 在部分 Linux 环境启动时发生段错误。
- Release Workflow 对 Linux amd64 二进制执行启动冒烟测试，并随发布包提供 `SHA256SUMS`。

### 贡献者

- [@neouks](https://github.com/neouks)

## [0.3.2] - 2026-08-20

### Added

- 新建任务支持关联多个已有任务，实时、只读继承直接来源任务的事实、漏洞、已完成意图、资产范围和黑板上下文；新任务仍使用独立的执行队列、工作目录和会话历史。
- 任务支持有序 LLM 配置链。明确识别到供应商额度不足时自动切换到下一配置，并持久化当前配置、耗尽状态和结构化审计活动。
- 运行中和暂停任务支持编辑 LLM 配置链、调整顺序及手动切换当前配置；自动切换、手动切换和全链耗尽会在任务详情页提示。
- 运行中的 Worker 支持暂停、恢复和取消。暂停保留黑板数据，取消会在 Worker 停止写入后事务性清理该意图及其直接产出的事实、漏洞和执行记录。
- 删除任务可选择同时清理关联资产、流量、漏洞和任务落地文件，并增加删除屏障、并发保护和可审计的删除统计。
- 增加可选的任务并发上限；达到上限的新任务按 FIFO 排队，并在运行槽位释放后自动启动。
- 增加任务资产分页、公司资产分页、任务分类统计及分页意图 Mock 契约。
- 增加 `build.sh` 单二进制构建脚本，支持静态前端导出、资源嵌入、跨平台目标和构建版本注入。

### Changed

- 任务级显式 LLM 配置链与现有全局 LLM Pool 并存；显式链继续采用严格的额度故障转移语义，无显式链时沿用 Agent 绑定和全局配置规则。
- 主 Agent 输入框支持自动增长的多行输入，`Enter` 发送、`Shift+Enter` 换行，并避免中文输入法组合态误发送。
- Planner、Worker 和主 Agent 共享任务级 LLM runtime；任务链使用候选模型中最小上下文窗口作为安全压缩阈值。
- 任务详情页按真实 LLM 调用状态展示运行、空闲和暂停状态；来源任务的事实、漏洞、意图、资产引用和图谱节点统一标记来源并保持只读。
- Agent 预览、任务报告和相关详情视图统一使用共享 Markdown 渲染组件。
- LLM 模型配置采用卡片和抽屉交互，模型列表在抽屉内支持独立滚动。
- 任务暂停不再拦截主 Agent 对话：主 Agent 编排会话独立于任务暂停，暂停中仍可继续发送新消息（暂停只终止当前进行中的那一轮）。
- Worker 单次 run 的墙钟默认时长由 600 秒调整为 1200 秒。

### Fixed

- 移除主 Agent 控制台的乐观回显，改为纯服务端数据渲染，修复暂停或发送失败等场景下消息错乱、串入其他会话内容的问题。
- 打开主 Agent 会话默认滚动到底并完整显示最后一条回复：最后一条回复的完整内容懒加载展开后自动贴底，不再被顶出屏幕。
- 修复暂停任务后主 Agent 会话仍继续运行，以及编排 Agent 暂停任务时未同步停止主 Agent 的问题。
- 修复任务完成、Planner、Worker 或主 Agent 实际运行时，任务状态徽标与操作按钮状态不同步的问题。
- 修复 Worker 取消、任务删除和并发写入之间可能产生迟到黑板写入或残留文件的问题。
- 修复 Markdown 预览失效、删除确认长文本溢出、移动端宽度和部分任务详情按钮未对齐的问题。
- 为所有 Agent 取消路径增加具名终止原因，活动详情可显示取消方、终态、运行轮数、耗时、Token 使用量和未返回的工具调用。
- 修复后端关闭时父 context 可能抢先覆盖具名 `shutdown` 原因的竞态，以及中文活动摘要按字节截断导致乱码的问题。
- 修复带部分流式输出的取消事件丢失真实终止原因的问题，同时保留取消前已生成的内容。

### 贡献者

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)

[Unreleased]: https://github.com/Autumn-27/ARTEX/compare/v0.3.10...HEAD
[0.3.10]: https://github.com/Autumn-27/ARTEX/compare/v0.3.9...v0.3.10
[0.3.9]: https://github.com/Autumn-27/ARTEX/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/Autumn-27/ARTEX/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/Autumn-27/ARTEX/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/Autumn-27/ARTEX/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/Autumn-27/ARTEX/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/Autumn-27/ARTEX/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Autumn-27/ARTEX/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Autumn-27/ARTEX/compare/v0.3.1...v0.3.2
