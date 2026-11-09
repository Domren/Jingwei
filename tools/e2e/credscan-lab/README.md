# 弱口令检测协议真机验证台（credscan-lab）

规划表 B3a 的验收口径是「**每个协议都要在真实服务上验证命中与拒绝两条路径**」，不接受
「字典加载跑通」当验证。这个目录就是为这条口径存在的：`up.sh` 在宿主机上摆出一批**真守护进程**，
`scanner/credscan_lab_test.go` 用被测代码本身的适配器逐个打它们。

## 为什么不能只靠进程内靶子

适配器的错误绝大多数只有在线上路得出来：MySQL 包序号差一格、PG 的 SASLInitialResponse
长度少算一个 NUL、SCRAM 的 nonce 拼接多一个字节——自写的 Go 靶子和自写的适配器**可能错得
一模一样**，两边一对，测试还是绿的。真库另有两件事自写靶子给不了：PG 16 默认就是
scram-sha-256、MariaDB 默认是 native，而 `caching_sha2_password` 的**完整认证通道**（RSA-OAEP
公钥加密那一段）只有真 MySQL 8 会逼你走。

## 用法

```bash
tools/e2e/credscan-lab/up.sh                                    # 起服务、生成清单
JW_CRED_LAB=1 go test ./scanner -run TestCred -count=1          # 引擎单测 + 真机用例一起跑（约 156s）
tools/e2e/credscan-lab/down.sh                                  # 关服务、恢复系统配置、删临时账号
```

`up.sh` 可以反复跑：口令每次**现生成**（同一 (协议, 标签, 主机, 端口) 的条目会被替换而不是追加），
Ubuntu-1 上的软件包只有在本轮新装时才由 `down.sh` 卸载（用 `/tmp/jw-cred-lab/*-installed-by-lab` 标记）并写进 `/tmp/jw-cred-lab/lab.json`（600 权限，不落仓库、
不打印），检测到上一次遗留的实例时会重启并重新登记，避免「服务在跑但口令已经换了」这种
假失败（WRONGPASS / Authentication failed 都是这么来的，别把它当成适配器的缺陷）。
没开 `JW_CRED_LAB=1` 或缺清单文件时测试直接 Skip——所以普通 `go test ./...` 不碰网络。

`go test ./...` 默认口径下这个包也是绿的，**这是刻意的**：真机验证没跑就要红，得靠人记得
在发版前带上 `JW_CRED_LAB=1` 重跑一次，并把结果写进进度手册 §4 的台账。

## 这一台覆盖什么

| 协议 | 覆盖的认证形态 | 位置 |
| :-- | :-- | :-- |
| Redis | `requirepass` 命中/拒绝；**未开认证**（空口令就是命中本身） | 宿主机 16399 / 16400 |
| PostgreSQL | scram-sha-256、**md5**（`password_encryption` 逐档切）、**trust**（期望 `hit`，且没有口令可言）；**服务端开着 TLS，三档都在通道内认证** | 容器 `jw-cred-pg`，127.0.0.1:55455 |
| MongoDB | scram-sha-256 与 **scram-sha-1**（同一个 `jwadmin` 两个机制） | 容器 `jw-cred-mongo`，127.0.0.1:27077 |
| MySQL | `caching_sha2_password` 与 `mysql_native_password` 两个账号 | 边界靶机 Ubuntu-1:3306 |
| SSH | 口令认证命中/拒绝 | Ubuntu-1 转发到宿主机的 2201 |
| Socks5 | danted 的 **username 认证**；`ssh -D` 的**无认证**代理 | 10800 / 10801 |
| FTP | vsftpd + PAM 本地账号 | 宿主机 21 |
| Telnet | netkit telnetd（经 socat 起在 23230） | 宿主机 23230 |
| HTTP Basic | Apache 2.4 + `AuthType Basic` + htpasswd | Ubuntu-1:8092 |
| WebDAV | Apache 2.4 `Dav On` + 认证（用 `/sub/`：2.4.52 对文档根本身的 PROPFIND 返回 405） | Ubuntu-1:8093 |
| Tomcat 管理台 | tomcat9-admin 的 `/manager/html` + manager-gui 角色（验完恢复 tomcat-users 并卸载包） | Ubuntu-1:8081 |
| Elasticsearch | 8.15 X-Pack Basic（HTTP 层关 TLS，认证语义不变） | 容器 `jw-cred-es`，127.0.0.1:9200 |
| Memcached | 文本协议、默认无认证（`version` 有应答即命中空凭据） | 宿主机 11212 |
| SNMP | 真 `snmpd` 的 v2c community 认证（**UDP**）：正确 community 命中；错 community 按 RFC 3412 静默丢弃 → 期望 `inconclusive` | 宿主机 16161/udp |
| SVN | 真 `svnserve` 的 **CRAM-MD5**（原生机制）：`( step ( <len>:<challenge> ) )` → `HMAC-MD5(口令, challenge)`；拒绝态措辞是 `( failure ( 18:Password incorrect ) )` | 宿主机 3691 |
| Zookeeper | 四字命令 `ruok` 有应答（3.4 默认放开） | Ubuntu-1:2181 |
| SMTP | postfix（2525 上的 SASL 入口）+ dovecot auth 套接字；`AUTH PLAIN` 235/535 | Ubuntu-1:2525 |
| POP3 / IMAP | dovecot + passwd-file（文件必须 root:dovecot 0640） | Ubuntu-1:110 / 143 |
| POP3-SSL / IMAP-SSL | dovecot 隐式 TLS（安装时自签证书） | Ubuntu-1:995 / 993 |
| LDAP / LDAPS | slapd + `uid=jwcred,ou=people,dc=lab,dc=local` 简单 bind；LDAPS 用自签证书（`SLAPD_SERVICES` 要含 `ldaps:///`） | Ubuntu-1:389 / 636 |
| VNC | TigerVNC VncAuth（`-BlacklistThreshold 1000` 关闭验证期间的黑名单） | Ubuntu-1:5901 |

每个用例都断言四件事：`Identify` 在真服务上确认协议**且留下非空 banner**（报告要能说明凭什么）；
正确凭据落到清单声明的结果态；错误凭据落到 `deny` 并**同样留下证据**；清单里写了 `expect_tls` 的用例，
结果的 `TLS` 标记必须为真、且证据必须说明「字节是 TLS 通道内的明文」。最后这条是必要的：
「悄悄退回明文」不会改变 outcome，只会让报告里的复现命令变成一条发不出去的裸 socket。
只验命中等于没验「拒绝长什么样」，而 deny 是报告里唯一能说「这组口令被排除」的态。

除逐协议用例外还有两条真机守卫：

- **不靠端口猜协议**：把 8 个适配器逐个按在 HTTP 端口（默认 `127.0.0.1:8080`，可用
  `JW_CRED_LAB_HTTP` 指到别处）上，任何一个确认成功都是缺陷。
- **空凭据不能判成命中**：Redis 未开认证与 PG trust 两类除外——那两条的空口令本身就是结论。

## 本台覆盖不到、且**没有**真机验证的协议

1.6.0 补的二档/三档适配器里有 10 条在这台机器上起不了真服务。这不是「暂时跳过」，
是**缺口**，写在各自的适配器文件头里，发版台账也不许把它们算成已验证：

| 协议 | 为什么这里跑不了 | 现在验到了哪一步 |
| :-- | :-- | :-- |
| MSSQL | 服务端是 Windows/Linux 的 TDS 实现，镜像拉不动（`mcr.microsoft.com` 出网受限）；且 Login7 布局尚未按 [MS-TDS] 逐字段核对、TLS/SSPI 未实现 | 进程内协议桩：LOGINACK(0xAD)→hit、ERROR(0xAA)→deny |
| SMB | 同上；且 [MS-NLMP] 的 NTOWFv1(MD4)/NTLMv2 未实现，Type3 的 NT 应答是派生占位值——真 Samba 必然拒绝，跑出来的 deny 与适配器无关 | 进程内协议桩：STATUS_SUCCESS→hit、0xC000006D→deny、0xC0000234→locked |
| RDP | 需要 Windows 终端服务或 xrdp；适配器只到 TPKT/X.224 + 连接确认，安全层（CredSSP/NLA）未实现 | 进程内协议桩 |
| WinRM | 只在 Windows 上；且本平台不实现 SPNEGO，服务端要 Negotiate 时只能落 inconclusive | 进程内协议桩 + `TestCredWinRMNegotiateIsInconclusive` |
| Oracle | 没有可用实例；O3LOGON(DES/AUTH_SESSKEY) 与 12c PBKDF2 未实现 | 进程内协议桩：AUTH_OK→hit、ORA-01017→deny |
| RouterOS | 只能跑在 Mikrotik 设备/CHR 上 | 进程内协议桩 |
| Cobalt Strike | 商业 Team Server，私协议 | 进程内协议桩 |
| WebLogic / JBoss | 控制台容器太重且镜像拉不动；JBoss 走 Basic（一轮）、WebLogic 走表单三跳 | 进程内协议桩 |
| Jenkins | 可装但需要 JDK + 服务；表单三跳（crumb → j_acegi_security_check → whoAmI）已在桩里钉住 | 进程内协议桩 |

「进程内协议桩」指的是 `scanner/credscan_new_adapters_test.go`：桩按协议真实编码回帧
（Login7/NTLMSSP 的用户名是 UTF-16LE、svnserve 的 PLAIN 是 base64、WinRM 的识别证据是
`Microsoft-HTTPAPI` 的 Server 头），因此它能抓住实现错误，但**代替不了真服务**——
这也是把缺口逐条列出来的原因。

## 已知的环境坑（写下来是为了下次别再踩）

- **svn 的报文没有换行**：svnserve 的 S-expression 以空格分隔、不以 `\n` 结尾。照行读会在
  每条报文收尾处白等到「首包耐心」（6s），一轮 CRAM-MD5 四条报文直接吃光单次尝试的 20s
  上限，表现为 `dial tcp: i/o timeout`——其实是前一条读把预算耗完了。适配器里用
  `svnReadMsg`（按静默期收一条）就是这个原因。
- **svnserve 的 hello 必须带客户端标识**：`( 2 ( edit-pipeline svndiff1 ) <len>:<url> <len>:<client> ( ) )`
  少了 `<len>:<client>` 这一项，服务端解析后续项错位，发完 hello 直接断连——看起来像
  「svnserve 不认这个协议」。客户端标识原样用 `SVN/1.14.5 (x86_64-pc-linux-gnu)`。
- **svnserve 的 passwd 文件必须有 `[users]` 段**：没有它 svnserve 认为一个用户都没有，
  表现是口令正确也 `Authentication failed`（并且 `svn` 客户端同样连不上，可以先拿客户端自证配置）。
- **CRAM-MD5 的 challenge 要原样算**：HMAC 的 msg 是服务端 `( step ( <len>:<challenge> ) )`
  里那串字节本体（**含尖括号**），去掉 `<>` 或去掉长度前缀算出来的值都对不上。口径是用
  真 svnserve 抓包 + 已知口令反推确认的。
- **snmpd 在 WSL 里要 `-u root`**：net-snmp 默认降权到 `Debian-snmp`，在 WSL 的 rootfs 上
  起不来，日志里只有一句权限错误，端口根本不监听。
- **vsftpd 用不了自定义配置**：给 `vsftpd /tmp/xxx.conf` 会 rc=2 退出。改发行版自带的
  `/etc/vsftpd.conf`，`up.sh` 先备份到 `/tmp/jw-cred-lab/vsftpd.conf.orig`，`down.sh` 恢复。
- **danted 1.4 的配置语法**与 1.x 旧教程不同（`client pass` / `socks pass` 两段式），
  且要 `/etc/pam.d/sockd` 存在才走 username 认证；`up.sh` 建了这个文件，`down.sh` 只在
  确认是自己建的（留下 `sockd-pam-created` 标记）时才删。
- **PG 的 pg_hba 在容器里**：`up.sh` 用 `show hba_file` 取路径再写，不能假设 `/etc/postgresql/...`；
  切 md5 与 scram 靠 `alter system set password_encryption` + `reload`，顺序错了存进去的哈希
  就是下一种机制的，表现为「口令明明对却 deny」。
- **PG 的 TLS 必须重启才生效**：`ssl` 是 postmaster 级参数，`pg_reload_conf()` 不动它。`up.sh`
  在主机上用 openssl 生成自签证书、`docker cp` 进数据目录、`chown root:root` + `chmod 600` 私钥
  （权限不对 postmaster 直接拒绝加载），再 `alter system set ssl='on'` 与证书路径，最后
  `docker restart`。开 TLS 不是为了加密本身，而是为了让 `Identify` 与 `Try` **两条路径都被真的走过**
  ——就是这样抓到「`Identify` 收到 `'S'` 后没升 TLS，明文发启动包被服务端直接断开」这条缺陷。
- **MongoDB 镜像拉不动**：dockerd 的代理指向宿主 Clash，Clash 关着时 `docker pull` 必然失败
  （这不是缺陷，别去改那个 drop-in）。用 `skopeo copy docker://docker.m.daocloud.io/library/mongo:...
  docker-daemon:` 绕。
- **Ubuntu-1 的 MySQL 管理口**要用 `mysql --defaults-file=/etc/mysql/debian.cnf`，不是随便一个 root 口令。
- **靶机没开时**：`up.sh` 里 SSH/MySQL/Socks5 三档会跳过并说明原因，清单只剩本机的用例。
  跑完整 14 条要先把 Ubuntu-1 起来（`wslrun.sh`，路径可用 `JW_LAB_RUN` / `JW_LAB_DISTRO` 覆盖）。
- **`down.sh` 只清理本验证台**：它删临时容器、临时用户、恢复被改过的系统配置、删清单与口令文件；
  **不动三台边界/内网靶机上已有的渗透载荷**，那是另一套台账管的。
