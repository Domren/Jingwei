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

### 1.6.0 那一批（六个协议，独立清单）

Jenkins / MSSQL / SMB / JBoss(WildFly) / RDP / RouterOS 这六条的口令是起服务时写死的（容器
`init` 与 CHR 首次配置），不能像 `up.sh` 那样现生成，所以单独一份清单：

```bash
tools/e2e/credscan-lab/docker-labs.sh up        # jenkins / mssql / wildfly 三个容器
tools/e2e/credscan-lab/six-pack.sh              # 写 /tmp/jw-cred-lab-6/lab.json
JW_CRED_LAB=1 JW_CRED_LAB_MANIFEST=/tmp/jw-cred-lab-6/lab.json \
  go test ./scanner -run TestCredLabProtocols -count=1 -v
```

只用 `-run TestCredLabProtocols`：`up.sh` 那批服务（Redis/PG/MySQL/…）这会儿没起，跑整包会
先失败在「真机清单读不到」上——**这不是回归**，是清单来源不同。`six-pack.sh` 只写清单不起服务；
SMB / RDP / RouterOS 三条按下面「手动起剩下三条」起。

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
| Jenkins | 真 Jenkins LTS（容器，`init.groovy.d` 预建账号跳过安装向导）：`/j_spring_security_check` 提交 + `whoAmI` 认证探针 | 容器 `jw-lab-jenkins`，127.0.0.1:18080 |
| MSSQL | 真 SQL Server 2022 Linux（TDS 与 Windows 版同协议，差别只在 SSPI）：PreLogin + Login7 → `LOGINACK(0xAD)`/`ERROR(0xAA)` | 容器 `jw-lab-mssql`，127.0.0.1:11433 |
| SMB | 真 Samba 4.24：SMB2 NEGOTIATE + NTLMSSP 三消息，**NTLMv2 应答真算**（MD4 + HMAC-MD5） | 宿主机 445，配置在 `/tmp/jw-smb` |
| JBoss / WildFly | 真 WildFly 25 管理接口：`/management` 的 **HTTP Digest**（ManagementRealm）；Basic 带着正确口令也是 401 | 容器 `jw-lab-wildfly`，127.0.0.1:19990 |
| RDP | 真 xrdp 0.10：X.224 + RDP Negotiation。**只验识别与安全层判定**——xrdp 只允许 TLS，适配器据此落 `inconclusive`，不判口令 | 宿主机 3389 |
| RouterOS | 真 RouterOS 7.16.2 CHR（qemu + KVM）：句子协议 `/login`，`!done` 才算接受 | 127.0.0.1:18728（转发到 CHR 的 8728） |

容器批用 `docker-labs.sh up`（jenkins / mssql / wildfly 三条），Samba 与 xrdp 直接起在宿主机上，
RouterOS 走 qemu（见下）。

### 手动起剩下三条（不进 `up.sh`）

`up.sh` 只碰「装包能还原」的服务；Samba/xrdp 要 root、CHR 要 128MB 镜像与串口自动化，
所以单独起：

```bash
# Samba（445）：/run/samba/ncalrpc 必须先建，否则 smbd 直接退
mkdir -p /run/samba/ncalrpc
useradd -M -s /usr/sbin/nologin jwlab
printf 'jwlab123\njwlab123\n' | smbpasswd -s -a jwlab
smbd -D --no-process-group

# xrdp（3389）
mkdir -p /var/run/xrdp/sockdir && xrdp -n >/tmp/xrdp.log 2>&1 &

# RouterOS CHR：官源慢，用 Range 分段下；qemu 起来后必须走完首次改密码
qemu-system-x86_64 -enable-kvm -m 512 -smp 2 \
  -drive file=chr-7.16.2.img,format=raw,if=ide \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:18728-:8728 -device e1000,netdev=n0 \
  -display none -serial unix:/tmp/chr-serial.sock,server=on,wait=off \
  -daemonize -pidfile /tmp/chr.pid
# 串口：admin / 空密码 → 强制改密码 → jwlab123（两次）
```

每个用例都断言四件事：`Identify` 在真服务上确认协议**且留下非空 banner**（报告要能说明凭什么）；
正确凭据落到清单声明的结果态；错误凭据落到 `deny` 并**同样留下证据**；清单里写了 `expect_tls` 的用例，
结果的 `TLS` 标记必须为真、且证据必须说明「字节是 TLS 通道内的明文」。最后这条是必要的：
「悄悄退回明文」不会改变 outcome，只会让报告里的复现命令变成一条发不出去的裸 socket。
只验命中等于没验「拒绝长什么样」，而 deny 是报告里唯一能说「这组口令被排除」的态。

除逐协议用例外还有两条真机守卫：

- **不靠端口猜协议**：把 8 个适配器逐个按在 HTTP 端口（默认 `127.0.0.1:8080`，可用
  `JW_CRED_LAB_HTTP` 指到别处）上，任何一个确认成功都是缺陷。
- **空凭据不能判成命中**：Redis 未开认证与 PG trust 两类除外——那两条的空口令本身就是结论。

## 已删除的四个协议（2026-11-09，负责人决定）

Oracle / WebLogic 控制台 / WinRM / CobaltStrike 这四条在这里起不了真服务，也找不到别的
可复现环境，**按负责人决定整条删除**——协议名、适配器、进程内桩、字典条目一起删，协议目录
从 35 个降到 31 个。这不是「暂时跳过」：只靠桩的「支持」不算支持，留着选项反而会让一次
`inconclusive` 被读成「环境不通」。

| 协议 | 当时为什么验不了 |
| :-- | :-- |
| Oracle | 认证要 O3LOGON（DES + AUTH_SESSKEY）与 12c 的 PBKDF2，原型只做到「发认证请求 + 按 ORA-01017 判拒绝」，命中路径走不通；XE 镜像要 Oracle 账号登录下载 |
| WebLogic | 官方镜像要 Oracle 账号接受协议、约 12GB；表单登录与版本强相关（12c/14c 差异未覆盖） |
| WinRM | 只在 Windows 上，且服务端普遍要求 SPNEGO——不实现 SPNEGO 时正确口令也只能落 `inconclusive`。为它准备的 `windows-sandbox/`（.wsb + 反代脚本）随之一并删除 |
| Cobalt Strike | 商业 Team Server，私协议且拿不到合法服务端 |

要加回来必须三件一起：可复现的真服务、适配器、本目录里的真机用例。原型的实现可查
`8de3869` 之前的提交。

**留下的教训**（比这四条本身值钱）：上面已经真机验过的 8 条，桩仍保留作回归保护，但桩的帧
必须按真机抓到的形状写——MSSQL/SMB/JBoss/Jenkins 四条最初的桩是按**错误实现**写的，测试一直绿
（见下面「坑」里对应的几条）。桩与适配器由同一个人按同一份（错的）理解写出来，两边对得上，
测试就绿了。

**唯一没有真机用例的协议**是 `smtp-ssl`（465 隐式 TLS）：它和 `pop3-ssl`/`imap-ssl` 走同一套
`upgradeTLS` 路径，但那两个验过不代表它验过。补法很便宜（postfix 开 465 + 自签证书），本轮没做。

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
- **docker daemon 的代理指向 Clash 时什么都拉不下来**：`/etc/systemd/system/docker.service.d/http-proxy.conf`
  里写着 `127.0.0.1:7890`，Clash 关着时 `docker pull` 直接 `connection refused`。不是缺陷，是环境：
  把 drop-in 挪走、镜像走 `docker.m.daocloud.io` / `docker.1ms.run` 前缀直连即可。
  `mcr.microsoft.com` 的镜像要用 `m.daocloud.io/mcr.microsoft.com/...`；`jenkins` 的官方仓库是
  `jenkins/jenkins`（`library/jenkins` 是 2018 年废弃的旧镜像，镜像源上普遍 403/404）。
- **Samba 4.24 起 smbd 要求 `/run/samba/ncalrpc` 存在**，否则启动即退，日志只有一句
  `mkdir failed on directory /run/samba/ncalrpc`。另外 `smb ports` 在这个版本已改成
  `server smb transports`（值是 tcp/rdma，**不是端口号**），想换端口只能改监听地址或在
  容器里做映射。
- **WildFly 官方镜像只绑 127.0.0.1**：`jboss/wildfly` 的 CMD 是 `standalone.sh -b 0.0.0.0`，
  没带 `-bmanagement`，所以 9990 只监听容器内回环，宿主端口映射连不进去。要 `-bmanagement 0.0.0.0`。
- **WildFly 管理台是 Digest，不是 Basic**：`/management` 回
  `WWW-Authenticate: Digest realm="ManagementRealm"`，`curl -u admin:正确口令` 照样 401；
  而 `/console` 未认证直接 302 到 index.html，**根本不做认证**——拿它当认证探针永远判不出结论。
  管理用户要用 `add-user.sh -m`（ManagementRealm），`-a` 建的是 application realm。
- **CHR 镜像官源单连接只有 ~18KB/s**：40MB 的 zip 要下 40 分钟。官源支持 Range，用 8 段并行
  （每段校验长度并重试）能压到 3 分钟。首次启动的串口是**全屏重绘**，按行读会错过
  `new password>`；而且它会**强制改密码**——没按提示走完就退出，镜像里的 admin 密码会变成
  一个谁都不知道的值，只能重新解压镜像重来。
- **真机最值钱的地方是「桩按错误实现写的」**：MSSQL 的桩按错误的 Login7 布局回帧、SMB 的桩
  按占位 NT 应答回帧、JBoss 的桩按 Basic 回帧，三条测试当时全绿，真机一跑全崩。桩只能证明
  「代码与桩一致」，证明不了「与协议一致」。
