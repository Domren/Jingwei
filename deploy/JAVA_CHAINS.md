# Java Chains 反序列化验证（可选）

Jingwei 可以把 [vulhub/java-chains](https://github.com/vulhub/java-chains) 作为独立 sidecar，并通过它的 **Streamable MCP** 把生成、服务、任务能力接入 Agent。Agent 调用 `java-chains` Skill 时解锁 `java_chains_*` 工具，直接完成选链、生成 payload、启动 JNDI/JRMP/FakeMySQL、发布任务和读取回连日志。sidecar **默认不启动**，也不包含在 Jingwei 镜像内。

> **许可证提醒**：java-chains 仓库当前未提供开源许可证，且应用本身闭源。请仅在你自己的环境中按官方方式拉取和运行，不要把它的镜像、二进制或配置打进 Jingwei 镜像/Release 分发。镜像版本固定为 `javachains/javachains:2.0.0-beta7`，升级前先在测试环境验证。

## 启动

在 `docker-compose.yml` 所在目录：

```bash
# 1) 在 .env 中设置强密码（会注入 Jingwei 容器，供 setup 脚本和 UI 登录使用）
#    JAVA_CHAINS_PASS=...
# 2) 只启动 sidecar（不会重启 Jingwei/PostgreSQL）
docker compose --profile java-chains up -d java-chains
# 3) 创建/轮换 Jingwei 专用 MCP token，启用 java-chains MCP，并写入 .env
bash deploy/java-chains-setup.sh
# 4) 让 Jingwei 读取新 token 并注册 JavaChains MCP
docker compose up -d --no-deps jingwei
```

访问 `http://localhost:9792`，用户名为 `admin`，密码为 `JAVA_CHAINS_PASS`（日志的 `Auth admin / ...` 行也会给出）。Jingwei 容器内使用 `http://java-chains:8011`（由 `JAVA_CHAINS_URL` 注入）。

`java-chains-setup.sh` 是幂等的：它登录 sidecar、启用 API token、复用/轮换名为 `jingwei-skill` 的 token（缺失则新建），再启用 MCP，最后把 token 写入 `.env` 的 `JAVA_CHAINS_MCP_TOKEN`（文件权限 600）。需要 python3，不会打印完整 token。

停止：

```bash
docker compose --profile java-chains stop java-chains
```

## 端口

| 宿主机 | 容器 | 用途 | 默认绑定 |
| --- | --- | --- | --- |
| 9792 | 8011 | Web UI（有登录） | `127.0.0.1` |
| 58080 | 58080 | JNDI HTTP | `127.0.0.1` |
| 50389 | 50389 | JNDI LDAP | `127.0.0.1` |
| 50388 | 50388 | JNDI RMI | `127.0.0.1` |
| 13999 | 13999 | JRMP Listener | `127.0.0.1` |
| 3308 | 3308 | FakeMySQL | `127.0.0.1` |
| 50000 | 50000 | HTTP Server | `127.0.0.1` |
| 11527 | 11527 | TCP Server | `127.0.0.1` |

回调端口默认只绑定本机，适合验证本机/容器内目标。**目标在远端时**，把 `.env` 中的 `JAVA_CHAINS_CALLBACK_BIND` 改为 `0.0.0.0` 或指定网卡地址，重建 sidecar，并放行防火墙；在 Web UI 里把回调地址设为目标可达的宿主机 IP/域名。测试结束立即关闭端口、恢复绑定。

回调端口没有认证，不能长期暴露公网。

### 宿主机发布地址 ≠ 容器内监听地址

`JAVA_CHAINS_CALLBACK_BIND` 只决定 docker **在宿主机哪块网卡上发布**这些端口；sidecar 进程自己的监听地址由
`JAVA_CHAINS_LISTEN_BIND` 决定（默认 `0.0.0.0`），因为容器有独立网络命名空间，docker-proxy 是把连接转发到
**容器的 eth0 IP**，不是容器自己的 loopback。把监听也设成 `127.0.0.1`，宿主机端口看着是开的、`curl` 也通，
后面却没有任何进程在容器内的 eth0 上监听，于是无论目标是本机、其他容器还是远端主机，永远回连不上——
LDAP 表现为 `anonymous bind failed` / `LDAP connection has been closed`，日志里连一条 lookup 都没有。

`JAVA_CHAINS_LISTEN_BIND` 不改变暴露面：外部能否连到回调端口仍由 `JAVA_CHAINS_CALLBACK_BIND` 决定。
`java_bind_host` 走的是这个监听地址，`java_callback_host` 才是写进 payload 的回连地址，两者可以不同
（本机靶场：bind `0.0.0.0` + callback `127.0.0.1`；远端靶机：bind `0.0.0.0` + callback 宿主机可达 IP）。

## 正路径实测

反序列化 payload 的构造—投递—回连—确认全链路已在真机上跑通，两侧都是真实组件（不是 mock）：
java-chains sidecar `javachains/javachains:2.0.0-beta7` + Tomcat9/JSP on JDK17 上的 fastjson 型
JNDI sink（读 body 里的 `dataSourceName` 后 `new InitialContext().lookup(...)`）。

集成测试 `server/java_chains_deep_live_test.go` 默认 `t.Skip`，同时设置以下变量才会执行：

```bash
JAVA_CHAINS_MCP_TOKEN=... JAVA_CHAINS_URL=http://127.0.0.1:9792 \
JAVA_CHAINS_LIVE_TARGET=http://<靶机>:8081 \
JINGWEI_PG_DSN=postgres://... go test -p 1 -count=1 -run TestJavaChainsLive ./server/
```

它按自动链路的原样入口 `runJavaChains` 跑一条本地构造的 nuclei 模板（`ldap://{{interactsh-url}}/jwlab`），
断言的不只是「没报错」：

- 预设 `java.fastjson.jndi` 被选中并成功发布，投递的是**改写后**的原始报文（含 `ldap://<callback>:50389/<token>`，
  不再有 `{{interactsh-url}}` 占位符）；
- sidecar `runtime_logs` 出现该 token 的 `outcome=lookup|serve`，模板因此被判为**已确认复现**
  （`verdict=confirmed`，证据保留请求/响应），而不是「已投递」；
- 回调端口登记成受管资源，任务结束后发布数归零、JNDI 服务停止、台账行 released；
- 另一条用例先把 JNDI 服务起在 `127.0.0.1` 再要求 `0.0.0.0`，验证平台会察觉 `bound.host` 与要求不一致、
  重启服务并重新发布，而不是把 payload 投到一个没人监听的地址上。

JDK17 上 lookup 到达侧车后，对象反序列化会被 JDK 自己拒掉（`Object deserialization is not allowed`），
这不影响「目标确实回连了」的判定——回连确认的是注入点可达，不是链子打通。

## Skill / MCP 集成

`skills/java-chains/SKILL.md` 随镜像构建进入 `/app/skills`，默认对 `auto`、`pentest`、`worker` 可见。它声明 `mcps: JavaChains`：

- Jingwei 启动时若检测到 `JAVA_CHAINS_MCP_TOKEN`，会 upsert 一个名为 `JavaChains` 的 Streamable HTTP MCP，地址为 `${JAVA_CHAINS_URL}/api/mcp`，请求头 `X-Api-Token` 取自该变量。
- MCP 工具是 **skill-gated**：默认不出现在 Agent 的工具列表里；Agent 调用 `Skill("java-chains")` 后，这 27 个 `java_chains_*` 工具才会解锁。
- 能力覆盖：预设/目录搜索与校验、`quick_generate`、`quick_jndi`、artifact 管理、JNDI/MySQL/JRMP/TCP/HTTP 服务启停、异步任务提交/日志/取消。
- 生成结果是私有 artifact（约 1 小时过期）。Skill 内的 `scripts/fetch-artifact.sh` 用容器环境里的 token 下载字节，供注入使用。

在「系统 → Skill」可查看可见性；把 Skill 分配给其他 Agent 即可让它们也获得这套工具。`JAVA_CHAINS_MCP_TOKEN` 为空时不会注册 MCP，Skill 会降级为 Playwright 操作 Web UI。token 轮换后重跑 `bash deploy/java-chains-setup.sh` 并重启 Jingwei。

Web UI（`http://127.0.0.1:9792`）仅用于排障和手动操作，不进入 Jingwei 侧栏，也不参与 Skill/MCP 调用。

## 深度任务自动调用

「漏洞验证」「漏洞利用」任务在检测到 Java 反序列化 POC（fastjson/fastjson2、Shiro、Jackson、XStream、WebLogic、JBoss、WebSphere、Log4j2，以及带 CWE-502 的 Java POC）时，会**自动**调用 java-chains，无需 Agent 参与：

1. 用 `presets_search` 按漏洞家族选预设（优先 `outbound-jndi`，其次 `command-exec`）；
2. `quick_jndi` 发布 JNDI payload（默认执行 `id`）；
3. 把模板 raw request 里的 `ldap://{{interactsh-url}}/...`、`rmi://...` 改写为 java-chains 的 LDAP 地址；
4. 向目标投递（最多 2 个变形），随后轮询 `runtime_logs`，以 token + `outcome=lookup|serve` 判定回连；
5. 证据以 `mode=java_chains` 写入任务详情：`confirmed`（回连确认）、`attempted`（已投递未回连）、`payload_generated`（模板无 JNDI 注入点，仅生成 payload 取证，artifact 随即删除）。

每个任务最多处理 5 个反序列化 POC。任务结束会删除所有 java-chains job，并在没有其他有效发布时自动停止 JNDI 服务；sidecar 容器本身保持运行，空闲时仍应手动 `docker compose --profile java-chains stop java-chains`。

任务参数（创建时可覆盖）：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `java_chains` | `auto` | 设为 `off` 关闭本任务自动调用 |
| `java_cmd` | `id` | 通过预设执行的低风险命令 |
| `java_bind_host` | `JAVA_CHAINS_LISTEN_BIND`（默认 `0.0.0.0`） | JNDI 服务在**容器内**的监听地址，不要填 `127.0.0.1` |
| `java_callback_host` | `JAVA_CHAINS_CALLBACK_HOST` | 写入 payload、供目标回连的地址 |
| `java_chains_wait` | `12` | 回连等待秒数（3–30） |

前端通过 `GET /api/deep/java-chains/status` 显示未配置/未启动/在线状态（不回显 token）。sidecar 未启动时任务照常执行，只在 summary 中记录 `java_chains_note`。

## 数据与升级

默认不挂载 `chains-config`，这样镜像内置的插件、预设和配置不会被空目录覆盖；sidecar 删除后这些运行期修改会丢失。需要持久化时：

```bash
docker cp jingwei-java-chains-1:/chains/chains-config ./java-chains-config
```

然后在 Compose 的 `java-chains` 服务下增加：

```yaml
volumes:
  - ./java-chains-config:/chains/chains-config
```

升级只需修改 `JAVA_CHAINS_IMAGE`（或编辑默认 tag）后重建该服务。先备份 `chains-config`，并确认新版本仍兼容现有插件。

## 故障排查

- **拉取镜像失败**：java-chains 在 Docker Hub，网络受限时给 Docker 配置代理或可用镜像源；不要修改 Jingwei 的镜像地址。
- **worker 访问不到**：确认 sidecar 已启动、与 Jingwei 在同一 Compose 网络；在 Jingwei 容器内执行 `curl -fsS http://java-chains:8011`。
- **java_chains_* 工具没出现**：看 `docker logs jingwei-jingwei-1 | grep -i java-chains` 是否有注册/发现日志；确认 `JAVA_CHAINS_MCP_TOKEN` 非空、重建过 Jingwei，且 Agent 已绑定 java-chains Skill。token 失效时重跑 setup 脚本。
- **MCP 注册了但工具发现失败**：在宿主机 `curl -H "X-Api-Token: $JAVA_CHAINS_MCP_TOKEN" http://127.0.0.1:9792/api/mcp -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"check","version":"1"}}}'` 自检；403 表示 token 无 `mcp:invoke` 或已轮换。
- **登录失败**：`JAVA_CHAINS_PASS` 必须与 sidecar 启动时一致；修改后重建 sidecar。
- **没有回连**：先问「侧车到底监听在哪」——`java_chains_services_get {"service":"jndi"}` 看 `bound.host`，
  是 `127.0.0.1` 就是监听落在容器 loopback 上、目标永远到不了（见上文「宿主机发布地址 ≠ 容器内监听地址」，
  改 `JAVA_CHAINS_LISTEN_BIND` 后需重启 JNDI 服务，`quick_jndi` 对已运行的服务不会换绑）。已确认 Jingwei 会自动
  察觉并重启重发，日志里会写「JNDI 服务实际监听 …，与要求的 … 不一致，重启服务后重新发布」。
  其余检查：目标到回调 IP/端口的连通性、JDK 版本（JDK 的 JNDI LDAP provider 默认
  `trustSerialData=false`，新 JDK 上 lookup 可达但对象不会被反序列化）、gadget 依赖和编码；
  目标侧有 WAF/黑名单时换链或换编码。

## 安全

- 仅用于已授权、在范围内的目标；外发利用请求仍应经过平台拦截/审批。
- 先做低破坏性证明（`id`、`whoami`、`sleep`、DNSLog），确认后再执行任务许可的动作。
- 不要把 8011 或回调端口直接暴露到公网；需要远程访问时放在带认证的反向代理和防火墙之后。
