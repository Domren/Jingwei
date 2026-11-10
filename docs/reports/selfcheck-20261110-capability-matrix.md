# 1.5.0 / 1.6.0 能力矩阵真机回归报告（2026-11-10）

- 测试目标：独立 jingwei 测试实例 `http://127.0.0.1:9792`（容器 `jw-test`，不触碰用户实例 `9790/9791`）
- 靶场：三台 Ubuntu 容器 + Tomcat 容器，网络 `jwlab`(10.10.0.0/24) + `jwlab-int`(10.10.1.0/24)
  - `jw-a` 10.10.0.11（边界 Web：nginx + PHP + MySQL + FTP + SSH）
  - `jw-b` 10.10.0.12 / 10.10.1.12（服务面：SSH/Redis/SMB/SNMP/Memcached + cron/socat）
  - `jw-c` 10.10.1.13（仅内网纵深）
  - `jw-java` 10.10.0.14:8080（tomcat:9-jdk17）
  - `jw-dns` 10.10.0.15（DNS）
- 数据库：`jingwei-test-pg`（127.0.0.1:55433，库 `jingwei_lab`）
- 结论：**已覆盖能力 PASS；发现 2 处缺陷并修复回归；未测项均为 LLM/外部服务依赖，已标注**

## 一、能力矩阵

### 1.5.0

| 能力 | 结论 | 证据 |
| :-- | :-- | :-- |
| 弱口令检测（21 协议） | PASS | t03 通过 6 协议（SSH/FTP/MySQL/Redis/SMB/SNMP）；SMB 访客会话假命中已修 |
| 显式端口目标解析 | PASS | t02 扫描按目标端口精确匹配服务 |
| 两次扫描增量 diff | PASS（修复后） | t11：`new`/`gone`/`severity_changed` 序列化为 `[]`，原 `null` 已修 |
| 复测结论进报告 | 部分 | 复测入口返回 503（LLM 未配置），属外部依赖；导出 client-md 已验证 |
| 对外交付导出（audience=external + client-md） | PASS | t14：client-md 外部版 200，仅含已确认项；md-zip 内部版 200 |
| 目录枚举 + JS URL 提取 | PASS | t02 full 模式产出 `baseline_pages` 6 |
| 授权清单与范围审批 | PASS | t10d：申请→approved 写任务范围→重复 409；rejected 路径 |
| guard 拒绝统计 | PASS | t13：越权目标 400 拒绝，授权项可增删 |
| 内网脚本库 | PASS | t14：linux-endpoint 执行落库，运行历史可查 |
| 撤离残留扫描与痕迹矩阵 | PASS | t10：dry_run + 实做残留 0，报告含痕迹矩阵 |
| 运维事件通知 | PASS | t13：webhook 渠道创建/测试投递/回环 SSRF 拒绝/非法类型拒绝 |
| SSH PowerShell 会话 | 未测 | 靶机均为 Linux，无 Windows 目标 |

### 1.6.0

| 能力 | 结论 | 证据 |
| :-- | :-- | :-- |
| 断点续扫 + 增量 diff | PASS | t11：取消→can_resume=true→续扫只补剩余分片→done，结果数不回退 |
| 扫描性能基线 | 未测 | 非运行时 API，由 CI 基准覆盖 |
| 隧道并发预算 | PASS | t13：proxy 扫描日志出现「已收敛」，占用表可见 |
| exec-form 静态换算 | PASS | t13：shell/argv/single 三语境齐全，不可单串表达时有原因 |
| 密钥轮换自检与补救 | PASS | t15：轮换后审计检出 unreadable=2，dry-run 不落地，恢复后干净 |
| 撤离报告痕迹矩阵 | PASS | 见 1.5.0 撤离项 |
| 子域名枚举 | PASS | t09：DNS 容器，枚举与解析正常 |
| 终端防护识别（Linux） | PASS | t14：linux-endpoint 签名表扫描，无命中则明确说明 |
| 终端防护补丁基线（Windows） | 未测 | 无 Windows 靶机 |
| 浏览器 XSS 真执行验证 | PASS | t07：dalfox + Chromium 真执行，URL 编码判定已修 |
| 凭据复用批次 | PASS | t10：复用台账 + 批量撤销 |
| Java 内存马 | PASS | t12：v2 JSP 父壳→auto 选型 filter→check/exec→删除清理 |
| JDK 利用链路由 | 未测 | jw-java 为 JDK17，无低版本 JDK 目标 |
| IPv6 字面量目标 | PASS | t14：授权后扫描接受 `[2001:db8::1]:8080`，跳过不可达项，有效目标出结果 |
| WAF 自适应绕过 | PASS | t06：模式/预算/止损参数生效 |
| MCP 托管 | PASS | t13：stdio Node 服务注册→工具发现→刷新→删除 |
| java-chains MCP | 未测 | `JAVA_CHAINS_MCP_TOKEN` 未配置，外部依赖 |

## 二、发现的缺陷与修复

### 缺陷 1：增量 diff 空列表序列化为 null 导致前端白屏

- **现象**：当某次扫描与基线相比无新增/无消失/无严重度变化时，`GET /api/scans/{id}/diff` 返回
  `"new":null,"gone":null,"severity_changed":null`。前端 `scans/page.tsx` 直接调用
  `diff.new.length` 与 `diff.new.map(...)`，`null` 抛 `TypeError`，增量面板整页白屏。
- **根因**：`server/scan_diff.go` 的 `computeScanDiff` 用零值 `scanDiff{}` 返回，三个切片为 `nil`。
- **修复**：初始化三个字段为非 nil 空切片 `[]scanDiffItem{}` 等。
- **回归**：`TestScanDiffEmptyListsMarshalAsArrays` 断言 JSON 中三类字段均为 `[]`；`go test ./server -run TestScanDiff` PASS。

### 缺陷 2：对外交付导出因空正文 blob 缺失而整体失败

- **现象**：`GET /api/exploration/findings/export?format=client-md&audience=external` 返回 422
  `open /app/data/evidence/blobs/e3/...bin: no such file or directory`。
- **根因**：GET 类请求请求体长度为 0，其 blob 哈希恒为空串 SHA256（`e3b0c44...`）。容器重建导致
  `/app/data/evidence` 丢失后，该 0 字节 blob 不存在；`evidence/store.go` 的 `copySnapshots`
  对空正文也走 `OpenBody` 读源文件，直接报错，整份导出被拖垮。
- **修复**：对「长度 0 + 空正文哈希」的条目，直接在目标路径写一个 0 字节文件（内容可由哈希无损
  校验）；非空正文缺失仍报错以保证证据完整性。
- **回归**：`TestCopySnapshotsRecoversMissingEmptyBody` 覆盖空正文还原、非空缺失仍报错、补齐后
  整体成功；`go test ./evidence` PASS。

## 三、回归结果

```
go build ./...                          OK
gofmt -l server/scan_diff*.go evidence/store*.go   （无输出）
go vet ./server/... ./evidence/...                 OK
staticcheck ./server/... ./evidence/...            仅预存告警，无新增
go test ./server -run TestScanDiff -count=1        PASS
go test ./evidence -count=1                        PASS
```

## 四、未测项与原因

| 项 | 原因 |
| :-- | :-- |
| 复测（retest）端到端 | 依赖 LLM 对话 Agent，本环境无 LLM 凭证；入口返回 503「LLM 未配置」属预期 |
| 报告生成（GET /api/report?task=） | 依赖 Agent 任务内存态，无 LLM |
| JDK 利用链路由 | 无低版本 JDK 靶机（jw-java 为 JDK17） |
| Windows 补丁基线 / PowerShell 会话 | 靶场均为 Linux |
| java-chains MCP | 未配置 `JAVA_CHAINS_MCP_TOKEN` |
| 扫描性能基线 | 非运行时 API，由 CI 基准覆盖 |

未测项均因环境/外部依赖缺失，非平台能力缺失，已明确标注而非用桩冒充。

## 五、测试脚本

全部测试脚本位于 `/root/lab-jw16/`：

| 脚本 | 覆盖 |
| :-- | :-- |
| t01–t09 | 扫描/弱口令/SQLi/XSS/WAF/WebShell/子域名 |
| t10-intranet.py | 内网横向全链（会话/recon/上传/cron/凭据复用/隧道/撤离） |
| t10d-scope.py | 范围审批流 |
| t11-cancel-resume.py | 断点续扫 + 增量 diff |
| t12-java-memshell.py | Java 内存马全链 |
| t13-caps.py | 调度/通知/MCP/exec-form/导出/隧道预算 |
| t14-followups.py | 导出修复验证/diff 空数组/IPv6/内网脚本 |
| t15-seal-rotation.py | 密钥轮换自检与补救 |
