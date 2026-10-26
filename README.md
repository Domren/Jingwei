<div align="center">

# Jingwei（精卫）

LLM 驱动的全链自动化红队渗透平台 · Docker 分发版

[![Release](https://img.shields.io/github/v/release/Domren/Jingwei?label=release)](https://github.com/Domren/Jingwei/releases)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Docker](https://img.shields.io/badge/ghcr.io-domren%2Fjingwei-2496ED?logo=docker&logoColor=white)](https://github.com/Domren/Jingwei/pkgs/container/jingwei)

> 本项目基于 [RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX) **v0.3.23** 二次开发，
> 保留原始提交历史、版权声明与 AGPL-3.0 许可证；上游项目源自
> [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)。

</div>

---

## Jingwei 1.1.0

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
- **完整工作台**：任务与计划任务、发现与报告（DOCX/HTML 导出）、资产与 ScopeSentry 同步、流量录制、工具执行、LLM 记录。
- **人在环路**：拦截规则、审批记录、旁路问答与通知推送。
- **Docker 分发**：`linux/amd64` / `linux/arm64` 多架构镜像，Compose 一键部署，升级只换镜像。

> 未配置 LLM 时，POC 库、资产、流量、发现/报告查看、系统管理等仍可使用；
> 对话、任务执行与 Agent 自动规划需要先在「系统 → LLM」配置模型。

## 截图

| 仪表盘 | 任务列表 |
| :---: | :---: |
| ![仪表盘](screenshots/dashboard.png) | ![任务](screenshots/tasks.png) |

| 任务执行过程 | 探索链路 |
| :---: | :---: |
| ![执行过程](screenshots/sessions.png) | ![探索链路](screenshots/graph.png) |

| 发现 | 资产 |
| :---: | :---: |
| ![发现](screenshots/findings.png) | ![资产](screenshots/assets.png) |

| 流量录制 | 人在环路对话 |
| :---: | :---: |
| ![流量](screenshots/traffic.png) | ![对话](screenshots/chat.png) |

| 拦截审批 | LLM 配置 |
| :---: | :---: |
| ![拦截](screenshots/intercept.png) | ![LLM](screenshots/llm.png) |

---

## 快速开始（Docker）

> 自 1.0.0 起仅通过 Docker 镜像分发，不再提供预编译二进制或页面一键换装。
> 完整参数、备份恢复与故障排查见 [DEPLOY.md](DEPLOY.md)。

**环境要求**：Docker Engine 24+、Docker Compose v2，`linux/amd64` 或 `linux/arm64`，
建议 2 核 CPU / 4 GB 内存 / 10 GB 磁盘。

### 方式一：使用仓库内 Compose（推荐）

```bash
git clone --depth 1 --branch v1.1.0 https://github.com/Domren/Jingwei.git
cd Jingwei/deploy
cp .env.example .env
# 编辑 .env：至少修改 POSTGRES_PASSWORD
docker compose pull
docker compose up -d
```

### 方式二：只下载 Release 部署文件

```bash
mkdir jingwei && cd jingwei
curl -fsSLO https://github.com/Domren/Jingwei/releases/download/v1.1.0/docker-compose.yml
curl -fsSLo .env https://raw.githubusercontent.com/Domren/Jingwei/v1.1.0/deploy/.env.example
# 编辑 .env 后启动
docker compose pull
docker compose up -d
```

启动后访问 `http://<服务器IP>:9790`。首次进入会跳转到初始化页，设置管理员密码；
用户名固定为 `Jingwei`。流量录制代理只监听宿主机 `127.0.0.1:9791`。

### 镜像访问

镜像发布在 GitHub Container Registry：

```bash
docker pull ghcr.io/domren/jingwei:1.1.0
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
| `JINGWEI_IMAGE` | 否 | 默认 `ghcr.io/domren/jingwei:1.1.0` |
| `JINGWEI_WEB_PORT` | 否 | Web/API 宿主端口，默认 `9790` |
| `JINGWEI_PROXY_PORT` | 否 | 流量代理宿主端口，默认 `9791`，仅绑定 `127.0.0.1` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | 否 | 也可启动后在 UI 配置 |
| `ARTEX_LLM_PROVIDER` / `ARTEX_LLM_MODEL` / `ARTEX_LLM_BASE_URL` / `ARTEX_LLM_PROXY` | 否 | 自定义 OpenAI 兼容端点或代理 |

密码含 `@`、`:`、`/` 等特殊字符时会被直接拼入 DSN，请改用 URL 编码后的
`ARTEX_PG_DSN` 覆盖完整连接串，或使用字母数字密码。

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
  -ldflags "-s -w -X main.version=1.1.0" -o dist/amd64/artex ./cmd/artex

# 3. 构建运行镜像
docker build --network=host --build-arg TARGETARCH=amd64 \
  -t jingwei:1.1.0 .
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

更细的引擎生命周期、意图状态机与多轮规划说明见上游
[ARTEX 文档](https://github.com/RuoJi6/ARTEX)。

## 发布流程

1. 更新版本号与 `CHANGELOG.md`，提交到 `main`。
2. 创建并推送 `vX.Y.Z` 标签。
3. GitHub Actions 自动构建前端与双架构二进制，在原生 runner 上启动容器做健康检查，
   推送 GHCR 镜像，并创建 GitHub Release（附带 `docker-compose.yml`、部署文档与镜像 digest）。

发布只使用仓库内置 `GITHUB_TOKEN`，无需配置 Docker Hub 凭据。

## 许可与免责声明

### 开源协议

本项目采用 **GNU Affero General Public License v3.0（AGPL-3.0）**，完整条款见
[LICENSE](LICENSE)。任何人都可以自由使用、修改和分发本项目，但衍生作品必须同样以
AGPL-3.0 开源；若修改后通过网络向用户提供服务，必须向这些用户公开对应的完整源码。
原始版权、许可与署名信息不得移除，详见 [NOTICE](NOTICE)。

本项目基于 ARTEX 二次开发：

- 上游：[RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX)（AGPL-3.0）
- 上游源头：[Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)
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
