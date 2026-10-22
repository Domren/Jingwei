# Jingwei（精卫）Docker 部署指南

适用版本：**v1.0.0** 及以后。Jingwei 1.0.0 只通过容器镜像分发，
部署、升级和回滚都使用 Docker Compose。

- 镜像：`ghcr.io/domren/jingwei`
- 架构：`linux/amd64`、`linux/arm64`
- 源码：<https://github.com/Domren/Jingwei>
- 发布：<https://github.com/Domren/Jingwei/releases>

## 1. 环境要求

| 项目 | 要求 |
| --- | --- |
| Docker Engine | 24+ |
| Docker Compose | v2（`docker compose`） |
| 架构 | amd64 / arm64 |
| 资源 | 建议 2 核 CPU、4 GB 内存、10 GB 可用磁盘 |
| 端口 | `9790`（Web/API），`9791`（流量代理，仅本机） |

不需要预装 Go、Node.js、PostgreSQL 或 nuclei，运行依赖全部在镜像内。
LLM 不是启动必需项，但对话、任务执行和 Agent 自动规划需要配置模型。

## 2. 获取部署文件

### 2.1 使用仓库内 Compose（推荐）

```bash
git clone --depth 1 --branch v1.0.0 https://github.com/Domren/Jingwei.git
cd Jingwei/deploy
cp .env.example .env
```

### 2.2 只下载 Release 资产

```bash
mkdir -p jingwei && cd jingwei
curl -fsSLO https://github.com/Domren/Jingwei/releases/download/v1.0.0/docker-compose.yml
curl -fsSLo .env https://raw.githubusercontent.com/Domren/Jingwei/v1.0.0/deploy/.env.example
```

两种方式得到的目录结构相同：

```text
.
├── docker-compose.yml
└── .env
```

## 3. 获取镜像

镜像默认发布到 GitHub Container Registry：

```bash
docker pull ghcr.io/domren/jingwei:1.0.0
```

维护者把 Package 可见性设为 **Public** 后，以上命令无需登录。

若镜像仍为私有，先创建具备 `read:packages` 权限的 GitHub Token，再登录。
Token 只放在当前 shell 或密码管理器中，不要写入 `.env`、Compose 或 Git：

```bash
read -rsp "GitHub Token: " GHCR_TOKEN; echo
echo "$GHCR_TOKEN" | docker login ghcr.io -u Domren --password-stdin
unset GHCR_TOKEN
```

可用的镜像标签：

| 标签 | 说明 |
| --- | --- |
| `1.0.0` / `v1.0.0` | 固定版本，生产环境推荐 |
| `latest` | 最新正式版 |
| `v1.0.0-amd64` / `v1.0.0-arm64` | 单架构中间镜像，一般不用 |

## 4. 配置 `.env`

至少修改数据库密码：

```dotenv
POSTGRES_USER=jingwei
POSTGRES_PASSWORD=请替换为强随机密码
POSTGRES_DB=jingwei
JINGWEI_IMAGE=ghcr.io/domren/jingwei:1.0.0
JINGWEI_WEB_PORT=9790
JINGWEI_PROXY_PORT=9791
```

说明：

- `POSTGRES_PASSWORD` 会被拼进数据库连接串，建议只使用字母和数字。
  若必须包含 `@`、`:`、`/` 等字符，请对整段 DSN 做 URL 编码并通过
  `ARTEX_PG_DSN` 覆盖，例如：
  ```dotenv
  ARTEX_PG_DSN=postgres://jingwei:URL_ENCODED_PASSWORD@postgres:5432/jingwei?sslmode=disable
  ```
- `.env` 含密码与密钥，建议 `chmod 600 .env`，且不要提交到 Git。
- LLM 可先在 `.env` 填写，也可启动后进入「系统 → LLM」配置。
  使用 OpenAI 兼容服务时，通常填写 `OPENAI_API_KEY`、`ARTEX_LLM_BASE_URL` 和
  `ARTEX_LLM_MODEL`。
- 如果需要限制访问来源，建议保持 `JINGWEI_PROXY_PORT` 只绑定 `127.0.0.1`，
  公网只开放反向代理端口。

## 5. 启动与验收

```bash
docker compose pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:9790/api/health
```

期望健康检查返回：

```json
{"ok":true,"service":"jingwei","version":"1.0.0"}
```

浏览器访问 `http://<服务器IP>:9790`：

1. 首次进入会跳转到初始化页，设置管理员密码（至少 8 位）。
2. 用户名固定为 `Jingwei`。
3. 登录后进入任务页面；默认没有 LLM，可先在「系统 → LLM」配置。

查看启动日志：

```bash
docker compose logs -f --tail=100 jingwei
```

## 6. 数据持久化与备份

Compose 使用两个命名卷：

| 卷 | 挂载点 | 内容 |
| --- | --- | --- |
| `jingwei_pgdata` | PostgreSQL 数据目录 | 任务、配置、POC 模板、审批、资产等 |
| `jingwei_jingwei_data` | `/app/data` | JWT 签名密钥、流量录制等运行数据 |

PostgreSQL 默认只在 Compose 内部网络暴露，不映射到宿主机端口。

### 6.1 备份

```bash
mkdir -p backups
docker compose exec -T postgres \
  pg_dump -U jingwei -d jingwei -Fc > "backups/jingwei-db-$(date +%F-%H%M).dump"

docker run --rm \
  -v jingwei_jingwei_data:/data:ro \
  -v "$PWD/backups":/backup \
  alpine tar czf "/backup/jingwei-data-$(date +%F-%H%M).tar.gz" -C /data .
```

如果修改过 `POSTGRES_USER` 或 `POSTGRES_DB`，请同步替换命令中的值。
建议在升级、迁移和修改系统配置前各备份一次，并将备份文件移到另一台机器。

### 6.2 恢复数据库

先停止应用，避免恢复期间有写入：

```bash
docker compose stop jingwei

docker compose exec -T postgres dropdb -U jingwei --if-exists jingwei
docker compose exec -T postgres createdb -U jingwei jingwei
docker compose exec -T postgres pg_restore -U jingwei -d jingwei --no-owner < backups/jingwei-db-YYYYMMDD-HHMM.dump

docker compose start jingwei
curl -fsS http://127.0.0.1:9790/api/health
```

### 6.3 恢复 data 卷

应用停止后，将备份解压回卷中。该操作会覆盖卷内现有文件：

```bash
docker compose stop jingwei
docker run --rm \
  -v jingwei_jingwei_data:/data \
  -v "$PWD/backups":/backup \
  alpine sh -c 'rm -rf /data/* && tar xzf /backup/jingwei-data-YYYYMMDD-HHMM.tar.gz -C /data'
docker compose start jingwei
```

如果数据库和 data 卷要恢复到同一时间点，请一起恢复。

## 7. 升级与回滚

### 7.1 升级

```bash
# 1. 备份（见上一节）
# 2. 修改 .env 中的 JINGWEI_IMAGE 为新版本
# 3. 拉取并重建应用容器
docker compose pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:9790/api/health
```

数据库迁移在应用启动时幂等执行，无需手动跑 SQL。PostgreSQL 容器不会被重建，
数据卷保持不变。

### 7.2 回滚

把 `.env` 中的 `JINGWEI_IMAGE` 改回上一版本，然后：

```bash
docker compose pull
docker compose up -d
```

注意：镜像回滚不会回退数据库结构或数据变更。若新版本已经执行过不兼容迁移，
需要同时恢复升级前的数据库备份。

### 7.3 关于页面更新提示

Docker 模式下，系统配置页仍会检查 GitHub 最新 Release，但不会替换容器内二进制
（容器重建后会丢失）。升级请始终使用 `docker compose pull && docker compose up -d`。

## 8. 反向代理与 HTTPS

前端、API 和 SSE 活动流由同一个容器端口提供，宿主机默认映射到 `9790`。
公网部署建议只开放 443，把 `9790` 留在本机或内网。

```nginx
server {
    listen 443 ssl;
    server_name jingwei.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass http://127.0.0.1:9790;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE 必须关闭缓冲并延长读超时
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

开启 HTTPS 后，可在「系统配置 → HTTP Basic Auth」再增加一层访问验证；
它和应用登录是两套独立凭据。`/api/health` 始终公开，便于负载均衡和监控探活。

## 9. 从源码开发

以下流程仅用于开发或构建自定义镜像；正式部署直接使用 GHCR 镜像。

### 9.1 本地开发

```bash
# 一次性安装前端依赖
cd web && npm ci && cd ..

# 同时启动后端(:8787)、流量代理(:8788)、前端(:5173)
./dev.sh
```

也可以分别启动：

```bash
go run ./cmd/artex
cd web && npm run dev
```

测试：

```bash
go test ./...
cd web && npm run check
```

### 9.2 构建镜像

```bash
cd web && npm ci && npm run build:static && cd ..

rm -rf server/webui/dist
cp -r web/out server/webui/dist

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embedui -trimpath \
  -ldflags "-s -w -X main.version=1.0.0" -o dist/amd64/artex ./cmd/artex

docker build --network=host --build-arg TARGETARCH=amd64 -t jingwei:1.0.0 .
```

ARM64 构建时把 `GOARCH` 与 `TARGETARCH` 改为 `arm64`，并在对应架构的机器上
执行 `docker build`。

### 9.3 多架构发布

维护者推送 `vX.Y.Z` 标签即可触发
[`.github/workflows/release.yml`](.github/workflows/release.yml)：

1. 构建一次前端静态产物，交叉编译 linux/amd64 与 linux/arm64 二进制；
2. 在原生 AMD64 / ARM64 runner 上构建镜像，连接临时 PostgreSQL 验证启动、
   版本号和内嵌前端；
3. 推送 GHCR 单架构镜像，合并为多架构 manifest，打上 `vX.Y.Z`、`X.Y.Z`、`latest`；
4. 创建 GitHub Release，附加 `docker-compose.yml`、本部署文档和镜像 digest。

工作流只使用仓库内置 `GITHUB_TOKEN`，不需要额外 Secrets。

## 10. 常见问题

### 10.1 容器反复重启

```bash
docker compose logs --tail=200 jingwei
docker compose logs --tail=100 postgres
```

常见原因：`POSTGRES_PASSWORD` 含特殊字符导致 DSN 解析失败、数据库尚未就绪、
端口被占用。健康检查依赖 `/api/health`，正常启动通常需要数秒。

### 10.2 无法拉取 GHCR 镜像

- 确认镜像版本存在：`docker manifest inspect ghcr.io/domren/jingwei:1.0.0`
- 若 Package 是私有的，先按第 3 节登录；Token 需要 `read:packages`。
- 确认 Docker 所在网络可以访问 `ghcr.io`。

### 10.3 端口冲突

修改 `.env`：

```dotenv
JINGWEI_WEB_PORT=19790
JINGWEI_PROXY_PORT=19791
```

然后 `docker compose up -d`。

### 10.4 配置了模型仍无法执行任务

检查「系统 → LLM」中的 Provider、Base URL、模型名与密钥；保存后可点击测试。
OpenAI 兼容服务通常需要同时设置 `ARTEX_LLM_PROVIDER=openai`（或 UI 中对应选项）、
`ARTEX_LLM_BASE_URL` 和 `ARTEX_LLM_MODEL`。如果服务端需要代理访问外网，
在「系统配置」中填写服务端可达的代理地址，注意容器内的 `127.0.0.1` 指容器自身。

### 10.5 忘记管理员密码

管理员密码以 bcrypt 哈希保存在 PostgreSQL 的 `settings` 表中。没有通用后门；
请从备份恢复，或在确认数据可丢弃后重建数据库卷。生产环境请妥善保管密码与备份。

## 11. 安全建议

- 修改默认数据库密码，`.env` 权限设为 `600`。
- 不要将 PostgreSQL 端口或 `9791` 流量代理暴露到公网。
- 公网访问一律走 HTTPS 反向代理，按需开启 HTTP Basic Auth。
- 定期备份数据库和 data 卷，并验证恢复流程。
- 关注 GitHub Releases 与 GHCR 新版本，及时升级镜像。
- 仅在你拥有明确授权的隔离环境中使用本工具。

## 12. 许可

Jingwei 基于 [RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX) 二次开发，
采用 **AGPL-3.0** 许可证。完整条款见 [LICENSE](LICENSE)，上游版权与修改说明见
[NOTICE](NOTICE)。通过网络向第三方提供本软件时，必须按 AGPL-3.0 公开对应源码。
