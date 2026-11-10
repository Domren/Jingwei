# Jingwei（精卫）Docker 部署指南

适用版本：**v1.6.1**。Jingwei 自 1.0.0 起只通过容器镜像分发，
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
git clone --depth 1 --branch v1.6.1 https://github.com/Domren/Jingwei.git
cd Jingwei/deploy
cp .env.example .env
```

### 2.2 只下载 Release 资产

```bash
mkdir -p jingwei && cd jingwei
curl -fsSLO https://github.com/Domren/Jingwei/releases/download/v1.6.1/docker-compose.yml
curl -fsSLo .env https://raw.githubusercontent.com/Domren/Jingwei/v1.6.1/deploy/.env.example
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
docker pull ghcr.io/domren/jingwei:1.6.1
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
| `1.6.1` / `v1.6.1` | 固定版本，生产环境推荐 |
| `latest` | 最新正式版 |
| `v1.6.1-amd64` / `v1.6.1-arm64` | 单架构中间镜像，一般不用 |

## 4. 配置 `.env`

至少修改数据库密码：

```dotenv
POSTGRES_USER=jingwei
POSTGRES_PASSWORD=请替换为强随机密码
POSTGRES_DB=jingwei
JINGWEI_IMAGE=ghcr.io/domren/jingwei:1.6.1
JINGWEI_WEB_PORT=9790
JINGWEI_PROXY_PORT=9791
```

说明：

- `POSTGRES_PASSWORD` 会被拼进数据库连接串，建议只使用字母和数字。
  若必须包含 `@`、`:`、`/` 等字符，请对整段 DSN 做 URL 编码并通过
  `JINGWEI_PG_DSN` 覆盖，例如：
  ```dotenv
  JINGWEI_PG_DSN=postgres://jingwei:URL_ENCODED_PASSWORD@postgres:5432/jingwei?sslmode=disable
  ```
- `.env` 含密码与密钥，建议 `chmod 600 .env`，且不要提交到 Git。
- LLM 可先在 `.env` 填写，也可启动后进入「系统 → LLM」配置。
  使用 OpenAI 兼容服务时，通常填写 `OPENAI_API_KEY`、`JINGWEI_LLM_BASE_URL` 和
  `JINGWEI_LLM_MODEL`。
- `JINGWEI_LLM_CALL_TIMEOUT` 限制单次模型调用的总墙钟（含 SDK 重试与流式读取），默认 `15m`。
  网关变慢时会出现「任务在跑、日志里持续出现 `单次调用超过硬性墙钟`、漏洞数为 0」，
  此时调小为 `300s` 可让 worker 尽快放弃卡住的那一次并继续推进。
- 如果需要限制访问来源，建议保持 `JINGWEI_PROXY_PORT` 只绑定 `127.0.0.1`，
  公网只开放反向代理端口。
- **内网横向前必须先配 `JINGWEI_PIVOT_SERVER`**：隧道（chisel / `ssh -R`）的自动部署命令
  需要一个**目标机能访问到**的控制端地址，格式 `host:port`（只写主机名时按 chisel 默认的 8788 处理）。
  没配时深度利用的隧道「自动生成」会直接返回「未配置 JINGWEI_PIVOT_SERVER」，只能手写 `deploy_command`。
  单机组网常见填法是宿主机在靶机可达网段的地址；这个地址会被写进下发到目标机的命令里，
  所以别用公网监听口，用完把控制端端口关掉。
  注意 chisel 与 ssh 两条路用的**不是同一个端口**：`JINGWEI_PIVOT_SERVER` 的端口是 chisel server 监听的端口，
  `ssh -R` 回连控制端用的端口由 `JINGWEI_PIVOT_SSH_PORT` 单独指定（留空＝22，sshd 通常就在这）。
  两者合成一个值时必然有一条路是错的——目标会去 ssh 登录 chisel 的端口。
  ssh 这条路还要配 `JINGWEI_PIVOT_SSH_USER`：留空时 ssh 沿用**目标侧**的登录名，两端不同名就直接认证失败，
  而命令是 `BatchMode` 跑的，现象是隧道秒挂而不是卡在口令。
  还要给控制端准备 **chisel server**（若要用 chisel 这条路）：必须带 `--reverse`，
  因为平台生成的是 `chisel client <控制端> R:<端口>:socks` 这类反向请求——不带 `--reverse` 时服务端会直接拒绝，
  隧道一条也建不起来。监听只绑目标可达的内网地址，用完关掉。
  用 `ssh -R` 时控制端那个 sshd 必须把 `GatewayPorts` 设为 `clientspecified`（或 `yes`）并允许端口转发，
  否则它拒绝在非回环地址上监听：ssh 进程活着、控制端却没有监听，verify 会以「端口不可达」失败。
  两条路都是「控制端监听、由目标往外拨号」，这正是穿透到**只有目标可达**的网段所需的朝向；
  `ssh -D` / `ssh -L` 的目的地由控制端发起，打不到那种网段，平台不再生成它们。
- 其余运行时开关都在 `.env.example` 里带注释列出，留空即用内置默认值，改完需要
  `docker compose up -d` 重建容器才生效（`restart` 不会重读 `.env`）。其中两条与安全行为有关：
  `JINGWEI_GUARD_ENFORCEMENT` 默认 `strict`（读不到授权范围即拒绝），改成 `warn`/`off` 是主动放宽边界，
  只在确认误伤且能承担后果时使用；`JINGWEI_WEBSHELL_TTL_HOURS` / `JINGWEI_MEMSHELL_TTL_HOURS`
  控制落地物自动过期时间，长跑任务别把它调到超出作业窗口。
- 仓库自带一份 `.env.example` 与两份 compose：根目录 `docker-compose.yml`（源码构建 / 本机自测）和
  `deploy/docker-compose.yml`（Release 里给用户的）。两者的可注入变量由
  `go test ./tools/envaudit/` 保持同步，新增运行时开关时那份测试会拦住漏写。

## 5. 启动与验收

```bash
docker compose pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:9790/api/health
```

期望健康检查返回：

```json
{"ok":true,"service":"jingwei","version":"1.6.1"}
```

从 v1.1.0 升级时注意：环境变量前缀已由 `ARTEX_` 改为 `JINGWEI_`，旧变量不再读取。
需要把 `.env` / compose 中的 `ARTEX_PG_DSN`、`ARTEX_LLM_*`、`ARTEX_CONFIG`、
`ARTEX_SKILL_DIR` 换成对应的 `JINGWEI_*`，镜像入口二进制也由 `/app/artex` 改为
`/app/jingwei`（官方 compose 已同步，无需手动改入口）。

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
| `jingwei_pgdata` | PostgreSQL 数据目录 | 任务、配置、POC 模板、审批、资产，以及**平台签名密钥**（`platform_secret` 单行表） |
| `jingwei_jingwei_data` | `/app/data` | 流量录制、导出物等可浏览工作区数据（**不含**签名密钥） |

PostgreSQL 默认只在 Compose 内部网络暴露，不映射到宿主机端口。

> **签名密钥跟着库走。** 这把钥匙派生出三样东西：会话 JWT 的签名、webshell / 内存马 / 半持久化密钥的密封、
> HTTP Basic 认证门的 cookie。因此 6.1 的 `pg_dump` 就是密钥备份，不需要另外保存文件。只恢复 `data` 卷而丢了库
> （或反过来）会重新铸一把，后果是所有登录会话失效 **加上** 所有已投放 webshell 报「密钥解封失败，请重新投放载荷」
> ——目标上的文件还在，但平台打不开了。1.4.0 之前密钥写在 `/app/jwt.key`（容器可写层，不在任何卷内），
> `docker compose up --force-recreate` 一次就轮换一次；首次升级到本版时旧文件会被原样搬进库并删除，不改变钥匙本身。

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

「系统设置 → 版本与更新」检查的是 GitHub 上最新的正式版本，以**服务端**结果为准：下载是后端做的，
只有后端能访问 GitHub 才谈得上更新（浏览器能连而服务器连不上的情况很常见，那时页面会在「检查」这一步
就报错，而不是点了「立即更新」才失败）。

Docker 模式下点「立即更新」**确实会换装**，但要知道它的边界：

- 换的是**容器可写层里的二进制**，镜像里的 playwright / nmap / webcrack 等工具链不会跟着变。
  新版本若依赖新工具，页面更新是不够的，必须换镜像。
- 换装写的是可写层，所以 `docker compose up -d --force-recreate`（或改了 `JINGWEI_IMAGE` 之后重建）
  会退回**镜像自带的那个版本**。页面更新是临时的，不是升级。
- 换装带标记与备份：新版起不来、连续崩溃会自动回滚到上一版；也可以在页面上手动回滚。

所以两条路分工明确：**临时热修**用页面更新；**正式升级**改 `.env` 里的 `JINGWEI_IMAGE` 为新版本号，
再 `docker compose pull && docker compose up -d`，这样程序与工具链一起换。

### 7.4 签名根密钥换过之后怎么办

平台签名根密钥存在数据库 `platform_secret` 单行表里。它派生出会话 JWT 签名、webshell / 内存马
密钥密封、内网凭据密封与模型 API 密钥密封。**这把值一变，之前登记的一切密封记录都解不开**：
所有人掉登录；每条 webshell 命令回「密钥解封失败（JWT 密钥可能已更换，请重新投放载荷）」；
凭据复用与 SSH 会话直接拒绝并提示重新登记。启动时会自检并打印条数：

```bash
docker compose logs jingwei | grep '\[seal\]'
```

不存在「换一把密钥再把旧密文解一遍」的路径——密封用的就是这把密钥，旧密文对新密钥不可逆；
逐壳的 `POST /api/deep/webshells/{id}/rotate` 也需要旧密钥才能发起。所以只有两条恢复方式：

1. **找回旧密钥**：从换密钥之前的数据库备份里读出 `platform_secret` 那一行，写回当前库，重启即全部恢复。
   这就是 §6.1 的 `pg_dump` 必须按密钥备份来管的原因。
2. **重新投放**：备份也丢了，就按台账逐条重做——重新投放 webshell 载荷、重新注入内存马、重新登记凭据、
   在系统设置里重新填写模型 API 密钥。旧记录里的目标路径仍然可用，照着覆盖投放即可，但目标上那份用旧密钥
   的载荷必须被换掉，否则它会拒绝新密钥的握手。

正常情况下升级与容器重建都不会换这把密钥（1.4.0 之前会，因为密钥写在容器可写层里，每次
`--force-recreate` 重新生成一把）。

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

应用登录使用 `HttpOnly` + `SameSite=Strict` 的会话 Cookie，有效期 24 小时。HTTPS
反向代理必须保留上面的 `proxy_set_header X-Forwarded-Proto $scheme;`，后端据此设置
`Secure` 属性；缺失时浏览器不会在 HTTPS 页面保存登录态。修改密码会立即吊销其他已
登录会话。登录失败锁定按客户端 IP 在进程内计数，重启后清零。

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
go run ./cmd/jingwei
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
  -ldflags "-s -w -X main.version=1.6.1" -o dist/amd64/jingwei ./cmd/jingwei

docker build --network=host --build-arg TARGETARCH=amd64 -t jingwei:1.6.1 .
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

- 确认镜像版本存在：`docker manifest inspect ghcr.io/domren/jingwei:1.6.1`
- 若 Package 是私有的，先按第 3 节登录；Token 需要 `read:packages`。
- 确认 Docker 所在网络可以访问 `ghcr.io`。
- 如果报错是 `proxyconnect tcp: dial tcp 127.0.0.1:<port>: connect: connection refused`，
  问题不在镜像而在 dockerd 的代理：`/etc/systemd/system/docker.service.d/` 里配了 HTTP(S) 代理，
  而代理进程此刻没在监听（本地科学上网软件关掉是最常见的成因）。要么把代理开起来，
  要么删掉那个 drop-in 并 `systemctl daemon-reload && systemctl restart docker`。
  注意这只影响拉取，本地已构建好的镜像与容器运行都不受影响。

### 10.3 端口冲突

修改 `.env`：

```dotenv
JINGWEI_WEB_PORT=19790
JINGWEI_PROXY_PORT=19791
```

然后 `docker compose up -d`。

### 10.4 配置了模型仍无法执行任务

检查「系统 → LLM」中的 Provider、Base URL、模型名与密钥；保存后可点击测试。
OpenAI 兼容服务通常需要同时设置 `JINGWEI_LLM_PROVIDER=openai`（或 UI 中对应选项）、
`JINGWEI_LLM_BASE_URL` 和 `JINGWEI_LLM_MODEL`。如果服务端需要代理访问外网，
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

Jingwei 基于 **Autumn-27/ARTEX** 二次开发（上游现由
[RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX) 持续维护），
采用 **AGPL-3.0** 许可证。完整条款见 [LICENSE](LICENSE)，上游版权与修改说明见
[NOTICE](NOTICE)。通过网络向第三方提供本软件时，必须按 AGPL-3.0 公开对应源码。
