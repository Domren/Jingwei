# tools/e2e — 浏览器端到端验证

真机验证深度利用页用的 Playwright 脚本。它们打的是**运行中的实例**，不是 mock，所以
跑之前要有一个部署好的 Jingwei 和一个可打的靶机。

## 前置

```bash
npm install --no-save playwright   # 或指向已有的 playwright 安装
npx playwright install chromium    # 首次需要下载浏览器
```

已经装过 playwright 的话，不必重装，指给 node 即可：

```bash
export NODE_PATH=/path/to/where/playwright/is/installed/node_modules
```

登录需要滑块验证码与管理员密码，脚本拿不到，所以用平台自己的签名密钥现签一个短期会话：

```bash
./mint-session.sh          # 写 /tmp/jw.token（600），不打印令牌
```

`mint-session.sh` 需要 `docker` 能访问 `jingwei-jingwei-1` 与 `jingwei-postgres-1`：
签名根密钥在库里的 `platform_secret`，会话失效版本在 `settings.auth.token_version`，
两者都从 Postgres 读，再在容器内用 python 签一个 1 小时有效的 HS256 JWT。

## 脚本

| 脚本 | 覆盖 |
| --- | --- |
| `verify-webshell-workbench.js` | WebShell 工作台三页签：终端（目录/退出码/stderr/超时/跳转）、文件管理（大马）、系统信息（12 分区 + PHP 运行时自述），以及旧协议壳的禁用说明 |
| `verify-intranet-terminal.js` | 内网 SSH 会话终端复用同一组件：目录续用、退出码徽章、超时标记、系统族下拉、上传结果徽章、执行记录台账 |
| `verify-repeater-clock.js` | 请求重发页上方的时钟块：公历到秒、每秒走字、带边框、鼠标左右拖拽、拖不出正文区、偏移存 localStorage 并在刷新后保持 |

两个脚本各自输出 `PASS=n FAIL=m` 与失败明细，截图写进 `shots/`（已 gitignore）。

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `JW_BASE` | `http://127.0.0.1:9790` | 实例地址 |
| `JW_TOKEN_FILE` | `/tmp/jw.token` | `mint-session.sh` 写出的会话令牌 |
| `JW_SHOTS` | `shots` | 截图目录 |
| `JW_SESSION_NAME` | `Ubuntu-1 SSH 终端验证` | 终端脚本要点的大内网会话行（按名称匹配） |

## 需要的靶机状态

`verify-intranet-terminal.js` 要一条 `transport=ssh` 的**活跃**会话，`verify-webshell-workbench.js`
要两条加密 v2 壳（PHP + JSP）。这些记录由平台 API 建立，脚本不会自己创建（除了它自己用完就删的
旧协议壳夹具）。示例：

```bash
curl -s -X POST -H "Cookie: jingwei_token=$(cat /tmp/jw.token)" -H 'Content-Type: application/json' \
  -d '{"host":"172.23.0.1","port":2201,"protocol":"ssh","username":"lab","password":"<靶机口令>","source":"manual","task_id":1}' \
  http://127.0.0.1:9790/api/intranet/credentials
```

脚本里的默认值对应本机 WSL 的 Ubuntu-1 边界靶机（Apache :8080 / Tomcat9 :8081 / sshd :2201，
从容器内经桥网关 `172.23.0.1` 访问）。换靶机时用上面的环境变量覆盖即可。

## i2-mock-crawl.js — 逐页巡检 + 每页截图（I4 的 CI 门禁就是它）

这个脚本不打真实例：它遍历**静态导出的每一个页面**（默认 `web/out`），逐页用真 Chromium 打开，
记下脚本错误与正文长度，并给每个页面留一张截图。演示模式的接口是本地假路由，漏一个路径就表现为
「页面空白」或 `undefined.length` 崩溃，而这类崩溃在真实实例上不会出现——所以它是独立的一道检查，
不依赖靶机。

```bash
cd web && NEXT_PUBLIC_MOCK=1 npx next build        # 产出带假数据的 web/out（build:static 加 NEXT_PUBLIC_MOCK=1）
python3 -m http.server 3006 --bind 127.0.0.1 --directory out &
MOCK_BASE=http://127.0.0.1:3006 OUT_DIR=out \
JW_SHOTS=shots UI_REPORT=ui-visual.md \
NODE_PATH=/root/browser-check/node_modules node ../tools/e2e/i2-mock-crawl.js
```

判据三条，任一不满足就**非零退出**（发版流水线据此拦下发版）：

1. 页面有未捕获异常或 `console.error`；
2. 正文短于 `MIN_TEXT`（默认 12 字）且没登记在 `ALLOW_EMPTY` 里；
3. 页面渲染出 Next 的错误块（`Application error` / `Unhandled Runtime Error`）——这种页面正文很长，
   只按字数判会被放过去。

量正文时优先量 `<main>`；外壳之外的页面（`/404/`）没有 `main`，退到量整页并在表格里标「量整页」——
不把这类页面当成「需要豁免的空页面」，那是测量口径的问题，不是页面的问题。

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `MOCK_BASE` | `http://127.0.0.1:3006` | 静态服务地址 |
| `OUT_DIR` | `out` | 静态导出目录（路由表从它的 `index.html` 推出来） |
| `JW_SHOTS` | `shots` | 截图目录，路由名摊平成 `function-deep-intranet.png` |
| `UI_REPORT` | 空 | 额外写一份 Markdown 台账（页面 / 字数 / 截图 / 问题） |
| `ALLOW_EMPTY` | 空 | 逗号分隔的路由前缀，登记过才允许正文为空 |
| `MIN_TEXT` | `12` | 低于这个字数算空页面 |

它证明的是「每个页面能渲染、控制台不报错」，**不证明业务数据正确**：跑的是 mock 构建，没有后端、
没有靶机，也不点任何真会发包的按钮。真数据的界面核验仍是 `verify-*.js` 那一套（要实例与靶机）。

## CI 里的两道自动检查（I4）

`.github/workflows/release.yml` 里：

- **`ui-visual` 作业**：构建 mock 静态导出 → 起本地静态服务 → 跑 `i2-mock-crawl.js` →
  把每个页面一张截图与台账表格作为 `ui-visual-<tag>` 产物上传。**`release` 作业依赖它**，
  有问题的页面直接让发版失败（镜像已经推出去了，但 Release 不会建）。
  装的是钉住的 `PLAYWRIGHT_VERSION`，浏览器版本跟着它走，避免上游换版把发版卡住。
- **`docker` 作业里的 `selfcheck.sh`**：对**刚构建出的那个镜像**跑平台自身安全回归，
  位置在「推镜像」之前——自检不过的镜像不该变成发布物。报告作为 `selfcheck-<arch>-<tag>` 上传。

两道检查都 `if: always()` 上传产物：失败时那份截图与报告正是要看的东西。

`web/out` 是构建产物目录：mock 构建覆盖过它之后，**记得用正式构建再跑一次**
（`cd web && npm run build:static`），`server/webui/dist` 是从它拷进二进制的——把带假数据的
导出打进镜像，界面就停在演示态。

## selfcheck.sh — 平台自身安全回归（发版前必跑）

对大版本待发布的实例跑一轮**只读**探测：12 个敏感接口的未认证面（必须 401）、健康检查不泄漏内部
信息、跨源请求被拒、登录缺滑块被拒且不泄漏账号是否存在、响应头不带技术栈、首页不夹带机密字段名、
回调端口只绑回环、带令牌可访问。报告写到 `docs/reports/selfcheck-<时间>.md`，随版本归档。

```bash
BASE=http://127.0.0.1:9790 REPORT_DIR=docs/reports TOKEN_FILE=/tmp/jw.token ./tools/e2e/selfcheck.sh
```

它**不发起认证尝试**：登录接口的滑块是必经之路，脚本解不了，硬试只会把自己的 IP 锁在门外；
滑块之后的限流、Cookie 属性与 JWT 吊销由 `server/auth*_test.go` 覆盖。首跑就抓到过 CORS 对任意
来源回 `*`（见进度手册 §5.6 第 13 条）。

**给本机开发的注记**：历史上有「Go 起在 8787、`next dev` 在 3000，两个端口都要带凭据」的用法，
那条跨源通道现在默认关闭。需要时设 `JINGWEI_DEV_CORS=1` 启动后端，只对回环来源回许可；
生产部署不要开。

## scan-bench.py / scan-bench.sh — nuclei 扫描性能基线（D4）

跑在**一次性隔离容器**里，绝不碰运行中的实例：`--network=none`（无外网）、`--cpus=2 --memory=1g
--pids-limit=128`、`--read-only`、`--cap-drop=ALL`、`--security-opt=no-new-privileges`、`--pull=never`
（镜像必须已在本机，禁止临时拉取），环境变量整片清空后只留 PATH——不把宿主/生产容器的密钥、代理、
口令带进去。夹具是容器自己起的 loopback HTTP 服务（每个目标一个独立端口、每个模板一个独立路径，
命中靠路径里唯一的 marker 判定），扫描目标只有 127.0.0.1，不会有第二台机器被牵连。

每一格都断言**真实工作量**，而不只是耗时——这是旧基线被撤销的原因（默认请求聚类下「模板数」根本
不等于请求数，夹具路径又和模板对不上，跑出来的 100ms 级数字量的不是同一样东西）：

- nuclei 退出码必须为 0（子进程失败、模板加载不出来都不再是「跑完了」）；
- 夹具收到的请求集合必须**恰好等于** `模板数 × 目标数`，多一条少一条都算失败；
- JSONL 里的 `(template-id, matched-at)` 必须等于预期集合：不重、不漏、没有外来条目；
- 命令固定带 `-disable-clustering`（聚类会让多个模板共用一次请求，量出来的就不是模板成本）、
  `-retries 0`、`-disable-redirects`、`-no-httpx`、`-scan-strategy template-spray`；
- 基线文件带环境指纹（nuclei 版本、镜像 ID、cgroup 限额、CPU 型号、夹具与参数哈希），
  指纹不一致时**拒绝比对**，只让 `--update-baseline` 重建。

```bash
tools/e2e/scan-bench.py --validate-only    # 断言预检（两格各一次），不写基线
tools/e2e/scan-bench.py --update-baseline  # 重建基线（18 格 × 3 次采样，约 7 分钟）
tools/e2e/scan-bench.sh                    # 回归：与 scan-bench-baseline.json 比对，超阈值非零退出
python3 -B tools/e2e/test_scan_bench.py    # 基准自身的单测（不跑 nuclei）
```

矩阵是 200/1000/3000 模板 × 1/4 目标 × 并发 10/20/50，限速固定 500/s；取 3 次采样的中位数，
比基线慢超过 60%（`--tolerance`）判回归。

**当前基线**（2 vCPU / 1 GiB 限额，`jingwei:1.5.0`，nuclei 随镜像钉住；单位：中位秒）：

| 模板 × 目标 | c10 | c20 | c50 |
| :-- | --: | --: | --: |
| 200 × 1 | 0.28 | 0.27 | 0.26 |
| 200 × 4 | 1.35 | 1.38 | 1.35 |
| 1000 × 1 | 1.47 | 1.48 | 1.48 |
| 1000 × 4 | 7.54 | 7.50 | 7.51 |
| 3000 × 1 | 5.52 | 5.45 | 5.48 |
| 3000 × 4 | 24.25 | 23.61 | 23.49 |

怎么读这张表：

- 吞吐约 **510–740 请求/秒**（2 vCPU 限额下），且随规模略降——固定成本摊薄有限、模板编译占比上升；
- **并发 10/20/50 基本无差**：这个量级上限制速度的是 `-rate-limit 500`，不是并发；把并发调大
  只在目标响应慢（要等超时）时才换来得出吞吐；
- 外推按**一次全量扫描实际执行的模板数**算，不是库里的总数：全量模式一次最多加载 10,000 条
  （按危险等级优先，当前库里 13,141 条启用 POC 中等级最低的约 3,100 条这一轮不跑）。
  10,000 × 1 目标 ≈ **18–20 秒**、× 4 目标 ≈ **75–80 秒**的 nuclei 净时间；真实扫描还要加资产发现、
  指纹、目录枚举、弱口令、深挖与专项基线，以及**目标不可达/超时**的等待——对慢目标或在墙上时间预算内，
  实测差距会远大于此表；
- 分片执行（D5）按每片一段模板 × 一组目标调用 nuclei，一次调用约 0.2–0.3 秒固定成本，
  10,000 条切成 25 片大约多花 5–8 秒，换来的是中断后只补剩余分片（实测见进度手册 §4.5）。

