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

## i2-mock-crawl.js — 演示站逐页巡检

这个脚本不打真实例：它遍历**静态导出的每一个页面**（默认 `web/out`），逐页打开，记录脚本错误
与正文长度。演示模式的接口是本地假路由，漏一个路径就表现为「页面空白」或 `undefined.length`
崩溃，而这类崩溃在真实实例上不会出现——所以它是独立的一道检查，不依赖靶机。

```bash
cd web && NEXT_PUBLIC_MOCK=1 NEXT_EXPORT=1 npx next build   # 产出带假数据的 web/out
python3 -m http.server 3006 --directory out                 # 或在别处起静态服务，用 MOCK_BASE 指过去
MOCK_BASE=http://127.0.0.1:3006 OUT_DIR=out node ../tools/e2e/i2-mock-crawl.js
```

期望输出：`有脚本错误的页面=0`、`正文过短的页面` 只包含 `/404/`。跑完记得把 `web/out` 用正式
构建覆盖回去——`server/webui/dist` 是从它拷进二进制的。

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
