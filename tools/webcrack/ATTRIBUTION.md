# Vendored: WebCrack Pro

Web 登录页弱口令 / 万能密码检测引擎，Jingwei 固定渗透基线的「弱口令」步骤使用它。
扫描流水线不自己实现爆破逻辑：`scanner/webcrack.go` 调用本目录的
`jingweibridge.py`，由后者驱动这里的 `src/`。

## 来源

- 上游：<https://github.com/2t8a/WebCrack-Pro>（分支 main，commit `81846a6a25752a5b2cd2f021e80d9f3148d0fdb1`，2025-12-08）
- 上游的上游：<https://github.com/yzddmr6/WebCrack>（原作者 @yzddmr6，最后提交 `eb64610`，2021-09-07）
- 许可状态：**两个上游仓库都没有 LICENSE 文件**（GitHub API 返回 `license: null`），
  原始 README 仅声明「请勿用于非法用途」。本目录按原作者署名保留代码，
  不代表获得了再分发许可。
- 决定（2026-10-26，项目负责人确认）：**保持现状**，随源码仓库与本镜像一起保留，
  分发范围限定为自用 / 私有镜像。若要公开分发镜像（如 GHCR 公开发布、
  把镜像托管给第三方），需先向上游作者取得授权，或改为运行时下载。

## 本仓库的改动

只改了两处行为，其余保持上游原样（改动处均有注释）：

1. `src/core/brute_force.py`：去掉「响应里出现用户名/密码字段就跳过」的判断。
   上游用它降低误报，但登录失败后仍原样输出表单的页面（靶场、多数 CMS 后台）
   会被全部跳过，导致永远测不到。长度基线 + 失败关键字 + 二次复验已经足够定案。
2. `src/core/brute_force.py`：`run()` / `_run_attack()` 由返回 `True/False`
   改为返回 `(username, password)`，并把 `found_kind`（`weak` / `universal`）与
   `task_timeout` 配置项暴露给桥接层；不改判定算法。

新增文件：`jingweibridge.py`（Jingwei 侧的 JSON 桥接，含原始请求/响应取证）、
`requirements-core.txt`（引擎本体依赖：requests / beautifulsoup4 / lxml / pyfiglet）。
`requirements.txt` 保持上游原样，仅作参考——镜像默认只装 core，`ddddocr`（连同 onnxruntime、
opencv，约 200MB，且国内 pip 源经常缺包）改为按需构建：
`docker compose build --build-arg WEBCRACK_OCR=true`。未装 OCR 时只有带验证码的登录页会被跳过，
判定算法与无验证码站点不受影响。

## 判定流程（上游算法，未改动）

1. `PageParser` 解析页面：找登录表单、用户名/密码字段名、提交地址、验证码元素；
   非登录页直接结束。
2. 用固定错误凭据打两次，得到「失败响应长度基线」，长度不稳定则放弃该 URL。
3. 依次跑基础字典（+ 域名派生字典）与万能密码字典；
   每次响应先看失败关键字黑名单，再看长度是否偏离基线。
4. 疑似命中后用「错误凭据 + 命中凭据」各打一次做二次复验，长度不同且非 403 才算确认。
5. 验证码页面：装了 `ddddocr` 时自动识别并填入；没装则跳过该站点。
