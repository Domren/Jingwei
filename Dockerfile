# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/jingwei。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/jingwei ./cmd/jingwei
#   docker build -t jingwei:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# 可选代理：构建时传 --build-arg HTTP_PROXY=http://<host>:7890 让 curl/npm/apt 走代理加速外网下载。
# 不传时为空（等价直连）；NO_PROXY 排除国内镜像源，避免绕路变慢。
ARG HTTP_PROXY=""
ARG HTTPS_PROXY=""
ARG NO_PROXY=""
ENV HTTP_PROXY=$HTTP_PROXY HTTPS_PROXY=$HTTPS_PROXY NO_PROXY=$NO_PROXY
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# Node 22.x：从 npmmirror 国内镜像下载二进制（避免 nodesource 外网直连）。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip xz-utils \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && case "${TARGETARCH}" in \
         amd64) narch="x64" ;; \
         arm64) narch="arm64" ;; \
         *) echo "不支持的架构 ${TARGETARCH}" && exit 1 ;; \
       esac \
    && curl -fsSL --connect-timeout 8 --max-time 300 \
         "https://npmmirror.com/mirrors/node/v22.12.0/node-v22.12.0-linux-${narch}.tar.xz" \
         -o /tmp/node.tar.xz \
    && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
    && rm -f /tmp/node.tar.xz \
    && rm -rf /var/lib/apt/lists/* \
    && node -v && npm -v
# nuclei：POC 模板库的执行引擎（Jingwei 二开新增）。固定版本，多架构按 TARGETARCH 选择。
ARG NUCLEI_VERSION=3.11.1
RUN curl -fsSL --connect-timeout 8 --max-time 300 "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" -o /tmp/nuclei.zip \
    || curl -fsSL --connect-timeout 8 --max-time 300 "https://gh-proxy.com/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip \
    && nuclei -version
# sqlmap / dalfox：SQL 注入与 XSS 的专项验证器（Jingwei 二开新增）。深度任务的
# sqli_probe / xss_probe 用它们替代 POC 模板下结论，镜像缺件时任务会直接报「未安装」。
# sqlmap 走 pip（基础镜像就是 python）；dalfox 官方只发二进制包。
#
# pip 源：默认走国内镜像。本网络实测：中科大源 ~3.4MB/s，北外源 ~20KB/s，官方源更慢。
# 需要别的源时：docker compose build --build-arg PIP_INDEX_URL=https://pypi.org/simple
# 用 cache mount（不是 --no-cache-dir）：大包下载失败后重试能续用已下载的 wheel。
ARG PIP_INDEX_URL=https://mirrors.ustc.edu.cn/pypi/simple
RUN --mount=type=cache,target=/root/.cache/pip pip3 install -i "${PIP_INDEX_URL}" --retries 5 --timeout 60 sqlmap \
    && sqlmap --version >/dev/null
# WebCrack：Web 登录页弱口令/万能密码检测引擎（vendor 进 tools/webcrack，二开集成）。
# 扫描流水线「固定渗透基线」用它测登录表单：页面解析→验证码识别（ddddocr）→
# 长度基线+失败关键字判定→二次复验。纯 Python，装依赖即可用；桥接脚本只输出
# 一个 JSON 文档，Go 侧按原始报文登记发现。
#
# 依赖分两档：requirements-core.txt 是引擎本体（requests/bs4/lxml/pyfiglet，约 10MB）；
# ddddocr+onnxruntime+opencv 约 200MB 且国内源常常缺包，只用于**带验证码**的登录页。
# 上游代码对 ddddocr 是 try/except 导入，缺件时带验证码的站点会被跳过并记录原因，
# 不带验证码的站点（绝大多数靶场与 CMS 后台）不受影响。需要 OCR 时：
#   docker compose build --build-arg WEBCRACK_OCR=true
COPY tools/webcrack/ /app/tools/webcrack/
ARG WEBCRACK_OCR=false
RUN --mount=type=cache,target=/root/.cache/pip pip3 install -i "${PIP_INDEX_URL}" --retries 5 --timeout 60 \
        -r /app/tools/webcrack/requirements-core.txt \
    && if [ "${WEBCRACK_OCR}" = "true" ]; then \
         pip3 install -i "${PIP_INDEX_URL}" --retries 5 --timeout 60 ddddocr || echo "[webcrack] ddddocr 安装失败，带验证码的登录页将被跳过"; \
       fi \
    && python3 -c "import requests, bs4, lxml, pyfiglet" \
    && python3 -c "import ddddocr; print('[webcrack] OCR 可用')" || echo "[webcrack] OCR 未安装（WEBCRACK_OCR=false）" \
    && python3 /app/tools/webcrack/jingweibridge.py --help >/dev/null
ARG DALFOX_VERSION=3.2.4
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) arch="x86_64" ;; \
      arm64) arch="aarch64" ;; \
      *) echo "dalfox 不支持架构 ${TARGETARCH}" && exit 1 ;; \
    esac; \
    url="https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-${arch}.tar.gz"; \
    curl -fsSL --connect-timeout 8 --max-time 300 "$url" -o /tmp/dalfox.tgz \
      || curl -fsSL --connect-timeout 8 --max-time 300 "https://gh-proxy.com/$url" -o /tmp/dalfox.tgz; \
    tar -xzf /tmp/dalfox.tgz -C /tmp; \
    install -m 0755 "/tmp/dalfox-v${DALFOX_VERSION}-linux-${arch}/dalfox" /usr/local/bin/dalfox; \
    rm -rf /tmp/dalfox.tgz "/tmp/dalfox-v${DALFOX_VERSION}-linux-${arch}"; \
    dalfox --version
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
# 浏览器下载源可覆盖：官方 CDN 在部分网络下会中途断连，默认使用国内镜像。
ARG PLAYWRIGHT_DOWNLOAD_HOST=https://cdn.npmmirror.com/binaries/playwright
RUN export PLAYWRIGHT_DOWNLOAD_HOST="${PLAYWRIGHT_DOWNLOAD_HOST}" \
    && npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && (playwright install --with-deps chromium || echo "WARN: playwright chromium install failed, browser features degraded") \
    && rm -rf /var/lib/apt/lists/*
# @playwright/cli 内置的 playwright-core 可能比全局 playwright 旧一个版本，
# 会按自己的 revision 找浏览器；复用已安装的 Chromium，避免再下载一份。
RUN set -eux; \
    root="$(npm root -g)"; \
    rev="$(node -p "require('$root/@playwright/cli/node_modules/playwright-core/browsers.json').browsers.find(b => b.name === 'chromium').revision")"; \
    installed="$(find /root/.cache/ms-playwright -maxdepth 1 -type d -name 'chromium-*' | sort -V | tail -1)"; \
    target="/root/.cache/ms-playwright/chromium-${rev}"; \
    if [ ! -x "$target/chrome-linux64/chrome" ] && [ ! -x "$target/chrome-linux/chrome" ] && [ -n "$installed" ]; then \
      ln -sfn "$installed" "$target"; \
    fi
WORKDIR /app
# 预编译好的对应架构二进制（dist/amd64/jingwei 或 dist/arm64/jingwei）
COPY dist/${TARGETARCH}/jingwei /app/jingwei
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 jingwei —— docker stop 只把信号发给 PID 1，
# 不转发的话 jingwei 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/jingwei /app/start.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
