#!/usr/bin/env bash
# 为 java-chains 创建/轮换 Jingwei 专用 MCP token，并把 token 写入 .env。
# 用法（在 docker-compose.yml 所在目录执行）：
#   bash deploy/java-chains-setup.sh
# 可选环境变量：
#   ENV_FILE=.env  JAVA_CHAINS_WEB_URL=http://127.0.0.1:9792
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
BASE_URL="${JAVA_CHAINS_WEB_URL:-http://127.0.0.1:9792}"

if [ ! -f "$ENV_FILE" ]; then
  echo "找不到 $ENV_FILE，请在 docker-compose.yml 所在目录运行" >&2
  exit 1
fi
command -v python3 >/dev/null 2>&1 || {
  echo "需要 python3 来调用 java-chains API" >&2
  exit 1
}

python3 - "$ENV_FILE" "$BASE_URL" <<'PY'
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request

env_file, base = sys.argv[1], sys.argv[2].rstrip("/")


def read_env(path):
    vals = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip().strip('"').strip("'")
    return vals


env = read_env(env_file)
password = env.get("JAVA_CHAINS_PASS", "")
if not password:
    sys.exit("JAVA_CHAINS_PASS 为空：请在 .env 设置密码并重建 java-chains sidecar")

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def csrf_token():
    for c in jar:
        if c.name == "XSRF-TOKEN":
            return c.value
    return ""


def req(method, path, data=None, token=None, extra_headers=None):
    url = base + path
    headers = {"Accept": "application/json"}
    body = None
    if method != "GET" and csrf_token():
        headers["X-XSRF-TOKEN"] = csrf_token()
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Api-Token"] = token
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(request, timeout=15) as resp:
            raw = resp.read() or b"{}"
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read() or b"{}")
        except Exception:
            payload = {}
        return e.code, payload
    except urllib.error.URLError as e:
        sys.exit(f"无法连接 {url}: {getattr(e, 'reason', e)}（先启动 java-chains sidecar）")


status, body = req("POST", "/auth/login", {"username": "admin", "password": password})
if status != 200 or not body.get("success"):
    sys.exit(f"登录失败: HTTP {status} {body.get('message', '')}")

status, body = req("POST", "/api/tokens/enabled", {"enabled": True})
if status != 200:
    sys.exit(f"启用 API token 失败: HTTP {status} {body.get('message', '')}")

scopes = [
    "catalog:read",
    "chain:validate",
    "generate",
    "runtime:read",
    "runtime:publish",
    "runtime:control",
    "logs:read",
    "mcp:invoke",
]


def token_works(tok):
    if not tok:
        return False
    status, _ = req(
        "POST",
        "/api/mcp",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "jingwei-setup", "version": "1"},
            },
        },
        token=tok,
        extra_headers={"Accept": "application/json, text/event-stream"},
    )
    return status == 200


secret = env.get("JAVA_CHAINS_MCP_TOKEN", "").strip()
action = "复用"
if not token_works(secret):
    status, body = req("GET", "/api/tokens")
    if status != 200:
        sys.exit(f"读取 token 列表失败: HTTP {status}")
    tokens = ((body.get("data") or {}).get("tokens") or [])
    target = next((t for t in tokens if t.get("name") == "jingwei-skill" and t.get("enabled")), None)
    if target:
        status, body = req("POST", f"/api/tokens/{target['id']}/rotate")
        action = "轮换"
    else:
        status, body = req("POST", "/api/tokens", {"name": "jingwei-skill", "scopes": scopes})
        action = "新建"
    if status != 200 or not body.get("success"):
        sys.exit(f"{action} token 失败: HTTP {status} {body.get('message', '')}")
    secret = (body.get("data") or {}).get("secret", "")
    if not secret:
        sys.exit(f"{action} token 响应缺少 secret")

status, body = req("POST", "/api/mcp/config", {"enabled": True})
if status != 200 or not body.get("success"):
    sys.exit(f"启用 MCP 失败: HTTP {status} {body.get('message', '')}")

old = env.get("JAVA_CHAINS_MCP_TOKEN", "").strip()
if secret != old:
    with open(env_file, encoding="utf-8") as f:
        lines = f.read().splitlines()
    out, found = [], False
    for line in lines:
        if line.startswith("JAVA_CHAINS_MCP_TOKEN="):
            out.append("JAVA_CHAINS_MCP_TOKEN=" + secret)
            found = True
        else:
            out.append(line)
    if not found:
        if out and out[-1].strip():
            out.append("")
        out.append("# java-chains MCP 令牌（java-chains-setup.sh 生成）")
        out.append("JAVA_CHAINS_MCP_TOKEN=" + secret)
    with open(env_file, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.chmod(env_file, 0o600)
    print(f"{action} JAVA_CHAINS_MCP_TOKEN 并写入 {env_file}（前缀 {secret[:8]}…）")
else:
    print("JAVA_CHAINS_MCP_TOKEN 有效，无需更新")

print("MCP 已启用。下一步：docker compose up -d --no-deps jingwei")
PY
