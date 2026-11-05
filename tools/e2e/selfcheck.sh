#!/usr/bin/env bash
# 平台自身安全回归（I3）——每次大版本发布前对一台已部署实例跑一遍，报告归档。
#
# 只做**只读探测**：不发认证尝试、不改配置、不登录。登录链路的滑块与限流由
# server/auth*_test.go 钉住（脚本化登录绕不过滑块，能测到的只有「滑块是必经之路」）。
#
# 用法：BASE=http://127.0.0.1:9790 REPORT_DIR=docs/reports ./tools/e2e/selfcheck.sh
# 可选：TOKEN_FILE=/tmp/jw.token（有则顺带验一次「带令牌可访问」）
#       JW_CONTAINER=jingwei-jingwei-1（有则在宿主上检查回调端口是否只绑回环）
set -uo pipefail

BASE="${BASE:-http://127.0.0.1:9790}"
REPORT_DIR="${REPORT_DIR:-docs/reports}"
TOKEN_FILE="${TOKEN_FILE:-/tmp/jw.token}"
JW_CONTAINER="${JW_CONTAINER:-jingwei-jingwei-1}"
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$REPORT_DIR/selfcheck-$STAMP.md"
mkdir -p "$REPORT_DIR"

pass=0 fail=0 skip=0
rows=""
note() { printf '  %s\n' "$*"; }
record() { # record <PASS|FAIL|SKIP> <name> <detail>
  case $1 in PASS) pass=$((pass+1));; FAIL) fail=$((fail+1));; *) skip=$((skip+1));; esac
  rows+="| $1 | $2 | $3 |"$'\n'
  printf '[%s] %s — %s\n' "$1" "$2" "$3"
}
code_of() { curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$@"; }
body_of() { curl -s --max-time 8 "$@"; }

# ── 1. 未认证面：敏感接口必须 401/403 ─────────────────────────────────────
while IFS='|' read -r method path; do
  [ -z "$path" ] && continue
  code=$(code_of -X "$method" "$BASE$path")
  case $code in
    401|403) record PASS "未认证 $method $path" "拒绝（$code）" ;;
    5*)      record FAIL "未认证 $method $path" "服务端错误 $code，本应是鉴权拒绝" ;;
    *)       record FAIL "未认证 $method $path" "返回 $code —— 鉴权没兜住" ;;
  esac
done <<'EOF'
GET|/api/settings
GET|/api/tasks
GET|/api/assets
GET|/api/exploration/findings
GET|/api/scans
GET|/api/credscan/tasks
GET|/api/authorizations
GET|/api/intranet/scripts
GET|/api/intranet/sessions
GET|/api/intercept/rules
GET|/api/managed-resources
GET|/api/notify/channels
EOF

# ── 2. 公开面：健康检查可匿名读，且不泄漏内部信息 ──────────────────────────
health=$(body_of "$BASE/api/health")
if printf '%s' "$health" | grep -qiE 'postgres|password|dsn|jwt|secret|token'; then
  record FAIL "GET /api/health 内容" "响应里出现了内部信息关键词：$(printf '%s' "$health" | head -c 120)"
else
  record PASS "GET /api/health 内容" "可匿名读，未见内部信息关键词"
fi

# ── 3. CORS：任何来源都不该拿到 ACAO ─────────────────────────────────────
aca=$(curl -s -D- -o /dev/null --max-time 8 -H 'Origin: https://evil.example' "$BASE/api/health" | tr -d '\r' | grep -i '^access-control-allow-origin' || true)
if [ -z "$aca" ]; then
  record PASS "CORS 拒绝跨源" "未回 Access-Control-Allow-Origin"
else
  record FAIL "CORS 拒绝跨源" "回了 $aca"
fi

# ── 4. 登录入口：滑块是必经之路，且不区分「用户不存在」 ─────────────────────
no_cap=$(curl -s -o /tmp/selfcheck_login1.json -w '%{http_code}' --max-time 8 \
  -H 'Content-Type: application/json' -d '{"username":"selfcheck","password":"x"}' "$BASE/api/auth/login")
bad_cap=$(curl -s -o /tmp/selfcheck_login2.json -w '%{http_code}' --max-time 8 \
  -H 'Content-Type: application/json' -d '{"username":"selfcheck","password":"x","captcha_id":"deadbeef","captcha_x":10}' "$BASE/api/auth/login")
if [ "$no_cap" = "400" ] && grep -q '滑块' /tmp/selfcheck_login1.json; then
  record PASS "登录缺滑块被拒" "400 且提示滑块"
else
  record FAIL "登录缺滑块被拒" "返回 $no_cap：$(head -c 120 /tmp/selfcheck_login1.json)"
fi
if [ "$bad_cap" = "400" ] && ! grep -qiE '用户不存在|用户名不存在|no such user' /tmp/selfcheck_login2.json; then
  record PASS "伪造滑块被拒" "400，未泄漏账号是否存在"
else
  record FAIL "伪造滑块被拒" "返回 $bad_cap：$(head -c 120 /tmp/selfcheck_login2.json)"
fi

# ── 5. 响应头：不泄漏技术栈 ───────────────────────────────────────────────
hdrs=$(curl -s -D- -o /dev/null --max-time 8 "$BASE/api/health" | tr -d '\r')
if printf '%s' "$hdrs" | grep -qiE '^(x-powered-by|server:.*(go|gin|next))'; then
  record FAIL "响应头" "$(printf '%s' "$hdrs" | grep -iE '^(x-powered-by|server:)' | head -2 | tr '\n' ' ')"
else
  record PASS "响应头" "未见 X-Powered-By / Server 技术栈标识"
fi

# ── 6. 前端资源不夹带机密字段名 ───────────────────────────────────────────
if curl -s --max-time 8 "$BASE/" | grep -qiE 'jwt_key|platform_secret|BEGIN (RSA|OPENSSH)'; then
  record FAIL "前端资源" "首页内容里出现了机密字段名"
else
  record PASS "前端资源" "首页未见机密字段名"
fi

# ── 7. 回调端口只绑回环（需要在宿主上能看容器端口） ─────────────────────────
if command -v docker >/dev/null 2>&1 && docker inspect "$JW_CONTAINER" >/dev/null 2>&1; then
  cb=$(docker port "$JW_CONTAINER" 8788 2>/dev/null | head -1)
  if [ -z "$cb" ]; then
    record SKIP "回调端口绑定" "容器未发布 8788（可能未启用回调）"
  elif printf '%s' "$cb" | grep -q '^127\.0\.0\.1:'; then
    record PASS "回调端口绑定" "$cb（仅回环）"
  else
    record FAIL "回调端口绑定" "$cb 不是仅回环——无认证回调端口不得对外"
  fi
else
  record SKIP "回调端口绑定" "没有可用的 docker/$JW_CONTAINER"
fi

# ── 8. 带令牌可访问（可选，证明鉴权链路本身是通的） ──────────────────────────
if [ -f "$TOKEN_FILE" ]; then
  code=$(code_of -H "Authorization: Bearer $(cat "$TOKEN_FILE")" "$BASE/api/settings")
  if [ "$code" = "200" ]; then
    record PASS "带令牌访问" "200（鉴权链路通）"
  else
    record FAIL "带令牌访问" "$code（令牌过期或鉴权异常）"
  fi
else
  record SKIP "带令牌访问" "无 $TOKEN_FILE"
fi

# ── 报告 ─────────────────────────────────────────────────────────────────
{
  echo "# 平台自身安全回归（selfcheck $STAMP）"
  echo
  echo "- 目标：$BASE"
  echo "- 结论：**PASS $pass / FAIL $fail / SKIP $skip**"
  echo "- 说明：只读探测。滑块与登录限流的前端路径、Cookie 属性、JWT 吊销由 Go 测试覆盖，"
  echo "  脚本不发起认证尝试（脚本化登录绕不过滑块，硬试只会把自己锁在门外）。"
  echo
  echo "| 结论 | 项 | 细节 |"
  echo "| :-- | :-- | :-- |"
  printf '%s' "$rows"
} > "$OUT"
echo "报告：$OUT"
[ $fail -eq 0 ]
