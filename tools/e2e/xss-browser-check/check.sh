#!/usr/bin/env bash
# D1 端到端验证：在 jingwei 镜像里用真实 Chromium 跑 XSS 判定的三种形态。
#
# 为什么放在镜像里跑：验证器依赖 node + playwright + chromium，这三样只在镜像内
# 齐备；在宿主上跑不了就如实跳过，而不是把「没跑」写成「通过」。
#
# 用法：bash tools/e2e/xss-browser-check/check.sh [容器名]
set -uo pipefail

CONTAINER="${1:-jingwei-jingwei-1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
VERIFY="$REPO/scanner/xssbrowser_verify.cjs"
FIXTURE="$HERE/fixture.cjs"
WORK=/tmp/jw-xss-browser-check
PORT=8791

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "SKIP: 容器 $CONTAINER 未运行"
  exit 0
fi

if ! docker exec "$CONTAINER" sh -lc 'command -v node >/dev/null'; then
  echo "SKIP: 容器内没有 node"
  exit 0
fi

GLOBAL_MODULES="$(docker exec "$CONTAINER" sh -lc 'npm root -g' 2>/dev/null | tr -d '\r')"
if [ -z "$GLOBAL_MODULES" ]; then
  echo "SKIP: 容器内取不到 npm 全局目录"
  exit 0
fi
PLAYWRIGHT_MODULE="$GLOBAL_MODULES/playwright"
if ! docker exec "$CONTAINER" env JW_PLAYWRIGHT_MODULE="$PLAYWRIGHT_MODULE" \
  node -e "require(process.env.JW_PLAYWRIGHT_MODULE)" >/dev/null 2>&1; then
  echo "SKIP: 容器内没有 playwright 模块（$PLAYWRIGHT_MODULE）"
  exit 0
fi

cleanup() {
  docker exec "$CONTAINER" sh -lc "pkill -f 'fixture.cjs $PORT' || true; rm -rf $WORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker exec "$CONTAINER" sh -lc "mkdir -p $WORK"
docker cp "$VERIFY" "$CONTAINER:$WORK/verify.cjs" >/dev/null
docker cp "$FIXTURE" "$CONTAINER:$WORK/fixture.cjs" >/dev/null

docker exec -d "$CONTAINER" sh -lc "cd $WORK && node fixture.cjs $PORT > $WORK/fixture.log 2>&1"
for _ in $(seq 1 40); do
  if docker exec "$CONTAINER" node -e "fetch('http://127.0.0.1:$PORT/reflect?q=ping').then(r=>r.text()).then(t=>process.exit(t.includes('ping')?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

PAYLOAD='<img src=x onerror=alert(1)>'
cat > "$HERE/input.json" <<JSON
{"timeout_ms":15000,"targets":[
 {"url":"http://127.0.0.1:$PORT/reflect?q=$PAYLOAD","payload":"$PAYLOAD"},
 {"url":"http://127.0.0.1:$PORT/escape?q=$PAYLOAD","payload":"$PAYLOAD"},
 {"url":"http://127.0.0.1:$PORT/textarea?q=$PAYLOAD","payload":"$PAYLOAD"}
]}
JSON
docker cp "$HERE/input.json" "$CONTAINER:$WORK/input.json" >/dev/null
rm -f "$HERE/input.json"

OUT="$(docker exec "$CONTAINER" env JW_PLAYWRIGHT_MODULE="$PLAYWRIGHT_MODULE" \
  node "$WORK/verify.cjs" "$WORK/input.json" 2>&1 | tail -n 1)"
printf '%s' "$OUT" > /tmp/jw-xss-browser-result.json

python3 - "$OUT" <<'PY'
import json, sys
raw = sys.argv[1].strip()
try:
    data = json.loads(raw)
except Exception as e:
    print(f"FAIL: 输出不是 JSON（{e}）: {raw[:400]}")
    sys.exit(1)
if data.get("missing"):
    print("SKIP: playwright 不可用: " + str(data.get("error", "")))
    sys.exit(0)
if data.get("error"):
    print("FAIL: " + str(data["error"]))
    sys.exit(1)
res = {}
for r in data.get("results", []):
    path = r["url"].split("/")[3].split("?")[0]
    res[path] = r
fail = []
reflect = res.get("reflect", {})
if not reflect.get("executed"):
    fail.append(f"/reflect 应执行但未执行: {json.dumps(reflect, ensure_ascii=False)}")
escape = res.get("escape", {})
if escape.get("executed"):
    fail.append(f"/escape 不应执行: {json.dumps(escape, ensure_ascii=False)}")
if escape.get("reflected"):
    fail.append(f"/escape 已转义却判成反射: {json.dumps(escape, ensure_ascii=False)}")
textarea = res.get("textarea", {})
if textarea.get("executed"):
    fail.append(f"/textarea 不应执行: {json.dumps(textarea, ensure_ascii=False)}")
if not textarea.get("reflected"):
    fail.append(f"/textarea 应判为「仅反射」: {json.dumps(textarea, ensure_ascii=False)}")
if fail:
    print("FAIL:\n  - " + "\n  - ".join(fail))
    sys.exit(1)
print(f"PASS: playwright={data.get('version','?')} 三种形态判定正确 "
      f"(reflect executed={reflect.get('executed')}, escape reflected={escape.get('reflected')}, "
      f"textarea reflected_only={textarea.get('reflected') and not textarea.get('executed')})")
PY
