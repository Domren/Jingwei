#!/usr/bin/env bash
# 全量测试：并行/串行 × URI/keyword DSN 四种口径，一次跑完。
# 用法：先起测试库（compose profile test 或手工 docker run），然后直接执行本脚本。
#
# 两条不能省的设置，都是真踩过坑之后加上的：
#   TMPDIR 落盘 —— 默认的 /run/user/0 是几百兆的 tmpfs，并行时 go test 把测试二进制
#     拷进去会写爆，报出来是「fork/exec .../*.test: no such file or directory」这种
#     看着像代码问题、其实是磁盘问题的假故障。
#   先核对 HEAD 能否单独检出编译 —— 有两次「功能代码没进提交」：工作树全绿、按提交检出
#     编不出来。只跑工作树测试拦不住这一类。
set -uo pipefail

cd "$(dirname "$0")/.."
REPO=$(pwd)
export TMPDIR="${TMPDIR:-/var/tmp/jingwei-test-tmp}"
mkdir -p "$TMPDIR"

PG_CONTAINER="${JINGWEI_TEST_PG_CONTAINER:-jingwei-test-pg}"
if ! docker inspect "$PG_CONTAINER" >/dev/null 2>&1; then
  echo "找不到测试库容器 $PG_CONTAINER（可用 JINGWEI_TEST_PG_CONTAINER 指定）" >&2
  exit 1
fi
PW=$(docker inspect "$PG_CONTAINER" --format '{{json .Config.Env}}' | python3 -c '
import sys, json
for e in json.load(sys.stdin):
    if e.startswith("POSTGRES_PASSWORD="):
        print(e.split("=", 1)[1], end="")')
PG_HOST="${JINGWEI_TEST_PG_HOST:-127.0.0.1}"
PG_PORT="${JINGWEI_TEST_PG_PORT:-55433}"
PG_DB="${JINGWEI_TEST_PG_DB:-jingwei_gotest}"
# 口令里的特殊字符必须转义，否则 URI 形式直接被 libpq 解析错。
URI_PW=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$PW")
URI="postgres://jingwei:${URI_PW}@${PG_HOST}:${PG_PORT}/${PG_DB}?sslmode=disable"
KW="host=${PG_HOST} port=${PG_PORT} user=jingwei password=${PW} dbname=${PG_DB} sslmode=disable"
export JINGWEI_TEST_ALLOW_DB_WIPE=1

echo "=== 0 按提交检出编译（HEAD 自洽）==="
WT=$(mktemp -d)
git worktree add -q "$WT" HEAD || { echo "worktree 建不起来" >&2; exit 1; }
(cd "$WT" && go build ./... && go vet ./...) && echo "HEAD 编译与 vet 通过" || { echo "HEAD 不自洽：有文件只在工作树里，没进提交" >&2; git worktree remove --force "$WT"; exit 1; }
git worktree remove --force "$WT"

for i in 1 2 3 4; do
  case $i in
    1) MODE=""; DSN="$URI"; LABEL="并行 URI" ;;
    2) MODE="-p 1"; DSN="$URI"; LABEL="串行 URI" ;;
    3) MODE=""; DSN="$KW"; LABEL="并行 keyword" ;;
    4) MODE="-p 1"; DSN="$KW"; LABEL="串行 keyword" ;;
  esac
  LOG="${JW_TEST_LOG_DIR:-/tmp}/jingwei-test-$i.log"
  echo "=== $i $LABEL → $LOG ==="
  # shellcheck disable=SC2086
  JINGWEI_PG_DSN="$DSN" go test ./... $MODE -count=1 >"$LOG" 2>&1
  echo "EXIT$i=$? 失败包=$(grep -c '^FAIL[[:space:]]' "$LOG") 失败用例=$(grep -c '^--- FAIL' "$LOG")"
done

echo "=== 汇总 ==="
rc=0
for i in 1 2 3 4; do
  LOG="${JW_TEST_LOG_DIR:-/tmp}/jingwei-test-$i.log"
  if grep -qE '^(--- FAIL|FAIL[[:space:]])' "$LOG"; then
    rc=1
    echo "run$i 有失败："
    grep -hE '^(--- FAIL|FAIL[[:space:]])' "$LOG" | head -10
  fi
done
[ $rc -eq 0 ] && echo "四种口径全绿" || echo "有失败，见上面日志"
exit $rc
