#!/usr/bin/env bash
# smtp-ssl（465 隐式 TLS）真机用例：起一个真实 SMTPS 服务并写出一份只有它一条的清单。
#
#   ./smtps-lab.sh up        # 起服务 + 写清单
#   ./smtps-lab.sh test      # 跑适配器
#   ./smtps-lab.sh down      # 停服务（顺手删清单）
#
# 为什么单独一个脚本：up.sh 管的是「弱口令靶场全家桶」，每次重跑都会重写
# /tmp/jw-cred-lab/lab.json；smtp-ssl 的账号与端口固定，混进去会被冲掉（six-pack.sh 同理）。
#
# 依赖：python3-venv。aiosmtpd 从 venv 装，走中科大源（本机不启用任何代理进程）。
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
WORK=${JW_SMTPS_DIR:-/tmp/jw-smtps-lab}
PORT=${JW_SMTPS_PORT:-1465}
USER_NAME=${JW_SMTPS_USER:-admin}
PASS=${JW_SMTPS_PASS:-jwlab123}
MANIFEST=${JW_SMTPS_MANIFEST:-$WORK/lab.json}
PIDFILE=$WORK/smtps.pid
LOG=$WORK/smtps.log

ensure_venv() {
  if [ ! -x "$WORK/venv/bin/python" ]; then
    python3 -m venv "$WORK/venv"
  fi
  if ! "$WORK/venv/bin/python" -c 'import aiosmtpd' 2>/dev/null; then
    "$WORK/venv/bin/pip" install -q -i https://mirrors.ustc.edu.cn/pypi/web/simple aiosmtpd
  fi
}

write_manifest() {
  mkdir -p "$(dirname "$MANIFEST")"
  python3 - "$MANIFEST" "$PORT" "$USER_NAME" "$PASS" <<'PY'
import json, sys
out, port, user, pw = sys.argv[1:5]
json.dump({"cases": [{
    "protocol": "smtp-ssl",
    "label": "aiosmtpd 1.4.6 隐式 TLS (SMTPS 465)",
    "host": "127.0.0.1",
    "port": int(port),
    "username": user,
    "password": pw,
    "wrong_password": "definitely-wrong-pw",
    "expect_good": "hit",
    "expect_bad": "deny",
    # 这一条的价值就在 TLS：服务端是隐式 TLS，适配器必须一上来就握手，
    # 走明文连 banner 都读不到（会被当成 unreachable），所以要显式断言。
    "expect_tls": True,
}], }, open(out, "w"), ensure_ascii=False, indent=2)
print("manifest ->", out)
PY
}

case "${1:-up}" in
  up)
    ensure_venv
    mkdir -p "$WORK"
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "已在运行 (pid $(cat "$PIDFILE"))"
    else
      nohup "$WORK/venv/bin/python" "$HERE/smtps-lab.py" \
        --port "$PORT" --user "$USER_NAME" --password "$PASS" --cert-dir "$WORK" \
        >"$LOG" 2>&1 &
      echo $! >"$PIDFILE"
    fi
    for _ in $(seq 1 50); do
      if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then break; fi
      sleep 0.2
    done
    if ! (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
      echo "SMTPS 没起来，日志：" >&2
      tail -20 "$LOG" >&2
      exit 1
    fi
    write_manifest
    echo "smtps ready: 127.0.0.1:$PORT (user=$USER_NAME)"
    ;;
  test)
    cd "$ROOT"
    JW_CRED_LAB=1 JW_CRED_LAB_MANIFEST="$MANIFEST" \
      go test ./scanner -run TestCredLabProtocols -count=1 -v
    ;;
  down)
    if [ -f "$PIDFILE" ]; then
      kill "$(cat "$PIDFILE")" 2>/dev/null || true
      rm -f "$PIDFILE"
    fi
    rm -f "$MANIFEST"
    echo "stopped"
    ;;
  *)
    echo "用法: $0 {up|test|down}" >&2
    exit 2
    ;;
esac
