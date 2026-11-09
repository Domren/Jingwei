#!/usr/bin/env bash
# 把 1.6.0 真机验证用到的六条用例写成一份清单，一条命令跑完：
#
#   ./six-pack.sh                      # 写 /tmp/jw-cred-lab-6/lab.json
#   JW_CRED_LAB=1 JW_CRED_LAB_MANIFEST=/tmp/jw-cred-lab-6/lab.json \
#     go test ./scanner -run TestCredLabProtocols -count=1 -v
#
# 六条用例分三种起法，脚本只管清单，不管起服务：
#   jenkins / mssql / wildfly  -> ./docker-labs.sh up
#   smb / rdp                  -> 宿主机直接起（README「手动起剩下三条」）
#   routeros                   -> qemu + CHR（同上）
#
# 为什么单独留一份清单：这六条的口令是固定的（容器初始化时写死），不能像 up.sh 那样现生成；
# 而 up.sh 每次重跑都会整体重写 /tmp/jw-cred-lab/lab.json，混在一起会被冲掉。
set -eu

OUT=${1:-/tmp/jw-cred-lab-6/lab.json}
JENKINS_PORT=${JW_LAB_JENKINS_PORT:-18080}
MSSQL_PORT=${JW_LAB_MSSQL_PORT:-11433}
WILDFLY_PORT=${JW_LAB_WILDFLY_PORT:-19990}
SMB_PORT=${JW_LAB_SMB_PORT:-445}
RDP_PORT=${JW_LAB_RDP_PORT:-3389}
ROUTEROS_PORT=${JW_LAB_ROUTEROS_PORT:-18728}
MSSQL_PW=${JW_LAB_MSSQL_PW:-'JwLab!Pass2026'}

mkdir -p "$(dirname "$OUT")"
python3 - "$OUT" "$JENKINS_PORT" "$MSSQL_PORT" "$WILDFLY_PORT" "$SMB_PORT" "$RDP_PORT" "$ROUTEROS_PORT" "$MSSQL_PW" <<'PY'
import json, sys
out, jp, mp, wp, sp, rp, rop, pw = sys.argv[1:9]
cases = [
    {"protocol": "jenkins", "label": "jenkins lts-jdk17 真实例", "host": "127.0.0.1", "port": int(jp),
     "username": "admin", "password": "jwlab123", "wrong_password": "definitely-wrong-pw",
     "expect_good": "hit", "expect_bad": "deny"},
    {"protocol": "mssql", "label": "SQL Server 2022 Linux 真实例", "host": "127.0.0.1", "port": int(mp),
     "username": "sa", "password": pw, "wrong_password": "Wrong!pw2026",
     "expect_good": "hit", "expect_bad": "deny"},
    {"protocol": "smb", "label": "samba 4.24 真实例", "host": "127.0.0.1", "port": int(sp),
     "username": "jwlab", "password": "jwlab123", "wrong_password": "definitely-wrong-pw",
     "expect_good": "hit", "expect_bad": "deny"},
    {"protocol": "jboss-console", "label": "WildFly 25 management (Digest)", "host": "127.0.0.1", "port": int(wp),
     "username": "admin", "password": "jwlab123", "wrong_password": "definitely-wrong-pw",
     "expect_good": "hit", "expect_bad": "deny"},
    # xrdp 只允许 TLS，适配器按「安全层被拒」落 inconclusive，不判口令——
    # 所以这条没有 expect_bad：错口令也走不到认证那一步，写 deny 就是伪造结论。
    {"protocol": "rdp", "label": "xrdp 0.10 (security_layer=negotiate)", "host": "127.0.0.1", "port": int(rp),
     "username": "jwlab", "password": "jwlab123", "wrong_password": "definitely-wrong-pw",
     "expect_good": "inconclusive"},
    {"protocol": "routeros", "label": "RouterOS 7.16.2 CHR (qemu)", "host": "127.0.0.1", "port": int(rop),
     "username": "admin", "password": "jwlab123", "wrong_password": "definitely-wrong-pw",
     "expect_good": "hit", "expect_bad": "deny"},
]
json.dump({"cases": cases}, open(out, "w"), ensure_ascii=False, indent=2)
print("manifest ->", out, "cases =", len(cases))
PY
