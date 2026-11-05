#!/usr/bin/env bash
# 弱口令检测真机验证：把「每个协议都有一个真实服务」搭起来，再由
# scanner/credscan_lab_test.go 对每个服务跑「命中」与「拒绝」两条路径。
#
# 为什么这么麻烦：规划表 B3a 不接受「字典加载跑通」当验证。协议适配器的错只有在线上
# 才路得出来——SCRAM 的 nonce 少一位、md5 的 salt 取错偏移、MySQL 的包序号差一格，
# 进程内靶子可能和适配器错得一模一样（这批适配器写作过程中真的各错过一次）。
#
# 口令都是这里现生成的，只写进 /tmp/jw-cred-lab/lab.json（600），不落仓库、不回显。
# 用完跑同目录 down.sh：停服务、删临时账号、恢复被改过的系统配置、删凭据文件。
set -uo pipefail

LAB_DIR=/tmp/jw-cred-lab
LAB_JSON="$LAB_DIR/lab.json"
mkdir -p "$LAB_DIR"; chmod 700 "$LAB_DIR"
FAILED=0
note() { printf '%s\n' "$*" >&2; }
bad() { note "!! $*"; FAILED=1; }
genpw() { openssl rand -hex 10; }

P_REDIS_PASS=16399
P_REDIS_OPEN=16400
P_PG=55455
P_MONGO=27077
P_FTP=21        # vsftpd 只在发行版默认配置上起得来，见下面注释
P_TELNET=23230
P_SOCKS=10800
P_SOCKS_OPEN=10801
P_U1_SSH=2201
P_U1_MYSQL=3306
LABRUN=${JW_LAB_RUN:-/root/lab-ubuntu/wslrun.sh}
LAB_DISTRO=${JW_LAB_DISTRO:-Ubuntu-1}

echo '{"cases":[]}' > "$LAB_JSON"; chmod 600 "$LAB_JSON"

# add_case <协议> <标签> <host> <port> <用户名> <口令> <错口令> <对的结果> <错的结果> [params JSON]
add_case() {
  python3 - "$LAB_JSON" "$@" <<'PY'
import json, sys
a = sys.argv[1:]
p, proto, label, host, port, user, pw, wrong, egood, ebad = a[:10]
extra = a[10] if len(a) > 10 else ""
flags = a[11] if len(a) > 11 else ""
d = json.load(open(p))
case = {"protocol": proto, "label": label, "host": host, "port": int(port),
        "username": user, "password": pw, "wrong_password": wrong,
        "expect_good": egood, "expect_bad": ebad}
if extra:
    case["params"] = json.loads(extra)
if flags:
    case.update(json.loads(flags))
d["cases"].append(case)
json.dump(d, open(p, "w"), indent=1)
PY
  note "case + $1/$2 :$4"
}

wait_port() {
  local h=$1 p=$2 t=${3:-30} i=0
  while [ "$i" -lt "$t" ]; do
    (exec 3<>"/dev/tcp/$h/$p") 2>/dev/null && { exec 3<&-; return 0; }
    sleep 0.5; i=$((i + 1))
  done
  return 1
}

# ── Redis：一个开了 requirepass，一个完全不开认证 ────────────────────────────
# 每次都重启自己那一档并记下口令。沿用旧实例是不行的：端口被占时新的 redis-server
# 直接退出，而 wait_port 对着旧实例返回成功——清单里记的是新生成的口令，线上跑的是
# 旧口令，测出来的 WRONGPASS 与适配器无关（这一条是真机跑出来的第二个坑）。
restart_redis() { # port extra...
  local port=$1; shift
  # requirepass 那一档没法用 redis-cli shutdown（没有旧口令），按进程名精确杀自己起的那一档。
  # 端口被占时新的 redis-server 直接退出、wait_port 又对着旧实例成功，于是清单里是新生成的
  # 口令、线上是旧口令——测出来的 WRONGPASS 与适配器无关。
  [ -f "$LAB_DIR/redis-$port.pid" ] && kill "$(cat "$LAB_DIR/redis-$port.pid")" 2>/dev/null
  pkill -f "redis-server 127.0.0.1:$port" 2>/dev/null
  redis-cli -p "$port" shutdown nosave 2>/dev/null
  sleep 0.6
  redis-server --port "$port" --bind 127.0.0.1 --save '' \
    --pidfile "$LAB_DIR/redis-$port.pid" --logfile "$LAB_DIR/redis-$port.log" --daemonize yes "$@"
  wait_port 127.0.0.1 "$port" 20
}
REDIS_PW=$(genpw)
if restart_redis $P_REDIS_PASS --requirepass "$REDIS_PW"; then
  printf '%s' "$REDIS_PW" > "$LAB_DIR/redis-pass.value"; chmod 600 "$LAB_DIR/redis-pass.value"
  add_case redis "requirepass" 127.0.0.1 $P_REDIS_PASS "" "$REDIS_PW" "buhaig-$REDIS_PW" hit deny
else
  bad "redis(requirepass) 没起来"
fi
if restart_redis $P_REDIS_OPEN; then
  add_case redis "未开认证" 127.0.0.1 $P_REDIS_OPEN "" "" "suiyi123" hit deny
else
  bad "redis(无认证) 没起来"
fi

# ── PostgreSQL：一个实例里做出 scram / md5 / trust 三种认证 ──────────────────
PG_PW=$(genpw)
if ! docker ps --format '{{.Names}}' | grep -qx jw-cred-pg; then
  docker rm -f jw-cred-pg >/dev/null 2>&1
  docker run -d --name jw-cred-pg -p 127.0.0.1:$P_PG:5432 \
    -e POSTGRES_PASSWORD="$PG_PW" postgres:16-alpine >/dev/null || bad "postgres 容器起不来"
  echo "$PG_PW" > "$LAB_DIR/pg-super.pass"; chmod 600 "$LAB_DIR/pg-super.pass"
fi
if docker ps --format '{{.Names}}' | grep -qx jw-cred-pg; then
  wait_port 127.0.0.1 $P_PG 60 || bad "postgres 端口没就绪"
  # 打开服务端 TLS：适配器「服务端支持就升 TLS」这条分支只有真开着 SSL 的实例才会走到，
  # 而证书校验被刻意跳过（目标的 CA 不可能预装在本机），所以必须靠真握手来证明
  # 「记录的是通道内明文」这件事没写错。ssl 是 postmaster 级参数，reload 不生效——只能重启。
  if [ "$(docker exec jw-cred-pg psql -U postgres -tAc 'show ssl;')" != "on" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
      -keyout "$LAB_DIR/pg-server.key" -out "$LAB_DIR/pg-server.crt" \
      -subj "/CN=jw-cred-pg" >/dev/null 2>&1 || bad "自签证书生成失败"
    DD=$(docker exec jw-cred-pg psql -U postgres -tAc "show data_directory;")
    docker cp "$LAB_DIR/pg-server.crt" "jw-cred-pg:$DD/server.crt" >/dev/null
    docker cp "$LAB_DIR/pg-server.key" "jw-cred-pg:$DD/server.key" >/dev/null
    # 私钥必须 root 所有且非群/ worldwide 可读，否则 postmaster 直接拒绝加载。
    docker exec jw-cred-pg sh -c "chown root:root $DD/server.key $DD/server.crt && chmod 600 $DD/server.key"
    docker exec jw-cred-pg psql -U postgres -q \
      -c "alter system set ssl='on';" \
      -c "alter system set ssl_cert_file='server.crt';" \
      -c "alter system set ssl_key_file='server.key';" >/dev/null
    docker restart jw-cred-pg >/dev/null && wait_port 127.0.0.1 $P_PG 60 || bad "开 TLS 后 postgres 没起来"
    note "postgres TLS 已开：$(docker exec jw-cred-pg psql -U postgres -tAc 'show ssl;')"
  fi
  HBA=$(docker exec jw-cred-pg psql -U postgres -tAc "show hba_file;")
  # pg_hba 首条匹配生效，按用户写的规则必须排在通配前面。踩过一次：trust 规则写在文件
  # 末尾时所有连接都被后面的 scram 拦掉，看起来像「trust 不生效」，其实是规则顺序。
  docker exec jw-cred-pg sh -c "cat > $HBA <<'EOF'
local   all             all                                     trust
host    all             jwtrust 0.0.0.0/0                       trust
host    all             jwmd5   0.0.0.0/0                       md5
host    all             all     0.0.0.0/0                       scram-sha-256
EOF"
  MD5_PW='md5weak1'
  docker exec jw-cred-pg psql -U postgres -q -c "alter system set password_encryption='md5';" \
    -c "select pg_reload_conf();" >/dev/null; sleep 1
  docker exec jw-cred-pg psql -U postgres -q -c "drop user if exists jwmd5;" \
    -c "create user jwmd5 password '$MD5_PW';" >/dev/null 2>&1
  docker exec jw-cred-pg psql -U postgres -q -c "alter system set password_encryption='scram-sha-256';" \
    -c "select pg_reload_conf();" >/dev/null; sleep 1
  docker exec jw-cred-pg psql -U postgres -q -c "drop user if exists jwscram;" \
    -c "create user jwscram password '$PG_PW';" >/dev/null 2>&1 \
    && docker exec jw-cred-pg psql -U postgres -q -c "drop user if exists jwtrust;" \
       -c "create user jwtrust password 'cancha1';" >/dev/null 2>&1 \
    || bad "postgres 测试账号建不出来"
  add_case postgresql "scram-sha-256" 127.0.0.1 $P_PG jwscram "$PG_PW" "buhaig-$PG_PW" hit deny '{"database":"postgres"}' '{"expect_tls":true}'
  add_case postgresql "md5" 127.0.0.1 $P_PG jwmd5 "$MD5_PW" "buhaig-1" hit deny '{"database":"postgres"}' '{"expect_tls":true}'
  # trust 那条：能用的是「这个账号不需要口令」。空口令命中，非空口令只能是不可判定。
  add_case postgresql "trust" 127.0.0.1 $P_PG jwtrust "" "cancha1" hit inconclusive '{"database":"postgres"}' '{"expect_tls":true}'
fi

# ── MongoDB：root 用户同时带 SCRAM-SHA-256 与 SCRAM-SHA-1 两套凭据 ───────────
MONGO_PW=$(genpw)
MONGO_PW_FILE="$LAB_DIR/mongo-root.pass"
if docker image inspect mongo:8.0 >/dev/null 2>&1; then
  # 容器在跑但没记下口令 = 这一档的凭据已经无从得知（root 用户只在容器第一次初始化时建）。
  # 沿用下去就是拿一个新口令去撞旧实例，报出来的 Authentication failed 与适配器无关。
  if docker ps --format '{{.Names}}' | grep -qx jw-cred-mongo && [ ! -s "$MONGO_PW_FILE" ]; then
    note "jw-cred-mongo 在跑但没记录口令，重建这一档"
    docker rm -f jw-cred-mongo >/dev/null 2>&1
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx jw-cred-mongo; then
    docker rm -f jw-cred-mongo >/dev/null 2>&1
    docker run -d --name jw-cred-mongo -p 127.0.0.1:$P_MONGO:27017 \
      -e MONGO_INITDB_ROOT_USERNAME=jwadmin -e MONGO_INITDB_ROOT_PASSWORD="$MONGO_PW" \
      mongo:8.0 >/dev/null || bad "mongo 容器起不来"
    printf '%s' "$MONGO_PW" > "$MONGO_PW_FILE"; chmod 600 "$MONGO_PW_FILE"
  else
    MONGO_PW=$(cat "$MONGO_PW_FILE")
  fi
  if wait_port 127.0.0.1 $P_MONGO 60; then
    add_case mongodb "scram-sha-256" 127.0.0.1 $P_MONGO jwadmin "$MONGO_PW" "buhaig-$MONGO_PW" hit deny
    add_case mongodb "scram-sha-1" 127.0.0.1 $P_MONGO jwadmin "$MONGO_PW" "buhaig-$MONGO_PW" hit deny \
      '{"mechanism":"SCRAM-SHA-1"}'
  else
    bad "mongo 端口没就绪"
  fi
else
  note "跳过 MongoDB：本机没有 mongo:8.0 镜像。docker pull 走不通（dockerd 的代理指向关着的 Clash，"
  note "  这是本机既定配置不是故障），用 skopeo 绕开守护进程拉一次就永久可用："
  note "  skopeo copy docker://docker.m.daocloud.io/library/mongo:8.0 docker-daemon:mongo:8.0"
fi

# ── 一个临时系统用户，供 FTP / Telnet / SOCKS5 三个走 PAM 的服务共用 ─────────
SYS_USER=jwcred
SYS_PW=$(genpw)
id "$SYS_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$SYS_USER" 2>/dev/null || bad "临时用户建不出来"
echo "$SYS_USER:$SYS_PW" | chpasswd 2>/dev/null || bad "临时用户口令设不上"

# vsftpd：发行版包只在 /etc/vsftpd.conf 上起得来（自带的最小配置在本机总是 rc=2 退出，
# 连不上原因没进日志），所以这里改系统配置：先备份到 LAB_DIR，down.sh 负责恢复。
if [ ! -f "$LAB_DIR/vsftpd.conf.orig" ]; then
  cp /etc/vsftpd.conf "$LAB_DIR/vsftpd.conf.orig" || bad "vsftpd 配置备份失败"
fi
sed -i 's/^#local_enable=YES/local_enable=YES/; s/^write_enable=YES/write_enable=NO/' /etc/vsftpd.conf
pkill -x vsftpd 2>/dev/null; sleep 1
nohup /usr/sbin/vsftpd /etc/vsftpd.conf >"$LAB_DIR/vsftpd.out" 2>&1 &
if wait_port 127.0.0.1 $P_FTP 15; then
  add_case ftp "vsftpd 本地账号" 127.0.0.1 $P_FTP "$SYS_USER" "$SYS_PW" "buhaig-$SYS_PW" hit deny
else
  bad "vsftpd 没起来：$(tail -2 "$LAB_DIR/vsftpd.out" 2>/dev/null | tr '\n' ' ')"
fi

# in.telnetd 由 inetd 拉起；这里用 socat 顶替 inetd，把连接接到它的 stdin/stdout
pkill -f "TCP-LISTEN:$P_TELNET" 2>/dev/null
nohup socat "TCP-LISTEN:$P_TELNET,bind=127.0.0.1,fork,reuseaddr" EXEC:/usr/sbin/in.telnetd \
  >"$LAB_DIR/telnet.out" 2>&1 &
echo $! > "$LAB_DIR/telnet.pid"
if wait_port 127.0.0.1 $P_TELNET 15; then
  add_case telnet "netkit telnetd" 127.0.0.1 $P_TELNET "$SYS_USER" "$SYS_PW" "buhaig-$SYS_PW" hit deny
else
  bad "telnetd 没起来：$(tail -2 "$LAB_DIR/telnet.out" 2>/dev/null | tr '\n' ' ')"
fi

# dante(SOCKS5 用户名口令)。1.4 版的关键字是 client pass / socks pass，且老式 pass 块里
# 不能出现 clientfrom——写错时 danted 直接 shutting down，端口根本不监听。
if [ ! -f /etc/pam.d/sockd ]; then
  cat > /etc/pam.d/sockd <<'EOF'
auth      required  pam_unix.so
account   required  pam_unix.so
session   required  pam_permit.so
EOF
  touch "$LAB_DIR/sockd-pam-created"
fi
SOCKD="$LAB_DIR/sockd.conf"
cat > "$SOCKD" <<EOF
logoutput: $LAB_DIR/danted.log
internal: 127.0.0.1 port = $P_SOCKS
external: 127.0.0.1
clientmethod: none
socksmethod: username
user.privileged: root
user.notprivileged: nobody

client pass {
    from: 127.0.0.1/32 to: 0.0.0.0/0
    log: error connect
}

socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect
}
EOF
pkill -f "danted -D -f $SOCKD" 2>/dev/null
danted -D -f "$SOCKD" >/dev/null 2>&1 &
echo $! > "$LAB_DIR/danted.pid"
if wait_port 127.0.0.1 $P_SOCKS 15; then
  add_case socks5 "danted username" 127.0.0.1 $P_SOCKS "$SYS_USER" "$SYS_PW" "buhaig-$SYS_PW" hit deny
else
  bad "danted 没起来：$(tail -3 "$LAB_DIR/danted.log" 2>/dev/null | tr '\n' ' ')"
fi

# ── 边界靶机 Ubuntu-1 上的 SSH 与 MySQL ──────────────────────────────────────
# 与平台日常在用的那三个弱口令账号分开：这里自建专用账号，验完删掉，
# 免得把「适配器把口令打错」和「靶机原有账号被动过」混进同一份记录。
SSH_PW=$(genpw)
MYSQL_PW=$(genpw)
NATIVE_PW=$(genpw)
if [ -f "$LABRUN" ]; then
  cat > "$LAB_DIR/u1-ssh-user.sh" <<EOF
set -e
id jwcred >/dev/null 2>&1 || useradd -m -s /bin/bash jwcred
echo "jwcred:$SSH_PW" | chpasswd
echo SSH-USER-OK
EOF
  if bash "$LABRUN" "$LAB_DISTRO" "$LAB_DIR/u1-ssh-user.sh" 2>&1 | grep -q SSH-USER-OK; then
    if wait_port 127.0.0.1 $P_U1_SSH 5; then
      add_case ssh "Ubuntu-1 sshd:$P_U1_SSH" 127.0.0.1 $P_U1_SSH jwcred "$SSH_PW" "buhaig-$SSH_PW" hit deny
      # 无认证 SOCKS5：ssh -D 出来的动态代理只接受「无认证」方法，正好覆盖另一条分支。
      pkill -f "ProxyCommand=none -D 127.0.0.1:$P_SOCKS_OPEN" 2>/dev/null
      sshpass -p "$SSH_PW" nohup ssh -N -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ProxyCommand=none -D "127.0.0.1:$P_SOCKS_OPEN" -p $P_U1_SSH "jwcred@127.0.0.1" \
        >"$LAB_DIR/socks-open.out" 2>&1 &
      echo $! > "$LAB_DIR/socks-open.pid"
      if wait_port 127.0.0.1 $P_SOCKS_OPEN 15; then
        add_case socks5 "无认证(ssh -D)" 127.0.0.1 $P_SOCKS_OPEN "" "" "anyuser/anypass" hit deny
      else
        note "跳过：无认证 SOCKS5 没起来：$(tail -2 "$LAB_DIR/socks-open.out" 2>/dev/null | tr '\n' ' ')"
      fi
    else
      note "跳过：Ubuntu-1 的 sshd 端口 $P_U1_SSH 没在听（靶机没开？）"
    fi
  else
    note "跳过：Ubuntu-1 上的 SSH 测试账号建不出来"
  fi

  # MySQL 8：caching_sha2 是默认插件，除了快速通道还要走服务端 RSA 公钥的完整认证；
  # 再建一个 mysql_native_password 账号，两条实现路径都要有线上证据。
  cat > "$LAB_DIR/u1-mysql-user.sh" <<EOF
set -e
M="mysql --defaults-file=/etc/mysql/debian.cnf"
if \$M -e "select 1" >/dev/null 2>&1; then
  \$M -e "DROP USER IF EXISTS 'jwcred'@'%'; CREATE USER 'jwcred'@'%' IDENTIFIED WITH caching_sha2_password BY '$MYSQL_PW'; GRANT USAGE ON *.* TO 'jwcred'@'%';"
  \$M -e "DROP USER IF EXISTS 'jwnative'@'%'; CREATE USER 'jwnative'@'%' IDENTIFIED WITH mysql_native_password BY '$NATIVE_PW'; GRANT USAGE ON *.* TO 'jwnative'@'%';"
  mysql -h 127.0.0.1 -P $P_U1_MYSQL -ujwcred -p'$MYSQL_PW' -e "select 1" >/dev/null 2>&1 && echo MYSQL-USER-OK
else
  echo NO-MAINT-AUTH
fi
EOF
  if bash "$LABRUN" "$LAB_DISTRO" "$LAB_DIR/u1-mysql-user.sh" 2>&1 | grep -q MYSQL-USER-OK; then
    add_case mysql "Ubuntu-1 caching_sha2" 127.0.0.1 $P_U1_MYSQL jwcred "$MYSQL_PW" "buhaig-$MYSQL_PW" hit deny
    add_case mysql "Ubuntu-1 native" 127.0.0.1 $P_U1_MYSQL jwnative "$NATIVE_PW" "buhaig-$NATIVE_PW" hit deny
  else
    note "跳过：Ubuntu-1 上的 MySQL 测试账号建不出来（debian-sys-maint 不可用？）"
  fi
else
  note "跳过 SSH/MySQL：没有 $LABRUN（边界靶机不在这台机器上时设 JW_LAB_RUN 指过去）"
fi

chmod 600 "$LAB_JSON"
note "───────────────────────────────"
note "靶环境清单：$LAB_JSON（600，down.sh 会删）"
python3 - "$LAB_JSON" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
seen = {}
for c in d["cases"]:
    seen.setdefault(c["protocol"], []).append(c["label"])
for p in sorted(seen):
    print("  %-10s %d 条: %s" % (p, len(seen[p]), ", ".join(seen[p])))
print("共 %d 条，覆盖 %d 个协议" % (len(d["cases"]), len(seen)))
PY
[ "$FAILED" -eq 0 ] || note "上面标 !! 的服务没起来；缺的协议在测试里算未覆盖，不会当成通过"
exit 0
