#!/usr/bin/env bash
# 关掉 up.sh 起的验证服务，并清掉它留下的东西：临时用户、被改过的系统配置、
# 现场生成的口令文件、临时容器。
#
# 这份脚本是 up.sh 的一部分而非装饰：验证过程会在宿主机上加用户、改 /etc/vsftpd.conf、
# 建临时容器。留下这些就是「测试环境只在一台机器上能跑」的成因。
set -uo pipefail
LAB_DIR=/tmp/jw-cred-lab
note() { printf '%s\n' "$*" >&2; }

for pidfile in "$LAB_DIR/redis-pass.pid" "$LAB_DIR/redis-open.pid"; do
  [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null && rm -f "$pidfile"
done
[ -f "$LAB_DIR/telnet.pid" ] && kill "$(cat "$LAB_DIR/telnet.pid")" 2>/dev/null && rm -f "$LAB_DIR/telnet.pid"
[ -f "$LAB_DIR/memcached.pid" ] && kill "$(cat "$LAB_DIR/memcached.pid")" 2>/dev/null && rm -f "$LAB_DIR/memcached.pid"
[ -f "$LAB_DIR/danted.pid" ] && kill "$(cat "$LAB_DIR/danted.pid")" 2>/dev/null && rm -f "$LAB_DIR/danted.pid"
[ -f "$LAB_DIR/socks-open.pid" ] && kill "$(cat "$LAB_DIR/socks-open.pid")" 2>/dev/null && rm -f "$LAB_DIR/socks-open.pid"
pkill -x vsftpd 2>/dev/null
pkill -f "TCP-LISTEN:23230" 2>/dev/null
pkill -f "danted -D -f $LAB_DIR/sockd.conf" 2>/dev/null
pkill -f "ProxyCommand=none -D 127.0.0.1:10801" 2>/dev/null

# 恢复被改过的系统配置
if [ -f "$LAB_DIR/vsftpd.conf.orig" ]; then
  cp "$LAB_DIR/vsftpd.conf.orig" /etc/vsftpd.conf && note "已恢复 /etc/vsftpd.conf"
fi
if [ -f "$LAB_DIR/sockd-pam-created" ]; then
  rm -f /etc/pam.d/sockd && note "已删除临时 /etc/pam.d/sockd"
fi

# 宿主机上的临时验证用户
if id jwcred >/dev/null 2>&1; then
  userdel -r jwcred 2>/dev/null && note "已删除本机临时用户 jwcred"
fi

# 一次性容器
docker rm -f jw-cred-pg >/dev/null 2>&1 && note "已删除 jw-cred-pg 容器"
docker rm -f jw-cred-mongo >/dev/null 2>&1 && note "已删除 jw-cred-mongo 容器"
docker rm -f jw-cred-es >/dev/null 2>&1 && note "已删除 jw-cred-es 容器"

# 边界靶机上的 Apache 验证站点（配置、口令文件、页面）
LABRUN=${JW_LAB_RUN:-/root/lab-ubuntu/wslrun.sh}
LAB_DISTRO=${JW_LAB_DISTRO:-Ubuntu-1}
if [ -f "$LABRUN" ]; then
  cat > /tmp/jw-cred-lab-apache-down.sh <<'EOF'
a2disconf jw-cred-lab >/dev/null 2>&1 || true
rm -f /etc/apache2/conf-available/jw-cred-lab.conf
rm -f /etc/apache2/jw-cred-lab.htpasswd
rm -rf /var/www/jw-cred-lab
apache2ctl graceful >/dev/null 2>&1 || true
echo APACHE-LAB-DOWN
EOF
  bash "$LABRUN" "$LAB_DISTRO" /tmp/jw-cred-lab-apache-down.sh 2>&1 | grep -q APACHE-LAB-DOWN \
    && note "已清理 Ubuntu-1 上的 Apache 验证站点" || note "Ubuntu-1 的 Apache 验证站点未能清理（靶机没开？）"
  rm -f /tmp/jw-cred-lab-apache-down.sh
fi

# 边界靶机上的 Tomcat 验证用户与包（恢复到验证前的状态）
if [ -f "$LABRUN" ]; then
  cat > /tmp/jw-cred-lab-tomcat-down.sh <<'EOF'
if [ -f /tmp/jw-cred-lab-tomcat-users.orig ]; then
  cp /tmp/jw-cred-lab-tomcat-users.orig /etc/tomcat9/tomcat-users.xml
  rm -f /tmp/jw-cred-lab-tomcat-users.orig
  systemctl restart tomcat9 >/dev/null 2>&1 || service tomcat9 restart >/dev/null 2>&1 || true
fi
DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq tomcat9-admin >/dev/null 2>&1 || true
echo TOMCAT-DOWN
EOF
  bash "$LABRUN" "$LAB_DISTRO" /tmp/jw-cred-lab-tomcat-down.sh 2>&1 | grep -q TOMCAT-DOWN \
    && note "已恢复 Ubuntu-1 的 tomcat-users.xml 并移除 tomcat9-admin" || note "Ubuntu-1 的 Tomcat 清理未完成（靶机没开？）"
  rm -f /tmp/jw-cred-lab-tomcat-down.sh

  cat > /tmp/jw-cred-lab-zk-down.sh <<'EOF'
systemctl stop zookeeper >/dev/null 2>&1 || service zookeeper stop >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq zookeeperd zookeeper >/dev/null 2>&1 || true
echo ZK-DOWN
EOF
  bash "$LABRUN" "$LAB_DISTRO" /tmp/jw-cred-lab-zk-down.sh 2>&1 | grep -q ZK-DOWN \
    && note "已停止并移除 Ubuntu-1 的 Zookeeper" || note "Ubuntu-1 的 Zookeeper 清理未完成（靶机没开？）"
  rm -f /tmp/jw-cred-lab-zk-down.sh
fi

# 边界靶机上的专用账号（靶机没开时静默跳过，别把清理失败说成已清理）
LABRUN=${JW_LAB_RUN:-/root/lab-ubuntu/wslrun.sh}
LAB_DISTRO=${JW_LAB_DISTRO:-Ubuntu-1}
if [ -f "$LABRUN" ]; then
  cat > /tmp/jw-cred-lab-drop-user.sh <<'EOF'
set -e
id jwcred >/dev/null 2>&1 && userdel -r jwcred 2>/dev/null && echo SSH-USER-DROPPED
M="mysql --defaults-file=/etc/mysql/debian.cnf"
$M -e "DROP USER IF EXISTS 'jwcred'@'%'; DROP USER IF EXISTS 'jwnative'@'%';" 2>/dev/null && echo MYSQL-USER-DROPPED
EOF
  bash "$LABRUN" "$LAB_DISTRO" /tmp/jw-cred-lab-drop-user.sh 2>&1 | grep -E "DROPPED" | sed 's/^/  /' >&2 || true
  rm -f /tmp/jw-cred-lab-drop-user.sh
fi

# 口令文件
if [ -d "$LAB_DIR" ]; then
  find "$LAB_DIR" -maxdepth 1 -name '*.pass' -delete 2>/dev/null
  rm -f "$LAB_DIR/lab.json" "$LAB_DIR/sockd.conf" \
    "$LAB_DIR/pg-server.crt" "$LAB_DIR/pg-server.key"
  note "已删除 $LAB_DIR/lab.json 与 *.pass"
fi
left=$(ls -A "$LAB_DIR" 2>/dev/null | wc -l)
note "验证目录 $LAB_DIR 还剩 $left 个文件（日志与 vsftpd.conf.orig 留着备查；不再需要时 rm -rf）"
exit 0
