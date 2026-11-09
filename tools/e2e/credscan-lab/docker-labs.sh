#!/usr/bin/env bash
# 用官方镜像起三个「容器里就是真服务」的协议端点，并把清单写到 lab 台同一个 manifest。
#
#   jenkins   真 Jenkins LTS（init.groovy.d 预建账号，跳过安装向导）
#   mssql     SQL Server 2022 Linux（TDS 与 Windows 版同协议，除 SSPI/集成认证）
#   wildfly   WildFly（JBoss AS 7+ 的开源上游，管理台同样是 HTTP 认证）
#
# 只起 Docker 能装下的这三个；Samba/SNMP/svnserve 在 up.sh 里（需要 root 与宿主机端口）。
# 用法：
#   ./docker-labs.sh up   [manifest.json]   起服务并追加用例
#   ./docker-labs.sh down                   删容器
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
LAB_DIR=${JW_CRED_LAB_DIR:-/tmp/jw-cred-lab}
MANIFEST=${2:-$LAB_DIR/lab.json}
JENKINS_PORT=${JW_LAB_JENKINS_PORT:-18080}
MSSQL_PORT=${JW_LAB_MSSQL_PORT:-11433}
WILDFLY_PORT=${JW_LAB_WILDFLY_PORT:-19990}

MSSQL_PW='JwLab!Pass2026'

up() {
  mkdir -p "$LAB_DIR/jenkins/init.groovy.d"
  cat > "$LAB_DIR/jenkins/init.groovy.d/01-security.groovy" <<'GROOVY'
import jenkins.model.*
import hudson.security.*
def instance = Jenkins.getInstanceOrNull()
def realm = new HudsonPrivateSecurityRealm(false)
realm.createAccount("admin", "jwlab123")
instance.setSecurityRealm(realm)
def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
strategy.setAllowAnonymousRead(true)
instance.setAuthorizationStrategy(strategy)
instance.save()
GROOVY
  chmod -R 777 "$LAB_DIR/jenkins"

  docker rm -f jw-lab-jenkins jw-lab-mssql jw-lab-wildfly >/dev/null 2>&1 || true

  docker run -d --name jw-lab-jenkins \
    -p "127.0.0.1:$JENKINS_PORT:8080" \
    -e JAVA_OPTS="-Djenkins.install.runSetupWizard=false" \
    -v "$LAB_DIR/jenkins":/var/jenkins_home \
    jwlab/jenkins:lts-jdk17 >/dev/null

  docker run -d --name jw-lab-mssql \
    -p "127.0.0.1:$MSSQL_PORT:1433" \
    -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD="$MSSQL_PW" -e MSSQL_PID=Developer \
    jwlab/mssql:2022 >/dev/null

  # WildFly 官方镜像只绑 127.0.0.1（CMD 里没有 -bmanagement），端口映射进不来；
  # 管理用户必须建在 ManagementRealm（-m），-a 建的是 application realm。
  docker run -d --name jw-lab-wildfly -p "127.0.0.1:$WILDFLY_PORT:9990" \
    jwlab/wildfly:latest \
    /opt/jboss/wildfly/bin/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 >/dev/null
  for _ in $(seq 1 30); do
    docker exec jw-lab-wildfly test -d /opt/jboss/wildfly >/dev/null 2>&1 && break
    sleep 2
  done
  docker exec jw-lab-wildfly /opt/jboss/wildfly/bin/add-user.sh -m -u admin -p jwlab123 --silent >/dev/null 2>&1 || true
  docker restart jw-lab-wildfly >/dev/null

  echo "waiting for jenkins/mssql/wildfly ..."
  for _ in $(seq 1 120); do
    j=$(curl -s -o /dev/null -m 2 -w '%{http_code}' "http://127.0.0.1:$JENKINS_PORT/login" || true)
    m=$(docker logs jw-lab-mssql 2>&1 | grep -c "ready for client connections")
    w=$(curl -s -o /dev/null -m 2 -w '%{http_code}' "http://127.0.0.1:$WILDFLY_PORT/console" || true)
    if [ "$j" = "200" ] && [ "$m" -ge 1 ] && [ "$w" != "000" ]; then
      echo "all ready (jenkins=$j mssql=$m wildfly=$w)"
      break
    fi
    sleep 2
  done

  python3 - "$MANIFEST" "$JENKINS_PORT" "$MSSQL_PORT" "$WILDFLY_PORT" "$MSSQL_PW" <<'PY'
import json, os, sys
path, jp, mp, wp, pw = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
cases = []
if os.path.exists(path):
    try:
        cases = json.load(open(path)).get("cases", [])
    except Exception:
        cases = []
have = {c.get("protocol") for c in cases}
add = [
    {"protocol": "jenkins", "label": "jenkins LTS (docker)", "host": "127.0.0.1", "port": jp,
     "username": "admin", "password": "jwlab123", "wrong_password": "definitely-wrong-pw",
     "expect_good": "hit", "expect_bad": "deny"},
    {"protocol": "mssql", "label": "SQL Server 2022 (docker)", "host": "127.0.0.1", "port": mp,
     "username": "sa", "password": pw, "wrong_password": "Wrong!pw2026",
     "expect_good": "hit", "expect_bad": "deny"},
    {"protocol": "jboss-console", "label": "WildFly management (docker)", "host": "127.0.0.1", "port": wp,
     "username": "admin", "password": "jwlab123", "wrong_password": "definitely-wrong-pw",
     "expect_good": "hit", "expect_bad": "deny"},
]
for c in add:
    if c["protocol"] not in have:
        cases.append(c)
json.dump({"cases": cases}, open(path, "w"), ensure_ascii=False, indent=2)
print("manifest ->", path, "cases=", len(cases))
PY
}

down() {
  docker rm -f jw-lab-jenkins jw-lab-mssql jw-lab-wildfly >/dev/null 2>&1 || true
  echo "containers removed"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 {up|down} [manifest.json]"; exit 2 ;;
esac
