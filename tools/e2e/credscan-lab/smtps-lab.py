#!/usr/bin/env python3
"""smtp-ssl（隐式 TLS，465）真机验证用的最小 SMTPS 服务。

为什么用它而不是 postfix：postfix 要开 465 需要改 master.cf 的
`smtpd_tls_wrappermode=yes`，AUTH 还要另配 cyrus-sasl，两个都是「配置错一点就
静默不生效」的坑。这里要验的是**适配器在隐式 TLS 上的 AUTH PLAIN 判定**，
用 aiosmtpd（Python 官方生态里成熟的 SMTP 实现）能给出真实的 220 / EHLO 多行
应答 / 235 / 535 语义，且账号是显式写死的。

服务端只做三件事：
  1. 握手即 TLS（implicit TLS，不是 STARTTLS）；
  2. EHLO 应答里声明 AUTH PLAIN LOGIN；
  3. AUTH PLAIN 只接受 --user/--password，其余回 535。

用法（证书不存在会自动生成自签）：
    python3 smtps-lab.py --port 1465 --user admin --password jwlab123
"""
import argparse
import os
import ssl
import subprocess
import sys

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink
from aiosmtpd.smtp import AuthResult, LoginPassword


def ensure_cert(cert_dir: str, hostname: str) -> tuple[str, str]:
    os.makedirs(cert_dir, exist_ok=True)
    cert = os.path.join(cert_dir, "smtps.crt")
    key = os.path.join(cert_dir, "smtps.key")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    # 自签就够了：适配器 upgradeTLS 用的是 InsecureSkipVerify，验的是握手能起来。
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert, "-days", "30",
            "-subj", f"/CN={hostname}",
            "-addext", f"subjectAltName=DNS:{hostname},IP:127.0.0.1",
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return cert, key


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=1465)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="jwlab123")
    ap.add_argument("--cert-dir", default="/tmp/jw-smtps-lab")
    args = ap.parse_args()

    cert, key = ensure_cert(args.cert_dir, "localhost")
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    def authenticator(server, session, envelope, mechanism, auth_data):
        # PLAIN/LOGIN 都会走到这里；LoginPassword 是 aiosmtpd 解出来的账号口令。
        if isinstance(auth_data, LoginPassword):
            ok = auth_data.login.decode() == args.user and auth_data.password.decode() == args.password
        else:
            ok = False
        # 口令错回 535 5.7.8，与 Postfix/Exchange 的措辞同一档，适配器只看三位码。
        return AuthResult(success=ok, handled=False)

    ctrl = Controller(
        Sink(),
        hostname=args.host,
        port=args.port,
        server_hostname="localhost",
        ssl_context=ctx,
        authenticator=authenticator,
        # 已经是隐式 TLS，不能再要求 STARTTLS：开了这个开关 aiosmtpd 会拒绝 AUTH。
        auth_require_tls=False,
        auth_required=False,
        tls_context=ctx,
    )
    ctrl.start()
    print(f"smtps ready on {args.host}:{args.port} (implicit TLS, user={args.user})", flush=True)
    try:
        # 前台阻塞，方便被 nohup/systemd 拉起；SIGTERM 由 Ctrl-C 路径处理。
        while True:
            import time
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        ctrl.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
