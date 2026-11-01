#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the pure-HTTP slider captcha support.

Run from the repository root:
    python3 -m unittest discover -s tools/webcrack/tests -v
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import requests

from src.core import slider_captcha as sc
from src.utils.config import load_config
from src.utils.logger import init_logger

AJ_HTML = """
<html><body>
<form action="/login" method="post">
  <input name="username"><input name="password" type="password">
  <input type="hidden" name="captchaVerification" value="">
  <span>拖动滑块完成验证</span>
</form>
<script src="/js/captcha.js"></script>
</body></html>
"""

AJ_SECRET = "0123456789abcdef"

ERROR_HTML = ("<html><body><form>用户名或密码错误</form>"
              "<p>请返回重试</p></body></html>")
SUCCESS_HTML = ("<html><body><h1>登录成功</h1><p>欢迎 admin</p>"
                "<p>" + "dashboard " * 40 + "</p>"
                "<p>退出登录</p></body></html>")


def _fake_helper(directory, payload=None):
    path = Path(directory) / "fake-jingwei"
    answer = payload or {
        "ok": True, "offset": 130, "distance": 130, "y": 5,
        "confidence": 0.99, "elapsed_ms": 1,
        "track": [{"x": 10, "y": 0, "t": 0}, {"x": 130, "y": 0, "t": 300}],
    }
    quoted = json.dumps(answer, ensure_ascii=False).replace("'", "'\\''")
    path.write_text("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{}'\n".format(quoted),
                    encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _stale_helper(directory):
    path = Path(directory) / "stale-jingwei"
    path.write_text("#!/bin/sh\ncat >/dev/null\necho 'Jingwei banner'\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


class MockTarget:
    """Minimal AJ-Captcha + profile target; records every request."""

    def __init__(self, fail_checks=0):
        self.requests = []
        self.fail_checks = fail_checks
        self.check_count = 0
        self.challenge_count = 0
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # noqa: A003
                pass

            def _send(self, status, body, content_type="application/json"):
                raw = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _record(self, body):
                with outer._lock:
                    outer.requests.append({
                        "method": self.command,
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": body,
                    })

            def do_GET(self):
                self._record("")
                if self.path == "/js/captcha.js":
                    self._send(200, 'var baseUrl = "/";', "application/javascript")
                    return
                if self.path == "/login":
                    self._send(200, AJ_HTML, "text/html; charset=utf-8")
                    return
                self._send(404, "{}")

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode("utf-8", "replace")
                self._record(raw)
                if self.path == "/login":
                    form = parse_qs(raw)
                    user = (form.get("username") or [""])[0]
                    password = (form.get("password") or [""])[0]
                    verification = (form.get("captchaVerification") or [""])[0]
                    if user == "admin" and password == "123456" and verification:
                        page = SUCCESS_HTML.encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Set-Cookie", "PHPSESSID=ok-session; Path=/")
                        self.send_header("Content-Length", str(len(page)))
                        self.end_headers()
                        self.wfile.write(page)
                    else:
                        self._send(200, ERROR_HTML, "text/html; charset=utf-8")
                    return
                try:
                    body = json.loads(raw) if raw else {}
                except ValueError:
                    body = {}
                if self.path.endswith("/captcha/get"):
                    with outer._lock:
                        outer.challenge_count += 1
                        n = outer.challenge_count
                    self._send(200, json.dumps({
                        "repCode": "0000",
                        "repData": {
                            "originalImage": "ZmFrZS1iYWNrZ3JvdW5k",
                            "jigsawImage": "ZmFrZS1waWVjZQ==",
                            "token": "tok-{}".format(n),
                            "secretKey": AJ_SECRET,
                        },
                    }))
                    return
                if self.path.endswith("/captcha/check"):
                    with outer._lock:
                        outer.check_count += 1
                        failed = outer.check_count <= outer.fail_checks
                    if failed:
                        self._send(200, json.dumps({
                            "repCode": "6110", "repMsg": "验证码校验失败"}))
                    else:
                        self._send(200, json.dumps({"repCode": "0000"}))
                    return
                if self.path == "/slide/challenge":
                    self._send(200, json.dumps({
                        "data": {"bg": "ZmFrZS1iZw==", "piece": "ZmFrZS1waWVjZQ==",
                                 "token": "chal-1"},
                    }))
                    return
                if self.path == "/slide/verify":
                    ok = (body.get("token") == "chal-1"
                          and body.get("x") == 130
                          and isinstance(body.get("track"), list)
                          and len(body["track"]) == 2)
                    self._send(200, json.dumps({
                        "data": {"ok": ok, "token": "vt-1"},
                    }))
                    return
                self._send(404, "{}")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.origin = "http://127.0.0.1:{}".format(self.httpd.server_address[1])
        self.url = self.origin + "/login"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(2)

    def requests_to(self, suffix):
        with self._lock:
            return [r for r in self.requests if r["path"].endswith(suffix)]


class SliderCaptchaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="jingwei-slider-test-")
        self.addCleanup(self.tmp.cleanup)
        init_logger(self.tmp.name)
        self.saved_env = {}
        for name in ("JINGWEI_SLIDER_HELPER", "WEBCRACK_SLIDER_HELPER"):
            self.saved_env[name] = os.environ.pop(name, None)
        self.helper = _fake_helper(self.tmp.name)
        self.target = MockTarget()
        self.addCleanup(self.target.close)

    def tearDown(self):
        for name, value in self.saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def config(self, helper=None):
        cfg = load_config()
        cfg["slider"]["enabled"] = True
        cfg["slider"]["helper"] = helper if helper is not None else self.helper
        cfg["brute_force"]["timeout"] = 5
        cfg["brute_force"]["requests_proxies"] = {}
        return cfg

    def session(self):
        s = requests.Session()
        s.trust_env = False
        return s

    def run_bridge(self, pairs):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "jingweibridge.py"),
             "--url", self.target.url,
             "--pairs-stdin", "-",
             "--per-url-timeout", "30",
             "--delay", "0",
             "--slider-helper", self.helper],
            input=json.dumps(pairs), capture_output=True, text=True,
            timeout=120, cwd=str(ROOT), env=dict(os.environ),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-1000:])
        try:
            out = json.loads(proc.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            self.fail("bridge 未输出 JSON: stdout={!r} stderr={!r}".format(
                proc.stdout[-1000:], proc.stderr[-1000:]))
        self.assertEqual(len(out.get("results") or []), 1, proc.stdout[-1000:])
        return out["results"][0]

    # -- crypto -----------------------------------------------------------

    def test_aes_fips197_block(self):
        round_keys = sc._expand_key(bytes(range(16)))
        block = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(
            sc._encrypt_block(block, round_keys).hex(),
            "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_aes_ecb_pkcs7_matches_openssl(self):
        self.assertEqual(
            sc.aes_ecb_pkcs7_base64('{"x":130,"y":5}', "0123456789abcdef"),
            "cJs4ualGqnayG1zV5ropjA==")
        self.assertEqual(
            sc.aes_ecb_pkcs7_base64("abc", "0123456789abcdef01234567"),
            "N381R4r9QBJr3LTV+b6e5g==")
        self.assertEqual(
            sc.aes_ecb_pkcs7_base64("abc", "0123456789abcdef0123456789abcdef"),
            "nXq4Kb6LKP0NHxVo2IQuAA==")
        self.assertEqual(sc.aes_ecb_pkcs7_base64("abc", ""), "abc")

    # -- helper resolution ------------------------------------------------

    def test_missing_explicit_helper_has_clear_error(self):
        helper = sc.SliderHelper(str(Path(self.tmp.name) / "does-not-exist"))
        self.assertFalse(helper.available())
        self.assertIn("不存在或不可执行", helper.error)
        with self.assertRaises(sc.SliderError) as ctx:
            helper.solve("bg", "piece")
        self.assertIn("不存在或不可执行", str(ctx.exception))

    def test_invalid_env_helper_does_not_fall_back(self):
        os.environ["JINGWEI_SLIDER_HELPER"] = "/nonexistent/jingwei"
        helper = sc.SliderHelper("")
        self.assertFalse(helper.available())
        self.assertIn("JINGWEI_SLIDER_HELPER", helper.error)

    def test_stale_helper_reports_missing_subcommand(self):
        helper = sc.SliderHelper(_stale_helper(self.tmp.name))
        self.assertTrue(helper.available())
        with self.assertRaises(sc.SliderError) as ctx:
            helper.solve("bg", "piece")
        message = str(ctx.exception)
        self.assertIn("不支持 captcha-solve", message)
        self.assertIn("新版 jingwei", message)

    def test_fake_helper_returns_geometry(self):
        answer = sc.SliderHelper(self.helper).solve("bg", "piece")
        self.assertEqual(answer["offset"], 130)
        self.assertEqual(answer["distance"], 130)

    # -- detection --------------------------------------------------------

    def test_detects_aj_captcha(self):
        adapter = sc.build_slider_adapter(self.target.url, AJ_HTML, self.config())
        self.assertIsInstance(adapter, sc.AJCaptchaAdapter)
        self.assertEqual(adapter.kind, "aj-captcha")

    def test_commercial_slider_is_explicitly_unsupported(self):
        html = '<html><div id="nc_1_n1z"></div>极验滑块</html>'
        adapter = sc.build_slider_adapter(self.target.url, html, self.config())
        self.assertIsInstance(adapter, sc.UnsupportedSlider)
        with self.assertRaises(sc.SliderError) as ctx:
            adapter.prepare(self.session(), {})
        self.assertIn("商业滑块", str(ctx.exception))

    def test_slider_without_protocol_is_unsupported(self):
        html = "<html><form>拖动滑块完成验证码</form></html>"
        adapter = sc.build_slider_adapter(self.target.url, html, self.config())
        self.assertIsInstance(adapter, sc.UnsupportedSlider)

    def test_plain_login_page_has_no_slider(self):
        html = '<html><form><input name="username"><input name="password"></form></html>'
        self.assertIsNone(sc.build_slider_adapter(self.target.url, html, self.config()))

    # -- AJ-Captcha end to end -------------------------------------------

    def test_aj_adapter_solves_and_injects_verification(self):
        adapter = sc.AJCaptchaAdapter(self.target.url, AJ_HTML, self.config())
        form = {"username": "admin", "password": "123456",
                "captchaVerification": ""}
        adapter.prepare(self.session(), form)
        point_plain = '{"x":130,"y":5}'
        self.assertEqual(
            form["captchaVerification"],
            sc.aes_ecb_pkcs7_base64("tok-1---" + point_plain, AJ_SECRET))
        checks = self.target.requests_to("/captcha/check")
        self.assertEqual(len(checks), 1)
        check_body = json.loads(checks[0]["body"])
        self.assertEqual(check_body["token"], "tok-1")
        self.assertEqual(
            check_body["pointJson"],
            sc.aes_ecb_pkcs7_base64(point_plain, AJ_SECRET))
        self.assertEqual(adapter.get_stats()["solves"], 1)
        self.assertEqual(adapter.get_stats()["failures"], 0)

    def test_aj_adapter_retries_with_fresh_challenge(self):
        self.target.fail_checks = 1
        adapter = sc.AJCaptchaAdapter(self.target.url, AJ_HTML, self.config())
        form = {"username": "admin", "password": "123456"}
        adapter.prepare(self.session(), form)
        stats = adapter.get_stats()
        self.assertEqual(stats["solves"], 1)
        self.assertEqual(stats["retries"], 1)
        self.assertEqual(stats["failures"], 0)
        self.assertEqual(len(self.target.requests_to("/captcha/get")), 2)
        self.assertEqual(len(self.target.requests_to("/captcha/check")), 2)
        self.assertEqual(form["captchaVerification"],
                         sc.aes_ecb_pkcs7_base64(
                             "tok-2---" + '{"x":130,"y":5}', AJ_SECRET))

    # -- profile adapter --------------------------------------------------

    def profile(self, **overrides):
        data = {
            "name": "test-profile",
            "challenge": {
                "url": "/slide/challenge",
                "method": "POST",
                "body": {"ts": "{ts}"},
                "background": "data.bg",
                "piece": "data.piece",
                "token": "data.token",
            },
            "verify": {
                "url": "/slide/verify",
                "method": "POST",
                "body": {"token": "{token}", "x": "{offset}", "track": "{track}"},
                "success_path": "data.ok",
                "success_value": True,
                "token": "data.token",
            },
            "inject": {"field": "sliderTicket", "value": "{token}"},
            "track_points": 4,
            "track_duration_ms": 300,
        }
        data.update(overrides)
        return data

    def test_profile_adapter_end_to_end(self):
        adapter = sc.ProfileSliderAdapter(
            self.target.url, self.config(), self.profile())
        form = {"username": "admin", "password": "123456"}
        adapter.prepare(self.session(), form)
        self.assertEqual(form["sliderTicket"], "vt-1")
        stats = adapter.get_stats()
        self.assertEqual(stats["kind"], "test-profile")
        self.assertEqual(stats["solves"], 1)
        verify = self.target.requests_to("/slide/verify")
        self.assertEqual(len(verify), 1)
        body = json.loads(verify[0]["body"])
        self.assertEqual(body["token"], "chal-1")
        self.assertEqual(body["x"], 130)
        self.assertEqual(len(body["track"]), 2)

    def test_profile_rejects_cross_origin_endpoint(self):
        profile = self.profile()
        profile["challenge"]["url"] = "http://evil.example/captcha/get"
        with self.assertRaises(sc.SliderError) as ctx:
            sc.ProfileSliderAdapter(self.target.url, self.config(), profile)
        self.assertIn("同源", str(ctx.exception))

    def test_profile_with_invalid_helper_fails_clearly(self):
        with self.assertRaises(sc.SliderError) as ctx:
            sc.ProfileSliderAdapter(
                self.target.url,
                self.config(helper="/nonexistent/jingwei"), self.profile())
        self.assertIn("不存在或不可执行", str(ctx.exception))

    # -- bridge integration ----------------------------------------------

    def test_bridge_finds_credential_and_keeps_slider_evidence(self):
        entry = self.run_bridge([{"user": "admin", "password": "123456"}])
        self.assertTrue(entry["found"])
        self.assertEqual(entry["username"], "admin")
        self.assertEqual(entry["password"], "123456")
        self.assertTrue(entry["slider"])
        self.assertEqual(entry["slider_kind"], "aj-captcha")
        self.assertGreaterEqual(entry["slider_solves"], 5)
        self.assertEqual(entry["slider_failures"], 0)
        self.assertEqual(entry["slider_error"], "")
        self.assertIn("captchaVerification", entry["request"])
        self.assertIn("登录成功", entry["response"])
        self.assertIn("PHPSESSID=ok-session", entry["cookie"])

    def test_bridge_does_not_report_wrong_password(self):
        entry = self.run_bridge([{"user": "admin", "password": "wrong"}])
        self.assertFalse(entry["found"])
        self.assertEqual(entry["error"], "")
        self.assertTrue(entry["slider"])
        self.assertEqual(entry["slider_failures"], 0)
        self.assertGreaterEqual(entry["slider_solves"], 3)


if __name__ == "__main__":
    unittest.main()
