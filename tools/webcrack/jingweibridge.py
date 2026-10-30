#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jingwei bridge for the vendored WebCrack web-login weak credential checker.

Runs BruteForceTask against a bounded list of login URLs and reports the
outcome as one JSON document on stdout. Everything the tool prints is
captured into each result's "log" field so the scan journal stays quiet.

Usage:
    python3 jingweibridge.py --url http://host/login [--url ...]
        [--per-url-timeout 90] [--delay 0.05] [--user admin]
"""
import argparse
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from src.utils.config import load_config
from src.utils.logger import init_logger


def _silence_fd1():
    """Return (saved_fd, devnull_fd) with fd 1 pointed at /dev/null.

    ddddocr and friends print banners straight to the descriptor, which
    Python-level redirect_stdout cannot intercept.
    """
    saved = os.dup(1)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    return saved, devnull


def _restore_fd1(saved, devnull):
    os.dup2(saved, 1)
    os.close(devnull)
    os.close(saved)


# ddddocr prints a banner on import; swallow it so stdout stays JSON-only.
saved_fd, devnull_fd = _silence_fd1()
try:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        from src.core.brute_force import BruteForceTask, DDDDOCR_AVAILABLE
finally:
    _restore_fd1(saved_fd, devnull_fd)


def build_request_text(res):
    req = getattr(res, "request", None)
    if req is None:
        return ""
    lines = ["{} {} HTTP/1.1".format(req.method, req.path_url)]
    for k, v in req.headers.items():
        lines.append("{}: {}".format(k, v))
    body = req.body if isinstance(req.body, str) else ""
    text = "\r\n".join(lines) + "\r\n\r\n" + body
    return text


def build_response_text(res):
    try:
        reason = res.reason or ""
    except Exception:
        reason = ""
    lines = ["HTTP/1.1 {} {}".format(res.status_code, reason).rstrip()]
    for k, v in res.headers.items():
        # requests already decoded the body, so transport framing headers would
        # describe bytes that are not the body below.
        if k.lower() in ("content-encoding", "content-length", "transfer-encoding"):
            continue
        lines.append("{}: {}".format(k, v))
    body = res.text if res.text is not None else ""
    return "\r\n".join(lines) + "\r\n\r\n" + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", action="append", default=[], help="login URL to test")
    ap.add_argument("--per-url-timeout", type=int, default=90)
    ap.add_argument("--delay", type=float, default=0.05)
    ap.add_argument("--user", action="append", default=[], help="extra username")
    args = ap.parse_args()

    out = {"tool": "webcrack", "results": [], "missing": False, "error": ""}
    if not args.url:
        out["error"] = "no urls"
        print(json.dumps(out, ensure_ascii=False))
        return 0

    with tempfile.TemporaryDirectory(prefix="jingwei-webcrack-") as tmp:
        init_logger(tmp)
        cfg = load_config()
        if not DDDDOCR_AVAILABLE:
            # 无 ddddocr 时关闭验证码识别：否则页面仅出现「验证码」字样也会被
            # 关键字检测直接放弃（误判），导致带文字描述的登录页被整页跳过。
            cfg["captcha"]["enabled"] = False
        cfg["brute_force"]["delay"] = max(0.0, args.delay)
        cfg["brute_force"]["task_timeout"] = max(10, args.per_url_timeout)
        cfg["brute_force"]["requests_proxies"] = {}
        cfg["brute_force"]["max_workers"] = 1
        cfg["dictionary"]["file"]["enabled"] = False
        cfg["dictionary"]["domain"]["enabled"] = True
        cfg["dictionary"]["sql_injection"]["enabled"] = True
        if args.user:
            cfg["dictionary"]["base"]["username_list"] = list(args.user)

        for url in args.url:
            entry = {
                "url": url,
                "found": False,
                "username": None,
                "password": None,
                "kind": "",
                "attempts": 0,
                "request": "",
                "response": "",
                "error": "",
            }
            started = time.time()

            captured = []

            buf = io.StringIO()
            user = pwd = None
            # task construction instantiates ddddocr, which prints a banner
            # straight to fd 1: keep it out of our JSON-only stdout.
            saved_fd, devnull_fd = _silence_fd1()
            try:
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    task = BruteForceTask(cfg)
                    orig_request = task._brute_force_request

                    def wrapped(session, username, password, _orig=orig_request):
                        res = _orig(session, username, password)
                        captured.append((username, password, res))
                        return res

                    task._brute_force_request = wrapped
                    user, pwd = task.run(1, url)
            except Exception as e:  # noqa: BLE001
                entry["error"] = "webcrack exception: {}".format(e)
            finally:
                _restore_fd1(saved_fd, devnull_fd)

            if user and pwd:
                entry.update(found=True, username=user, password=pwd,
                             kind=getattr(task, "found_kind", "weak"))
                # find the successful exchange; it is the last request with the
                # same credential pair (recheck runs it right before success).
                for u, p, res in reversed(captured):
                    if u == user and p == pwd and getattr(res, "request", None) is not None:
                        entry["request"] = build_request_text(res)
                        entry["response"] = build_response_text(res)
                        break
            entry["attempts"] = len(captured)
            entry["elapsed_ms"] = int((time.time() - started) * 1000)
            log_lines = [re.sub(r"\s+", " ", ln).strip() for ln in buf.getvalue().splitlines()]
            log_lines = [ln for ln in log_lines if ln][-6:]
            entry["log"] = log_lines
            out["results"].append(entry)

    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
