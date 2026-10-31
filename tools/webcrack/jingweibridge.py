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
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from src.utils.config import load_config
from src.utils.logger import init_logger

# A captcha rejection means the credential was never actually evaluated. The
# engine solves a fresh image per attempt, so a rejected attempt is retried with
# the same pair; only a response that still rejects after the retries is scored.
CAPTCHA_FAIL_MARKERS = (
    "验证码错误", "验证码不正确", "验证码有误", "验证码输入错误",
    "验证码已失效", "验证码失效", "验证码已过期", "验证码过期",
    "无效的验证码", "请输入正确的验证码", "验证码不能为空", "验证码不匹配",
    "Invalid captcha", "invalid captcha", "Incorrect captcha", "incorrect captcha",
    "captcha is invalid", "Captcha is invalid", "captcha does not match",
    "wrong captcha", "CAPTCHA verification failed", "captcha verification failed",
)
CAPTCHA_RETRY_LIMIT = 2


def is_captcha_failure(res):
    if res is None:
        return False
    try:
        body = res.text or ""
    except Exception:  # noqa: BLE001
        return False
    low = body.lower()
    return any(marker.lower() in low for marker in CAPTCHA_FAIL_MARKERS)


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
    # requests >= 2.32 keeps Host out of PreparedRequest.headers (urllib3 adds
    # it at send time), so the evidence packet must re-add it for replay.
    if not any(k.lower() == "host" for k in req.headers):
        parsed = urlparse(req.url or "")
        if parsed.netloc:
            lines.append("Host: {}".format(parsed.netloc))
    for k, v in req.headers.items():
        lines.append("{}: {}".format(k, v))
    body = req.body or ""
    if isinstance(body, (bytes, bytearray)):
        # requests prepares form bodies as bytes; leaving them out would strip
        # the credentials and captcha from the evidence request.
        body = body.decode("utf-8", "replace")
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


def cookie_header(session):
    # The login exchange follows redirects, so the Set-Cookie headers of the
    # intermediate 302 never reach the final response. The session jar keeps
    # every cookie regardless of which hop set it, and it is what a follow-up
    # request (e.g. an authenticated upload) must carry.
    try:
        items = session.cookies.get_dict()
    except Exception:
        return ""
    return "; ".join("{}={}".format(k, v) for k, v in items.items())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", action="append", default=[], help="login URL to test")
    ap.add_argument("--per-url-timeout", type=int, default=90)
    ap.add_argument("--delay", type=float, default=0.05)
    ap.add_argument("--user", action="append", default=[], help="extra username")
    ap.add_argument("--proxy", default="", help="http/https/socks5 proxy URL")
    ap.add_argument("--pairs-stdin", default="",
                    help="'-' = read JSON [{user,password}] from stdin and test only those pairs")
    args = ap.parse_args()

    out = {"tool": "webcrack", "results": [], "missing": False, "error": ""}
    if not args.url:
        out["error"] = "no urls"
        print(json.dumps(out, ensure_ascii=False))
        return 0

    pairs = []
    if args.pairs_stdin:
        try:
            loaded = json.loads(sys.stdin.read())
        except Exception as e:  # noqa: BLE001
            out["error"] = "pairs-stdin 解析失败: {}".format(e)
            print(json.dumps(out, ensure_ascii=False))
            return 0
        for item in loaded if isinstance(loaded, list) else []:
            user = str(item.get("user", "") or "")
            password = str(item.get("password", "") or "")
            if user:
                pairs.append((user, password))
        if not pairs:
            out["error"] = "pairs-stdin 为空"
            print(json.dumps(out, ensure_ascii=False))
            return 0

    proxy = (args.proxy or "").strip()
    if proxy.startswith("socks"):
        try:
            import socks  # noqa: F401
        except ImportError:
            out["error"] = "Python 环境缺少 PySocks（requests[socks]），无法使用 SOCKS5 代理"
            print(json.dumps(out, ensure_ascii=False))
            return 0

    with tempfile.TemporaryDirectory(prefix="jingwei-webcrack-") as tmp:
        init_logger(tmp)
        cfg = load_config()
        if not DDDDOCR_AVAILABLE:
            # 无 ddddocr 时关闭验证码识别：否则页面仅出现「验证码」字样也会被
            # 关键字检测直接放弃（误判），导致带文字描述的登录页被整页跳过。
            cfg["captcha"]["enabled"] = False
        # The engine scores a response as invalid only when a fail word matches.
        # Captcha rejections must never pass the length heuristic: a recheck on
        # such a page can otherwise report a credential that was never tested.
        fail_words = list(cfg["brute_force"].get("fail_words") or [])
        for marker in CAPTCHA_FAIL_MARKERS:
            if marker not in fail_words:
                fail_words.append(marker)
        cfg["brute_force"]["fail_words"] = fail_words
        cfg["brute_force"]["delay"] = max(0.0, args.delay)
        cfg["brute_force"]["task_timeout"] = max(10, args.per_url_timeout)
        cfg["brute_force"]["requests_proxies"] = {"http": proxy, "https": proxy} if proxy else {}
        cfg["brute_force"]["max_workers"] = 1
        cfg["dictionary"]["file"]["enabled"] = False
        cfg["dictionary"]["domain"]["enabled"] = not pairs
        cfg["dictionary"]["sql_injection"]["enabled"] = not pairs
        if args.user:
            cfg["dictionary"]["base"]["username_list"] = list(args.user)

        for url in args.url:
            attempts = pairs if pairs else [None]
            task = None
            captured = []
            captcha_state = {"detected": False, "retries": 0, "failures": 0}

            def wrapped(session, username, password, _task=None):
                # _task is unused; the closure keeps one captured list per URL so
                # pair mode can clear it between runs.
                _orig = _wrapped_orig[0]
                res = _orig(session, username, password)
                retries = 0
                # A rejected captcha leaves the credential untested; solve a new
                # image and try the same pair again before judging the response.
                while retries < CAPTCHA_RETRY_LIMIT and is_captcha_failure(res):
                    retries += 1
                    captcha_state["retries"] += 1
                    res = _orig(session, username, password)
                if is_captcha_failure(res):
                    captcha_state["failures"] += 1
                captured.append((username, password, cookie_header(session), res))
                return res

            _wrapped_orig = [None]
            if pairs:
                # ddddocr init is expensive; build one task per URL and reuse it
                # for every candidate pair.
                saved_fd, devnull_fd = _silence_fd1()
                try:
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        task = BruteForceTask(cfg)
                except Exception as e:  # noqa: BLE001
                    for idx, pair in enumerate(pairs):
                        out["results"].append({
                            "url": url, "found": False, "username": None, "password": None,
                            "pair_user": pair[0], "pair_index": idx, "kind": "", "cookie": "",
                            "attempts": 0, "request": "", "response": "",
                            "error": "webcrack exception: {}".format(e), "log": [],
                        })
                    continue
                finally:
                    _restore_fd1(saved_fd, devnull_fd)
                _wrapped_orig[0] = task._brute_force_request
                task._brute_force_request = wrapped

            for idx, pair in enumerate(attempts):
                entry = {
                    "url": url,
                    "found": False,
                    "username": None,
                    "password": None,
                    "kind": "",
                    "cookie": "",
                    "attempts": 0,
                    "request": "",
                    "response": "",
                    "error": "",
                }
                if pair is not None:
                    entry["pair_user"] = pair[0]
                    entry["pair_index"] = idx
                    cfg["dictionary"]["base"]["username_list"] = [pair[0]]
                    cfg["dictionary"]["base"]["password_list"] = [pair[1]]
                    captured.clear()
                    captcha_state["retries"] = 0
                    captcha_state["failures"] = 0
                started = time.time()

                buf = io.StringIO()
                user = pwd = None
                # task construction instantiates ddddocr, which prints a banner
                # straight to fd 1: keep it out of our JSON-only stdout.
                saved_fd, devnull_fd = _silence_fd1()
                try:
                    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                        if task is None:
                            task = BruteForceTask(cfg)
                            _wrapped_orig[0] = task._brute_force_request
                            task._brute_force_request = wrapped
                        user, pwd = task.run(1, url)
                except Exception as e:  # noqa: BLE001
                    entry["error"] = "webcrack exception: {}".format(e)
                finally:
                    _restore_fd1(saved_fd, devnull_fd)

                if task is not None and getattr(task, "parser", None) is not None:
                    parser = task.parser
                    captcha_state["detected"] = bool(
                        getattr(parser, "captcha_input_name", "")
                        or getattr(parser, "captcha_img_url", ""))
                found_res = None
                for u, p, cookie, res in reversed(captured):
                    if u == user and p == pwd and getattr(res, "request", None) is not None:
                        found_res = (cookie, res)
                        break
                if user and pwd:
                    # The engine's recheck only compares response lengths, so a
                    # captcha rejection can masquerade as a success. Reject the
                    # pair when the decisive response is still a captcha failure.
                    if found_res is not None and is_captcha_failure(found_res[1]):
                        entry["error"] = (
                            "验证码识别失败：最终响应仍为验证码错误，未确认凭据（换码重试 {} 次）"
                            .format(captcha_state["retries"]))
                    else:
                        entry.update(found=True, username=user, password=pwd,
                                     kind=getattr(task, "found_kind", "weak"))
                        if found_res is not None:
                            entry["request"] = build_request_text(found_res[1])
                            entry["response"] = build_response_text(found_res[1])
                            entry["cookie"] = found_res[0]
                entry["captcha"] = captcha_state["detected"]
                entry["captcha_retries"] = captcha_state["retries"]
                entry["captcha_ocr_failures"] = captcha_state["failures"]
                entry["attempts"] = len(captured)
                if not entry["found"] and entry["attempts"] > 0 and \
                        captcha_state["failures"] >= entry["attempts"]:
                    entry["error"] = (
                        "验证码 OCR 识别失败：{} 次请求均被验证码拒绝（换码重试 {} 次），未能评估任何凭据"
                        .format(captcha_state["failures"], captcha_state["retries"]))
                entry["elapsed_ms"] = int((time.time() - started) * 1000)
                log_lines = [re.sub(r"\s+", " ", ln).strip() for ln in buf.getvalue().splitlines()]
                log_lines = [ln for ln in log_lines if ln][-6:]
                entry["log"] = log_lines
                out["results"].append(entry)

    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
