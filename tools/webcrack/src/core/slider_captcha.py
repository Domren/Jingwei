#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
滑块验证码自动处理 for WebCrack

纯 HTTP 流程：探测挑战接口 → 取背景图/滑块图 → 调本地 Go 求解器 →
提交校验 → 把校验结果注入登录表单。内置 AJ-Captcha（anji-plus）适配，
其他实现可通过 JSON profile 描述。

所有接口都限制在登录页同源，避免把页面数据发往第三方。
"""

import base64
import html as html_lib
import json
import os
import platform
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from ..utils.logger import Info


class SliderError(Exception):
    """滑块无法完成校验（取图、求解或提交失败）。"""


# 登录响应里出现这些词说明滑块/验证码本身没有通过：本次尝试的凭据并未被
# 真正评估，需要换一张图重试，不能按响应长度当成结果。
SLIDER_FAIL_MARKERS = (
    "滑块验证失败", "滑块校验失败", "滑块验证未通过", "滑动验证失败",
    "验证码校验失败", "验证码验证失败", "验证码错误", "验证码不正确",
    "请完成验证", "请先完成验证", "请拖动滑块", "拖动滑块完成验证",
    "captcha verification failed", "slide verification failed",
    "captcha is invalid", "invalid captcha", "incorrect captcha",
)

_AJ_MARKERS = (
    "captchaverification", "blockpuzzle", "/captcha/get", "/captcha/check",
    "anji-plus", "aj-captcha",
)
_UNSUPPORTED_MARKERS = (
    "geetest", "gt_captcha", "nc_1_n1z", "yidun", "dingxiang", "易盾", "极验",
)
_SLIDER_HINTS = (
    "滑块", "拖动", "拖拽", "滑动验证", "拼图", "slide to", "slider captcha",
    "slider-verify", "drag the slider",
)
_SCRIPT_HINT = re.compile(r"(captcha|slider|verify|drag)", re.I)


# ---------------------------------------------------------------------------
# AES-128/192/256 ECB + PKCS7
#
# AJ-Captcha 用 secretKey 对 pointJson 和最终 captchaVerification 做
# AES/ECB/PKCS5Padding（与 PKCS7 等价）。镜像里不保证有 pycryptodome，
# 因此这里实现标准 AES，避免给纯 HTTP 引擎新增依赖。
# ---------------------------------------------------------------------------


def _gf_mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return out


def _gf_pow(a, n):
    out = 1
    while n:
        if n & 1:
            out = _gf_mul(out, a)
        a = _gf_mul(a, a)
        n >>= 1
    return out


def _build_sbox():
    table = [0] * 256
    for x in range(256):
        inv = 0 if x == 0 else _gf_pow(x, 254)
        y = inv
        for shift in range(1, 5):
            y ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        table[x] = y ^ 0x63
    return table


_SBOX = _build_sbox()


def _expand_key(key):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES 密钥长度必须为 16/24/32 字节")
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[i * 4:i * 4 + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _gf_mul(rcon, 2)
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return [bytes(sum(words[r * 4:r * 4 + 4], [])) for r in range(rounds + 1)]


def _add_round_key(state, round_key):
    for i in range(16):
        state[i] ^= round_key[i]


def _sub_bytes(state):
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _shift_rows(state):
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            state[r + 4 * c] = row[c]


def _mix_columns(state):
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = state[i:i + 4]
        state[i] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        state[i + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        state[i + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        state[i + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)


def _encrypt_block(block, round_keys):
    state = list(block)
    _add_round_key(state, round_keys[0])
    for rnd in range(1, len(round_keys) - 1):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[-1])
    return bytes(state)


def aes_ecb_pkcs7_base64(text, secret_key, encoding="utf-8"):
    """与 crypto-js AES.encrypt(Utf8.parse(text), Utf8.parse(key), ECB/Pkcs7) 一致。"""
    if not secret_key:
        return text
    try:
        key = secret_key.encode(encoding)
    except UnicodeEncodeError:
        key = secret_key.encode("utf-8")
    raw = text.encode(encoding)
    pad = 16 - len(raw) % 16
    raw += bytes([pad]) * pad
    round_keys = _expand_key(key)
    out = bytearray()
    for i in range(0, len(raw), 16):
        out.extend(_encrypt_block(raw[i:i + 16], round_keys))
    return base64.b64encode(bytes(out)).decode("ascii")


# ---------------------------------------------------------------------------
# 本地 Go 求解器
# ---------------------------------------------------------------------------


def _helper_candidates():
    here = Path(__file__).resolve()
    repo = here.parents[4] if len(here.parents) > 4 else here.parent
    arch = platform.machine().lower()
    for name in ("amd64", "x86_64"):
        if arch in (name, "x64"):
            arch = "amd64"
            break
    for name in ("arm64", "aarch64"):
        if arch == name:
            arch = "arm64"
            break
    return [
        "/app/jingwei",
        shutil.which("jingwei") or "",
        str(repo / "dist" / arch / "jingwei"),
    ]


def _resolve_helper(explicit=""):
    """Return (path, error).

    An explicitly configured helper (--slider-helper or env) is authoritative:
    if it is missing or not executable, fail with that path instead of
    silently falling back to another jingwei binary on the host.
    """
    configured = []
    if explicit:
        configured.append(("--slider-helper", explicit))
    for name in ("JINGWEI_SLIDER_HELPER", "WEBCRACK_SLIDER_HELPER"):
        value = os.environ.get(name, "")
        if value:
            configured.append((name, value))
            break
    for label, candidate in configured:
        path = Path(candidate).expanduser()
        if path.is_file() and os.access(str(path), os.X_OK):
            return str(path), ""
        return "", "{} 指向的求解器不存在或不可执行: {}".format(label, candidate)
    for candidate in _helper_candidates():
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file() and os.access(str(path), os.X_OK):
            return str(path), ""
    return "", "未找到 Jingwei 求解器（可设置 JINGWEI_SLIDER_HELPER 指向新版 jingwei 二进制）"


def _find_helper(explicit=""):
    return _resolve_helper(explicit)[0]


def _json_path(data, path):
    if path in (None, ""):
        return None
    cur = data
    for part in str(path).split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            if idx >= len(cur):
                return None
            cur = cur[idx]
        else:
            return None
        if cur is None:
            return None
    return cur


def _first_path(data, paths):
    if isinstance(paths, str):
        paths = [paths]
    for p in paths or []:
        value = _json_path(data, p)
        if value not in (None, ""):
            return value
    return None


class SliderHelper:
    """调用 `jingwei captcha-solve`，图片只经 stdin 传递，不落盘。"""

    def __init__(self, explicit=""):
        self.path, self.error = _resolve_helper(explicit)
        self.timeout = 20.0

    def available(self):
        return bool(self.path)

    def unavailable_message(self):
        return self.error or "未找到 Jingwei 求解器（可设置 JINGWEI_SLIDER_HELPER）"

    def solve(self, background, piece, initial_x=0, min_offset=0, max_offset=0,
              track=False, track_points=0, track_duration_ms=0, track_seed=0):
        if not self.path:
            raise SliderError(self.unavailable_message())
        req = {
            "background": background,
            "piece": piece,
            "initial_x": int(initial_x or 0),
            "min_offset": int(min_offset or 0),
            "max_offset": int(max_offset or 0),
            "track": bool(track),
            "track_points": int(track_points or 0),
            "track_duration_ms": int(track_duration_ms or 0),
            "track_seed": int(track_seed or 0),
        }
        try:
            proc = subprocess.run(
                [self.path, "captcha-solve"],
                input=json.dumps(req, ensure_ascii=False).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            raise SliderError("滑块求解超时（{}s）".format(int(self.timeout)))
        except OSError as e:
            raise SliderError("启动滑块求解器失败: {}".format(e))
        raw = (proc.stdout or b"").decode("utf-8", "ignore").strip()
        err_text = (proc.stderr or b"").decode("utf-8", "ignore").strip()
        if not raw:
            raise SliderError("滑块求解器无输出（exit={}）{}".format(
                proc.returncode, (": " + _truncate(err_text, 200)) if err_text else ""))
        try:
            answer = json.loads(raw.splitlines()[-1])
        except ValueError:
            # A jingwei binary predating the captcha-solve subcommand prints its
            # banner/usage instead of JSON. Say how to fix that instead of
            # reporting an opaque parse failure.
            raise SliderError(
                "滑块求解器不支持 captcha-solve 子命令（请使用新版 jingwei 二进制）: {}"
                .format(_truncate(raw.splitlines()[-1], 120)))
        if not isinstance(answer, dict):
            raise SliderError(
                "滑块求解器不支持 captcha-solve 子命令（请使用新版 jingwei 二进制）")
        if "ok" not in answer:
            raise SliderError(
                "滑块求解器不支持 captcha-solve 子命令（请使用新版 jingwei 二进制）")
        if not answer.get("ok"):
            raise SliderError(answer.get("error") or "滑块求解失败")
        for key in ("offset", "distance"):
            if not isinstance(answer.get(key), int):
                raise SliderError("滑块求解器缺少 {}".format(key))
        return answer


# ---------------------------------------------------------------------------
# 适配器
# ---------------------------------------------------------------------------


def _same_origin(url, base_url):
    try:
        a, b = urlparse(url), urlparse(base_url)
    except ValueError:
        return False
    return a.scheme.lower() == b.scheme.lower() and a.netloc.lower() == b.netloc.lower()


def _truncate(text, limit=160):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text[:limit]


class _SliderAdapter:
    kind = "slider"

    def __init__(self, url, config):
        self.url = url
        self.config = config
        self.proxies = config["brute_force"].get("requests_proxies") or {}
        self.timeout = min(float(config["brute_force"].get("timeout") or 10), 8.0)
        self.slider_cfg = config.get("slider") or {}
        self.max_tries = max(1, int(self.slider_cfg.get("max_tries") or 3))
        self.stats = {
            "detected": True,
            "kind": self.kind,
            "solves": 0,
            "retries": 0,
            "failures": 0,
            "error": "",
        }
        self._lock = threading.Lock()

    def mark_solved(self):
        with self._lock:
            self.stats["solves"] += 1
            self.stats["error"] = ""

    def mark_retry(self):
        with self._lock:
            self.stats["retries"] += 1

    def mark_failure(self, message):
        with self._lock:
            self.stats["failures"] += 1
            self.stats["error"] = _truncate(message)

    def get_stats(self):
        with self._lock:
            return dict(self.stats)

    def prepare(self, session, form_data):
        """完成一次滑块校验，把结果写进登录表单。失败抛 SliderError。"""
        raise NotImplementedError


class AJCaptchaAdapter(_SliderAdapter):
    """AJ-Captcha（anji-plus/captcha）blockPuzzle 协议。"""

    kind = "aj-captcha"

    def __init__(self, url, html, config):
        super().__init__(url, config)
        self.html = html or ""
        self.origin = "{0.scheme}://{0.netloc}".format(urlparse(url))
        self.client_uid = str(uuid.uuid4())
        self.helper = SliderHelper(self.slider_cfg.get("helper") or "")
        self.base_url = ""
        self.bases = []
        self.script_urls = []
        self.scripts_loaded = False
        self._collect_initial()
        self._logged = False

    def _collect_initial(self):
        for m in re.finditer(r'<script[^>]+src\s*=\s*(["\'])(.*?)\1', self.html, re.I | re.S):
            src = html_lib.unescape(m.group(2)).strip()
            if not src or not _SCRIPT_HINT.search(src):
                continue
            absolute = urljoin(self.url, src)
            if _same_origin(absolute, self.url) and absolute not in self.script_urls:
                self.script_urls.append(absolute)
            if len(self.script_urls) >= 3:
                break
        self._collect_bases(self.html, self.url)
        # 部分应用把接口挂在登录页同级目录下。放在默认候选里，排最后。
        page_dir = self.url[:self.url.rfind("/") + 1]
        self._add_base(page_dir, self.url)
        self._add_base("", self.url)
        self._add_base("/api", self.url)
        self._add_base("/captcha-api", self.url)

    def _add_base(self, raw, ref_url):
        raw = (raw or "").strip()
        absolute = self.origin if not raw else urljoin(ref_url, raw)
        if absolute and not _same_origin(absolute, self.url):
            return
        absolute = absolute.rstrip("/")
        for item in self.bases:
            if item["base"] == absolute:
                return
        self.bases.append({"base": absolute, "source": raw})

    def _collect_bases(self, text, ref_url):
        if not text:
            return
        for m in re.finditer(r'baseUrl\s*[:=]\s*(["\'])(.*?)\1', text, re.I | re.S):
            self._add_base(m.group(2), ref_url)
        for m in re.finditer(r'(["\'])([^"\']{0,200}?/captcha/get)\1', text, re.I):
            endpoint = m.group(2)
            self._add_base(endpoint[:-len("/captcha/get")], ref_url)

    def _load_scripts(self, session):
        if self.scripts_loaded:
            return
        self.scripts_loaded = True
        for src in self.script_urls:
            try:
                res = session.get(
                    src, timeout=self.timeout, verify=False,
                    proxies=self.proxies,
                    headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*",
                             "Referer": self.url},
                )
                if res.status_code == 200 and len(res.content) <= 1 << 20:
                    self._collect_bases(res.text, src)
            except requests.RequestException:
                continue

    def _headers(self):
        from ..utils.header_generator import get_random_headers
        headers = get_random_headers(self.config)
        headers["Content-Type"] = "application/json;charset=UTF-8"
        headers["Accept"] = "application/json, text/plain, */*"
        headers["Referer"] = self.url
        parsed = urlparse(self.url)
        if parsed.scheme and parsed.netloc:
            headers["Origin"] = "{}://{}".format(parsed.scheme, parsed.netloc)
        return headers

    def _post_json(self, session, url, payload):
        res = session.post(
            url, data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(), timeout=self.timeout, verify=False,
            proxies=self.proxies, allow_redirects=True,
        )
        if len(res.content) > 4 << 20:
            raise SliderError("滑块接口响应过大（{} 字节）".format(len(res.content)))
        try:
            return res, res.json()
        except ValueError:
            raise SliderError("滑块接口返回的不是 JSON（HTTP {}）".format(res.status_code))

    def _challenge_from(self, doc):
        if not isinstance(doc, dict):
            return None
        data = doc.get("repData")
        if not isinstance(data, dict):
            data = doc.get("data") if isinstance(doc.get("data"), dict) else doc
        background = (_first_path(data, ("originalImage", "originalImageBase64", "bgImage", "background"))
                      or _first_path(doc, ("originalImage", "originalImageBase64")))
        piece = (_first_path(data, ("jigsawImage", "jigsawImageBase64", "pieceImage", "sliderImage"))
                 or _first_path(doc, ("jigsawImage", "jigsawImageBase64")))
        token = (_first_path(data, ("token", "id"))
                 or _first_path(doc, ("token", "id")))
        if not background or not piece or not token:
            return None
        secret = _first_path(data, "secretKey") or _first_path(doc, "secretKey") or ""
        return {
            "background": background,
            "piece": piece,
            "token": str(token),
            "secret": str(secret or ""),
        }

    def _fetch_challenge(self, session):
        self._load_scripts(session)
        candidates = list(self.bases)
        if self.base_url:
            candidates = [c for c in candidates if c["base"] == self.base_url] + \
                         [c for c in candidates if c["base"] != self.base_url]
        attempts = []
        for item in candidates:
            endpoint = item["base"] + "/captcha/get"
            payload = {
                "captchaType": "blockPuzzle",
                "clientUid": self.client_uid,
                "ts": int(time.time() * 1000),
            }
            try:
                res, doc = self._post_json(session, endpoint, payload)
            except SliderError as e:
                attempts.append("{}: {}".format(endpoint, e))
                continue
            challenge = self._challenge_from(doc)
            rep_code = str((doc or {}).get("repCode", ""))
            if challenge and (res.status_code < 400 or rep_code in ("0000", "0")):
                self.base_url = item["base"]
                return challenge
            attempts.append("{}: HTTP {} repCode={} repMsg={}".format(
                endpoint, res.status_code, rep_code,
                _truncate((doc or {}).get("repMsg", ""), 80)))
            if len(attempts) >= 6:
                break
        if not self.helper.available():
            raise SliderError("检测到 AJ-Captcha 滑块，但求解器不可用：{}".format(
                self.helper.unavailable_message()))
        raise SliderError("未找到 AJ-Captcha 挑战接口（已尝试 {}）".format(
            "; ".join(attempts[-4:]) or "无候选"))

    def _check(self, session, challenge, point_plain, point_json):
        base = self.base_url
        payload = {
            "captchaType": "blockPuzzle",
            "pointJson": point_json,
            "token": challenge["token"],
            "clientUid": self.client_uid,
            "ts": int(time.time() * 1000),
        }
        res, doc = self._post_json(session, base + "/captcha/check", payload)
        rep_code = str((doc or {}).get("repCode", ""))
        data = (doc or {}).get("repData") if isinstance(doc, dict) else None
        ok = rep_code in ("0000", "0", "200", "")
        if isinstance(data, dict) and data.get("result") is False:
            ok = False
        if isinstance(data, bool) and not data:
            ok = False
        if rep_code not in ("0000", "0", "200", "") and rep_code:
            ok = False
        if not ok:
            raise SliderError("滑块校验未通过（repCode={} {}）".format(
                rep_code, _truncate((doc or {}).get("repMsg", ""))))
        if challenge["secret"]:
            try:
                verification = aes_ecb_pkcs7_base64(
                    challenge["token"] + "---" + point_plain, challenge["secret"])
            except Exception as e:  # noqa: BLE001
                raise SliderError("生成 captchaVerification 失败: {}".format(e))
        else:
            verification = challenge["token"] + "---" + point_plain
        return verification

    def _inject(self, form_data, verification):
        field = "captchaVerification"
        for key in form_data:
            if key.lower() == field.lower():
                form_data[key] = verification
                return
        form_data[field] = verification

    def prepare(self, session, form_data):
        if not self.helper.available():
            msg = "检测到 AJ-Captcha 滑块，但求解器不可用：{}".format(
                self.helper.unavailable_message())
            self.mark_failure(msg)
            raise SliderError(msg)
        if not self._logged:
            self._logged = True
            Info("[*] 检测到 AJ-Captcha 滑块，启用纯 HTTP 自动求解")
        last = ""
        for attempt in range(self.max_tries):
            if attempt:
                self.mark_retry()
            try:
                challenge = self._fetch_challenge(session)
                answer = self.helper.solve(challenge["background"], challenge["piece"])
                x = int(round(float(answer["offset"]) * float(
                    self.slider_cfg.get("x_scale") or 1.0)))
                y = 5
                point_plain = json.dumps({"x": x, "y": y}, separators=(",", ":"))
                if challenge["secret"]:
                    point_json = aes_ecb_pkcs7_base64(point_plain, challenge["secret"])
                else:
                    point_json = point_plain
                verification = self._check(session, challenge, point_plain, point_json)
            except SliderError as e:
                last = str(e)
                continue
            except Exception as e:  # noqa: BLE001
                last = "滑块处理异常: {}".format(e)
                continue
            self._inject(form_data, verification)
            self.mark_solved()
            return
        self.mark_failure(last or "滑块校验失败")
        raise SliderError(last or "滑块校验失败")


class ProfileSliderAdapter(_SliderAdapter):
    """用 JSON profile 描述的自定义滑块协议。"""

    kind = "profile"

    def __init__(self, url, config, profile):
        super().__init__(url, config)
        self.profile = profile or {}
        self.kind = str(self.profile.get("name") or "profile")
        self.stats["kind"] = self.kind
        self.helper = SliderHelper(self.slider_cfg.get("helper") or "")
        self.client_uid = str(uuid.uuid4())
        self._validate()

    def _url(self, raw):
        absolute = urljoin(self.url, str(raw or ""))
        if not _same_origin(absolute, self.url):
            raise SliderError("profile 接口必须与登录页同源: {}".format(absolute))
        return absolute

    def _validate(self):
        if not self.helper.available():
            raise SliderError("配置了滑块 profile，但求解器不可用：{}".format(
                self.helper.unavailable_message()))
        for section in ("challenge", "verify"):
            if not isinstance(self.profile.get(section), dict):
                raise SliderError("滑块 profile 缺少 {}".format(section))
        if not self.profile["challenge"].get("url"):
            raise SliderError("滑块 profile 缺少 challenge.url")
        if not self.profile["verify"].get("url"):
            raise SliderError("滑块 profile 缺少 verify.url")
        self.challenge_url = self._url(self.profile["challenge"]["url"])
        self.verify_url = self._url(self.profile["verify"]["url"])

    def _render(self, value, values):
        if isinstance(value, dict):
            return {k: self._render(v, values) for k, v in value.items()}
        if isinstance(value, list):
            return [self._render(v, values) for v in value]
        if isinstance(value, str):
            for key, val in values.items():
                if value == "{" + key + "}":
                    return val
            def repl(match):
                key = match.group(1)
                if key in values:
                    return str(values[key])
                return match.group(0)
            return re.sub(r"\{(\w+)\}", repl, value)
        return value

    def _request(self, session, spec, payload, values):
        method = str(spec.get("method") or "GET").upper()
        headers = {"Referer": self.url, "Accept": "application/json, text/plain, */*"}
        headers.update(spec.get("headers") or {})
        content_type = str(spec.get("content_type") or "json").lower()
        body = self._render(payload, values) if payload is not None else None
        kwargs = {
            "headers": headers,
            "timeout": self.timeout,
            "verify": False,
            "proxies": self.proxies,
            "allow_redirects": True,
        }
        if body is not None:
            if content_type == "form":
                data = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
                        for k, v in body.items()}
                kwargs["data"] = data
            else:
                headers["Content-Type"] = "application/json;charset=UTF-8"
                kwargs["data"] = json.dumps(body, separators=(",", ":")).encode("utf-8")
        res = session.request(method, self._url(spec["url"]), **kwargs)
        try:
            return res, res.json()
        except ValueError:
            raise SliderError("滑块接口返回的不是 JSON（HTTP {}）".format(res.status_code))

    def prepare(self, session, form_data):
        last = ""
        for attempt in range(self.max_tries):
            if attempt:
                self.mark_retry()
            try:
                now = int(time.time() * 1000)
                values = {"ts": now, "client_uid": self.client_uid}
                ch_spec = self.profile["challenge"]
                _, doc = self._request(session, ch_spec, ch_spec.get("body"), values)
                background = _first_path(doc, ch_spec.get("background"))
                piece = _first_path(doc, ch_spec.get("piece"))
                token = _first_path(doc, ch_spec.get("token")) or ""
                if not background or not piece:
                    raise SliderError("挑战响应缺少背景图或滑块图")
                verify_spec = self.profile["verify"]
                body_tpl = verify_spec.get("body") or {}
                track_needed = "{track}" in json.dumps(body_tpl)
                answer = self.helper.solve(
                    background, piece,
                    initial_x=int(self.profile.get("initial_x") or 0),
                    track=track_needed,
                    track_points=int(self.profile.get("track_points") or 0),
                    track_duration_ms=int(self.profile.get("track_duration_ms") or 0),
                )
                x = answer["offset"] if str(self.profile.get("x_source") or "offset") == "offset" else answer["distance"]
                values.update({
                    "token": str(token),
                    "challenge_token": str(token),
                    "offset": int(x),
                    "distance": int(answer["distance"]),
                    "y": int(answer["y"]),
                    "track": answer.get("track") or [],
                    "x": int(x),
                })
                res, doc2 = self._request(session, verify_spec, body_tpl, values)
                success_path = verify_spec.get("success_path")
                if success_path:
                    actual = _json_path(doc2, success_path)
                    expected = verify_spec.get("success_value", 0)
                    if isinstance(expected, bool):
                        ok = actual is expected
                    else:
                        ok = str(actual).lower() == str(expected).lower()
                else:
                    ok = res.status_code < 400
                if not ok:
                    raise SliderError("滑块校验未通过（{}）".format(
                        _truncate(actual if success_path else "HTTP {}".format(res.status_code))))
                verify_token = _first_path(doc2, verify_spec.get("token")) or token
                inject = self.profile.get("inject") or {}
                field = str(inject.get("field") or "slider_token")
                values["token"] = verify_token
                value = self._render(inject.get("value") or "{token}", values)
                target = None
                for key in form_data:
                    if key.lower() == field.lower():
                        target = key
                        break
                form_data[target or field] = value
            except SliderError as e:
                last = str(e)
                continue
            except Exception as e:  # noqa: BLE001
                last = "滑块处理异常: {}".format(e)
                continue
            self.mark_solved()
            return
        self.mark_failure(last or "滑块校验失败")
        raise SliderError(last or "滑块校验失败")


class UnsupportedSlider(_SliderAdapter):
    kind = "unsupported"

    def __init__(self, url, config, reason):
        super().__init__(url, config)
        self.reason = reason

    def prepare(self, session, form_data):
        self.mark_failure(self.reason)
        raise SliderError(self.reason)


def load_slider_profile(path):
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise SliderError("读取滑块 profile 失败: {}".format(e))


def build_slider_adapter(url, html, config):
    """根据页面特征或显式 profile 选择适配器；无滑块时返回 None。"""
    slider_cfg = config.get("slider") or {}
    if not slider_cfg.get("enabled", True):
        return None
    profile_path = slider_cfg.get("profile") or os.environ.get("JINGWEI_WEBCRACK_SLIDER_PROFILE", "")
    if profile_path:
        profile = load_slider_profile(profile_path)
        if profile:
            return ProfileSliderAdapter(url, config, profile)
    text = (html or "").lower()
    if any(marker in text for marker in _UNSUPPORTED_MARKERS):
        return UnsupportedSlider(url, config,
                                 "检测到商业滑块（极验/易盾等），当前纯 HTTP 引擎不支持；"
                                 "可使用 JINGWEI_WEBCRACK_SLIDER_PROFILE 指定协议")
    if any(marker in text for marker in _AJ_MARKERS):
        return AJCaptchaAdapter(url, html, config)
    if _SCRIPT_HINT.search(text) and re.search(r"<script[^>]+src\s*=", text, re.I) \
            and any(h in text for h in _SLIDER_HINTS):
        return AJCaptchaAdapter(url, html, config)
    if any(hint in text for hint in _SLIDER_HINTS) and (
            "验证码" in text or "captcha" in text or "drag" in text):
        return UnsupportedSlider(url, config,
                                 "检测到滑块验证码，但未匹配到支持的协议；"
                                 "可使用 JINGWEI_WEBCRACK_SLIDER_PROFILE 描述挑战/校验接口")
    return None
