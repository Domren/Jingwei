#!/usr/bin/env python3
"""
js_denoise_extract.py —— api-recon 自动化升级（P6）的 JS 去噪 + 端点/参数提取。

用途：扫描完成后自动跑，不再等 agent 手动加载 skill。
输入：混淆/打包后的 JS 文件（一个或多个）或目录；可选的「既有结果」JSON
      （1.5.0 的目录枚举 dir_enum.json / JS-URL 提取 js_urls.json）。
输出：去重后的 endpoint 清单 + 参数候选 + 权限树线索（route map）。

设计口径：
  - 去噪只删注释、sourceMappingURL、data: URI / 长 base64 串等噪声，
    **保留**所有带 API 语义的字符串，避免把真端点洗掉；
  - 与既有 1.5.0 结果去重时按「归一化路径」比较（去协议/主机/查询串），
    所以手动跑与自动跑得到同一份产出（确定性）。
"""
import argparse
import json
import os
import re
import sys

API_HINT = re.compile(r'/(?:api|rest|service|services|gateway|graphql|v\d|web|admin|backend|open|manage)\b', re.I)
ASSET_EXT = re.compile(r'\.(?:js|css|png|jpe?g|svg|gif|woff2?|ttf|ico|map|json|mp4|webp)(?:\?|$)', re.I)
ENDPOINT_RE = re.compile(r'["\'](\/[^"\'\s`]{2,200})["\']')
# 参数候选：带引号或不带引号的对象键（pageSize: 20 / "keyword": "x"）。
PARAM_RE = re.compile(r'["\']?([A-Za-z_][\w.-]{1,40})["\']?\s*:')

# 噪声形态：行/块注释、sourceMappingURL、data URI、长 base64/hex 串。
RE_LINE_COMMENT = re.compile(r'(?m)^\s*//.*$')
RE_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.S)
RE_SOURCEMAP = re.compile(r'(?m)^\s*//#\s*sourceMappingURL=.*$')
RE_DATA_URI = re.compile(r'data:[a-zA-Z0-9/;+=-]{10,},[A-Za-z0-9+/=]{40,}')
RE_LONG_B64 = re.compile(r'\b[A-Za-z0-9+/]{80,}={0,2}\b')


def strip_js_noise(js: str) -> str:
    """去掉不影响端点提取的噪声；保留 API 字符串字面量。"""
    if not js:
        return ""
    out = RE_SOURCEMAP.sub("", js)
    out = RE_BLOCK_COMMENT.sub(" ", out)
    out = RE_LINE_COMMENT.sub(" ", out)
    out = RE_DATA_URI.sub('""', out)
    out = RE_LONG_B64.sub('""', out)
    return out


def normalize_path(raw: str) -> str:
    """把 URL / 路径归一化成可比较的键：去协议主机、去查询串与 hash、去尾斜杠。"""
    if not raw:
        return ""
    s = raw.strip()
    m = re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+(/.*)$', s)
    if m:
        s = m.group(1)
    s = s.split('?', 1)[0].split('#', 1)[0]
    s = re.sub(r'/\{[^}]+\}', '/{}', s)  # 路径参数归一
    s = re.sub(r'/:[A-Za-z_]\w*', '/{}', s)
    s = s.rstrip('/')
    return s


def extract_endpoints(js: str) -> list[str]:
    """从（最好已去噪的）JS 里抽取 API 端点，返回按路径排序的去重列表。"""
    found = set()
    for m in ENDPOINT_RE.finditer(strip_js_noise(js)):
        path = m.group(1)
        if ASSET_EXT.search(path) or not API_HINT.search(path):
            continue
        norm = normalize_path(path)
        if norm and len(norm) > 2:
            found.add(norm)
    return sorted(found)


def extract_params(js: str) -> list[str]:
    """抽取端点附近的字符串候选键（参数名），基于简单锚点扩窗。"""
    cleaned = strip_js_noise(js)
    params = set()
    lines = cleaned.splitlines()
    for i, line in enumerate(lines):
        if not API_HINT.search(line):
            continue
        window = "\n".join(lines[i:i + 6])
        for m in PARAM_RE.finditer(window):
            name = m.group(1)
            if name.lower() in {"api", "url", "path", "method", "data", "type", "name", "value", "key"}:
                continue
            params.add(name)
    return sorted(params)


def extract_route_map(js: str) -> dict[str, str]:
    """还原前端路由表线索：KEY:{name:"...",link:"/path"}。"""
    out: dict[str, str] = {}
    pat = re.compile(r'([A-Z_][A-Z0-9_]*):\{[^{}]*?(?:name|title):"([^"]*)"[^{}]*?(?:link|path|url):"([^"]+)"')
    for m in pat.finditer(strip_js_noise(js)):
        out[m.group(1)] = m.group(3)
    return dict(sorted(out.items()))


def load_existing(path: str | None) -> set[str]:
    """读 1.5.0 目录枚举 / JS-URL 提取的产出，抽出路径集合。

    兼容三种 Commonplace 形态：{"paths": [...]}, [...], 或按行一个路径的文本。
    """
    if not path or not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        text = f.read()
    paths: set[str] = set()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("paths", "endpoints", "urls", "items"):
                v = data.get(key)
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            paths.add(normalize_path(item))
                        elif isinstance(item, dict):
                            for k in ("path", "url", "endpoint"):
                                if isinstance(item.get(k), str):
                                    paths.add(normalize_path(item[k]))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    paths.add(normalize_path(item))
                elif isinstance(item, dict):
                    for k in ("path", "url", "endpoint"):
                        if isinstance(item.get(k), str):
                            paths.add(normalize_path(item[k]))
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('/'):
                paths.add(normalize_path(line))
    return {p for p in paths if p}


def dedupe_against_existing(endpoints: list[str], existing: set[str]) -> list[str]:
    """与既有 1.5.0 结果去重，返回自动新增的端点（确定性排序）。"""
    return sorted({normalize_path(e) for e in endpoints} - existing)


def build_result(endpoints: list[str], params: list[str], routes: dict[str, str],
                 existing: set[str]) -> dict:
    return {
        "endpoints_auto": dedupe_against_existing(endpoints, existing),
        "params_auto": params,
        "route_map": routes,
        "deduped_against_count": len(existing),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="JS 去噪 + 端点/参数/权限树线索提取")
    ap.add_argument("inputs", nargs="+", help="JS 文件或目录")
    ap.add_argument("--existing", help="1.5.0 既有结果 JSON/文本，用于去重")
    ap.add_argument("--out", help="输出 JSON 文件；缺省打印到 stdout")
    args = ap.parse_args()

    chunks: list[str] = []
    for item in args.inputs:
        if os.path.isdir(item):
            for root, _, files in os.walk(item):
                for name in files:
                    if name.endswith(".js"):
                        with open(os.path.join(root, name), encoding="utf-8", errors="ignore") as f:
                            chunks.append(f.read())
        elif os.path.isfile(item):
            with open(item, encoding="utf-8", errors="ignore") as f:
                chunks.append(f.read())
    js = "\n".join(chunks)
    endpoints = extract_endpoints(js)
    params = extract_params(js)
    routes = extract_route_map(js)
    result = build_result(endpoints, params, routes, load_existing(args.existing))
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
