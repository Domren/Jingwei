#!/usr/bin/env bash
# R11 · 统计口径脚本化
#
# 手册 §1「现状一页」里的代码行数、测试数、路由数、页面数等数字，以前是收口时
# 手数一次写进去，下次就没人知道是怎么数的。这里把每条口径写成可复现的规则：
# 同一份代码跑两遍必须得到同一组数，口径变了必须改这个脚本而不是改文档。
#
# 用法：
#   tools/stats.sh                # 打印 Markdown 表格（可直接贴进手册 §1）
#   tools/stats.sh --json         # 机器可读
#   tools/stats.sh --check FILE   # 与手册里的数字比对，不一致时退出码 1
#   tools/stats.sh --dsn postgres://...   # 顺带统计库里的表数/POC 数
#
# 口径（改动必须写进本注释，否则下一个人对不上）：
#   Go 文件       仓库内全部 .go，排除 node_modules / vendor / .git / .next / testdata
#   Go 行数       物理行（换行符个数；最后一行无换行也计入）
#   测试文件      *_test.go；测试函数 ^func Test…(
#   /api 路由     server 包里 mux.HandleFunc("<方法> /api…" 的注册条数（含重复路径的
#                 不同方法，即「注册条数」；另给唯一路径数）
#   前端          web/src 下 .ts/.tsx；静态页 web/out 下 index.html 的目录数
#   指纹          scanner/fpdata/fingerprints_merged.json 的 total_rules
#   表数 / POC    需 --dsn（连库实测），不猜
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
MODE="table"
CHECK_FILE=""
DSN="${JINGWEI_PG_DSN:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --json) MODE="json" ;;
    --check) MODE="check"; CHECK_FILE="${2:-}"; shift ;;
    --dsn) DSN="${2:-}"; shift ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "未知参数：$1（--help 看用法）" >&2; exit 2 ;;
  esac
  shift
done

PY="${BOX_AGENT_PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || { echo "找不到 python3（可用 BOX_AGENT_PYTHON 指定）" >&2; exit 1; }

"$PY" - "$ROOT" "$MODE" "$CHECK_FILE" "$DSN" <<'PY'
import json
import os
import re
import subprocess
import sys

root, mode, check_file, dsn = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
os.chdir(root)

SKIP_DIRS = {"node_modules", "vendor", ".git", ".next", "out", "testdata", "shots"}


def walk(base):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            yield os.path.join(dirpath, f)


def norm(p):
    return p.replace(os.sep, "/")


def nlines(p):
    data = open(p, "rb").read()
    if not data:
        return 0
    return data.count(b"\n") + (0 if data.endswith(b"\n") else 1)


go_files = [p for p in walk(".") if p.endswith(".go")]
go_prod = [p for p in go_files if not p.endswith("_test.go")]
go_test = [p for p in go_files if p.endswith("_test.go")]

test_funcs = 0
for p in go_test:
    test_funcs += len(re.findall(r"^func (Test\w*)\(",
                                open(p, encoding="utf-8", errors="ignore").read(), re.M))

src = ""
for p in go_prod:
    src += open(p, encoding="utf-8", errors="ignore").read() + "\n"
routes = re.findall(r'mux\.HandleFunc\("(GET|POST|PATCH|PUT|DELETE) (/api[^"]*)"', src)
route_paths = {r[1] for r in routes}

fe = [p for p in walk("web/src") if p.endswith((".ts", ".tsx"))]
pages = [p for p in walk("web/out") if os.path.basename(p) == "index.html"]

fp_rules = ""
fp_path = "scanner/fpdata/fingerprints_merged.json"
if os.path.exists(fp_path):
    fp_rules = json.load(open(fp_path, encoding="utf-8")).get("total_rules", "")

skill_dirs = []
if os.path.isdir("skills"):
    skill_dirs = sorted(d for d in os.listdir("skills") if os.path.isdir(os.path.join("skills", d)))

stats = {
    "go_files": len(go_files),
    "go_lines": sum(nlines(p) for p in go_files),
    "go_prod_files": len(go_prod),
    "go_prod_lines": sum(nlines(p) for p in go_prod),
    "go_test_files": len(go_test),
    "go_test_lines": sum(nlines(p) for p in go_test),
    "go_test_funcs": test_funcs,
    "api_routes": len(routes),
    "api_unique_paths": len(route_paths),
    "web_ts_files": len(fe),
    "web_ts_lines": sum(nlines(p) for p in fe),
    "static_pages": len(pages),
    "skill_dirs": len(skill_dirs),
    "fingerprints": fp_rules,
}

# 库内实测：表数与 POC 条数只能连库拿，静态数不出来就不写。
if dsn:
    def q(sql):
        out = subprocess.run(["psql", dsn, "-tAc", sql], capture_output=True, text=True)
        if out.returncode != 0:
            sys.stderr.write("psql 失败：" + out.stderr.strip() + "\n")
            return None
        return out.stdout.strip()

    tables = q("SELECT count(*) FROM information_schema.tables "
               "WHERE table_schema='public' AND table_type='BASE TABLE'")
    pocs = q("SELECT count(*) FROM poc_templates")
    if tables:
        stats["db_tables"] = int(tables)
    if pocs:
        stats["poc_templates"] = int(pocs)
    dsn_masked = re.sub(r"//[^@]*@", "//***@", dsn)
    stats["dsn"] = dsn_masked

if mode == "json":
    print(json.dumps(stats, ensure_ascii=False, indent=2, sort_keys=True))
    sys.exit(0)

LABELS = [
    ("go_files", "Go 文件（含测试）"),
    ("go_lines", "Go 行数（含测试）"),
    ("go_prod_files", "Go 生产文件"),
    ("go_prod_lines", "Go 生产行数"),
    ("go_test_files", "Go 测试文件"),
    ("go_test_lines", "Go 测试行数"),
    ("go_test_funcs", "测试函数"),
    ("api_routes", "/api 路由注册条数"),
    ("api_unique_paths", "/api 唯一路径"),
    ("web_ts_files", "前端 ts/tsx"),
    ("web_ts_lines", "前端 ts/tsx 行数"),
    ("static_pages", "静态导出页"),
    ("skill_dirs", "skill 目录"),
    ("fingerprints", "Web 指纹规则"),
    ("db_tables", "数据库表（实测）"),
    ("poc_templates", "POC 模板（实测）"),
]

if mode == "check":
    if not check_file:
        sys.stderr.write("--check 需要手册路径\n")
        sys.exit(2)
    text = open(check_file, encoding="utf-8").read()
    # 只核对手册「代码与测试（R11）」这一行里真正写出来的数字：其余口径
    # （生产/测试拆分、唯一路径数）是本次新增的细账，不能反过来当成欠账。
    row = ""
    for line in text.splitlines():
        if line.startswith("| 代码与测试"):
            row = line
            break
    if not row:
        print("手册里没有『代码与测试』这一行，无从比对")
        sys.exit(2)
    # 这一行是「收口时点值」：脚本算出的是当前工作树，和手册差值本身就是有用的
    # 信息（R11 的原意就是让这个差值看得见）。因此逐项打印并有差异就退出 1。
    def has_num(v):
        if isinstance(v, int):
            return [str(v), f"{v:,}"]
        return [str(v)]

    checks = [
        ("Go 文件", "go_files"),
        ("Go 行数（万）", "go_lines"),
        ("测试文件", "go_test_files"),
        ("测试函数", "go_test_funcs"),
        ("/api 路由", "api_routes"),
        ("前端 ts/tsx", "web_ts_files"),
        ("静态页", "static_pages"),
    ]
    bad = 0
    for label, key in checks:
        val = stats[key]
        if key == "go_lines":
            shown = f"{val/10000:.1f} 万"
            cands = [shown, f"{val/10000:.1f}万", str(val), f"{val:,}"]
        else:
            shown = f"{val:,}"
            cands = [str(val), f"{val:,}"]
        hit = any(c in row for c in cands)
        mark = "OK  " if hit else "DIFF"
        print(f"{mark} {label}：脚本 {shown}")
        if not hit:
            bad += 1
    print("一致" if bad == 0 else f"有 {bad} 项与手册不一致（手册是收口时点值，按需更新或在此登记差值）")
    sys.exit(0 if bad == 0 else 1)

print("| 指标 | 值 |")
print("| :--- | :--- |")
for key, label in LABELS:
    if key not in stats:
        continue
    val = stats[key]
    print(f"| {label} | {val:,} |" if isinstance(val, int) else f"| {label} | {val} |")
if "dsn" in stats:
    print(f"\n库口径：`{stats['dsn']}`")
else:
    print("\n库口径未统计（加 `--dsn postgres://…` 取表数与 POC 条数）")
PY
