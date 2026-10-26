#!/usr/bin/env python3
"""Coverage ledger for lab backfill rounds.

usage: coverage.py <add|cover|report> <lab> [args...]
  add   <lab> <category> <endpoint>      register a vulnerable endpoint
  cover <lab> <round> <endpoint>[:note]  mark an endpoint verified in a round
  na    <lab> <endpoint> <reason>        mark an endpoint not testable (menu / hardened)
  report <lab>                           print covered / na / uncovered
State lives in /data/audit/<lab>.json (endpoint -> {category, covered_by, na_reason}).
"""
import json
import os
import sys

STATE_DIR = os.environ.get("JINGWEI_AUDIT_DIR", "data/audit")


def path(lab):
    return os.path.join(STATE_DIR, f"{lab}.json")


def load(lab):
    with open(path(lab)) as f:
        return json.load(f)


def save(lab, data):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = path(lab) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, path(lab))


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd, lab = argv[1], argv[2]
    if cmd == "add":
        _, _, _, category, endpoint = argv
        data = load(lab) if os.path.exists(path(lab)) else {}
        data.setdefault(endpoint, {"category": category, "covered_by": []})
        data[endpoint]["category"] = category
        save(lab, data)
        return 0
    if cmd == "cover":
        _, _, _, rnd, spec = argv
        endpoint = spec.split(":", 1)[0]
        data = load(lab)
        if endpoint not in data:
            print(f"unknown endpoint {endpoint}", file=sys.stderr)
            return 1
        if rnd not in data[endpoint]["covered_by"]:
            data[endpoint]["covered_by"].append(rnd)
        save(lab, data)
        return 0
    if cmd == "na":
        _, _, _, endpoint, reason = argv[:5]
        data = load(lab)
        if endpoint not in data:
            print(f"unknown endpoint {endpoint}", file=sys.stderr)
            return 1
        data[endpoint]["na_reason"] = reason
        save(lab, data)
        return 0
    if cmd == "report":
        data = load(lab)
        cats = {}
        for ep, info in data.items():
            cats.setdefault(info["category"], []).append(
                (ep, info["covered_by"], info.get("na_reason", "")))
        total = done = skipped = 0
        for cat in sorted(cats):
            items = sorted(cats[cat])
            hit = sum(1 for _, c, n in items if c)
            na = sum(1 for _, c, n in items if n and not c)
            total += len(items)
            done += hit
            skipped += na
            print(f"{cat}: {hit}/{len(items)} covered, {na} n/a")
            for ep, c, n in items:
                if not c:
                    print(f"   {'NA  ' if n else 'MISSING'} {ep}" + (f"  ({n})" if n else ""))
        print(f"TOTAL {done}/{total} covered, {skipped} n/a, {total - done - skipped} missing")
        return 0 if done + skipped == total else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
