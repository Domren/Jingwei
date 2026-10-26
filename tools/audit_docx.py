#!/usr/bin/env python3
"""Audit a Jingwei findings DOCX at the OOXML level (no LibreOffice needed).

usage: audit_docx.py file.docx [--expect-raw N]

Checks pagination, control-byte cleanliness, per-finding section headings and
that protocol labelling matches the captured packets.
"""
import re
import sys
import zipfile

PAGE_BREAK_RE = re.compile(r'<w:br[^>]*w:type="page"')
BREAK_BEFORE_RE = re.compile(r"<w:pageBreakBefore/>")
RUN_TEXT_RE = re.compile(r"<w:t(?:\s[^>]*)?>(.*?)</w:t>", re.S)
PARA_RE = re.compile(r"<w:p[ >].*?</w:p>", re.S)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def unescape(s: str) -> str:
    return (s.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
            .replace("&quot;", '"').replace("&apos;", "'"))


def paragraphs(xml: str):
    for para in PARA_RE.findall(xml):
        text = "".join(unescape(m) for m in RUN_TEXT_RE.findall(para))
        yield text


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml").decode("utf-8")
    texts = [t.strip() for t in paragraphs(xml) if t.strip()]
    joined = "\n".join(texts)

    problems = []
    breaks = len(PAGE_BREAK_RE.findall(xml)) + len(BREAK_BEFORE_RE.findall(xml))
    if breaks < 3:
        problems.append(f"page breaks={breaks} (expected cover/chapter/section separation)")
    ctl = CONTROL_RE.findall(joined)
    if ctl:
        problems.append(f"{len(ctl)} control bytes leaked into text: {[hex(ord(c)) for c in set(ctl)][:6]}")

    headings = [t for t in texts if re.match(r"^(原始\s?(?:HTTP|协议)?\s*报文|原始请求数据|原始响应数据|验证步骤|验证数据|证据|漏洞详情|PoC)", t)]
    counts = {}
    for h in headings:
        # Each extra evidence packet renders its own heading; bucket them so the
        # section summary stays readable on reports with dozens of bindings.
        key = "证据 #<n> · …" if h.startswith("证据 #") else h
        counts[key] = counts.get(key, 0) + 1
    for key in ("验证步骤", "验证数据"):
        if key not in counts:
            problems.append(f"missing section heading: {key}")
    packet_heading_re = re.compile(r"^原始\s?(?:HTTP|协议)?\s*报文")
    if not any(packet_heading_re.match(t) for t in texts):
        problems.append("no packet section heading at all")

    # Every finding page is identified by its 漏洞编号 value (#<id> alone). A page
    # without a packet heading means that finding ships no reproducible bytes.
    pages = []          # finding ids in document order
    page_has_packet = {}
    current = None
    for t in texts:
        if re.fullmatch(r"#\d+", t):
            current = t
            pages.append(current)
            page_has_packet.setdefault(current, False)
        elif current is not None and packet_heading_re.match(t):
            page_has_packet[current] = True
    missing_pages = [p for p in pages if not page_has_packet[p]]
    if missing_pages:
        problems.append(f"finding pages without packet section: {missing_pages}")

    for label in ("原始协议报文", "原始 HTTP 报文"):
        if label in counts:
            idx = texts.index(label)
            window = "".join(texts[idx:idx + 6])
            want = "原始请求数据" if label == "原始协议报文" else "HTTP 请求报文"
            if want not in window:
                problems.append(f"{label} section lacks {want}")

    http_only_missing = re.findall(r"未采集到原始 HTTP[^。]*", joined)
    raw_missing = re.findall(r"未采集到原始(?:协议|报文)[^。]*", joined)

    print(f"file={path}")
    print(f"paragraphs={len(texts)} page_breaks={breaks}")
    print(f"finding_pages={len(pages)} with_packet_section={len(pages) - len(missing_pages)}")
    print("section counts:", {k: v for k, v in sorted(counts.items()) if v > 0})
    print(f"http-missing-notes={len(http_only_missing)} raw-missing-notes={len(raw_missing)}")
    if problems:
        print("PROBLEMS:")
        for p in problems:
            print("  -", p)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
