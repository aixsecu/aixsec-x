#!/usr/bin/env python3
"""
aixsec-x — mock_mssql_sqli.py
Mock MSSQL SQLi server (offline test fixture cho v1.4.7).

Tái dựng hành vi quan sát được của target ASP.NET/MSSQL thật (example.com
WebTinTuc/TimKiem): form tìm kiếm CONTAINS/LIKE, câu query gốc nằm trong
stored procedure SP_WEB_GetTinTucForWeb (Entity Framework), lỗi SqlException
dạng multi-error (3 fragment nối bởi \\n), trang lỗi vàng ASP.NET.

HÀNH VI v1.4.7 — KHỚP probe LIVE example.com 2026-09-20 (6 requests):
  MẶC ĐỊNH (không --waf) — quote-parity oracle, KHÔNG còn conversion/
  WAITFOR/time-based (live: chúng đều vỡ cú pháp trên template thật):
    số quote CHẴN (0, 2, 4...): 200 trang FIXED byte-identical — payload bị
        hấp thụ trong string literal ('...'' OR 1=1' không bao giờ thực thi),
        KHÔNG có boolean row-count oracle; chẵn-quote → 200 hệt control.
    số quote LẺ:                 500 parse-error leak 3 fragment hệt live:
        "Incorrect syntax near '<token>'"  (token rút từ kw)
        \\t×14 + " CONTAINS(tt.MoTa, ''."
        "Unclosed quotation mark after the character string ''))'."
  --waf mode (LEGACY v1.4.5/6 — để tái hiện các live-run cũ có status-0
  resets): request chứa chữ ký attack (CONVERT(, WAITFOR, '; IF, UNION,
  --, ASCII(, ...) → đóng kết nối ngay (status 0, ~0.02s); conversion
  oracle `')AND CONVERT(...)` → 500 conversion; WAITFOR DELAY → sleep;
  quote trần → 500 GT_MSG.

API (giống target):
  GET  /                          → trang chủ + form tìm kiếm
  GET|POST /search                → xử lý keyword (param `keyword`)
  GET|POST /WebTinTuc/TimKiem     → alias như /search

Cốt lõi là hàm PURE `_decide(kw, waf)` → (status|None, body|None, delay_secs)
— KHÔNG sleep/IO, unit-test được trực tiếp (xem tests/test_agent.py). Evaluator
SQL mini giữ nguyên cho chế độ --waf legacy (conversion/time-based).

Chạy:
  python3 mock_mssql_sqli.py                 # 127.0.0.1:8099 (mặc định parity)
  python3 mock_mssql_sqli.py --waf           # legacy: WAF reset + conversion + WAITFOR
  python3 mock_mssql_sqli.py --port 8098
"""
from __future__ import annotations

import argparse
import html
import re
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

# ─────────────────────────────────────────────────────────────────────────────
# Ground truth (verbatim từ /tmp/example_500.html — Exception Details, thay <br>=\\n)
# ─────────────────────────────────────────────────────────────────────────────
# run giữa "OR" và "CONTAINS" trong HTML = 14 tab + 1 space (đã đếm byte).
_GT_TABS = "\t" * 14
GT_MSG = (
    "Incorrect syntax near '') OR\n"
    f"{_GT_TABS} CONTAINS(tt.MoTa, ''.\n"
    "Unclosed quotation mark after the character string ''))'."
)
# kw='AND' → dạng lỗi 1-error khác (example_err.html)
SILENT_MSG = "Incorrect syntax near the keyword 'AND'."
# lỗi syntax shape sai (đóng ngoặc sai / ngoặc trước quote) — oracle silent
BROKEN_MSG = "Incorrect syntax near ')'."

VERSION_STR = (
    "Microsoft SQL Server 2019 (RTM) 15.0.2000.5 (X64) - Enterprise Edition "
    "(64-bit) on Windows Server 2019 (X64) 10.0 <17763>"
)
DB_NAME = "example_web"
DB_USER = "sa"

# Dữ liệu mẫu (fictional) — bảng TinTuc (alias tt trong query thật).
TABLES = ["TinTuc", "LoaiTin", "DanhMuc", "QuangCao", "Users", "Config", "LienHe"]
COLUMNS = {
    "TinTuc": ["Id", "TieuDe", "MoTa", "NoiDungChiTiet", "NgayDang", "LuotXem", "IdDanhMuc"],
    "LoaiTin": ["Id", "TenLoai", "MoTa"],
    "DanhMuc": ["Id", "TenDanhMuc"],
    "Users": ["Id", "Username", "Password", "HoTen", "Email", "KichHoat"],
    "Config": ["Key", "Value"],
    "LienHe": ["Id", "DiaChi", "Email", "DienThoai"],
}
ROWS = {
    "TinTuc": [
        {"Id": "1", "TieuDe": "Truong Dai hoc Thu do Ha Noi tuyen sinh dai hoc chinh quy nam 2026",
         "MoTa": "Thong tin tuyen sinh va chi tieu cac nganh dao tao bac dai hoc.",
         "NoiDungChiTiet": "Xem them thong tin tai cot tuyen sinh cua truong.", "NgayDang": "2026-09-01", "LuotXem": "1250", "IdDanhMuc": "1"},
        {"Id": "2", "TieuDe": "Le khai giang nam hoc 2026-2027 va chao tan sinh vien khoa 60",
         "MoTa": "Truong long trong to chuc le khai giang dau nam hoc moi.",
         "NoiDungChiTiet": "Toan the can bo giang vien va sinh vien tham du.", "NgayDang": "2026-09-05", "LuotXem": "980", "IdDanhMuc": "1"},
        {"Id": "3", "TieuDe": "Hoi thao khoa hoc: Ung dung tri tue nhan tao trong giao duc",
         "MoTa": "Hoi thao quy tu cac chuyen gia ve chuyen doi so giao duc.",
         "NoiDungChiTiet": "Dac biet co bao cao cua doi ngu giang vien tre.", "NgayDang": "2026-09-10", "LuotXem": "640", "IdDanhMuc": "2"},
    ],
    "LoaiTin": [{"Id": "1", "TenLoai": "Tin tuc", "MoTa": "Tin tuc chung cua truong"}],
}

# ─────────────────────────────────────────────────────────────────────────────
# Regex hành vi
# ─────────────────────────────────────────────────────────────────────────────
# shape ĂN oracle: quote → 1-2 ngoặc → AND CONVERT(int,(expr)) → comment
CONVERT_RX = re.compile(
    r"^'\)(\)?)\s+AND\s+CONVERT\s*\(\s*int\s*,\s*\(\s*(?P<expr>.*?)\s*\)\s*\)\s*--",
    re.I | re.S)
# WAITFOR DELAY '0:0:N'  (có thể được bọc IF (cond))
WAITFOR_RX = re.compile(r"WAITFOR\s+DELAY\s+'0:0:(\d+)'", re.I)
IF_RX = re.compile(r"\bIF\s*\(", re.I)
# chữ ký WAF (chặn probe như live): CONVERT(, WAITFOR, '; IF, UNION, --, ...
WAF_RX = re.compile(
    r"(CONVERT\s*\(|CAST\s*\(|WAITFOR\s+DELAY|\bIF\s*\(|UNION\s+(ALL\s+)?SELECT|"
    r"\bEXEC(?:UTE)?\b|INFORMATION_SCHEMA|SUBSTRING\s*\(|ASCII\s*\(|UNICODE\s*\(|"
    r"STUFF\s*\(|--|;)", re.I)

# skeleton truy vấn data
DUMP_RX = re.compile(
    r"SELECT\s+TOP\s+1\s+CAST\((?P<col>[A-Za-z0-9_\[\]]+)\s+AS\s+nvarchar\(4000\)\)"
    r"\s+FROM\s+\(SELECT\s+[^,]+,\s+ROW_NUMBER\(\)\s+OVER\s+\(ORDER\s+BY\s+\(SELECT\s+NULL\)\)"
    r"\s+AS\s+rn\s+FROM\s+(?P<table>[A-Za-z0-9_]+)\)\s+AS\s+t\s+WHERE\s+t\.rn=(?P<rn>\d+)",
    re.I | re.S)
TABLES_RX = re.compile(r"INFORMATION_SCHEMA\.TABLES", re.I)
COLS_RX = re.compile(r"INFORMATION_SCHEMA\.COLUMNS", re.I)
CATALOG_RX = re.compile(r"TABLE_CATALOG=N'([^']*)'", re.I)
TBLNAME_RX = re.compile(r"TABLE_NAME=N'([^']*)'", re.I)

SQL_ESCAPE = re.compile(r"(?i)^SELECT\s+")


# ─────────────────────────────────────────────────────────────────────────────
# v1.4.7 — quote-parity oracle (hành vi MẶC ĐỊNH, khớp probe live example.com 2026-09-20)
# ─────────────────────────────────────────────────────────────────────────────
def _near_token(kw: str) -> str:
    """Token cho lỗi 'Incorrect syntax near <tok>': đoạn sau quote đầu tiên cho
    đến quote kế tiếp (hoặc hết kw), lấy WORD đầu tiên; rỗng → ground-truth
    '') OR (đúng live: test' → near '') OR)."""
    i = kw.find("'")
    if i < 0:
        return ""
    rest = kw[i + 1:]
    j = rest.find("'")
    seg = (rest[:j] if j >= 0 else rest).strip()
    if not seg:
        return "') OR"
    m = re.match(r"\W*(\w+)", seg)
    return m.group(1) if m else "') OR"


def parse_err_msg(kw: str) -> str:
    """3-fragment parse-error leak cho quote LẺ (shape hệt ground-truth example.com)."""
    tok = _near_token(kw)
    return (
        f"Incorrect syntax near '{tok}\n"
        f"{_GT_TABS} CONTAINS(tt.MoTa, ''.\n"
        "Unclosed quotation mark after the character string ''))'."
    )


def _fixed_page() -> str:
    """Trang 200 FIXED — KHÔNG nhúng kw → byte-identical cho mọi quote chẵn
    (đúng quan sát live: 99ZZQ và 99ZZQ'' trả sha giống hệt)."""
    rows = "\n".join(
        f"<li><a href='#'>{html.escape(r['TieuDe'])}</a></li>" for r in ROWS["TinTuc"])
    return f"""<!DOCTYPE html>
<html lang="vi">
<head><meta charset="utf-8"><title>Kết quả tìm kiếm</title></head>
<body>
<h1>Trường Đại học Thủ đô Hà Nội — Tìm kiếm tin tức</h1>
<form method="post" action="/WebTinTuc/TimKiem">
<input type="text" name="keyword" value="">
<input type="submit" value="Tìm kiếm">
</form>
<h2>Có N tin tức chứa: &quot;&quot;</h2>
<ul>
{rows}
</ul>
<p><small>SP_WEB_GetTinTucForWeb · dữ liệu mẫu (mock)</small></p>
</body>
</html>
"""


FIXED_PAGE = _fixed_page()


def _decide(kw: str, waf: bool) -> tuple[int | None, str | None, int]:
    """Quyết định phản hồi mock — PURE (không sleep/IO) để unit-test trực tiếp.
    Trả (status|None, body|None, delay_secs); status=None → đóng kết nối
    (client thấy status 0 — hệt WAF reset live).

    waf=False (MẶC ĐỊNH v1.4.7): quote-parity — quote lẻ → 500 parse-leak,
    quote chẵn → 200 FIXED byte-identical. Không conversion/WAITFOR (chúng
    vỡ cú pháp trên template thật — probe 2026-09-20: tất cả 500, không
    oracle dữ liệu nào ăn).
    waf=True (LEGACY v1.4.5/6): WAF_RX → reset; WAITFOR → sleep có điều kiện;
    CONVERT(...) → 500 conversion oracle; quote trần → 500 GT_MSG.
    """
    if waf:
        if WAF_RX.search(kw):
            return None, None, 0
        m = WAITFOR_RX.search(kw)
        if m:
            secs = min(int(m.group(1)), 5)
            cond = extract_if_cond(kw)
            if cond is not None:
                try:
                    if not _truthy(eval_expr(cond)):
                        secs = 0
                except Exception:
                    secs = 0
            return 200, search_page(kw, delayed=secs), secs
        if "'" in kw and "--" in kw:
            cm = CONVERT_RX.match(kw)
            if cm:
                try:
                    val = eval_expr(cm.group("expr"))
                    msg = conversion_msg(str(val))
                except Exception as e:  # eval lỗi → conversion với giá trị lạ
                    msg = conversion_msg(f"<eval error: {e}>")
                return 500, aspnet_500(msg), 0
            return 500, aspnet_500(BROKEN_MSG), 0
        if "'" in kw:
            return 500, aspnet_500(GT_MSG), 0
        return 200, search_page(kw), 0
    # default v1.4.7: quote-parity — KHÔNG có kênh dữ liệu nào (live xác nhận)
    if kw.count("'") % 2 == 1:
        return 500, aspnet_500(parse_err_msg(kw)), 0
    return 200, FIXED_PAGE, 0


# ─────────────────────────────────────────────────────────────────────────────
# Mini SQL evaluator (không exec — chỉ cú pháp con cần cho pipeline)
# ─────────────────────────────────────────────────────────────────────────────
def _split_top(s: str, sep: str) -> list[str]:
    """Tách theo sep ở depth paren 0, ngoài string literal."""
    out, depth, i, cur = [], 0, 0, ""
    slen = len(s)
    while i < slen:
        ch = s[i]
        if ch == "'":
            j = i + 1
            while j < slen:
                if s[j] == "'" and (j + 1 >= slen or s[j + 1] != "'"):
                    break
                if s[j] == "'":
                    j += 1
                j += 1
            cur += s[i:j + 1]
            i = j + 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and s.startswith(sep, i):
            out.append(cur)
            cur = ""
            i += len(sep)
            continue
        cur += ch
        i += 1
    out.append(cur)
    return out


def _peel(s: str) -> str:
    s = s.strip()
    while s.startswith("("):
        depth, i = 0, 0
        ok = True
        for ch in s:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            elif ch == "'":
                # bỏ qua string literal
                pass
            i += 1
        if depth == 0 and i == len(s) - 1:
            s = s[1:-1].strip()
        else:
            break
    return s


def _parse_literal(s: str):
    if s.startswith("N'") or s.startswith("n'"):
        s = s[1:]
    if s.startswith("'"):
        body = s[1:-1] if len(s) >= 2 and s.endswith("'") else s[1:]
        return body.replace("''", "'")
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return int(s) if "." not in s else float(s)
    return None


def _func(s: str):
    m = re.match(r"^([A-Za-z_@][\w@]*)\s*\((.*)\)$", s, re.S)
    if not m:
        return None
    name, args = m.group(1).upper(), m.group(2)
    if name == "@@VERSION":
        return VERSION_STR
    a = _split_top(args, ",") if args.strip() else []
    if name == "DB_NAME":
        return DB_NAME if not a else ""
    if name == "SUSER_SNAME":
        return DB_USER if not a else ""
    if name == "LEN" and a:
        return len(str(eval_expr(a[0])))
    if name == "ASCII" and a:
        v = str(eval_expr(a[0]))
        return ord(v[0]) if v else 0
    if name == "UNICODE" and a:
        v = str(eval_expr(a[0]))
        return ord(v[0]) if v else 0
    if name == "CHAR" and a:
        return chr(int(eval_expr(a[0])) & 0xFF)
    if name == "SUBSTRING" and len(a) == 3:
        base = str(eval_expr(a[0]))
        p, ln = int(eval_expr(a[1])), int(eval_expr(a[2]))
        if p < 1:
            p = 1
        return base[p - 1: p - 1 + ln]
    return None


def _skeleton(s: str) -> str | None:
    """Các truy vấn data đặc biệt → giá trị chữ."""
    dm = DUMP_RX.search(s)
    if dm:
        rows = ROWS.get(dm.group("table"), [])
        rn = int(dm.group("rn"))
        if 1 <= rn <= len(rows):
            col = dm.group("col").strip("[]")
            return str(rows[rn - 1].get(col, ""))
        return ""
    if TABLES_RX.search(s):
        db = CATALOG_RX.search(s)
        if db and db.group(1) != DB_NAME:
            return ""
        return ",".join(TABLES)
    if COLS_RX.search(s):
        t = TBLNAME_RX.search(s)
        if not t:
            return ""
        return ",".join(COLUMNS.get(t.group(1), []))
    return None


def eval_expr(s: str):
    """Đánh giá expr trong payload (KHÔNG dùng exec/eval). Trả str|int|bool."""
    s = (s or "").strip()
    v = _skeleton(s)
    if v is not None:
        return v
    s = SQL_ESCAPE.sub("", s).strip()
    s = _peel(s)
    # boolean OR
    parts = _split_top(s, " OR ")
    if len(parts) > 1:
        vals = [bool(eval_expr(p)) for p in parts]
        return any(vals)
    parts = _split_top(s, " AND ")
    if len(parts) > 1:
        vals = [bool(eval_expr(p)) for p in parts]
        return all(vals)
    # so sánh
    for op in (">=", "<=", "<>", "=", ">", "<"):
        parts = _split_top(s, op)
        if len(parts) == 2:
            l, r = eval_expr(parts[0]), eval_expr(parts[1])
            if isinstance(l, str) and isinstance(r, str):
                try:
                    l, r = int(l), int(r)
                except ValueError:
                    pass
            if op == "=":
                return l == r or str(l) == str(r)
            if op == "<>":
                return l != r
            try:
                return {"<": l < r, ">": l > r, "<=": l <= r, ">=": l >= r}[op]
            except TypeError:
                return False
    s2 = _peel(s)
    if s2 != s:
        s = s2
    lit = _parse_literal(s)
    if lit is not None:
        return lit
    f = _func(s)
    if f is not None:
        return f
    if re.fullmatch(r"@@[\w@]+", s):
        return {"@@VERSION": VERSION_STR}.get(s, "")
    return s  # bare identifier → chuỗi


def _truthy(v) -> bool:
    return bool(v)


def extract_if_cond(kw: str) -> str | None:
    """Lấy condition của IF (...) nếu có trong kw (cân bằng ngoặc)."""
    m = IF_RX.search(kw)
    if not m:
        return None
    i = kw.find("(", m.start())
    depth, j = 0, i
    while j < len(kw):
        if kw[j] == "(":
            depth += 1
        elif kw[j] == ")":
            depth -= 1
            if depth == 0:
                return kw[i + 1:j]
        j += 1
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Trang HTML (ASP.NET yellow screen + search page)
# ─────────────────────────────────────────────────────────────────────────────
def aspnet_500(sql_message: str) -> str:
    # GIỮ message THÔ (không html.escape) — khớp ground-truth example_500.html:
    # ASP.NET yellow screen render Exception Details với quote/<> trần.
    # (html.escape cũ biến ' thành &#x27; → VALUE_RX của client không đọc được
    # giá trị leak từ lỗi conversion — oracle detect/SUBSTRING fail.)
    esc = details = pre = sql_message
    details = details.replace("\n", "<br>")
    return f"""<!DOCTYPE html>
<html>
    <head>
        <title>{details}</title>
        <meta name="viewport" content="width=device-width" />
        <style>
         body {{font-family:"Verdana";font-weight:normal;font-size:.7em;color:black;}}
         p {{font-family:"Verdana";font-weight:normal;color:black;margin-top:-5px}}
         b {{font-family:"Verdana";font-weight:bold;color:white;background-color:navy}}
         h1 {{font-family:"Verdana";font-weight:normal;font-size:1em;color:white;background-color:navy;margin-left:-5px;margin-top:0px}}
         h2 {{font-family:"Verdana";font-weight:normal;font-size:.9em;color:white;background-color:navy;margin-left:-5px;margin-top:0px}}
        </style>
    </head>
    <body bgcolor="white">
            <span><H1>Server Error in '/' Application.<hr width=100% size=1 color=silver></H1>

            <h2> <i>{details}</i> </h2></span>

            <font face="Arial, Helvetica, Geneva, SunSans-Regular, sans-serif ">

            <b> Exception Details: </b>System.Data.SqlClient.SqlException: {details}<br><br>

            <b>Source Error:</b> <br><br>

            <table width=100% bgcolor="#ffffcc">
               <tr>
                  <td>
<code><pre>

[SqlException (0x80131904): {pre}]
   System.Data.SqlClient.SqlConnection.OnError(SqlException exception, Boolean breakConnection, Action`1 wrapCloseInAction)
   System.Data.SqlClient.TdsParser.ThrowExceptionAndWarning(TdsParserStateObject stateObj, Boolean callerHasConnectionLock, Boolean asyncClose)
   System.Data.SqlClient.SqlCommand.ExecuteReader(CommandBehavior behavior, String method)
   System.Data.SqlClient.SqlCommand.ExecuteReader(CommandBehavior behavior)
   System.Data.Entity.SqlServer.DefaultSqlExecutionStrategy.Execute[TResult](Func`1 operation)
   ASC.DATA.Models.HTWEntities.SP_WEB_GetTinTucForWeb(String domain, String subDomain, Nullable`1 isNew, Nullable`1 isNoiBat, Nullable`1 excludeID, String lstIDDanhMuc, String filter, Nullable`1 pageNumber, Nullable`1 rowspPage)
   System.Data.Entity.Core.EntityClient.Internal.EntityCommandDefinition.ExecuteStoreCommands(DbCommand command, DbCommandInterceptionContext`1 interceptionContext)
[EntityCommandExecutionException: An error occurred while executing the command definition. See the inner exception for details.]
   System.Data.Entity.Core.EntityClient.Internal.EntityCommandDefinition.ExecuteStoreCommands(DbCommand command, DbCommandInterceptionContext`1 interceptionContext)
</pre></code>

                  </td>
               </tr>
            </table>

            <br>

            <b> Stack Trace: </b> <br><br>

            <table width=100% bgcolor="#ffffcc">
               <tr>
                  <td>
<code><pre>
[SqlException (0x80131904): {pre}]
   at System.Data.SqlClient.SqlConnection.OnError(SqlException exception, Boolean breakConnection, Action`1 wrapCloseInAction)
   at System.Data.Entity.Core.Objects.ObjectContext.ExecuteFunction(String functionName, ExecutionOptions executionOptions, ObjectParameter[] parameters)
   at ASC.DATA.Models.HTWEntities.SP_WEB_GetTinTucForWeb(String domain, String subDomain, Nullable`1 isNew, Nullable`1 isNoiBat, Nullable`1 excludeID, String lstIDDanhMuc, String filter, Nullable`1 pageNumber, Nullable`1 rowspPage)
</pre></code>

                  </td>
               </tr>
            </table>

            <br>

            <b> Version Information: </b>&nbsp;Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.8.4770.0

            </font>

    </body>
</html>
<!--
[SqlException]: {esc}
   at System.Data.SqlClient.SqlConnection.OnError(SqlException exception, Boolean breakConnection, Action`1 wrapCloseInAction)
-->
"""


def conversion_msg(value: str) -> str:
    v = value.replace("'", "''")
    return f"Conversion failed when converting the nvarchar value '{v}' to data type int."


def search_page(kw: str, delayed: int = 0) -> str:
    e = html.escape(kw)
    note = f"<p style='color:gray'>({delayed}s)</p>" if delayed else ""
    rows = "\n".join(
        f"<li><a href='#'>{html.escape(r['TieuDe'])}</a></li>" for r in ROWS["TinTuc"])
    return f"""<!DOCTYPE html>
<html lang="vi">
<head><meta charset="utf-8"><title>Kết quả tìm kiếm: {e}</title></head>
<body>
<h1>Trường Đại học Thủ đô Hà Nội — Tìm kiếm tin tức</h1>
<form method="post" action="/WebTinTuc/TimKiem">
<input type="text" name="keyword" value="{e}">
<input type="submit" value="Tìm kiếm">
</form>
<h2>Có N tin tức chứa: &quot;{e}&quot;</h2>{note}
<ul>
{rows}
</ul>
<p><small>SP_WEB_GetTinTucForWeb · dữ liệu mẫu (mock)</small></p>
</body>
</html>
"""


HOME_PAGE = """<!DOCTYPE html>
<html lang="vi">
<head><meta charset="utf-8"><title>Trang chủ — Tìm kiếm tin tức</title></head>
<body>
<h1>Trường Đại học Thủ đô Hà Nội</h1>
<form method="post" action="/WebTinTuc/TimKiem">
<input type="text" name="keyword" placeholder="Nhập từ khóa...">
<input type="submit" value="Tìm kiếm">
</form>
<ul>
<li><a href="#">Truong Dai hoc Thu do Ha Noi tuyen sinh dai hoc chinh quy nam 2026</a></li>
<li><a href="#">Le khai giang nam hoc 2026-2027 va chao tan sinh vien khoa 60</a></li>
</ul>
</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────────────────
# HTTP handler
# ─────────────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Microsoft-IIS/10.0"
    sys_version = ""
    _RESET = ("__RESET__", None)

    def log_message(self, fmt, *args):
        pass  # log riêng trong _process

    def _read_kw(self) -> str:
        if self.command == "POST":
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode("utf-8", "replace")
            except (ValueError, OSError):
                body = ""
            d = parse_qs(body, keep_blank_values=True)
        else:
            d = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        vals = d.get("keyword")
        return vals[-1] if vals else ""

    def _send(self, status: int, body: str):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-AspNet-Version", "4.0.30319")
        self.send_header("X-Powered-By", "ASP.NET")
        self.end_headers()
        self.wfile.write(data)

    def _reset(self):
        """Đóng kết nối không trả response → client thấy status 0 (~0.02s)."""
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.connection.close()

    # ── xử lý chính (ủy quyền cho _decide — v1.4.7) ──
    def _process(self, kw: str):
        mode = "WAF" if self.server.waf else "no-WAF"
        status, body, delay = _decide(kw, self.server.waf)
        if status is None:
            self.log_action(mode, kw, "RESET (WAF)")
            return self._RESET
        if delay:
            time.sleep(delay)  # chỉ chế độ --waf legacy (WAITFOR)
        kind = {200: "200", 500: "500", None: "reset"}.get(status, str(status))
        label = " (WAITFOR %ds)" % delay if delay else ""
        self.log_action(mode, kw, kind + label)
        return body, status

    def log_action(self, mode: str, kw: str, result: str):
        k = kw[:48].replace("\n", "\\n")
        print(f"[{mode}] {self.command} {self.path} kw={k!r} → {result}", flush=True)

    def _handle(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        kw = self._read_kw()
        if path in ("/search", "/WebTinTuc/TimKiem"):
            r = self._process(kw)
        elif path == "/":
            if kw:
                r = self._process(kw)
            else:
                self._send(200, HOME_PAGE)
                return
        else:
            self._send(404, "<h1>404 Not Found</h1>")
            return
        if r == self._RESET:
            self._reset()
            return
        page, status = r
        self._send(status, page)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()


def main():
    ap = argparse.ArgumentParser(description="Mock MSSQL SQLi server (test fixture)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--waf", action="store_true",
                    help="Bật chế độ WAF: reset connection với payload attack")
    args = ap.parse_args()
    if args.waf:
        print("Chế độ WAF: BẬT (reset kết nối cho probe)", flush=True)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.waf = args.waf
    print(f"Mock MSSQL SQLi đang chạy: http://{args.host}:{args.port}"
          f"  (waf={args.waf})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
