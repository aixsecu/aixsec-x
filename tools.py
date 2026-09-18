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
        raise FileNotFoundError(f"{tool} chưa cài")


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
    _need("nikto")
    return run_cmd(["nikto", "-h", kw["url"], "-nointeractive", "-maxtime", "120"], kw["_timeout"])


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


def _ffuf_dir(**kw):
    _need("ffuf")
    wl = kw.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    if not os.path.exists(wl):
        # raise (→ outcome=error, bị đếm vào fail-count/URL-block) thay vì trả
        # chuỗi lỗi với outcome=ok — nếu không agent cứ gọi lại wordlist hỏng
        raise ValueError(f"[!] Wordlist không tồn tại: {wl}")
    args = ["ffuf", "-u", kw["url"].rstrip("/") + "/FUZZ",
            "-w", wl, "-mc", "200,204,301,302,307,401,403", "-t", "30",
            "-timeout", "10", "-s"]
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


def _sqli_manual_test(**kw):
    """Kiểm tra SQLi thủ công nhẹ nhàng: time-based với 2 payload so sánh."""
    url = kw["url"]
    param = kw["param"]
    baseline, delay = kw.get("baseline", "id=1"), kw.get("delay_payload", "id=1 AND SLEEP(3)")
    import time as t
    import requests
    results = []
    for label, payload in (("baseline", baseline), ("delay", delay)):
        try:
            sep = "&" if "?" in url else "?"
            r = requests.get(f"{url}{sep}{payload}", timeout=12,
                             headers={"User-Agent": "Mozilla/5.0"})
            results.append(f"{label}: status={r.status_code} time={r.elapsed.total_seconds():.2f}s "
                           f"len={len(r.content)}")
        except Exception as e:
            results.append(f"{label}: lỗi {e}")
    return "\n".join(results)


def _sqli_blind_extract(**kw):
    """SQLi time-based blind KHÔNG sqlmap: detect + extract (query & path injection).

    Wrap TimeBlindExploiter (sqli_blind_poc.py). Dùng khi sqlmap fail, ví dụ
    path-injection /search/123.html. Extraction rất chậm (mỗi ký tự ~13 probe).
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
    ToolSpec("sqli_manual_test", "Test SQLi time-based thủ công nhẹ (2 request: control vs SLEEP(3)). "
             "So sánh thời gian phản hồi.",
             {"type": "object",
              "properties": {"url": {"type": "string", "pattern": "^https?://"},
                             "param": {"type": "string"},
                             "baseline": {"type": "string"},
                             "delay_payload": {"type": "string"}},
              "required": ["url", "param"]}, _sqli_manual_test, risk="active"),
    ToolSpec("sqli_blind_extract",
             "SQLi time-based blind KHÔNG sqlmap: detect & extract dữ liệu bằng Python thuần "
             "(requests + timing + binary search). Hỗ trợ query (?id=1) VÀ path injection "
             "(/search/123.html). Dùng KHI sqlmap fail hoặc không bắt được path-injection. "
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
                               "description": "Độ dài tối đa của mỗi giá trị trích xuất"}},
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
