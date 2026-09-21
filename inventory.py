#!/usr/bin/env python3
"""aixsec-x — inventory.py
Attack Surface Inventory (v1.6.0) — ChatGPT roadmap Phase 1 items #1/#12/#13.

Ý tưởng: sau mỗi round, agent gom tool output OK của phiên vào MỘT inventory
thống nhất: host → port → service → URL → method → parameter → auth → technology.
Mọi tool phía sau dùng chung inventory này thay vì rescan lại (item #1); agent
dùng nó để chọn bước tiếp theo theo công nghệ đã phát hiện (adaptive selection,
item #13) và nhớ cái gì đã thử (attack memory, item #12).

NGUYÊN TẮC BẰNG CHỨNG: Dữ liệu chỉ lấy từ tool output THẬT (outcome=ok, output
không bắt đầu '[!]'). Tool bị chặn/lỗi/duplicate không được tính. Không suy
diễn tech/endpoint/param — mọi mục phải xuất hiện nguyên văn trong output.

Dữ liệu nguồn theo tool (khớp ĐÚNG format thực tế trong tools.py):
  http_probe                               → dòng `GET url → status (N bytes)`
      + dict-repr headers: {'Server': 'nginx/1.24.0', 'X-Powered-By': ...}
  http_request / headers_recon             → dòng `METHOD url → status` +
      dòng header `  Key: value` / `Key: value`
  detect_cms (whatweb)                     → HTTPServer[nginx/1.24.0], PHP[8.1.22],...
  waf_detect (wafw00f)                     → "... is behind Cloudflare WAF."
  ffuf_dir (ffuf -s)                       → path `/admin` mỗi dòng
  param_discovery (arjun -q)               → "params: id, name" / "[+] id" / "id"
  wapiti_scan                              → dòng detail `[SEV] CAT ⇒ (param=X) — METHOD /path
      [module=...]` + dòng scope `[✓] wapiti QUÉT XONG … — <target> [scope=…]`
      + dòng form sweep `[+] form sweep: SQLi CONFIRMED POST /path param=name`
  sqli_manual_test                         → `[✓] SQLI CONFIRMED — … tại param 'id' (GET url)`
  sqli_blind_extract                       → `[✓] SQLi CONFIRMED — …`
  subdomain_enum (subfinder -silent)       → 1 subdomain mỗi dòng (chưa probe — info)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


# ─────────────────────────────────────────────
# DATA MODEL
# ─────────────────────────────────────────────

@dataclass
class Endpoint:
    url: str
    methods: set[str] = field(default_factory=set)
    params: set[str] = field(default_factory=set)
    auth_hint: str = ""          # "" | basic | bearer | digest | ntlm | cookie
    sources: set[str] = field(default_factory=set)   # tên tool xác nhận

    def merge(self, other: "Endpoint") -> None:
        self.methods |= other.methods
        self.params |= other.params
        if other.auth_hint and not self.auth_hint:
            self.auth_hint = other.auth_hint
        self.sources |= other.sources


@dataclass
class HostInfo:
    host: str
    port: str = ""
    service: str = ""            # http | https (từ scheme thật)
    tech: dict[str, str] = field(default_factory=dict)   # {name: version-or-""}
    auth_hints: set[str] = field(default_factory=set)
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    sources: set[str] = field(default_factory=set)

    def add_endpoint(self, url: str) -> Endpoint:
        url = _norm_url(url)
        ep = self.endpoints.get(url)
        if ep is None:
            ep = Endpoint(url=url)
            self.endpoints[url] = ep
        return ep


_MAX_RENDER_LINES = 24   # tránh tràn context khi chèn vào message lượt sau


class Inventory:
    """Attack surface tích lũy trong một phiên. KHÔNG tự suy diễn gì."""

    def __init__(self):
        self.hosts: dict[str, HostInfo] = {}
        self.dns_only: set[str] = set()      # subdomain từ subfinder — chưa probe
        self._ports: dict[str, str] = {}     # cache host → port (thấy ở đâu thì ghi đó)

    # ── ingest ──
    def ingest(self, calls: list[dict]) -> int:
        """calls: [{name, args, outcome, output}] (transcript/results).
        Chỉ xử lý outcome=ok + output không mở đầu '[!]'. Trả số mục mới."""
        n_new = 0
        for c in calls or []:
            name = str(c.get("name") or "")
            if c.get("outcome") != "ok":
                continue
            out = str(c.get("output") or "")
            if out.lstrip().startswith("[!]"):
                continue
            args = c.get("args") or {}
            fn = _PARSERS.get(name)
            if fn is not None:
                n_new += fn(self, name, args, out)
        return n_new

    # ── host helpers ──
    def host(self, url: str) -> HostInfo | None:
        h = _url_host(url)
        return self.hosts.get(h) if h else None

    def ensure_web(self, url: str, source: str = "") -> HostInfo | None:
        """Đăng ký host web (http/https) từ URL có bằng chứng thật."""
        m = re.match(r"^(https?)://([^/?#]+)", (url or "").strip())
        if not m:
            return None
        scheme, netloc = m.group(1), m.group(2)
        h = netloc.split("@")[-1].lower().strip(".")
        if ":" in h:
            head, _, tail = h.rpartition(":")
            if tail.isdigit():
                h = head
                self._ports.setdefault(h, tail)
        host = self.hosts.get(h)
        if host is None:
            host = HostInfo(host=h, port=self._ports.get(h, ""),
                            service=scheme)
            self.hosts[h] = host
        if source:
            host.sources.add(source)
        return host

    def add_tech(self, host: HostInfo, name: str, version: str = "",
                 source: str = "") -> None:
        name = (name or "").strip().lower()
        if not name or host is None:
            return
        low = name.lower()
        if low in host.tech:
            if not host.tech[low] and version:
                host.tech[low] = version
        else:
            host.tech[low] = version
        if source:
            host.sources.add(source)

    def add_endpoint(self, host: HostInfo, url: str, method: str = "",
                     param: str = "", auth: str = "", source: str = "") -> Endpoint:
        ep = host.add_endpoint(url)
        if method:
            ep.methods.add(method.upper())
        if param:
            ep.params.add(param)
        if auth and not ep.auth_hint:
            ep.auth_hint = auth
        if source:
            ep.sources.add(source)
            host.sources.add(source)
        return ep

    # ── render ──
    def render(self, limit: int = _MAX_RENDER_LINES) -> str:
        """Block compact cho prompt lượt sau. Label tiếng Việt, chỉ dữ liệu thật."""
        if not self.hosts and not self.dns_only:
            return ""
        out = ["[ATTACK SURFACE]"]
        for hk in sorted(self.hosts):
            h = self.hosts[hk]
            tech_s = ", ".join(f"{t}{(' ' + v) if v else ''}"
                               for t, v in sorted(h.tech.items())) or "-"
            port_s = f":{h.port}" if h.port else ""
            auth_s = f" auth={','.join(sorted(h.auth_hints))}" if h.auth_hints else ""
            out.append(f"  {hk}{port_s} ({h.service}) tech=[{tech_s}]{auth_s}"
                       f" src={','.join(sorted(h.sources)) or '-'}")
            for url in sorted(h.endpoints):
                ep = h.endpoints[url]
                m = ",".join(sorted(ep.methods)) or "-"
                p = f" params={','.join(sorted(ep.params))}" if ep.params else ""
                a = f" auth={ep.auth_hint}" if ep.auth_hint else ""
                s = f" [{','.join(sorted(ep.sources)) or '-'}]"
                out.append(f"    {m} {url}{p}{a}{s}")
                if len(out) >= limit:
                    break
            if len(out) >= limit:
                break
        if self.dns_only and len(out) < limit:
            subs = sorted(self.dns_only)
            shown = subs[: max(1, limit - len(out))]
            out.append("  [i] subdomain mới (chưa probe — info): " + ", ".join(shown)
                       + (" …" if len(subs) > len(shown) else ""))
        if len(out) > limit:
            out = out[:limit]
            out[-1] = "  … (còn nhiều endpoint/tech khác — rescan KHÔNG cần, "
            out[-1] += "xem /capabilities để biết tool; next-round cứ chọn mục mới)"
        return "\n".join(out)

    # ── persist ──
    def to_dict(self) -> dict:
        return {
            "hosts": [
                {
                    "host": h.host, "port": h.port, "service": h.service,
                    "tech": dict(sorted(h.tech.items())),
                    "auth_hints": sorted(h.auth_hints),
                    "sources": sorted(h.sources),
                    "endpoints": [
                        {"url": e.url, "methods": sorted(e.methods),
                         "params": sorted(e.params), "auth_hint": e.auth_hint,
                         "sources": sorted(e.sources)}
                        for e in sorted(h.endpoints.values(), key=lambda e: e.url)
                    ],
                }
                for h in sorted(self.hosts.values(), key=lambda h: h.host)
            ],
            "dns_only": sorted(self.dns_only),
        }

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: str) -> "Inventory":
        inv = cls()
        with open(path) as f:
            data = json.load(f)
        for hd in data.get("hosts", []):
            host = HostInfo(host=hd["host"], port=hd.get("port", ""),
                            service=hd.get("service", ""),
                            tech=dict(hd.get("tech") or {}),
                            auth_hints=set(hd.get("auth_hints") or []),
                            sources=set(hd.get("sources") or []))
            for ed in hd.get("endpoints", []):
                ep = Endpoint(url=ed["url"], methods=set(ed.get("methods") or []),
                              params=set(ed.get("params") or []),
                              auth_hint=ed.get("auth_hint", ""),
                              sources=set(ed.get("sources") or []))
                host.endpoints[ep.url] = ep
            inv.hosts[host.host] = host
        inv.dns_only = set(data.get("dns_only") or [])
        return inv


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _norm_url(url: str) -> str:
    url = (url or "").strip()
    if len(url) > 1 and url.endswith("/"):
        url = url.rstrip("/")
    return url


def _url_host(url: str) -> str:
    m = re.match(r"^[a-z]+://([^/?#]+)", (url or "").strip())
    if not m:
        return ""
    netloc = m.group(1).split("@")[-1].split(":")[0].lower()
    return netloc.strip(".")


# ─────────────────────────────────────────────
# PARSERS — mỗi tool đăng ký (name, args, output) → thêm vào inventory
# ─────────────────────────────────────────────

_TECH_KEYWORDS = {
    "openresty": "openresty", "nginx": "nginx", "apache": "apache",
    "microsoft-iis": "iis", "iis": "iis", "litespeed": "litespeed",
    "caddy": "caddy", "tomcat": "tomcat", "jboss": "jboss",
    "wordpress": "wordpress", "joomla": "joomla", "drupal": "drupal",
    "magento": "magento", "prestashop": "prestashop", "opencart": "opencart",
    "woocommerce": "woocommerce", "laravel": "laravel", "django": "django",
    "flask": "flask", "rails": "rails", "express": "express",
    "asp.net": "asp.net", "spring": "spring", "php": "php",
    "python": "python", "node.js": "node.js", "java": "java",
    "cloudflare": "cloudflare", "fastly": "fastly", "varnish": "varnish",
    "haproxy": "haproxy", "envoy": "envoy",
}

# whatweb in kiểu "HTTPServer[nginx/1.24.0]", "PHP[8.1.22]" — regex version rõ ràng
_TECH_BRACKET = re.compile(
    r"(HTTPServer|PHP|Apache|nginx|OpenResty|LiteSpeed|Microsoft-IIS|IIS|"
    r"WordPress|Joomla|Drupal|Magento|PrestaShop|OpenCart|Laravel|Django|"
    r"Rails|Express|ASP\.NET|Spring|Caddy|Tomcat|JBoss|Node\.js|Python)"
    r"\[([0-9][0-9a-zA-Z_.+/-]*)\]")

# dòng phản hồi: "GET url → 200 (123 bytes)" / "HEAD url → 200" / "POST url → 500 (1 bytes, 2.1s)"
_RESP_LINE = re.compile(
    r"^(GET|POST|HEAD|PUT|OPTIONS|DELETE|PATCH)\s+(\S+)\s+→\s+(\d{3})")

# http_probe in headers dạng dict repr: headers: {'Server': 'nginx/1.24.0', ...}
_HDR_DICT_RE = re.compile(r"headers:\s*(\{.*?\})", re.S)

# header line: "  Server: nginx/1.24.0" (http_request) hoặc "Server: nginx" (headers_recon)
_HDR_LINE_RE = re.compile(
    r"^\s*(Server|X-Powered-By|Set-Cookie|WWW-Authenticate):\s*(.+)$",
    re.M | re.I)

# wapiti detail: "[HIGH] SQL Injection (param=id) — GET /page.php [module=sql]"
_WAPITI_DETAIL = re.compile(
    r"^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+?)(?:\s+\(param=([^)]+)\))?"
    r"\s+—\s+(\S+)\s+(\S+)(?:\s+\[module=([^\]]+)\])?$")
_WAPITI_SCOPE = re.compile(r"\[✓\] wapiti QUÉT XONG.*—\s+(\S+)\s+\[scope=")
_WAPITI_SWEEP = re.compile(r"SQLi CONFIRMED\s+(POST|GET)\s+(\S+)\s+param=([^\s\[,]+)")
_WAPITI_STOP = "[✓] TỔNG HỢP LỖ HỔNG"

# sqli_manual_test: "[✓] SQLI CONFIRMED — quote-differential (error-based) tại param 'id' (GET http://...)"
_SQLI_MANUAL = re.compile(
    r"SQLI CONFIRMED.*?tại param '([^']*)' \(([A-Z]+)\s+(\S+)\)", re.I)
# sqli_blind_extract: "[✓] SQLi CONFIRMED — ..." (param/url/method từ args)
_SQLI_ANY = re.compile(r"SQLI CONFIRMED", re.I)

_WAF_RE = re.compile(r"is behind\s+(.+?)\s+WAF\b", re.I)

_TECH_HEADER_MAP = {
    "server": None,             # xử lý riêng (có version trong value)
    "x-powered-by": None,
    "set-cookie": "cookie",
    "www-authenticate": None,   # auth scheme
}
_AUTH_SCHEMES = {"basic", "bearer", "digest", "ntlm", "negotiate"}


def _canon_tech(name: str) -> str:
    first = name.split("/", 1)[0].strip().lower()
    return _TECH_KEYWORDS.get(first, first)


def _apply_header(inv: Inventory, host: HostInfo, key: str, val: str,
                  source: str) -> None:
    key_l = key.strip().lower()
    val = val.strip().strip("'\"")
    if key_l == "server":
        canon = _canon_tech(val)
        ver = val.split("/", 1)[1] if "/" in val else ""
        inv.add_tech(host, canon, ver, source)
    elif key_l == "x-powered-by":
        canon = _canon_tech(val)
        ver = val.split("/", 1)[1] if "/" in val else ""
        # nếu cùng tech với Server (vd php) thì chỉ lưu version nếu Server không có
        if canon not in host.tech or not host.tech[canon]:
            inv.add_tech(host, canon, ver, source)
    elif key_l == "set-cookie":
        host.auth_hints.add("cookie")
        cname = val.split("=", 1)[0].lower()
        if "phpsessid" in cname:
            inv.add_tech(host, "php", source=source)
        elif "jsessionid" in cname:
            inv.add_tech(host, "java", source=source)
        elif "asp.net_sessionid" in cname:
            inv.add_tech(host, "asp.net", source=source)
    elif key_l == "www-authenticate":
        scheme = val.split(" ", 1)[0].lower()
        if scheme in _AUTH_SCHEMES:
            host.auth_hints.add(scheme)


def _tech_from_http(inv: Inventory, host: HostInfo, out: str, source: str) -> None:
    """Đọc headers theo 3 format: dict-repr (http_probe) / '  K: v' (http_request)
    / 'K: v' (headers_recon)."""
    m = _HDR_DICT_RE.search(out)
    if m:
        for km in re.finditer(r"'([^']+)':\s*'([^']*)'", m.group(1)):
            _apply_header(inv, host, km.group(1), km.group(2), source)
    for hm in _HDR_LINE_RE.finditer(out):
        _apply_header(inv, host, hm.group(1), hm.group(2), source)


def _probe(inv: Inventory, host: HostInfo, out: str, source: str) -> Endpoint | None:
    m = _RESP_LINE.match(out.strip())
    if not m:
        return None
    method, url = m.group(1), m.group(2)
    _tech_from_http(inv, host, out, source)
    return inv.add_endpoint(host, url, method=method, source=source)


def _host_of(inv: Inventory, url: str, source: str = "") -> HostInfo | None:
    return inv.ensure_web(url, source)


def _ingest_probe(inv: Inventory, name: str, args: dict, out: str) -> int:
    host = _host_of(inv, str(args.get("url") or ""), name)
    if host is None:
        return 0
    return 1 if _probe(inv, host, out, name) else 0


def _ingest_headers(inv: Inventory, name: str, args: dict, out: str) -> int:
    host = _host_of(inv, str(args.get("url") or ""), name)
    if host is None:
        return 0
    ep = _probe(inv, host, out, name)
    if ep is None:
        ep = inv.add_endpoint(host, str(args.get("url") or ""),
                              method="HEAD", source=name)
    return 1


def _ingest_cms(inv: Inventory, name: str, args: dict, out: str) -> int:
    host = _host_of(inv, str(args.get("url") or ""), name)
    if host is None:
        return 0
    low = out.lower()
    for kw, canon in _TECH_KEYWORDS.items():
        if kw in low:
            inv.add_tech(host, canon, source=name)
    for m in _TECH_BRACKET.finditer(out):
        inv.add_tech(host, _TECH_KEYWORDS.get(m.group(1).lower(),
                                              m.group(1).lower()),
                     m.group(2))
    return 0


def _ingest_waf(inv: Inventory, name: str, args: dict, out: str) -> int:
    host = _host_of(inv, str(args.get("url") or ""), name)
    if host is None:
        return 0
    m = _WAF_RE.search(out)
    if m:
        inv.add_tech(host, f"waf:{m.group(1).strip()}", source=name)
    return 0


def _ingest_ffuf(inv: Inventory, name: str, args: dict, out: str) -> int:
    url = str(args.get("url") or "").rstrip("/")
    host = _host_of(inv, url, name)
    if host is None:
        return 0
    n = 0
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln.startswith("/") or len(ln) > 300:
            continue
        if not re.match(r"^/[A-Za-z0-9_\-./~]+$", ln):
            continue
        inv.add_endpoint(host, url + ln, source=name)
        n += 1
    return n


_NOISE_PARAM = re.compile(
    r"^(error|found|loading|done|target|url|time|info|note|params?|parameters)$",
    re.I)
_PARAM_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{1,64}$")


def _ingest_params(inv: Inventory, name: str, args: dict, out: str) -> int:
    url = str(args.get("url") or "")
    host = _host_of(inv, url, name)
    if host is None:
        return 0
    ep = inv.add_endpoint(host, url, source=name)
    n = 0
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or len(ln) > 120:
            continue
        m = re.match(r"^(?:\[\+\]\s*)?([A-Za-z_][A-Za-z0-9_\-]{1,64})$", ln)
        if m and not _NOISE_PARAM.match(m.group(1)) and "/" not in ln:
            if m.group(1) not in ep.params:
                ep.params.add(m.group(1))
                n += 1
            continue
        m2 = re.search(r"(?:parameters?|params?|found)\s*:\s*(.+)", ln, re.I)
        if m2:
            for tok in re.split(r"[,;]\s*", m2.group(1)):
                tok = tok.strip(" .")
                if _PARAM_TOKEN.match(tok):
                    if tok not in ep.params:
                        ep.params.add(tok)
                        n += 1
    return n


def _ingest_wapiti(inv: Inventory, name: str, args: dict, out: str) -> int:
    m = _WAPITI_SCOPE.search(out)
    target = m.group(1) if m else str(args.get("url") or "")
    host = _host_of(inv, target, name)
    if host is None:
        return 0
    n = 0
    for line in out.splitlines():
        line = line.strip()
        if _WAPITI_STOP in line:
            break
        m = _WAPITI_DETAIL.match(line)
        if m:
            _sev, cat, param, method, path, module = m.groups()
            full = target.rstrip("/") + (path if path.startswith("/")
                                         else "/" + path)
            ep = inv.add_endpoint(host, full, method=method, source=name)
            if param:
                ep.params.add(param)
            n += 1
            continue
        sw = _WAPITI_SWEEP.search(line)
        if sw:
            smethod, spath, sparam = sw.group(1), sw.group(2), sw.group(3)
            full = target.rstrip("/") + (spath if spath.startswith("/")
                                         else "/" + spath)
            ep = inv.add_endpoint(host, full, method=smethod, param=sparam,
                                   source=name)
            n += 1
    return n


def _ingest_sqli(inv: Inventory, name: str, args: dict, out: str) -> int:
    if not _SQLI_ANY.search(out):
        return 0
    url = str(args.get("url") or "")
    host = _host_of(inv, url, name)
    if host is None:
        return 0
    method = str(args.get("method") or "get").upper() if args.get("method") else "GET"
    param = str(args.get("param") or "")
    m = _SQLI_MANUAL.search(out)
    if m:
        param = m.group(1) or param
        method = m.group(2) or method
    elif name == "sqli_blind_extract" and not param:
        # blind detect không in param — lấy từ args nếu có
        pass
    inv.add_endpoint(host, url, method=method, param=param, source=name)
    return 1


def _ingest_subdomain(inv: Inventory, name: str, args: dict, out: str) -> int:
    for ln in out.splitlines():
        ln = ln.strip().lower()
        if re.match(r"^[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?$", ln) and "." in ln:
            inv.dns_only.add(ln)
    return 0


_PARSERS = {
    "http_probe": _ingest_probe,
    "http_request": _ingest_probe,
    "headers_recon": _ingest_headers,
    "detect_cms": _ingest_cms,
    "waf_detect": _ingest_waf,
    "ffuf_dir": _ingest_ffuf,
    "param_discovery": _ingest_params,
    "wapiti_scan": _ingest_wapiti,
    "sqli_manual_test": _ingest_sqli,
    "sqli_blind_extract": _ingest_sqli,
    "subdomain_enum": _ingest_subdomain,
}
