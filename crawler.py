"""crawler.py — v1.9.0 Phase 2: Crawler + HTML link/form/parameter/JS discovery.

Dùng CHUNG HttpSession (`http_engine.session_for`) — KHÔNG implementation HTTP
thứ 2 (xem comment http_engine.py:589-594). GET-only BFS, KHÔNG submit form,
KHÔNG chạy exploit — form/param chỉ được INVENTORY hóa để các tool active
(sqli_manual_test, wapiti, sqlmap...) khai thác sau.

Discovery trên MỘT trang HTML (html.parser — stdlib, hermetic, không cần
binary ngoài):
  - links:  <a href> <area href> <link href> <iframe src> <base href>
  - forms:  <form action/method> + <input> <select> <textarea> <button name>
  - params: query string của page/link + field name của form
  - scripts:<script src> (tài nguyên JS — KHÔNG fetch nội dung)
  - js_hints: endpoint hint trong inline <script> (fetch/axios/$.ajax/XHR) với
    method ƯỚC LƯỢNG: axios.verb / xhr.open → verb thật; fetch('url') → GET;
    fetch('url', {method:...}) hoặc trường hợp không chắc → UNKNOWN (KHÔNG gán
    sai GET — review v1.9.1) — CHỈ LÀ ỨNG VIÊN (có thể là template/chuỗi
    tĩnh), phải xác minh trước khi dùng; inventory gắn source tag riêng
    "crawler:js".

Bounded & an toàn:
  - same-scope mặc định: scheme+host+port của start URL (giống _session_key).
    Redirect ra ngoài scope: KHÔNG theo (ghi redirect_out, dừng chuỗi).
  - max_depth (BFS), max_pages (limit trang đã fetch), max_body_bytes (cap
    phần HTML đem phân tích), timeout/request, politeness delay, time_budget
    (Python tool không bị kill ngoài → crawler TỰ dừng đúng hạn).
  - record=False trên engine: request crawler KHÔNG vào ring buffer evidence
    (replay/PoC giữ cho http_request).
"""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunsplit

import http_engine as he

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

_HTML_TYPES = frozenset(("text/html", "application/xhtml+xml"))

# redirect status cần theo Location
_REDIRECT_STATUS = frozenset((301, 302, 303, 307, 308))

# static asset — phát hiện qua link NHƯNG không enqueue (tránh fetch file
# nhị phân làm tốn max_pages; vẫn có trong links/scripts để AI biết mặt)
_STATIC_EXT = frozenset((
    "js", "css", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "avif",
    "woff", "woff2", "ttf", "eot", "otf",
    "pdf", "zip", "gz", "tar", "bz2", "xz", "7z", "rar",
    "mp4", "mp3", "webm", "avi", "mov", "ogg", "wav", "m4a",
    "exe", "dmg", "apk", "deb", "rpm", "bin",
))

# badge cho canonical endpoint shape: /product.php?id={value}
_BADGE = "{value}"

# inline JS endpoint hint — CHỈ chuỗi literal, heuristic (ứng viên)
# method ƯỚC LƯỢNG (v1.9.1): không chắc → None (inventory lưu UNKNOWN, KHÔNG
# gán GET bừa — review: "Nếu không chắc, UNKNOWN tốt hơn việc gán sai GET").
# Các hàm method nhận (match, text) — text để peek ký tự kế tiếp (fetch options).
# URL luôn ở named group 'url'; verb (nếu có) ở named group 'verb' (GHI CHÚ:
# tuyệt đối không dùng group(1) — thứ tự group phụ thuộc pattern).


def _hint_m_fetch(m: re.Match, text: str) -> str | None:
    """fetch('url') → GET. fetch('url', ...) — có options sau URL, không đủ
    chắc (có thể method:'POST') → None → UNKNOWN."""
    rest = text[m.end():m.end() + 32].lstrip(" \t\r\n")
    return None if rest.startswith(",") else "GET"


def _hint_m_verb(m: re.Match, text: str) -> str | None:
    """axios.get/post/... hoặc xhr.open('DELETE', ...) → verb upper."""
    v = m.group("verb")
    return v.upper() if v else None


def _hint_m_none(m: re.Match, text: str) -> str | None:
    """$.ajax — method nằm trong options object ({type:'POST'}) chưa parse
    (parser phức tạp chưa cần ngay): không chắc → None → UNKNOWN."""
    return None


_HINT_PATTERNS = (
    ("fetch",
     re.compile(r"\bfetch\s*\(\s*(?:['\"])(?P<url>[^'\"]+)(?:['\"])"),
     _hint_m_fetch),
    ("axios",
     re.compile(r"\baxios\.(?P<verb>get|post|put|patch|delete|head|options)"
                r"\s*\(\s*['\"](?P<url>[^'\"]+)['\"]"),
     _hint_m_verb),
    ("jquery.ajax",
     re.compile(r"\$\.ajax\s*\(\s*\{[^{}]*?url\s*:\s*['\"](?P<url>[^'\"]+)['\"]"),
     _hint_m_none),
    ("xhr",
     re.compile(r"\.open\s*\(\s*['\"](?P<verb>GET|POST|PUT|PATCH|DELETE|HEAD|"
                r"OPTIONS)['\"]\s*,\s*['\"](?P<url>[^'\"]+)['\"]"),
     _hint_m_verb),
)

# scheme bỏ qua khi gặp href/src (javascript:, mailto:, tel:, data:...)
_SKIP_SCHEMES = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)

# số mục in tối đa mỗi phần trong render() (output bounded, không tràn context)
_RENDER_CAPS = {
    "pages": 30, "links": 40, "forms": 15, "params": 30,
    "scripts": 20, "hints": 15, "errors": 10,
}


# ─────────────────────────────────────────────
# URL HELPERS (độc lập, unit-test được)
# ─────────────────────────────────────────────

def norm_url(url: str) -> str:
    """Chuẩn hóa URL tuyệt đối: scheme+host lowercase, bỏ fragment, query
    theo thứ tự SORTED (trùng dù thứ tự param khác). '' nếu không hợp lệ."""
    u = urlparse((url or "").strip())
    scheme = (u.scheme or "").lower()
    if not scheme or not u.netloc or scheme not in ("http", "https"):
        return ""
    netloc = u.netloc.lower()
    path = u.path or "/"
    pairs = parse_qsl(u.query, keep_blank_values=True)
    q = urlencode(sorted(pairs)) if pairs else ""
    return urlunsplit((scheme, netloc, path, q, ""))


def scope_key(url: str) -> str:
    """Khóa scope scheme://host:port (port mặc định 80/443 theo scheme) —
    cùng ngữ nghĩa _session_key của Session Engine."""
    u = urlparse((url or "").strip())
    scheme = (u.scheme or "http").lower()
    host = (u.hostname or "").lower()
    port = u.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return f"{scheme}://{host}:{port}"


def canon_url(url: str) -> str:
    """Canonical endpoint shape: giá trị query thay bằng {value} —
    /product.php?id=1&x=2 → /product.php?id={value}&x={value} (collapse tập
    giá trị của cùng endpoint, params giữ nguyên tên). Không percent-encode
    badge (render inventory đọc được)."""
    u = urlparse((url or "").strip())
    names = [k for k, _ in parse_qsl(u.query, keep_blank_values=True)]
    q = "&".join(f"{k}={_BADGE}" for k in names) if names else ""
    return urlunsplit((u.scheme.lower(), u.netloc.lower(), u.path or "/", q, ""))


def query_names(url: str) -> list[str]:
    """Tên query param (theo thứ tự xuất hiện, dedup) của URL."""
    out: list[str] = []
    seen: set[str] = set()
    for k, _ in parse_qsl(urlparse((url or "").strip()).query,
                          keep_blank_values=True):
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def is_same_scope(url: str, scope: str) -> bool:
    """url cùng scheme+host+port với khóa scope cho trước."""
    return scope_key(url) == scope


def _short(url: str, scope: str = "") -> str:
    """Hiển thị gọn: path?query cho URL cùng scope; full URL cho ngoài scope."""
    u = urlparse((url or "").strip())
    p = (u.path or "/") + (f"?{u.query}" if u.query else "")
    if scope and scope_key(url) == scope:
        return p
    return url


def _static_ext(url: str) -> bool:
    p = urlparse((url or "").strip()).path.rsplit("/", 1)[-1]
    return "." in p and p.rsplit(".", 1)[-1].lower() in _STATIC_EXT


# ─────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────

@dataclass
class PageRecord:
    url: str            # URL CUỐI (sau redirect) — norm
    status: int
    content_type: str
    depth: int


@dataclass
class FormSpec:
    action: str                 # URL tuyệt đối đã resolve
    method: str                 # GET/POST (upper)
    params: list[str] = field(default_factory=list)   # field name (dedup)
    fields: list[dict] = field(default_factory=list)  # {name,type,value}
    source: str = ""            # trang phát hiện


@dataclass
class JsHint:
    kind: str                   # fetch|axios|jquery.ajax|xhr
    url: str                    # đã resolve (norm)
    method: str | None = None   # GET/POST/... ước lượng; None → UNKNOWN
    in_scope: bool = False
    source: str = ""            # trang phát hiện


@dataclass
class CrawlResult:
    url: str                    # start URL (norm)
    scope: str
    same_scope: bool
    pages: list[PageRecord] = field(default_factory=list)
    links: set[str] = field(default_factory=set)          # same-scope
    external_links: set[str] = field(default_factory=set)
    forms: list[FormSpec] = field(default_factory=list)
    params: dict[str, set[str]] = field(default_factory=dict)  # canon → names
    scripts: set[str] = field(default_factory=set)        # same-scope
    external_scripts: set[str] = field(default_factory=set)
    hints: list[JsHint] = field(default_factory=list)
    redirect_out: list[tuple[int, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stopped: str = "done"       # done|max_pages|time_budget
    elapsed: float = 0.0

    # ── helpers ──
    def _add_params(self, url: str, extra: list[str] | None = None) -> None:
        names = query_names(url) + list(extra or [])
        if not names:
            return
        key = canon_url(url)
        s = self.params.setdefault(key, set())
        s.update(n for n in names if n)

    def to_data(self) -> dict:
        """Structured data cho inventory (_DATA_INGEST['crawler']) — determinis-*"""
        return {
            "url": self.url,
            "pages": [{"url": p.url, "status": p.status,
                       "content_type": p.content_type, "depth": p.depth}
                      for p in self.pages],
            "links": sorted(self.links),
            "external_links": sorted(self.external_links),
            "forms": [{"action": f.action, "method": f.method,
                       "params": list(f.params), "fields": list(f.fields),
                       "source": f.source} for f in self.forms],
            "params": [{"url": k, "params": sorted(v)}
                       for k, v in sorted(self.params.items())],
            "scripts": sorted(self.scripts),
            "external_scripts": sorted(self.external_scripts),
            "js_hints": [{"kind": h.kind, "url": h.url,
                          "method": h.method or "UNKNOWN",
                          "in_scope": h.in_scope, "source": h.source}
                         for h in self.hints],
            "errors": list(self.errors),
            "stats": {
                "pages_fetched": len(self.pages),
                "links_found": len(self.links),
                "forms_found": len(self.forms),
                "params_found": sum(len(v) for v in self.params.values()),
                "scripts_found": len(self.scripts),
                "hints_found": len(self.hints),
                "external_count": len(self.external_links)
                + len(self.external_scripts) + len(self.redirect_out),
                "stopped": self.stopped,
                "elapsed": round(self.elapsed, 2),
            },
        }

    def render(self, scope_short: bool = True) -> str:
        """Output text gọn cho model (bounded)."""
        scope = self.scope if scope_short else ""
        L = []
        L.append(f"[✓] CRAWL XONG {self.url} — {len(self.pages)} trang "
                 f"({round(self.elapsed, 2)}s, dừng: {self.stopped})")
        pg = self.pages[:_RENDER_CAPS["pages"]]
        for p in pg:
            L.append(f"  GET {_short(p.url, scope)} → {p.status} "
                     f"({p.content_type or '-'}, depth {p.depth})")
        if len(self.pages) > len(pg):
            L.append(f"  … (+{len(self.pages) - len(pg)} trang nữa)")
        if self.links:
            items = sorted(self.links)[:_RENDER_CAPS["links"]]
            L.append("links (internal): " +
                     ", ".join(_short(x, scope) for x in items))
            if len(self.links) > len(items):
                L[-1] += f" … (+{len(self.links) - len(items)})"
        if self.external_links or self.external_scripts or self.redirect_out:
            n = (len(self.external_links) + len(self.external_scripts)
                 + len(self.redirect_out))
            L.append(f"external/in-scope-skip: {n} item (không crawl) "
                     f"— ngoài scope hoặc redirect ra ngoài")
        if self.forms:
            forms = self.forms[:_RENDER_CAPS["forms"]]
            for f in forms:
                ps = ",".join(f.params) or "-"
                L.append(f"form: {f.method} {_short(f.action, scope)} "
                         f"params={ps} (src {_short(f.source, scope)})")
            if len(self.forms) > len(forms):
                L.append(f"  … (+{len(self.forms) - len(forms)} form nữa)")
        if self.params:
            items = sorted(self.params.items())[:_RENDER_CAPS["params"]]
            L.append("params: " + "; ".join(
                f"{_short(k, scope)} → {','.join(sorted(v))}"
                for k, v in items))
            if len(self.params) > len(items):
                L[-1] += f" … (+{len(self.params) - len(items)} endpoint nữa)"
        if self.scripts:
            items = sorted(self.scripts)[:_RENDER_CAPS["scripts"]]
            L.append("scripts: " + ", ".join(_short(x, scope) for x in items))
            if len(self.scripts) > len(items):
                L[-1] += f" … (+{len(self.scripts) - len(items)})"
        if self.hints:
            items = self.hints[:_RENDER_CAPS["hints"]]
            L.append("js_hints (ỨNG VIÊN — cần xác minh, chưa phải endpoint "
                     "thật): " + "; ".join(
                f"{h.kind} {h.method or 'UNKNOWN'} {_short(h.url, scope)} "
                f"({'in-scope' if h.in_scope else 'out-scope'})" for h in items))
            if len(self.hints) > len(items):
                L[-1] += f" … (+{len(self.hints) - len(items)})"
        if self.errors:
            items = self.errors[:_RENDER_CAPS["errors"]]
            L.append("errors: " + " ; ".join(items))
            if len(self.errors) > len(items):
                L[-1] += f" … (+{len(self.errors) - len(items)})"
        else:
            L.append("errors: (none)")
        return "\n".join(L)


# ─────────────────────────────────────────────
# HTML ANALYSIS (html.parser — hermetic, unit-test được)
# ─────────────────────────────────────────────

class _HtmlAnalyzer(HTMLParser):
    """Một lần duyệt HTML: gom link/form/script/js-hint. Resolution dùng
    <base href> nếu có (hiệu lực tại thời điểm gặp thẻ)."""

    def __init__(self, base_url: str, scope: str, same_scope: bool = True):
        super().__init__(convert_charrefs=True)
        self.base_url = norm_url(base_url) or base_url
        self.scope = scope
        self.same_scope = same_scope
        self.base_href: str | None = None
        self.links: set[str] = set()
        self.external_links: set[str] = set()
        self.scripts: set[str] = set()
        self.external_scripts: set[str] = set()
        self.forms: list[FormSpec] = []
        self.hints: list[JsHint] = []
        self._form_open: FormSpec | None = None
        self._select_field: dict | None = None
        self._script_buf: str | None = None

    # ── helpers ──
    def _eff_base(self) -> str:
        if self.base_href:
            return urljoin(self.base_url, self.base_href)
        return self.base_url

    def _resolve(self, href: str) -> str:
        href = (href or "").strip()
        if not href or href.startswith("#"):
            return ""
        m = _SKIP_SCHEMES.match(href)
        if m and m.group(0).rstrip(":").lower() not in ("http", "https"):
            return ""
        return norm_url(urljoin(self._eff_base(), href))

    def _add_link(self, href: str) -> None:
        n = self._resolve(href)
        if not n:
            return
        if self.same_scope and not is_same_scope(n, self.scope):
            self.external_links.add(n)
        else:
            self.links.add(n)

    def _add_script(self, src: str) -> None:
        n = self._resolve(src)
        if not n:
            return
        if self.same_scope and not is_same_scope(n, self.scope):
            self.external_scripts.add(n)
        else:
            self.scripts.add(n)

    def _flush_hints(self, text: str) -> None:
        for kind, rx, m_fn in _HINT_PATTERNS:
            for m in rx.finditer(text):
                raw = (m.group("url") or "").strip()
                if not raw or raw.startswith("#"):
                    continue
                n = norm_url(urljoin(self._eff_base(), raw))
                if not n:
                    continue
                self.hints.append(JsHint(
                    kind=kind, url=n, method=m_fn(m, text),
                    in_scope=not self.same_scope
                    or is_same_scope(n, self.scope),
                    source=self.base_url))

    # ── overrides ──
    def handle_starttag(self, tag: str, attrs: list) -> None:  # noqa: N802
        d = dict(attrs)
        if tag in ("a", "area", "link"):
            if d.get("href"):
                self._add_link(d["href"])
        elif tag == "iframe" and d.get("src"):
            self._add_link(d["src"])
        elif tag == "base" and d.get("href"):
            self.base_href = d["href"]
        elif tag == "form":
            self._form_open = FormSpec(
                action=(d.get("action") or "").strip() or self.base_url,
                method=(d.get("method") or "get").upper() or "GET",
                source=self.base_url)
            self.forms.append(self._form_open)
        elif tag == "input":
            if self._form_open and d.get("name"):
                self._form_open.fields.append({
                    "name": d["name"], "type": d.get("type") or "text",
                    "value": d.get("value") or ""})
        elif tag == "textarea":
            if self._form_open and d.get("name"):
                self._form_open.fields.append({
                    "name": d["name"], "type": "textarea",
                    "value": d.get("value") or ""})
        elif tag == "select":
            if self._form_open and d.get("name"):
                self._select_field = {
                    "name": d["name"], "type": "select",
                    "value": d.get("value") or "", "options": []}
                self._form_open.fields.append(self._select_field)
        elif tag == "option":
            if self._select_field is not None:
                opt = d.get("value") or ""
                if opt:
                    self._select_field.setdefault("options", []).append(opt)
        elif tag == "button":
            if self._form_open and d.get("name"):
                self._form_open.fields.append({
                    "name": d["name"], "type": "button",
                    "value": d.get("value") or ""})
        elif tag == "script":
            if d.get("src"):
                self._add_script(d["src"])
            else:
                self._script_buf = ""

    def handle_endtag(self, tag: str) -> None:  # noqa: N802
        if tag == "form":
            self._form_open = None
        elif tag == "select":
            self._select_field = None
        elif tag == "script" and self._script_buf is not None:
            self._flush_hints(self._script_buf)
            self._script_buf = None

    def handle_data(self, data: str) -> None:  # noqa: N802
        if self._script_buf is not None:
            self._script_buf += data


def parse_html(html: str, base_url: str, same_scope: bool = True):
    """Phân tích HTML string (bất kỳ nguồn nào) — dùng cho unit test và crawl.
    Trả _HtmlAnalyzer đã duyệt xong (fields: links/external_links/scripts/
    forms/hints). scope tự suy từ base_url."""
    a = _HtmlAnalyzer(base_url, scope_key(base_url), same_scope=same_scope)
    for chunk in _chunks(html or "", 65536):   # feed theo chunk — bounded
        a.feed(chunk)
    a.close()
    for f in a.forms:
        f.action = norm_url(urljoin(a._eff_base(), f.action)) or f.action
        seen: set[str] = set()
        for fd in f.fields:
            name = fd.get("name") or ""
            if name and name not in seen:
                seen.add(name)
                f.params.append(name)
        fd2 = [dict(x) for x in f.fields]
        for x in fd2:
            x.pop("options", None)
        f.fields = fd2
    return a


def _chunks(s: str, n: int):
    for i in range(0, len(s), n):
        yield s[i:i + n]


# ─────────────────────────────────────────────
# CRAWL (BFS qua Session Engine)
# ─────────────────────────────────────────────

def _fetch_page(he_mod, url: str, scope: str, same_scope: bool,
                timeout: float, headers: dict | None,
                max_redirects: int = 5):
    """GET url qua engine (record=False — không làm ô nhiễm ring buffer
    evidence). Theo redirect Thủ CÔNG: mỗi hop một request; hop ra ngoài
    scope KHÔNG theo. Trả (final_resp, final_url_norm, redirect_out|None)."""
    cur = url
    hops = 0
    while True:
        resp, _rec = he_mod.session_for(cur).request(
            "get", cur, headers=headers, follow_redirects=False,
            timeout=timeout, record=False)
        if (resp.status_code in _REDIRECT_STATUS and hops < max_redirects
                and (resp.headers.get("Location")
                     or resp.headers.get("location"))):
            loc = (resp.headers.get("Location")
                   or resp.headers.get("location") or "").strip()
            nxt = norm_url(urljoin(cur, loc))
            if nxt and (not same_scope or is_same_scope(nxt, scope)):
                cur = nxt
                hops += 1
                continue
            if nxt:
                return resp, norm_url(cur), (resp.status_code, nxt)
        return resp, norm_url(cur), None


def crawl(start_url: str, *, max_depth: int = 3, max_pages: int = 100,
          max_body_bytes: int = 2_000_000, same_scope: bool = True,
          delay: float = 0.0, timeout: float = 30.0,
          time_budget: float | None = None,
          headers: dict | None = None, max_redirects: int = 5) -> CrawlResult:
    """BFS crawl GET-only. start_url bắt buộc http(s) hợp lệ (ValueError nếu
    không). Mọi lỗi request từng trang được gom vào errors — không ném ra."""
    start = norm_url(start_url)
    if not start:
        raise ValueError("URL gốc không hợp lệ (cần http/https).")
    scope = scope_key(start)
    result = CrawlResult(url=start, scope=scope, same_scope=same_scope)
    t0 = time.monotonic()
    deadline = t0 + time_budget if time_budget else None
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    enqueued = {start}
    fetched: set[str] = set()
    n_req = 0
    hdrs = dict(headers) if headers else None

    while queue:
        if len(result.pages) >= max_pages:
            result.stopped = "max_pages"
            break
        if deadline is not None and time.monotonic() >= deadline:
            result.stopped = "time_budget"
            break
        url, depth = queue.popleft()
        if url in fetched or depth > max_depth:
            continue
        if delay and n_req:
            time.sleep(delay)
        n_req += 1
        try:
            resp, final_url, redir_out = _fetch_page(
                he, url, scope, same_scope, float(timeout), hdrs, max_redirects)
        except Exception as e:  # noqa: BLE001 — crawl phải chịu được trang lỗi
            result.errors.append(f"{_short(url, scope)} — "
                                 f"{e.__class__.__name__}: {e}")
            continue
        if final_url in fetched:
            continue
        fetched.add(final_url)
        ct = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        result.pages.append(PageRecord(url=final_url, status=resp.status_code,
                                       content_type=ct, depth=depth))
        result._add_params(final_url)
        if redir_out:
            result.redirect_out.append(redir_out)
            continue
        if ct not in _HTML_TYPES or not resp.content:
            continue
        body = resp.content[:max_body_bytes].decode("utf-8", "replace")
        try:
            analysis = parse_html(body, final_url, same_scope=same_scope)
        except Exception as e:  # noqa: BLE001 — HTMLParser hiếm fail, không chặn crawl
            result.errors.append(f"{_short(final_url, scope)} — parse fail: {e}")
            continue
        result.links |= analysis.links
        result.external_links |= analysis.external_links
        result.scripts |= analysis.scripts
        result.external_scripts |= analysis.external_scripts
        result.hints.extend(analysis.hints)
        for f in analysis.forms:
            f.source = final_url
            result.forms.append(f)
            result._add_params(f.action, f.params)
        for ln in analysis.links:
            result._add_params(ln)
            if (ln not in fetched and ln not in enqueued
                    and depth + 1 <= max_depth and not _static_ext(ln)):
                enqueued.add(ln)
                queue.append((ln, depth + 1))

    result.elapsed = round(time.monotonic() - t0, 3)
    return result