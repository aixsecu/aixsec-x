#!/usr/bin/env python3
"""
aixsec-x — http_engine.py
HTTP Session Engine (Phase 2, v1.8.1) — tầng HTTP có TRẠNG THÁI cho toàn agent:
cookie jar theo host, GET/POST/HEAD/PUT/PATCH/DELETE/OPTIONS, query params,
form-urlencoded/JSON/raw/multipart body, custom headers, basic/bearer/API-key
auth, redirect history, request/response timing, raw evidence, request replay,
proxy.

Kiến trúc (ChatGPT Phase 2 roadmap — "Làm HTTP Session Engine trước"):
    AI → http_request tool → HTTP Session Engine → requests.Session
Crawler (bước tiếp theo của Phase 2) sẽ REUSE engine này — KHÔNG tồn tại HTTP
implementation thứ hai trong dự án.

Phiên (Session) được tách theo netloc host:port (port mặc định theo scheme) để
cookie của host này KHÔNG rò sang host khác; reset_sessions() cô lập mỗi phiên
chạy/test. Mọi response đọc qua getattr-defensive nên engine chịu được
stub/FakeResp trong test hermetic (không cần network thật).

Design notes:
- Body precedence: files→multipart, json_body→JSON, form→form-urlencoded,
  body/data→raw (đúng thứ tự ưu tiên Phase 2 roadmap).
- RequestRecord: ring buffer MAX_RECORDS=20 — replay không cần lưu request thủ
  công; evidence dict redact giá trị auth (chỉ giữ kind + user/name header).
- v1.8.1: redact_headers/redact_cookies che authorization/cookie/api-key trên
  MỌI evidence/log (chủ động, không chỉ phụ thuộc auth parse); RequestSpec lưu
  ý định GỐC (pre-auth) để replay áp auth đúng 1 lần; session key gồm scheme
  (scheme://host:port) cô lập http/https cùng port.
- v1.9.1: EvidenceRedactor thống nhất redaction — headers/cookies/params/form/
  JSON body/URL (url, final_url, history) cùng cơ chế: field nhạy cảm
  (password/token/secret/api_key/...) KEY GIỮ, VALUE che <redacted>; bản COPY
  thuần, body gốc record/replay KHÔNG đổi; add_sensitive_field đăng ký theo
  instance. API redact_headers/redact_cookies v1.8.1 giữ nguyên (ủy quyền).
- Proxy: SessionManager cấp phát proxy đồng loạt (set_proxies) — http_request
  + crawler sau này dùng chung cấu hình WEBX_HTTP_PROXY/WEBX_HTTPS_PROXY.
"""
from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunsplit

import requests

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0"
# v1.8.0: mở rộng so với v1.5.6 (get|post|head|put|options) — thêm patch|delete
METHODS: tuple = ("get", "post", "head", "put", "options", "patch", "delete")
MAX_RECORDS = 20      # ring buffer cho request replay
MAX_BODY_SNIP = 2000  # body snippet (output text + evidence) — bounded như cũ
MAX_HISTORY = 10      # redirect history tối đa giữ trong data/evidence

# ── v1.8.1: header/cookie redaction — mọi evidence/log che giá trị nhạy cảm ──
REDACT_MASK = "<redacted>"
SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key",
})
_COOKIE_ATTRS = frozenset({
    "path", "domain", "max-age", "expires", "samesite", "secure", "httponly",
})
_extra_sensitive: set = set()
_redact_lock = threading.Lock()

# v1.9.1: field nhạy cảm mặc định trong JSON/form body + query params (KEY giữ,
# VALUE che <redacted>). Khớp theo tên chuẩn hóa (lowercase) hoặc hậu tố
# '_<field>' (access_token, _token, api_key...) — xem EvidenceRedactor._is_sensitive.
_SENSITIVE_FIELDS = frozenset((
    "password", "passwd", "pwd", "pass", "secret", "token",
    "access_token", "refresh_token", "client_secret", "api_key", "apikey",
))


def _norm_field(name: Any) -> str:
    """Tên field chuẩn hóa để so khớp nhạy cảm: lowercase + bỏ khoảng trắng."""
    return str(name or "").strip().lower()


def add_sensitive_header(name: str) -> None:
    """Đăng ký header nhạy cảm bổ sung (case-insensitive, tự config) — ngoài
    SENSITIVE_HEADERS mặc định còn che được x-token/session/... của khách."""
    n = str(name or "").strip().lower()
    if n:
        with _redact_lock:
            _extra_sensitive.add(n)


def _mask_header_value(key: str, val: Any) -> str:
    """Che giá trị theo loại header:
      - cookie/set-cookie: che từng value cặp name=value, GIỮ name + attr không
        bí mật (Path/Domain/Max-Age/Expires/SameSite/Secure/HttpOnly) — inventory
        vẫn dò được cookie-name prefix (PHPSESSID/JSESSIONID/ASP.NET...) và log
        vẫn đọc được cấu trúc mà không lộ giá trị.
      - headers nhạy cảm khác: che TOÀN BỘ giá trị."""
    if val is None:
        return REDACT_MASK
    k = str(key or "").strip().lower()
    if k in ("cookie", "set-cookie"):
        parts = []
        for pair in str(val).split(";"):
            pair = pair.strip()
            if not pair:
                continue
            name, sep, _ = pair.partition("=")
            name = name.strip()
            if not sep:
                parts.append(name)
            elif name.lower() in _COOKIE_ATTRS:
                parts.append(pair)
            else:
                parts.append(f"{name}={REDACT_MASK}")
        return "; ".join(parts)
    return REDACT_MASK


class EvidenceRedactor:
    """v1.9.1: redaction THỐNG NHẤT cho evidence — headers, cookies, query params,
    form-urlencoded, JSON body và URL. Tất cả method đều trả BẢN COPY (không
    mutate dữ liệu gốc: record/replay/body giữ nguyên). Field nhạy cảm mặc định
    trong _SENSITIVE_FIELDS (password/token/api_key/secret/...); mỗi instance có
    thể đăng ký thêm field riêng qua add_sensitive_field (không ảnh hưởng
    instance khác / redactor mặc định).

    Quy ước che: KEY GIỮ (AI còn biết tên field/param), VALUE thay bằng
    REDACT_MASK — cùng nguyên tắc v1.8.1 (cookie/header giữ name, che value)."""

    def __init__(self, sensitive_fields=None):
        self._fields: set = set(sensitive_fields or _SENSITIVE_FIELDS)

    def add_sensitive_field(self, name: str) -> None:
        """Đăng ký thêm field nhạy cảm cho RIÊNG instance này (vd 'session_id')."""
        n = _norm_field(name)
        if n:
            self._fields.add(n)

    def _is_sensitive(self, key: str, extra: tuple = ()) -> bool:
        """Khớp tên chuẩn hóa (lowercase) hoặc hậu tố '_<field>' — bắt được
        _token, access_token, refresh_token... mà không cần liệt kê mọi biến thể.
        extra: tên bổ sung theo ngữ cảnh request (vd param apiquery của auth)."""
        n = _norm_field(key)
        if not n:
            return False
        if any(n == f or n.endswith("_" + f) for f in self._fields):
            return True
        return any(n == _norm_field(x) for x in extra)

    def redact_headers(self, headers) -> dict:
        """Bản COPY headers đã che value nhạy cảm: SENSITIVE_HEADERS +
        _extra_sensitive (đăng ký toàn cục) + field của instance._fields
        (vd header 'X-Token') — case-insensitive, KHÔNG mutate dict gốc."""
        out: dict = {}
        for k, v in (headers or {}).items():
            key = str(k)
            if (key.lower() in SENSITIVE_HEADERS
                    or key.lower() in _extra_sensitive
                    or self._is_sensitive(key)):
                out[key] = _mask_header_value(key, v)
            else:
                out[key] = v
        return out

    def redact_cookies(self, cookies) -> dict:
        """Bản COPY dict cookie đã che value (giữ name) — dùng cho evidence/log."""
        return {str(k): REDACT_MASK for k in (cookies or {})}

    def redact_params(self, params, extra: tuple = ()) -> Any:
        """Bản COPY query params đã che value field nhạy cảm.

        Giữ nguyên *shape* của input để evidence không làm mất duplicate params:
        dict -> dict; list/tuple[(name, value)] -> list[(name, value)]. Điều này
        quan trọng với multi-value params / HTTP Parameter Pollution (vd
        ``id=1&id=2``). None -> {} để giữ tương thích với hành vi cũ.
        extra: tên param bổ sung theo ngữ cảnh (vd apiquery auth name).
        """
        if params is None:
            return {}
        if isinstance(params, dict):
            return {str(k): (REDACT_MASK if self._is_sensitive(str(k), extra) else v)
                    for k, v in params.items()}

        out: list = []
        for k, v in params:
            key = str(k)
            out.append((key, REDACT_MASK if self._is_sensitive(key, extra) else v))
        return out

    def redact_form(self, form, extra: tuple = ()) -> Any:
        """Bản COPY form-urlencoded đã che field nhạy cảm và giữ duplicate
        field khi input là list/tuple[(name, value)]."""
        return self.redact_params(form, extra)

    def redact_json(self, obj, extra: tuple = ()) -> Any:
        """Bản COPY deep JSON body: key nhạy cảm → value che <redacted> (key giữ);
        dict/list đệ quy; kiểu khác giữ nguyên. KHÔNG mutate obj gốc."""
        if isinstance(obj, dict):
            return {str(k): (REDACT_MASK if self._is_sensitive(k, extra)
                             else self.redact_json(v, extra))
                    for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.redact_json(x, extra) for x in obj]
        return obj

    def redact_url(self, url: str, extra: tuple = ()) -> str:
        """URL với value của query param nhạy cảm che <redacted> (giữ scheme/
        host/path/tên param/fragment). URL không parse được → trả nguyên bản."""
        u_raw = str(url or "")
        try:
            u = urlparse(u_raw)
        except ValueError:
            return u_raw
        if not u.query:
            return u_raw
        pairs = parse_qsl(u.query, keep_blank_values=True)
        new_q = urlencode(
            [(k, REDACT_MASK) if self._is_sensitive(k, extra) else (k, v)
             for k, v in pairs],
            safe="<>")
        return urlunsplit((u.scheme, u.netloc, u.path, new_q, u.fragment))


# redactor mặc định dùng chung cho mọi evidence (lazy singleton — agent chạy
# tuần tự nên không cần lock tinh vi; vẫn giữ lock cho an toàn đa luồng test).
_DEFAULT_REDACTOR: Optional[EvidenceRedactor] = None
_DEFAULT_REDACTOR_LOCK = threading.Lock()


def _default_redactor() -> EvidenceRedactor:
    global _DEFAULT_REDACTOR
    if _DEFAULT_REDACTOR is None:
        with _DEFAULT_REDACTOR_LOCK:
            if _DEFAULT_REDACTOR is None:
                _DEFAULT_REDACTOR = EvidenceRedactor()
    return _DEFAULT_REDACTOR


def redact_headers(headers) -> dict:
    """API v1.8.1 giữ nguyên — ủy quyền cho EvidenceRedactor mặc định."""
    return _default_redactor().redact_headers(headers)


def redact_cookies(cookies) -> dict:
    """API v1.8.1 giữ nguyên — ủy quyền cho EvidenceRedactor mặc định."""
    return _default_redactor().redact_cookies(cookies)


def parse_auth(spec: Any) -> Optional[dict]:
    """Chuỗi auth → dict cấu hình (None nếu sai định dạng). Hỗ trợ:
      'basic:user:pass'     → HTTP Basic (Authorization: Basic ...)
      'bearer:token'        → Authorization: Bearer <token>
      'api_key:name:value'  → header <name>: <value> (API key qua header)
      'apiquery:name:value' → query param <name>=<value> (API key qua query)
    Phân tách maxsplit=2 nên pass/token/secret chứa ':' vẫn giữ nguyên phần
    còn lại ('basic:u:p:a:ss' → user=u, pass='p:a:ss')."""
    if not isinstance(spec, str):
        return None
    parts = spec.split(":", 2)
    kind = parts[0].strip().lower()
    if kind == "basic" and len(parts) == 3 and parts[1] and parts[2] is not None:
        return {"kind": "basic", "user": parts[1], "pass": parts[2]}
    if kind == "bearer" and len(parts) == 2 and parts[1]:
        return {"kind": "bearer", "token": parts[1]}
    if kind == "api_key" and len(parts) == 3 and parts[1] and parts[2] is not None:
        return {"kind": "api_key", "name": parts[1].strip(), "value": parts[2]}
    if kind == "apiquery" and len(parts) == 3 and parts[1] and parts[2] is not None:
        return {"kind": "apiquery", "name": parts[1].strip(), "value": parts[2]}
    return None


@dataclass
class HttpResponse:
    """Response view của engine — mọi field đọc THẬN TRỌNG (getattr fallback)
    để không crash khi gặp stub/FakeResp trong test hermetic (chỉ có
    status_code/headers/text/content)."""
    url: str
    method: str
    status_code: int
    headers: dict
    text: str
    content: bytes
    elapsed: float          # giây (server-reported nếu có)
    history: list           # [{"url", "status", "headers"}...] — redirect chain
    cookies: dict           # Set-Cookie của response cuối
    request_url: str
    request_headers: dict
    reason: str
    body_snippet: str

    @classmethod
    def from_response(cls, r, url: str, method: str) -> "HttpResponse":
        status = getattr(r, "status_code", 0)
        hdrs = getattr(r, "headers", None) or {}
        hdrs = {str(k): str(v) for k, v in hdrs.items()}
        text = getattr(r, "text", "")
        if not isinstance(text, str):
            text = str(text)
        content = getattr(r, "content", b"") or b""
        if not isinstance(content, bytes):
            content = str(content).encode("utf-8", "replace")
        elapsed_raw = getattr(r, "elapsed", None)
        elapsed = 0.0
        if elapsed_raw is not None:
            secs = getattr(elapsed_raw, "total_seconds", None)
            try:
                elapsed = float(secs()) if callable(secs) else float(elapsed_raw)
            except (TypeError, ValueError):
                elapsed = 0.0
        history = []
        for h in (getattr(r, "history", None) or []):
            hh = getattr(h, "headers", None) or {}
            history.append({
                "url": getattr(h, "url", "") or "",
                "status": getattr(h, "status_code", 0) or 0,
                "headers": {str(k): str(v) for k, v in hh.items()},
            })
        cookies_raw = getattr(r, "cookies", None)
        cookies = {}
        if cookies_raw is not None:
            try:
                cookies = {str(k): str(v) for k, v in cookies_raw.items()}
            except Exception:  # noqa: BLE001 — stub lạ → không crash
                cookies = {}
        req = getattr(r, "request", None)
        request_url = getattr(req, "url", "") if req is not None else ""
        # requests đặt URL cuối (sau redirect chain) ở r.url — KHÔNG phải URL
        # request ban đầu; fallback về request url khi gặp stub thiếu attr.
        final_url = getattr(r, "url", "") or url
        req_headers = getattr(req, "headers", None) if req is not None else None
        request_headers = redact_headers(
            {str(k): str(v) for k, v in req_headers.items()}
            if req_headers is not None else {})
        reason = str(getattr(r, "reason", "") or "")
        body_snip = re.sub(r"\s+", " ", text)[:MAX_BODY_SNIP]
        return cls(url=final_url, method=method, status_code=status, headers=hdrs,
                   text=text, content=content, elapsed=elapsed, history=history,
                   cookies=cookies, request_url=request_url,
                   request_headers=request_headers, reason=reason,
                   body_snippet=body_snip)


@dataclass
class RequestSpec:
    """Ý định request GỐC do caller cung cấp — headers/params PRE-MERGE và
    PRE-AUTH (chưa UA mặc định, chưa Authorization/API-key). Replay (v1.8.1)
    dựng lại request từ spec rồi để request() áp auth đúng MỘT lần — tránh
    double-apply khi headers/params trong record đã bị merge/auth.
    body lưu theo body_kind như RequestRecord.body; multipart là
    [(field, name, path)] để replay mở lại file (path có thể đổi)."""
    method: str
    url: str
    headers: Optional[dict] = None
    params: Optional[dict] = None
    body_kind: str = "none"
    body: Any = None
    auth: Optional[str] = None
    cookies: Optional[dict] = None
    follow_redirects: bool = True
    timeout: float = 30.0


@dataclass
class RequestRecord:
    """Bản ghi request+response đầy đủ — evidence raw cho finding + dữ liệu để
    replay (ring buffer MAX_RECORDS). body lưu theo body_kind:
      raw→str, form→dict, json→object gốc, multipart→[(field, name, path)].
    v1.8.1: spec = ý định GỐC (pre-merge/pre-auth) — replay ưu tiên dùng spec
    để KHÔNG double-apply auth; record cũ (spec=None) vẫn replay được (fallback)."""
    id: int
    ts: float
    method: str
    url: str
    headers: dict
    params: dict
    body: Any
    body_kind: str
    auth: Optional[dict]       # parsed (internal, có giá trị)
    auth_spec: Optional[str]   # chuỗi auth gốc — replay parse lại sạch
    cookies: dict
    follow_redirects: bool
    timeout: float
    elapsed: float             # wall-clock (giây)
    response: Optional[HttpResponse]
    error: str = ""
    spec: Optional[RequestSpec] = None   # v1.8.1: ý định gốc trước merge/auth

    def evidence_dict(self) -> dict:
        """Evidence bounded (body ≤ MAX_BODY_SNIP) — giá trị auth KHÔNG lộ:
        chỉ kind (+ user cho basic, name cho api_key/apiquery); v1.8.1 mọi
        header/cookie NHẠY CẢM bị che <redacted> (redact_headers/redact_cookies);
        v1.9.1 EvidenceRedactor thống nhất thêm: field nhạy cảm (password/token/
        api_key/secret/...) trong JSON body, form body, query params và URL
        (url/final_url/history) đều che value <redacted> (KEY GIỮ); body GỐC
        của record KHÔNG bị mutate (redactor trả bản copy)."""
        red = _default_redactor()
        # apiquery: tên param auth theo yêu cầu request — che thêm trong params/URL
        # (requests ghép auth value vào query → final_url có thể chứa secret).
        extra_sensitive: tuple = ()
        if self.auth and self.auth.get("kind") == "apiquery" \
                and self.auth.get("name"):
            extra_sensitive = (self.auth["name"],)
        body_ev = ""
        if self.body_kind == "json" and self.body is not None:
            body_ev = json.dumps(red.redact_json(self.body, extra_sensitive),
                                 ensure_ascii=False)[:MAX_BODY_SNIP]
        elif self.body_kind == "form" and self.body:
            body_ev = json.dumps(red.redact_form(self.body, extra_sensitive),
                                 ensure_ascii=False)[:MAX_BODY_SNIP]
        elif self.body_kind == "multipart":
            body_ev = "; ".join(f"{f[0]}={f[1]}" for f in (self.body or []))
        elif self.body_kind == "raw" and self.body:
            body_ev = str(self.body)[:MAX_BODY_SNIP]
        auth_ev = None
        if self.auth:
            auth_ev = {"kind": self.auth["kind"]}
            if self.auth["kind"] == "basic":
                auth_ev["user"] = self.auth["user"]
            elif self.auth["kind"] in ("api_key", "apiquery"):
                auth_ev["name"] = self.auth["name"]
        params_ev = red.redact_params(self.params, extra_sensitive)
        ev = {
            "id": self.id, "ts": round(self.ts, 2), "method": self.method,
            "url": red.redact_url(self.url, extra_sensitive),
            "request_headers": red.redact_headers(self.headers),
            "params": params_ev, "body_kind": self.body_kind,
            "body": body_ev, "auth": auth_ev,
            "cookies": red.redact_cookies(self.cookies),
            "follow_redirects": self.follow_redirects,
            "timeout": self.timeout, "elapsed": round(self.elapsed, 2),
        }
        if self.error:
            ev["error"] = self.error
        if self.response is not None:
            ev.update({
                "status": self.response.status_code,
                "response_headers": red.redact_headers(self.response.headers),
                "body_snippet": self.response.body_snippet,
                "cookies_received": red.redact_cookies(self.response.cookies),
                "final_url": red.redact_url(self.response.url, extra_sensitive),
                "history": [{"status": h["status"],
                              "url": red.redact_url(h["url"], extra_sensitive)}
                            for h in self.response.history[:MAX_HISTORY]],
            })
        return ev


class HttpSession:
    """Phiên HTTP theo host — 1 requests.Session (cookie jar + proxy + UA mặc
    định) + ring buffer request records. Agent chạy tuần tự nên không cần lock
    bên trong request() (SessionManager có lock cho việc tạo/tra phiên)."""

    def __init__(self, key: str, proxies: Optional[dict] = None):
        self.key = key
        self.s = requests.Session()
        self.s.headers.setdefault("User-Agent", DEFAULT_UA)
        self.proxies: dict = dict(proxies or {})
        if self.proxies:
            self.s.proxies.update(self.proxies)
        self.records: list[RequestRecord] = []
        self._seq = 0

    # ── proxy ──
    def set_proxies(self, proxies: Optional[dict] = None) -> None:
        self.proxies = dict(proxies or {})
        self.s.proxies.clear()
        if self.proxies:
            self.s.proxies.update(self.proxies)

    # ── auth helpers ──
    @staticmethod
    def _apply_auth(headers: dict, auth: dict, params: dict) -> None:
        kind = auth["kind"]
        if kind == "basic":
            raw = f"{auth['user']}:{auth['pass']}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        elif kind == "bearer":
            headers["Authorization"] = "Bearer " + auth["token"]
        elif kind == "api_key":
            headers[auth["name"]] = auth["value"]
        elif kind == "apiquery":
            params[auth["name"]] = auth["value"]

    @staticmethod
    def _file_tuple(val: Any) -> tuple:
        """Giá trị trong dict files → tuple (name, fileobj[, ctype]) cho requests.
        Chấp nhận: 'path' | ('name','path') | ('name','path','ctype'). Lỗi file
        không tồn tại → ValueError (adapter báo lỗi sạch thay vì traceback)."""
        if isinstance(val, (tuple, list)):
            items = list(val)
            if len(items) == 3:
                src = str(items[1])
                if not os.path.isfile(src):
                    raise ValueError(f"file '{src}' không tồn tại")
                return tuple([str(items[0]), open(src, "rb"), str(items[2])])
            if len(items) == 2:
                src = str(items[1])
                if not os.path.isfile(src):
                    raise ValueError(f"file '{src}' không tồn tại")
                return (str(items[0]), open(src, "rb"))
            raise ValueError(
                f"files tuple cần (name, path[, ctype]) — nhận {len(items)} phần tử")
        if isinstance(val, str):
            if not os.path.isfile(val):
                raise ValueError(f"file '{val}' không tồn tại")
            return (os.path.basename(val), open(val, "rb"))
        raise ValueError(f"files[{val!r}] không hợp lệ — dùng 'path' hoặc (name, path[, ctype])")

    # ── core request ──
    def request(self, method: str, url: str, *, params=None, headers=None,
                body=None, data=None, json_body=None, form=None, files=None,
                auth=None, cookies=None, follow_redirects=True, timeout=30.0,
                record: bool = True) -> tuple[HttpResponse, RequestRecord]:
        """Thực thi 1 request qua requests.Session (cookie jar + proxy + UA mặc
        định). Body precedence: files→multipart, json_body→JSON, form→
        form-urlencoded, body/data→raw — đúng thứ tự Phase 2 roadmap.

        Trả (HttpResponse, RequestRecord). Lỗi requests (ConnectionError/
        Timeout/RequestException...) NÉM RA cho adapter xử lý — giữ nguyên
        thông điệp lỗi chuẩn của tool http_request (output format v1.5.6+).
        ValueError (method/auth/files sai) cũng ném ra để adapter báo "[!] ..."."""
        method = str(method or "get").lower().strip()
        if method not in METHODS:
            raise ValueError(
                f"method phải là {'|'.join(METHODS)} (nhận '{method}').")
        auth_cfg = None
        if auth is not None:
            auth_cfg = parse_auth(auth)
            if auth_cfg is None:
                raise ValueError(
                    "auth phải có dạng basic:user:pass | bearer:token | "
                    "api_key:name:value | apiquery:name:value")
        p = dict(params or {})
        hdrs = dict(self.s.headers)
        hdrs.update({str(k): str(v) for k, v in (headers or {}).items()})
        if auth_cfg:
            self._apply_auth(hdrs, auth_cfg, p)

        body_kind = "none"
        send: dict = {}
        opens: list = []
        try:
            if files:
                body_kind = "multipart"
                send["files"] = []
                for fld, v in files.items():
                    t = self._file_tuple(v)
                    opens.append(t[1])
                    send["files"].append((str(fld), t))
            elif json_body is not None:
                body_kind = "json"
                send["json"] = json_body
            elif form is not None:
                body_kind = "form"
                send["data"] = form
            else:
                raw = body if body is not None else data
                if raw is not None:
                    body_kind = "raw"
                    send["data"] = str(raw)

            t0 = time.time()
            r = self.s.request(
                method.upper(), url, headers=hdrs, params=p,
                cookies=dict(cookies or {}), allow_redirects=follow_redirects,
                timeout=timeout, **send)
            elapsed = round(time.time() - t0, 3)
            resp = HttpResponse.from_response(r, url, method.upper())
        finally:
            # đóng file đã mở cho multipart sau khi request (kể cả redirect) xong
            for fh in opens:
                try:
                    fh.close()
                except Exception:  # noqa: BLE001
                    pass

        if body_kind == "multipart":
            rec_body = [(str(fld), t[0], getattr(t[1], "name", None) or "")
                        for fld, t in (send.get("files") or [])]
        else:
            rec_body = send.get("json") if body_kind == "json" else (
                send.get("data") if body_kind in ("raw", "form") else None)
        # v1.8.1: spec = ý định GỐC (pre-merge/pre-auth) — replay dựng lại
        # request sạch từ đây rồi áp auth đúng 1 lần, không double-apply.
        spec = RequestSpec(
            method=method.upper(), url=url, headers=dict(headers or {}),
            params=dict(params or {}), body_kind=body_kind, body=rec_body,
            auth=auth if isinstance(auth, str) else None,
            cookies=dict(cookies or {}),
            follow_redirects=follow_redirects, timeout=timeout)
        rec = RequestRecord(
            id=self._seq, ts=t0, method=method.upper(), url=url,
            headers=hdrs, params=dict(p), body=rec_body, body_kind=body_kind,
            auth=auth_cfg, auth_spec=auth if isinstance(auth, str)
            else str(auth or ""),
            cookies=dict(cookies or {}), follow_redirects=follow_redirects,
            timeout=timeout, elapsed=elapsed, response=resp, spec=spec)
        self._seq += 1
        if record:
            self.records.append(rec)
            if len(self.records) > MAX_RECORDS:
                del self.records[: len(self.records) - MAX_RECORDS]
        return resp, rec

    # ── replay ──
    def replay(self, rec_id: Optional[int] = None, *, record: bool = True,
               timeout: Optional[float] = None) -> tuple[Optional[HttpResponse], Optional[RequestRecord]]:
        """Replay 1 request từ ring buffer — rec_id=None → record GẦN NHẤT.
        v1.8.1: ưu tiên dựng lại từ rec.spec (ý định GỐC, pre-auth) rồi để
        request() áp auth đúng MỘT lần; record cũ (spec=None) dùng legacy
        fallback từ rec fields. Cookie jar hiện tại vẫn merge vào — phản ánh
        state mới. Trả (None, None) nếu không có record. multipart: mở lại file
        theo path ghi lúc đầu — file đã bị xóa → ValueError."""
        if not self.records:
            return None, None
        rec = self.records[-1] if rec_id is None else next(
            (x for x in reversed(self.records) if x.id == rec_id), None)
        if rec is None:
            return None, None
        kwargs: dict = dict(
            method=rec.method, url=rec.url, record=record,
            follow_redirects=rec.follow_redirects,
            timeout=float(timeout) if timeout is not None else float(rec.timeout))
        if rec.spec is not None:
            spec = rec.spec
            # spec-first: headers/params GỐC (chưa merge UA mặc định, chưa auth)
            if spec.headers:
                kwargs["headers"] = dict(spec.headers)
            if spec.params:
                kwargs["params"] = dict(spec.params)
            if spec.cookies:
                kwargs["cookies"] = dict(spec.cookies)
            if spec.auth:
                kwargs["auth"] = spec.auth
            if spec.body_kind == "json":
                kwargs["json_body"] = spec.body
            elif spec.body_kind == "form":
                kwargs["form"] = dict(spec.body) if isinstance(spec.body, dict) else None
            elif spec.body_kind == "raw":
                kwargs["body"] = spec.body
            elif spec.body_kind == "multipart":
                files = {}
                for fld, name, path in (spec.body or []):
                    if not path or not os.path.isfile(path):
                        raise ValueError(
                            f"replay multipart: file '{path or name}' không còn — "
                            "tạo lại file hoặc gửi request mới")
                    files[fld] = (name, path)
                kwargs["files"] = files
        else:
            # legacy fallback (record trước v1.8.1, spec=None)
            if rec.headers:
                kwargs["headers"] = dict(rec.headers)
            if rec.params:
                kwargs["params"] = dict(rec.params)
            if rec.cookies:
                kwargs["cookies"] = dict(rec.cookies)
            if rec.auth_spec:
                kwargs["auth"] = rec.auth_spec
            if rec.body_kind == "json":
                kwargs["json_body"] = rec.body
            elif rec.body_kind == "form":
                kwargs["form"] = dict(rec.body) if isinstance(rec.body, dict) else None
            elif rec.body_kind == "raw":
                kwargs["body"] = rec.body
            elif rec.body_kind == "multipart":
                files = {}
                for fld, name, path in (rec.body or []):
                    if not path or not os.path.isfile(path):
                        raise ValueError(
                            f"replay multipart: file '{path or name}' không còn — "
                            "tạo lại file hoặc gửi request mới")
                    files[fld] = (name, path)
                kwargs["files"] = files
        return self.request(**kwargs)


class SessionManager:
    """Quản lý phiên theo scheme://host:port — module-level singleton để mọi tool/
    crawler dùng CHUNG cookie jar cho cùng host. Cô lập test qua reset()."""

    def __init__(self, proxies: Optional[dict] = None):
        self._sessions: dict[str, HttpSession] = {}
        self._lock = threading.Lock()
        self.proxies: dict = dict(proxies or {})

    def set_proxies(self, proxies: Optional[dict] = None) -> None:
        self.proxies = dict(proxies or {})
        with self._lock:
            for s in self._sessions.values():
                s.set_proxies(self.proxies)

    def for_url(self, url: str) -> HttpSession:
        key = _session_key(url)
        with self._lock:
            s = self._sessions.get(key)
            if s is None:
                s = HttpSession(key, proxies=self.proxies or None)
                self._sessions[key] = s
            return s

    def reset(self) -> int:
        with self._lock:
            n = len(self._sessions)
            self._sessions = {}
        return n

    def count(self) -> int:
        return len(self._sessions)


_manager = SessionManager()


def _session_key(url: str) -> str:
    """scheme://host:port — cookie của host này KHÔNG rò sang host khác, kể cả
    http/https cùng port (v1.8.1 thêm scheme vào key); port trong key để server
    test (127.0.0.1:port) tách biệt."""
    p = urlparse(url or "")
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower().strip(".")
    port = p.port or (443 if scheme == "https" else 80)
    return f"{scheme}://{host}:{port}"


# ── module-level API (adapter + crawler dùng chung) ──

def session_for(url: str) -> HttpSession:
    """Phiên của url (cookie jar + request records) — dùng CHUNG cho
    http_request tool và crawler (Phase 2 tiếp theo), không implementation thứ 2."""
    return _manager.for_url(url)


def reset_sessions() -> int:
    """Xóa mọi phiên — cookie jar + request records. Gọi đầu mỗi run()/test."""
    return _manager.reset()


def set_proxies(proxies: Optional[dict] = None) -> None:
    """Áp proxy đồng loạt cho mọi phiên (hiện tại + tương lai): {"http": ...,
    "https": ...} từ config WEBX_HTTP_PROXY/WEBX_HTTPS_PROXY. None = thẳng."""
    _manager.set_proxies(proxies)


def get_proxies() -> dict:
    return dict(_manager.proxies)


def session_count() -> int:
    return _manager.count()