#!/usr/bin/env python3
"""
aixsec-x — scope.py
Scope policy: URL/domain/IP-CIDR. Mọi tool call đều phải khớp scope khai báo
(WEBX_TARGETS). Tool parameter URL/host lệch scope → từ chối thực thi.
"""
from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse


_CIDR_RE = re.compile(r"^[0-9a-f.:]+/\d{1,2}$")


def normalize_host(raw: str) -> str:
    """'https://example.com:443/path?x=1' → 'example.com'. Giữ CIDR nguyên."""
    raw = (raw or "").strip().lower()
    if not raw:
        return ""
    if _CIDR_RE.match(raw):
        return raw  # CIDR (vd: 10.0.0.0/8, 2001:db8::/32)
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/")[0] if "/" in raw else raw
    if raw.startswith("["):  # IPv6 [::1]:443
        raw = raw[1:].split("]")[0]
    raw = raw.split(":")[0] if ":" in raw and raw.count(":") == 1 else raw
    return raw.rstrip(".")


class ScopePolicy:
    def __init__(self, allowed: list[str], src_dirs: list[str] | None = None):
        self._raw = [a for a in allowed if a]
        self._cidrs = []
        self.domains = []
        self.src_dirs = [d for d in (src_dirs or []) if d]
        self.src_roots = [os.path.abspath(os.path.expanduser(d)) for d in self.src_dirs]
        for a in self._raw:
            na = normalize_host(a)
            if "/" in na and re.match(r"^[0-9a-f.:]+/\d+$", na):
                try:
                    self._cidrs.append(ipaddress.ip_network(na))
                except ValueError:
                    pass
            else:
                self.domains.append(na)

    @property
    def has_scope(self) -> bool:
        return bool(self._raw)

    def in_scope_host(self, host: str) -> bool:
        h = normalize_host(host)
        if not self._raw:
            return False
        if not h:
            return False
        if h in ("localhost", "127.0.0.1", "::1"):
            return "localhost" in self.domains or "127.0.0.1" in self.domains
        if h in self.domains:
            return True
        if any("." in d and h.endswith("." + d) for d in self.domains):
            return True
        try:
            ip = ipaddress.ip_address(h.split("/")[0])
            return any(ip in net for net in self._cidrs)
        except ValueError:
            return False

    def in_scope_url(self, url: str) -> bool:
        try:
            p = urlparse(url)
        except ValueError:
            return False
        if p.scheme not in ("http", "https"):
            return False
        return self.in_scope_host(p.hostname or "")

    def in_scope(self, value: str) -> bool:
        if value.lower().startswith(("http://", "https://")):
            return self.in_scope_url(value)
        return self.in_scope_host(value)

    def check_param(self, spec_name: str, param_name: str, value) -> str | None:
        v = str(value or "").strip()
        if param_name == "src_path":
            return self._check_src_path(spec_name, v)
        if param_name not in ("host", "url", "target", "hostname"):
            return None
        if not v:
            return f"[SCOPE] {spec_name}.{param_name} rỗng — từ chối."
        if not self.has_scope:
            return ("[SCOPE] Chưa khai báo WEBX_TARGETS — từ chối chạy tool. "
                    "Đặt biến môi trường WEBX_TARGETS với target được ủy quyền.")
        if not self.in_scope(v):
            return (f"[SCOPE] '{v}' ngoài phạm vi {self._raw} — từ chối "
                    f"(tham số {spec_name}.{param_name}).")
        return None

    def _check_src_path(self, spec_name: str, value: str) -> str | None:
        if not value:
            return f"[SCOPE] {spec_name}.src_path rỗng — từ chối."
        if not self.src_roots:
            return ("[SCOPE] Chưa khai báo WEBX_SRC_DIRS — từ chối quét source. "
                    "Đặt biến môi trường WEBX_SRC_DIRS với thư mục code được ủy quyền.")
        p = os.path.abspath(os.path.expanduser(value))
        ok = any(p == root or p.startswith(root + os.sep) for root in self.src_roots)
        if not ok:
            return (f"[SCOPE] '{value}' ngoài phạm vi thư mục nguồn đã khai báo (WEBX_SRC_DIRS) "
                    f"{self.src_dirs} — từ chối (tham số {spec_name}.src_path).")
        return None

    def describe(self) -> str:
        parts = []
        if self._raw:
            parts.append(", ".join(self._raw))
        else:
            parts.append("(chưa khai báo target web — web tools bị khóa)")
        if self.src_dirs:
            parts.append("src: " + ", ".join(self.src_dirs))
        return " | ".join(parts)
