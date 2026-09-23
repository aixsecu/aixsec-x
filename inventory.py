#!/usr/bin/env python3
"""aixsec-x — inventory.py
Attack Surface Inventory (v1.7.0) — AIXSEC-X roadmap Phase 1 hoàn chỉnh:
#1 Attack Surface, #12 attack memory (TestHistory), #13 adaptive selection,
kèm structured ToolResult + evidence provenance.

Ý tưởng: sau mỗi round, agent gom kết quả THẬT của phiên vào MỘT inventory
thống nhất: host → service(port/scheme) → endpoint → method → parameter →
auth → tech, kèm provenance (source + evidence CHO TỪNG observation).

v1.7.0 (Phase 1 — 5 điểm chính):
1. STRUCTURED TOOLRESULT — tool tự sinh (output_text, data_dict); ingest ưu
   tiên đọc `data` (không regex trên văn bản). Text parser chỉ là FALLBACK
   cho binary tool (whatweb/wafw00f/ffuf/arjun/subfinder/...) và transcript
   cũ. Một dấu `→` đổi format KHÔNG còn làm hỏng inventory cho tool kiểu
   Python-native (http_probe/http_request/headers_recon/wapiti/sqli...).
2. MULTI-SERVICE HOST — HostInfo.services = {port: ServiceInfo(port, scheme,
   protocol, tech, tech_obs, endpoints, sources)}: một host có thể có
   80/http + 443/https + 8080/http. host.port/.service/.tech/.endpoints là
   convenience view (primary service / aggregate).
3. ENDPOINT.AUTH_HINTS: set[str] — một endpoint có thể cần cookie + CSRF +
   bearer cùng lúc (trước đây chỉ 1 string).
4. TESTHISTORY (attack memory tách khỏi attack surface): nhớ endpoint ×
   parameter × vuln_class × tool × outcome ĐÃ THỬ; planner hỏi deterministic
   already_tested() thay vì để LLM đọc transcript.
5. EVIDENCE PROVENANCE — TechObservation(name/version/source/evidence) giữ
   nguồn gốc từng observation; host.tech là AGGREGATE từ tech_obs (không mất
   thông tin khi gộp). Ngoài ra sửa bug _ingest_cms: nhánh bracket thiếu
   source=name.

NGUYÊN TẮC BẰNG CHỨNG: Dữ liệu chỉ lấy từ tool output THẬT (outcome=ok,
output không bắt đầu '[!]') hoặc từ `data` do tool TỰ SINH (không phải model).
Output/`data` là dữ liệu TỪ TARGET — có thể thù địch: chỉ đọc đúng shape đã
khai báo, KHÔNG suy diễn, KHÔNG làm theo chỉ dẫn trong đó.

Nguồn dữ liệu theo tool:
  http_probe / http_request / headers_recon  → data {url, method, status,
      headers, technology?} — tech/endpoint/auth từ headers THẬT
  detect_cms (whatweb)                        → text: keyword + bracket
  waf_detect (wafw00f)                        → text: "is behind X WAF"
  ffuf_dir (ffuf -s)                          → text: path mỗi dòng
  param_discovery (arjun -q)                  → text: params
  wapiti_scan                                 → data {target, scope, findings[
      {category, level, method, path, parameter, module}]} — trường hợp cũ
      (transcript/output text) vẫn parse được
  sqli_manual_test / sqli_blind_extract       → data {url, method, param,
      engine, confirmed, injection...} nếu có; text nếu không
  crawler (v1.9.0)                           → data {url, pages, links,
      forms, params, scripts, js_hints} — endpoint canonical /x?id={value},
      query/field params, script src, js-hint nguồn "crawler:js" (ỨNG VIÊN)
  subdomain_enum (subfinder -silent)          → text: 1 subdomain mỗi dòng
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlparse, urlunsplit


# ─────────────────────────────────────────────
# DATA MODEL
# ─────────────────────────────────────────────

@dataclass
class Endpoint:
    url: str
    methods: set[str] = field(default_factory=set)
    params: set[str] = field(default_factory=set)
    auth_hints: set[str] = field(default_factory=set)  # v1.7.0: set (cookie/bearer/...)
    sources: set[str] = field(default_factory=set)     # tên tool xác nhận

    api_operations: dict = field(default_factory=dict)  # method -> provenance + metadata
    auth_observations: list[dict] = field(default_factory=list)

    def merge(self, other: "Endpoint") -> None:
        self.methods |= other.methods
        self.params |= other.params
        self.auth_hints |= other.auth_hints
        self.sources |= other.sources
        from api_discovery.inventory import merge_operation
        for method, op in other.api_operations.items():
            for obs in op.get("observations", []):
                merge_operation(self, {**obs, "method": method})
        for observation in other.auth_observations:
            if observation not in self.auth_observations:
                self.auth_observations.append(observation)


@dataclass
class TechObservation:
    """Một observation công nghệ — event thô (non-destructive, có provenance)."""
    name: str
    version: str = ""
    source: str = ""          # tool nào thấy
    evidence: str = ""        # bằng chứng cụ thể (vd 'header:X-Powered-By',
                              # 'whatweb: PHP[8.1.22]', 'Set-Cookie: PHPSESSID')


@dataclass
class ServiceInfo:
    """Một service (port + scheme/protocol) của host. v1.7.0."""
    port: str
    scheme: str               # http | https (web); tương lai: ssh | mysql | ...
    protocol: str = ""        # == scheme với web; để dành non-web (nmap...)
    tech: dict[str, str] = field(default_factory=dict)      # AGGR: {name: version}
    tech_obs: list[TechObservation] = field(default_factory=list)  # provenance
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    sources: set[str] = field(default_factory=set)

    def add_tech_obs(self, obs: TechObservation) -> None:
        """Thêm observation CHƯA TỪNG CÓ (dedupe theo name/version/source/
        evidence) + cập nhật aggregate: version từ observation đầu tiên có
        version (không đè version đã có bằng rỗng)."""
        for o in self.tech_obs:
            if (o.name == obs.name and o.version == obs.version
                    and o.source == obs.source and o.evidence == obs.evidence):
                return
        self.tech_obs.append(obs)
        if obs.name not in self.tech or (not self.tech[obs.name] and obs.version):
            self.tech[obs.name] = obs.version


@dataclass
class HostInfo:
    host: str
    services: dict[str, ServiceInfo] = field(default_factory=dict)  # key: port
    auth_hints: set[str] = field(default_factory=set)  # host-level aggregate
    sources: set[str] = field(default_factory=set)

    # ── convenience views (multi-service) ──
    def primary(self) -> ServiceInfo | None:
        """Service 'chính': port nhỏ nhất (numeric), non-numeric đứng sau."""
        if not self.services:
            return None
        key = sorted(self.services,
                     key=lambda p: (int(p) if p.isdigit() else 10 ** 9, p))[0]
        return self.services[key]

    @property
    def port(self) -> str:
        s = self.primary()
        return s.port if s else ""

    @property
    def service(self) -> str:      # scheme service chính (http/https)
        s = self.primary()
        return s.scheme if s else ""

    @property
    def tech(self) -> dict[str, str]:
        """AGGREGATE tech trên mọi service."""
        agg: dict[str, str] = {}
        for s in self.services.values():
            for k, v in s.tech.items():
                if k not in agg or (not agg[k] and v):
                    agg[k] = v
        return agg

    @property
    def tech_obs(self) -> list[TechObservation]:
        return [o for s in self.services.values() for o in s.tech_obs]

    @property
    def endpoints(self) -> dict[str, Endpoint]:
        """Flatten endpoint trên mọi service (URL là key duy nhất toàn cục)."""
        out: dict[str, Endpoint] = {}
        for s in self.services.values():
            out.update(s.endpoints)
        return out

    def add_endpoint(self, url: str) -> Endpoint:
        url = _norm_url(url)
        svc = self.service_for_url(url)
        ep = svc.endpoints.get(url)
        if ep is None:
            ep = Endpoint(url=url)
            svc.endpoints[url] = ep
        return ep

    def service_for_url(self, url: str) -> ServiceInfo:
        """Chọn service theo (scheme, port) của URL; fallback primary."""
        svc = _service_match(self, url)
        return svc if svc is not None else self.primary()


_MAX_RENDER_LINES = 24   # tránh tràn context khi chèn vào message lượt sau


class Inventory:
    """Attack surface tích lũy trong một phiên. KHÔNG tự suy diễn gì."""

    def __init__(self):
        self.hosts: dict[str, HostInfo] = {}
        self.dns_only: set[str] = set()      # subdomain từ subfinder — chưa probe
        self.analysis: dict = {}             # Phase 3 plans/hypotheses/correlations

    # ── ingest ──
    def ingest(self, calls: list[dict]) -> int:
        """calls: [{name, args, outcome, output, data?}] (transcript/results).
        v1.7.0: ưu tiên `data` cấu trúc do tool tự sinh; nếu không có (binary
        tool / transcript cũ) thì fallback text parser. Chỉ xử lý outcome=ok
        + output không mở đầu '[!]'. Trả số mục đã xử lý (không phải số mục
        mới — dùng cho log/instrumentation)."""
        n_new = 0
        for c in calls or []:
            name = str(c.get("name") or "")
            if name in {"zap_baseline", "zap_active_scan"} and c.get("outcome") in {"ok", "partial", "timeout"}:
                for url in (c.get("data") or {}).get("endpoints", []):
                    host = self.ensure_web(url, name)
                    if host:
                        self.add_endpoint(host, url, method="UNKNOWN", source=name)
                        n_new += 1
                for alert in (c.get("data") or {}).get("alerts", []):
                    host = self.ensure_web(alert.get("url", ""), name)
                    if host:
                        ep = self.add_endpoint(host, alert["url"], method=alert.get("method", "UNKNOWN"), source=name)
                        if alert.get("parameter"):
                            ep.params.add(alert["parameter"])
                continue
            if c.get("outcome") != "ok":
                continue
            args = c.get("args") or {}
            data = c.get("data")
            if isinstance(data, dict):
                fn = _DATA_INGEST.get(name)
                if fn is not None:
                    n_new += fn(self, name, args, data)
                    from api_discovery.inventory import ingest_existing
                    ingest_existing(self, name, data)
                    continue
            out = str(c.get("output") or "")
            if out.lstrip().startswith("[!]"):
                continue
            fn = _PARSERS.get(name)
            if fn is not None:
                n_new += fn(self, name, args, out)
        return n_new

    # ── host helpers ──
    def host(self, url: str) -> HostInfo | None:
        h = _url_host(url)
        return self.hosts.get(h) if h else None

    def ensure_web(self, url: str, source: str = "") -> HostInfo | None:
        """Đăng ký host web (http/https) từ URL có bằng chứng thật. Tạo
        ServiceInfo theo port (mặc định 80/443 theo scheme) — nhiều service
        cho một host (v1.7.0)."""
        m = re.match(r"^(https?)://([^/?#]+)", (url or "").strip())
        if not m:
            return None
        scheme, netloc = m.group(1), m.group(2)
        netloc = netloc.split("@")[-1].lower().strip(".")
        host_part, port = _split_netloc(netloc, scheme)
        host = self.hosts.get(host_part)
        if host is None:
            host = HostInfo(host=host_part)
            self.hosts[host_part] = host
        if port not in host.services:
            host.services[port] = ServiceInfo(port=port, scheme=scheme,
                                              protocol=scheme)
        if source:
            host.sources.add(source)
            host.services[port].sources.add(source)
        return host

    def service_for(self, host: HostInfo, url: str) -> ServiceInfo | None:
        """ServiceInfo của URL (khớp host + port); None nếu không khớp host."""
        return _service_match(host, url)

    def add_endpoint(self, host: HostInfo, url: str, method: str = "",
                     param: str = "", auth: str = "", source: str = "") -> Endpoint:
        ep = host.add_endpoint(url)
        if method:
            ep.methods.add(method.upper())
        if param:
            ep.params.add(param)
        if auth:
            ep.auth_hints.add(auth)   # v1.7.0: set
        if source:
            ep.sources.add(source)
            host.sources.add(source)
            svc = host.service_for_url(url)
            svc.sources.add(source)
        return ep

    def add_tech(self, host: HostInfo, name: str, version: str = "",
                 source: str = "", evidence: str = "",
                 service: ServiceInfo | None = None) -> None:
        """Ghi MỘT technology observation (provenance giữ nguyên) và cập nhật
        aggregate. service=None → service chính của host."""
        name = (name or "").strip().lower()
        if not name or host is None:
            return
        svc = service if service is not None else host.primary()
        if svc is None:
            return
        svc.add_tech_obs(TechObservation(name=name, version=version or "",
                                         source=source or "", evidence=evidence or ""))
        if source:
            host.sources.add(source)
            svc.sources.add(source)

    # ── render ──
    def render(self, limit: int = _MAX_RENDER_LINES) -> str:
        """Block compact cho prompt lượt sau. Label tiếng Việt, chỉ dữ liệu thật."""
        if not self.hosts and not self.dns_only:
            return ""
        out = ["[ATTACK SURFACE]"]
        for hk in sorted(self.hosts):
            h = self.hosts[hk]
            auth_s = f" auth={','.join(sorted(h.auth_hints))}" if h.auth_hints else ""
            for port in sorted(h.services,
                               key=lambda p: (int(p) if p.isdigit() else 10 ** 9, p)):
                s = h.services[port]
                tech_s = ", ".join(f"{t}{(' ' + v) if v else ''}"
                                   for t, v in sorted(s.tech.items())) or "-"
                out.append(f"  {hk}:{s.port} ({s.scheme}) tech=[{tech_s}]"
                           f"{auth_s} src={','.join(sorted(s.sources)) or '-'}")
                for url in sorted(s.endpoints):
                    ep = s.endpoints[url]
                    m = ",".join(sorted(ep.methods)) or "-"
                    p = f" params={','.join(sorted(ep.params))}" if ep.params else ""
                    a = (f" auth={','.join(sorted(ep.auth_hints))}"
                         if ep.auth_hints else "")
                    s_ = (f" [{','.join(sorted(ep.sources)) or '-'}]"
                          if ep.sources else "")
                    out.append(f"    {m} {url}{p}{a}{s_}" +
                               (f" api={','.join(sorted(ep.api_operations))}" if ep.api_operations else "") +
                               (f" auth_obs={len(ep.auth_observations)}" if ep.auth_observations else ""))
                    if len(out) >= limit:
                        break
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
            "version": 1,
            "hosts": [
                {
                    "host": h.host,
                    "services": [
                        {
                            "port": s.port, "scheme": s.scheme,
                            "protocol": s.protocol,
                            "tech": dict(sorted(s.tech.items())),
                            "tech_obs": [
                                {"name": o.name, "version": o.version,
                                 "source": o.source, "evidence": o.evidence}
                                for o in s.tech_obs
                            ],
                            "sources": sorted(s.sources),
                            "endpoints": [
                                {"url": e.url, "methods": sorted(e.methods),
                                 "params": sorted(e.params),
                                 "auth_hints": sorted(e.auth_hints),
                                 "sources": sorted(e.sources),
                                 "api_operations": e.api_operations,
                                 "auth_observations": e.auth_observations}
                                for e in sorted(s.endpoints.values(),
                                                key=lambda e: e.url)
                            ],
                        }
                        for port in sorted(h.services,
                                           key=lambda p: (int(p) if p.isdigit()
                                                          else 10 ** 9, p))
                        for s in [h.services[port]]
                    ],
                    "auth_hints": sorted(h.auth_hints),
                    "sources": sorted(h.sources),
                }
                for h in sorted(self.hosts.values(), key=lambda h: h.host)
            ],
            "dns_only": sorted(self.dns_only),
            "analysis": self.analysis,
        }

    def api_inventory(self) -> list[dict]:
        """Canonical operation view for planners; legacy URL/query view is retained."""
        return [{"url": e.url, "method": method, **operation}
                for h in sorted(self.hosts.values(), key=lambda h: h.host)
                for e in sorted(h.endpoints.values(), key=lambda e: e.url)
                for method, operation in sorted(e.api_operations.items())]

    def auth_inventory(self) -> list[dict]:
        """Factual auth comparisons for Phase 3 authorization reasoning."""
        return [{"url": e.url, **observation}
                for h in sorted(self.hosts.values(), key=lambda h: h.host)
                for e in sorted(h.endpoints.values(), key=lambda e: e.url)
                for observation in e.auth_observations]

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: str) -> "Inventory":
        inv = cls()
        with open(path) as f:
            data = json.load(f)
        for hd in data.get("hosts", []):
            host = HostInfo(host=hd["host"],
                            auth_hints=set(hd.get("auth_hints") or []),
                            sources=set(hd.get("sources") or []))
            svcs = hd.get("services")
            if svcs:   # v1.7.0 schema
                for sd in svcs:
                    svc = ServiceInfo(port=str(sd.get("port", "")),
                                      scheme=sd.get("scheme", ""),
                                      protocol=sd.get("protocol", "") or
                                      sd.get("scheme", ""),
                                      sources=set(sd.get("sources") or []))
                    for od in sd.get("tech_obs") or []:
                        svc.add_tech_obs(TechObservation(
                            name=od.get("name", ""), version=od.get("version", ""),
                            source=od.get("source", ""),
                            evidence=od.get("evidence", "")))
                    # fallback: schema cũ có tech dict mà không có tech_obs
                    if not svc.tech_obs:
                        for t, v in (sd.get("tech") or {}).items():
                            svc.add_tech_obs(TechObservation(
                                name=t, version=v, source="legacy", evidence=""))
                    for ed in sd.get("endpoints", []):
                        url = ed["url"] if ed.get("api_operations") else _norm_url(ed["url"])
                        svc.endpoints[url] = Endpoint(
                            url=url,
                            methods=set(ed.get("methods") or []),
                            params=set(ed.get("params") or []),
                            auth_hints=set(ed.get("auth_hints")
                                           or ([ed["auth_hint"]]
                                               if ed.get("auth_hint") else [])),
                            sources=set(ed.get("sources") or []),
                            api_operations=ed.get("api_operations") or {},
                            auth_observations=ed.get("auth_observations") or [])
                    if svc.port:
                        host.services[svc.port] = svc
                        _recompute_tech(svc)
            else:      # v1.6.0 flat schema — synthesize một service
                port = str(hd.get("port") or "")
                scheme = str(hd.get("service") or "http")
                if not port:
                    port = "443" if scheme == "https" else "80"
                svc = ServiceInfo(port=port, scheme=scheme, protocol=scheme,
                                  sources=set(hd.get("sources") or []))
                for t, v in (hd.get("tech") or {}).items():
                    svc.add_tech_obs(TechObservation(name=t, version=v,
                                                     source="legacy", evidence=""))
                ends = hd.get("endpoints") or []
                for ed in ends:
                    url = ed["url"] if ed.get("api_operations") else _norm_url(ed["url"])
                    svc.endpoints[url] = Endpoint(
                        url=url, methods=set(ed.get("methods") or []),
                        params=set(ed.get("params") or []),
                        auth_hints=set(ed.get("auth_hints")
                                       or ([ed["auth_hint"]]
                                           if ed.get("auth_hint") else [])),
                        sources=set(ed.get("sources") or []),
                        api_operations=ed.get("api_operations") or {},
                        auth_observations=ed.get("auth_observations") or [])
                host.services[port] = svc
            inv.hosts[host.host] = host
        inv.dns_only = set(data.get("dns_only") or [])
        inv.analysis = data.get("analysis") if isinstance(data.get("analysis"), dict) else {}
        return inv


# ─────────────────────────────────────────────
# TEST HISTORY — attack memory (v1.7.0, #12)
# ─────────────────────────────────────────────

@dataclass
class TestRecord:
    """Một lần 'đã thử' — attack memory, không phải finding (chưa chắc có lỗi)."""
    endpoint: str
    parameter: str = ""
    vuln_class: str = ""     # sqli | xss | ssti | traversal | scan | recon | poc
    tool: str = ""
    outcome: str = ""        # ok | error | denied | blocked | duplicate | ...
    ts: float = 0.0
    evidence_id: str = ""    # liên kết finding/evidence (Phase 2 evidence state machine)


class TestHistory:
    """Attack memory: nhớ cái GÌ ĐÃ THỬ (endpoint × parameter × vuln_class ×
    tool × outcome) để planner hỏi deterministic already_tested() thay vì để
    LLM đọc transcript. Tách khỏi AttackSurface (cái ĐÃ BIẾT vs cái ĐÃ THỬ)."""

    def __init__(self):
        self.records: list[TestRecord] = []
        self._seen: set[tuple] = set()

    def add(self, endpoint: str, parameter: str = "", vuln_class: str = "",
            tool: str = "", outcome: str = "", evidence_id: str = "") -> bool:
        """Ghi một lần thử (dedupe theo endpoint/param/class/tool/outcome).
        Trả True nếu là record mới."""
        ep = _norm_url(endpoint)
        if not ep:
            return False
        key = (ep, parameter or "", vuln_class or "", tool or "", outcome or "")
        if key in self._seen:
            return False
        self._seen.add(key)
        self.records.append(TestRecord(endpoint=ep, parameter=parameter or "",
                                       vuln_class=vuln_class or "",
                                       tool=tool or "", outcome=outcome or "",
                                       ts=time.time(), evidence_id=evidence_id or ""))
        return True

    def already_tested(self, endpoint: str, parameter: str = "",
                       vuln_class: str = "") -> bool:
        """Planner query: endpoint này + (param) + (vuln class) đã thử chưa?
        - parameter rỗng → khớp mọi record của endpoint (+class nếu cho);
        - parameter có giá trị → chỉ khớp record CÙNG param (record không có
          param — vd recon probe — không tính là đã test param đó)."""
        ep = _norm_url(endpoint)
        if not ep:
            return False
        for r in self.records:
            if r.endpoint != ep:
                continue
            if vuln_class and r.vuln_class != vuln_class:
                continue
            if parameter and r.parameter != parameter:
                continue
            return True
        return False

    def tested_classes(self, endpoint: str, parameter: str = "") -> set[str]:
        ep = _norm_url(endpoint)
        if not ep:
            return set()
        return {r.vuln_class for r in self.records
                if r.endpoint == ep
                and (not parameter or r.parameter == parameter)}

    def record_count(self) -> int:
        return len(self.records)

    def render(self, limit: int = 12) -> str:
        """Block compact cho prompt lượt sau — newest first."""
        if not self.records:
            return ""
        out = ["[TEST HISTORY — đã thử, KHÔNG lặp lại; thay vì test lại, "
               "chọn endpoint/param/lớp lỗ hổng mới hoặc không gọi tool nữa]"]
        for r in reversed(self.records[-limit:]):
            p = f" param={r.parameter}" if r.parameter else ""
            out.append(f"  [{r.vuln_class or '?'}] {r.endpoint}{p}"
                       f" — {r.tool} ({r.outcome or '?'})")
        return "\n".join(out)


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


def _split_netloc(netloc: str, scheme: str) -> tuple[str, str]:
    """(host, port) — port mặc định 80/443 theo scheme nếu URL không ghi rõ."""
    head, _, tail = netloc.rpartition(":")
    if tail.isdigit():
        return head, tail
    return netloc, ("443" if scheme == "https" else "80")


def _service_match(host: HostInfo, url: str) -> ServiceInfo | None:
    """ServiceInfo khớp (host, scheme+port) của URL; None nếu khác host."""
    m = re.match(r"^(https?)://([^/?#]+)", (url or "").strip())
    if not m:
        return None
    scheme, netloc = m.group(1), m.group(2)
    host_part, port = _split_netloc(netloc.split("@")[-1].lower().strip("."),
                                    scheme)
    if host_part != host.host:
        return None
    return host.services.get(port)


def _recompute_tech(svc: ServiceInfo) -> None:
    """Dựng lại aggregate tech từ tech_obs (dùng sau load)."""
    svc.tech = {}
    for o in svc.tech_obs:
        if o.name not in svc.tech or (not svc.tech[o.name] and o.version):
            svc.tech[o.name] = o.version


# ─────────────────────────────────────────────
# STRUCTURED DATA INGEST (v1.7.0 — ưu tiên)
# ─────────────────────────────────────────────

def _ingest_data_http(inv: Inventory, name: str, args: dict, data: dict) -> int:
    """http_probe / http_request / headers_recon — data {url, method, status,
    headers, technology?}: không regex, đọc thẳng shape tool tự sinh."""
    url = _norm_url(str(data.get("url") or args.get("url") or ""))
    host = inv.ensure_web(url, name)
    if host is None:
        return 0
    method = str(data.get("method") or "get").upper()
    ep = inv.add_endpoint(host, url, method=method, source=name)
    n = 0
    # v1.8.0: redirect final_url (# http_request theo follow_redirects) — URL
    # cuối (site khác hoặc path khác) được ghi endpoint riêng để attack surface
    # phản ánh đúng nơi response THẬT tới. KHÔNG copy headers/tech (đó là của
    # response cuối thật: nếu final_url cùng host thì headers đã được áp qua
    # ensure_web/add_endpoint phía trên; khác host → ghi host+endpoint, header
    # của redirect target sẽ được thu khi có request trực tiếp tới nó).
    furl = str(data.get("final_url") or "")
    if furl and _norm_url(furl) != url:
        fhost = inv.ensure_web(furl, name)
        if fhost is not None:
            inv.add_endpoint(fhost, furl, method="GET", source=name)
            n += 1
    for k, v in (data.get("headers") or {}).items():
        if _apply_header(inv, host, url, str(k), str(v), name,
                         service=inv.service_for(host, url)):
            n += 1
    for tech in data.get("technology") or []:
        tech = str(tech).strip()
        if not tech:
            continue
        canon, ver = _tech_value(tech)
        inv.add_tech(host, canon, ver, source=name,
                     evidence=f"technology:{tech}",
                     service=inv.service_for(host, url))
        n += 1
    return n or 1


def _ingest_data_wapiti(inv: Inventory, name: str, args: dict, data: dict) -> int:
    target = str(data.get("target") or args.get("url") or "")
    host = inv.ensure_web(target, name)
    if host is None:
        return 0
    n = 0
    for f in data.get("findings") or []:
        if not isinstance(f, dict):
            continue
        path = str(f.get("path") or "")
        if not path:
            continue
        full = target.rstrip("/") + (path if path.startswith("/") else "/" + path)
        ep = inv.add_endpoint(host, full, method=str(f.get("method") or "GET"),
                              source=name)
        p = str(f.get("parameter") or "")
        if p:
            ep.params.add(p)
        n += 1
    return n


def _crawl_canon(url: str) -> str:
    """Canonical endpoint shape từ URL crawl: giá trị query → {value}
    (/product.php?id=1&x=2 → /product.php?id={value}&x={value}). Giữ
    scheme+host+path, lowercase scheme/host. '' nếu không phải URL tuyệt
    đối. Không percent-encode badge — inventory render đọc được."""
    u = urlparse((url or "").strip())
    if not u.scheme or not u.netloc:
        return ""
    names = [k for k, _ in parse_qsl(u.query, keep_blank_values=True)]
    q = "&".join(f"{k}={{value}}" for k in names) if names else ""
    return urlunsplit((u.scheme.lower(), u.netloc.lower(), u.path or "/", q, ""))


def _query_names(url: str) -> list[str]:
    """Tên query param (thứ tự xuất hiện, dedup) của URL crawl."""
    out: list[str] = []
    seen: set[str] = set()
    for k, _ in parse_qsl(urlparse((url or "").strip()).query,
                          keep_blank_values=True):
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _ingest_data_crawler(inv: Inventory, name: str, args: dict, data: dict) -> int:
    """crawler (v1.9.0) — data {url, pages[], links[], forms[], params[],
    scripts[], js_hints[]}: gom attack surface từ crawl GET-only (không có
    text parser — tool Python-native, data cấu trúc luôn có).
      - pages    → endpoint raw (URL cuối đã GET thật)
      - links    → endpoint CANONICAL /path?id={value} + tên query param
      - forms    → action + method + field name (params)
      - params   → bổ sung tên query param theo canonical key của crawler
      - scripts  → endpoint (tài nguyên JS — chưa fetch)
      - js_hints → endpoint nguồn "crawler:js" — CHỈ in-scope (ỨNG VIÊN,
        chưa phải endpoint thật; nguồn tag riêng để AI biết cần xác minh);
        method THẬT từ hint (axios.verb/xhr.open/fetch GET); UNKNOWN → methods
        rỗng, KHÔNG gán GET bừa (v1.9.1)
    external_links/external_scripts/redirect_out: KHÔNG thêm (ngoài scope)."""
    url = _norm_url(str(data.get("url") or args.get("url") or ""))
    host = inv.ensure_web(url, name)
    if host is None:
        return 0
    n = 0
    for p in data.get("pages") or []:
        if not isinstance(p, dict):
            continue
        pu = _norm_url(str(p.get("url") or ""))
        if not pu:
            continue
        inv.add_endpoint(host, pu, method="GET", source=name)
        n += 1
    for u in data.get("links") or []:
        u = _norm_url(str(u or ""))
        if not u:
            continue
        canon = _crawl_canon(u)
        if not canon:
            continue
        ep = inv.add_endpoint(host, canon, method="GET", source=name)
        for qn in _query_names(u):
            ep.params.add(qn)
        n += 1
    for f in data.get("forms") or []:
        if not isinstance(f, dict):
            continue
        fa = _norm_url(str(f.get("action") or ""))
        if not fa:
            continue
        ep = inv.add_endpoint(host, fa, method=str(f.get("method") or "GET"),
                              source=name)
        for pname in f.get("params") or []:
            if pname:
                ep.params.add(str(pname))
        n += 1
    for item in data.get("params") or []:
        if not isinstance(item, dict):
            continue
        cu = _norm_url(str(item.get("url") or ""))
        if not cu:
            continue
        ep = inv.add_endpoint(host, cu, method="GET", source=name)
        for pn in item.get("params") or []:
            if pn:
                ep.params.add(str(pn))
        n += 1
    for u in data.get("scripts") or []:
        u = _norm_url(str(u or ""))
        if not u:
            continue
        inv.add_endpoint(host, u, method="GET", source=name)
        n += 1
    for h in data.get("js_hints") or []:
        if not isinstance(h, dict) or not h.get("in_scope"):
            continue
        hu = _norm_url(str(h.get("url") or ""))
        if not hu:
            continue
        # v1.9.1: method THẬT từ hint (axios.verb/xhr.open/fetch GET). UNKNOWN
        # hoặc thiếu → KHÔNG gán GET bừa (endpoint methods rỗng — review:
        # "UNKNOWN tốt hơn việc gán sai GET").
        hm = str(h.get("method") or "").strip().upper()
        if hm in ("", "UNKNOWN"):
            hm = ""
        inv.add_endpoint(host, hu, method=hm, source=name + ":js")
        n += 1
    return n


def _ingest_data_sqli(inv: Inventory, name: str, args: dict, data: dict) -> int:
    if not data.get("confirmed") and data.get("verdict") != "CONFIRMED":
        return 0
    url = _norm_url(str(data.get("url") or args.get("url") or ""))
    host = inv.ensure_web(url, name)
    if host is None:
        return 0
    method = str(data.get("method") or args.get("method") or "get").upper()
    param = str(data.get("param") or args.get("param") or "")
    inv.add_endpoint(host, url, method=method, param=param, source=name)
    return 1


from api_discovery.inventory import ingest as _ingest_api_discovery


def _ingest_auth_compare(inv: Inventory, name: str, args: dict, data: dict) -> int:
    """Store factual per-context responses. No IDOR/BOLA classification here."""
    url = str(data.get("url") or "")
    method = str(data.get("method") or "GET").upper()
    host = inv.ensure_web(url, name)
    if host is None:
        return 0
    ep = inv.add_endpoint(host, url, method=method, source=name)
    observation = {
        "method": method,
        "contexts": list(data.get("contexts") or []),
        "observations": list(data.get("observations") or []),
        "comparisons": list(data.get("comparisons") or []),
        "interpretation": "facts_only",
    }
    if observation not in ep.auth_observations:
        ep.auth_observations.append(observation)
    return 1

_DATA_INGEST = {
    "api_discovery": _ingest_api_discovery,
    "api_import": _ingest_api_discovery,
    "auth_compare": _ingest_auth_compare,
    "http_probe": _ingest_data_http,
    "http_request": _ingest_data_http,
    "headers_recon": _ingest_data_http,
    "crawler": _ingest_data_crawler,
    "wapiti_scan": _ingest_data_wapiti,
    "sqli_manual_test": _ingest_data_sqli,
    "sqli_blind_extract": _ingest_data_sqli,
}


# ─────────────────────────────────────────────
# TEXT PARSERS — fallback cho binary tool / transcript cũ
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
    "haproxy": "haproxy", "envoy": "envoy", "httpserver": "httpserver",
}

# whatweb in kiểu "HTTPServer[nginx/1.24.0]", "PHP[8.1.22]" — v1.7.0: với
# HTTPServer, tên tech lấy từ VALUE (nginx/1.24.0 → nginx, version 1.24.0)
_TECH_BRACKET = re.compile(
    r"(HTTPServer|PHP|Apache|nginx|OpenResty|LiteSpeed|Microsoft-IIS|IIS|"
    r"WordPress|Joomla|Drupal|Magento|PrestaShop|OpenCart|Laravel|Django|"
    r"Rails|Express|ASP\.NET|Spring|Caddy|Tomcat|JBoss|Node\.js|Python)"
    r"\[([A-Za-z0-9][0-9A-Za-z_.+/-]*)\]")

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

_AUTH_SCHEMES = {"basic", "bearer", "digest", "ntlm", "negotiate"}


def _tech_value(raw: str) -> tuple[str, str]:
    """'nginx/1.24.0' → ('nginx', '1.24.0'); 'PHP' → ('php', '')."""
    raw = (raw or "").strip()
    head, _, tail = raw.partition("/")
    if "/" in raw and tail:
        return _canon_tech(raw), tail[:64]
    return _canon_tech(raw), ""


def _canon_tech(name: str) -> str:
    first = name.split("/", 1)[0].strip().lower()
    return _TECH_KEYWORDS.get(first, first)


def _apply_header(inv: Inventory, host: HostInfo, url: str, key: str,
                  val: str, source: str,
                  service: ServiceInfo | None = None) -> bool:
    """Một header → tech/auth observation. Trả True nếu tạo observation mới.
    v1.7.0: evidence ghi rõ header nguồn (provenance)."""
    key_l = key.strip().lower()
    val = (val or "").strip()
    changed = False
    if key_l == "server":
        canon = _canon_tech(val)
        ver = val.split("/", 1)[1] if "/" in val else ""
        inv.add_tech(host, canon, ver, source,
                     evidence=f"header:{key.strip()}",
                     service=service)
        changed = True
    elif key_l == "x-powered-by":
        canon = _canon_tech(val)
        ver = val.split("/", 1)[1] if "/" in val else ""
        # nếu cùng tech với Server (vd php) thì chỉ lưu version nếu Server không có
        if not any(o.name == canon and o.version for o in
                   (service or host.primary()).tech_obs):
            inv.add_tech(host, canon, ver, source,
                         evidence=f"header:{key.strip()}",
                         service=service)
            changed = True
    elif key_l == "set-cookie":
        host.auth_hints.add("cookie")
        changed = True
        cname = val.split("=", 1)[0].lower()
        if "phpsessid" in cname:
            inv.add_tech(host, "php", source=source,
                         evidence="Set-Cookie: PHPSESSID", service=service)
        elif "jsessionid" in cname:
            inv.add_tech(host, "java", source=source,
                         evidence="Set-Cookie: JSESSIONID", service=service)
        elif "asp.net_sessionid" in cname:
            inv.add_tech(host, "asp.net", source=source,
                         evidence="Set-Cookie: ASP.NET_SessionId", service=service)
    elif key_l == "www-authenticate":
        scheme = val.split(" ", 1)[0].lower()
        if scheme in _AUTH_SCHEMES:
            host.auth_hints.add(scheme)
            changed = True
    return changed


def _tech_from_http(inv: Inventory, host: HostInfo, url: str, out: str,
                    source: str) -> None:
    """Đọc headers theo 3 format: dict-repr (http_probe) / '  K: v' (http_request)
    / 'K: v' (headers_recon). v1.7.0: service theo URL để provenance đúng service."""
    svc = inv.service_for(host, url) or host.primary()
    m = _HDR_DICT_RE.search(out)
    if m:
        for km in re.finditer(r"'([^']+)':\s*'([^']*)'", m.group(1)):
            _apply_header(inv, host, url, km.group(1), km.group(2), source, svc)
    for hm in _HDR_LINE_RE.finditer(out):
        _apply_header(inv, host, url, hm.group(1), hm.group(2), source, svc)


def _probe(inv: Inventory, host: HostInfo, out: str, source: str,
           url_hint: str = "") -> Endpoint | None:
    m = _RESP_LINE.match(out.strip())
    if not m:
        return None
    method, url = m.group(1), m.group(2)
    _tech_from_http(inv, host, url, out, source)
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
    """v1.7.0 (bug fix review): nhánh bracket TRUYỀN source=name (trước đây để
    trống — provenance không nhất quán với nhánh keyword). HTTPServer[x] lấy
    tên tech từ VALUE. Evidence = token whatweb gốc."""
    host = _host_of(inv, str(args.get("url") or ""), name)
    if host is None:
        return 0
    low = out.lower()
    for kw, canon in _TECH_KEYWORDS.items():
        if kw in low and kw != "httpserver":
            inv.add_tech(host, canon, source=name, evidence=f"whatweb:{kw}")
    svc = host.primary()
    for m in _TECH_BRACKET.finditer(out):
        label, val = m.group(1), m.group(2)
        if label.lower() == "httpserver":
            canon, ver = _tech_value(val)
        else:
            canon = _TECH_KEYWORDS.get(label.lower(), label.lower())
            ver = val
        inv.add_tech(host, canon, ver, source=name,
                     evidence=f"whatweb:{m.group(0)}", service=svc)
    return 0


def _ingest_waf(inv: Inventory, name: str, args: dict, out: str) -> int:
    host = _host_of(inv, str(args.get("url") or ""), name)
    if host is None:
        return 0
    m = _WAF_RE.search(out)
    if m:
        inv.add_tech(host, f"waf:{m.group(1).strip()}",
                     source=name, evidence=m.group(0))
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
