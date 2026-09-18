#!/usr/bin/env python3
"""
aixsec-x — ledger.py
Finding ledger + status machine.
  candidate ──► needs_validation ──► confirmed
      └──────────────► ruled_out

LLM chỉ tạo candidate (giả thuyết). Confirmed chỉ sau vòng xác minh
(validation planner) hoặc operator quyết định — KHÔNG bao giờ do LLM tự chốt.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    name: str
    severity: str = "medium"
    url: str = ""
    port: str = ""
    service: str = ""
    description: str = ""
    fix: str = ""
    cves: list[str] = field(default_factory=list)
    status: str = "candidate"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)

    @property
    def has_evidence_gap(self) -> bool:
        return bool(self.evidence_gaps)

    @property
    def key(self) -> tuple:
        return (self.name.lower(), self.url, self.service.lower())


VALID_TRANSITIONS = {
    "candidate": {"needs_validation", "ruled_out"},
    "needs_validation": {"confirmed", "ruled_out"},
    "confirmed": {"needs_validation"},
    "ruled_out": {"needs_validation"},
}


class Ledger:
    def __init__(self):
        self.findings: dict[tuple, Finding] = {}

    def add(self, f: Finding) -> Finding:
        if f.key in self.findings:
            old = self.findings[f.key]
            old.evidence += [e for e in f.evidence if e not in old.evidence]
            return old
        self.findings[f.key] = f
        return f

    def transition(self, f: Finding, new_status: str) -> bool:
        if new_status not in VALID_TRANSITIONS.get(f.status, set()):
            return False
        f.status = new_status
        return True

    def by_status(self, status: str) -> list[Finding]:
        return [f for f in self.findings.values() if f.status == status]

    def all(self) -> list[Finding]:
        sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(self.findings.values(), key=lambda f: sev.get(f.severity, 5))


def parse_findings_json(text: str) -> list[Finding]:
    t = (text or "").strip()
    if t.startswith("```"):
        t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    try:
        data = json.loads(t)
    except json.JSONDecodeError:
        return []
    out = []
    for item in data.get("findings", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        out.append(Finding(
            name=str(item["name"]),
            severity=str(item.get("severity", "medium")).lower(),
            url=str(item.get("url", "")),
            port=str(item.get("port", "")),
            service=str(item.get("service", "")),
            description=str(item.get("description", "")),
            fix=str(item.get("fix", "")),
            cves=[c for c in item.get("cves", []) if str(c).startswith("CVE-")],
        ))
    return out


def host_of(url: str) -> str:
    """Rút hostname (lower) từ URL; rỗng nếu không phải URL http(s)."""
    m = re.match(r"https?://([^/]+)", (url or "").strip())
    return (m.group(1) if m else "").lower().strip(".")


# Token công nghệ: nếu được khai báo trong finding nhưng không xuất hiện
# nguyên văn trong BẤT KỲ tool output OK nào của host → nghi bịa.
_TECH_TOKENS = [
    "openresty", "nginx", "apache", "iis", "litespeed", "caddy", "varnish",
    "fastly", "cloudflare", "ladi", "express", "tomcat", "jboss",
    "wordpress", "joomla", "drupal", "magento", "shopify", "prestashop",
    "opencart", "laravel", "django", "rails", "spring", "asp.net", "php",
]


def _host_evidence(history: list[dict]) -> dict:
    """history: transcript calls [{name, args, outcome, output}].
    Chỉ dùng kết quả outcome=ok có nội dung thật (bỏ duplicate/blocked/error
    và output bắt đầu bằng '[!]'). Trả {host: {"tools": set, "text": str-lower}}."""
    ev: dict = {}
    for c in history or []:
        if c.get("outcome") != "ok":
            continue
        out = c.get("output") or ""
        if out.lstrip().startswith("[!]"):
            continue
        args = c.get("args") or {}
        u = str(args.get("url") or args.get("host") or "")
        h = host_of(u)
        if not h:
            continue
        e = ev.setdefault(h, {"tools": set(), "text": ""})
        e["tools"].add(str(c.get("name", "")))
        e["text"] += " " + out.lower()
    return ev


def check_findings_evidence(findings: list[Finding], history: list[dict]) -> int:
    """Đối chiếu từng finding với tool output thật của phiên; ghi evidence_gaps.
    Trả số finding bị gắn cờ thiếu bằng chứng. KHÔNG xóa finding — giữ để
    operator tự xác minh, chỉ đánh dấu rõ ràng."""
    ev = _host_evidence(history)
    flagged = 0
    for f in findings or []:
        gaps: list[str] = []
        h = host_of(f.url)
        nd = f"{f.name} {f.description} {f.service}".lower()
        if not f.url:
            gaps.append("finding không có URL — không đối chiếu được bằng chứng")
        elif h not in ev:
            gaps.append(
                f"không có tool output OK nào cho host '{h}' trong phiên này — "
                "mọi chi tiết đều chưa được hỗ trợ")
        else:
            e = ev[h]
            text = e["text"]
            if ("404" in nd or "error page" in nd or "not found page" in nd):
                if "404" not in text:
                    gaps.append("mô tả nói về 404/error page nhưng không tool output "
                                "nào trong phiên cho thấy trạng thái 404 trên host này")
            if "config" in f.name.lower():
                gaps.append("'cấu hình phát hiện được' — toolset không đọc được cấu hình "
                            "server, chỉ thấy banner/headers (không có cơ sở)")
            if "waf" in nd and "waf_detect" not in e["tools"]:
                gaps.append("nhắc đến WAF nhưng chưa chạy waf_detect trên host này")
            for tok in _TECH_TOKENS:
                if tok in nd and tok not in text:
                    gaps.append(f"khai báo công nghệ '{tok}' nhưng token này không xuất hiện "
                                "trong bất kỳ tool output OK nào của host")
                    break
            if not (e["tools"] & {"http_probe", "headers_recon", "detect_cms",
                                  "waf_detect", "_ffuf_dir", "ffuf_dir",
                                  "nikto_scan", "nuclei_scan", "param_discovery",
                                  "subdomain_probe"}):
                gaps.append("host chỉ mới xuất hiện qua subdomain_enum/dns_lookup — "
                            "chưa probe thật (info-only)")
        f.evidence_gaps = gaps
        if gaps:
            flagged += 1
    return flagged


def validation_plan(ledger: Ledger) -> list[dict]:
    """Sinh kế hoạch xác minh cho từng finding chưa confirmed."""
    plan = []
    for f in ledger.by_status("candidate") + ledger.by_status("needs_validation"):
        steps = []
        focus = (f.service or "").split()[-1] if f.service else ""
        if f.cves:
            steps.append(f"Tra cứu {', '.join(f.cves)} và so khớp version/stack thực tế trên {f.url or 'target'}")
        if f.url:
            svc = f" — kỳ vọng service {focus}" if focus else ""
            steps.append(f"Xác minh thủ công (không phụ thuộc nuclei): curl -sSI {f.url}{svc}")
            steps.append("Ghi request/response đối chứng: control vs payload")
        if f.port:
            steps.append(f"Verify cổng/dịch vụ thực tế trên {f.url or 'target'} (vd: curl -skI --max-time 10)")
        if not steps:
            steps.append("Xác minh thủ công với bằng chứng request/response")
        plan.append({"finding": f.name, "url": f.url, "status": f.status,
                     "severity": f.severity, "steps": steps})
    return plan


def render_markdown(ledger: Ledger, target: str, plan: list | None = None) -> str:
    lines = [f"# AIXSEC-X — Web Penetration Report", f"Target: {target}", ""]
    for f in ledger.all():
        lines.append(f"## {f.name} [{f.severity.upper()}] — **{f.status}** (conf {f.confidence:.0%})")
        if f.url:
            lines.append(f"- URL: {f.url}")
        lines.append(f"- Mô tả: {f.description}")
        if f.evidence_gaps:
            lines.append("- ⚠ THIẾU BẰNG CHỨNG TRONG PHIÊN (có thể model bịa):")
            lines += [f"  - {g}" for g in f.evidence_gaps]
        if f.cves:
            lines.append(f"- CVE: {', '.join(f.cves)}")
        if f.evidence:
            lines.append("- Evidence:")
            lines += [f"  - {e[:180]}" for e in f.evidence[-5:]]
        if f.reproduction_steps:
            lines.append("- Reproduction:")
            lines += [f"  1. {s}" for s in f.reproduction_steps]
        if f.fix:
            lines.append(f"- Fix: {f.fix}")
        lines.append("")
    if plan:
        lines.append("## Cần xác minh")
        for p in plan:
            lines.append(f"- **{p['finding']}** ({p['status']}): " + " | ".join(p["steps"]))
        lines.append("")
    return "\n".join(lines)
