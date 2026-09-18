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


def validation_plan(ledger: Ledger) -> list[dict]:
    """Sinh kế hoạch xác minh cho từng finding chưa confirmed."""
    plan = []
    for f in ledger.by_status("candidate") + ledger.by_status("needs_validation"):
        steps = []
        if f.cves:
            steps.append(f"Tìm template nuclei cho {', '.join(f.cves)} và chạy trên {f.url or 'target'}")
        if f.url:
            steps.append(f"Chạy nuclei -tags {f.service.split()[-1] if f.service else 'cve'} "
                         f"hoặc payload thủ công để xác nhận trên {f.url}")
            steps.append("Ghi request/response đối chứng: control vs payload")
        if f.port:
            steps.append(f"Verify dịch vụ thực tế trên port {f.port}")
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
