"""Deterministic technology and attack-surface capability planning.

This module consumes Inventory facts.  It never fingerprints a target and never
uses model output.  Profiles are declarative so adding a technology or payload
family does not require changing the decision algorithm.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import time
from typing import Any


TECHNOLOGY_PROFILES = {
    "php": {"aliases": ["php"], "capabilities": ["php-runtime"], "parents": []},
    "laravel": {"aliases": ["laravel"], "capabilities": ["laravel-framework", "php-runtime"], "parents": ["php"]},
    "wordpress": {"aliases": ["wordpress", "woocommerce"], "capabilities": ["wordpress-cms", "php-runtime"], "parents": ["php"]},
    "java": {"aliases": ["java", "jboss"], "capabilities": ["java-runtime"], "parents": []},
    "spring": {"aliases": ["spring"], "capabilities": ["spring-framework", "java-runtime"], "parents": ["java"]},
    "tomcat": {"aliases": ["tomcat"], "capabilities": ["java-servlet-container", "java-runtime"], "parents": ["java"]},
    "asp.net": {"aliases": ["asp.net"], "capabilities": ["dotnet-runtime"], "parents": []},
    "iis": {"aliases": ["iis", "microsoft-iis"], "capabilities": ["iis-server"], "parents": []},
    "node.js": {"aliases": ["node.js"], "capabilities": ["node-runtime"], "parents": []},
    "express": {"aliases": ["express"], "capabilities": ["express-framework", "node-runtime"], "parents": ["node.js"]},
    "python": {"aliases": ["python"], "capabilities": ["python-runtime"], "parents": []},
    "django": {"aliases": ["django"], "capabilities": ["django-framework", "python-runtime"], "parents": ["python"]},
    "flask": {"aliases": ["flask", "werkzeug"], "capabilities": ["flask-framework", "python-runtime"], "parents": ["python"]},
    "ruby": {"aliases": ["ruby"], "capabilities": ["ruby-runtime"], "parents": []},
    "rails": {"aliases": ["rails"], "capabilities": ["rails-framework", "ruby-runtime"], "parents": ["ruby"]},
    "go": {"aliases": ["go", "gin", "fiber", "echo"], "capabilities": ["go-runtime"], "parents": []},
    "nginx": {"aliases": ["nginx", "openresty"], "capabilities": ["reverse-proxy"], "parents": []},
    "apache": {"aliases": ["apache"], "capabilities": ["http-server"], "parents": []},
}


# required_surface is an AND condition.  technology_any is an OR condition.
# Scanner selectors are deliberately descriptive patterns, not scanner logic.
PAYLOAD_PROFILES = {
    "php-stream-wrappers": {"technology_any": ["php", "laravel", "wordpress"], "required_surface": ["file-input"], "threshold": .65, "capabilities": ["php://filter", "php://input", "expect://"], "selectors": [r"php", r"file.*include", r"lfi"]},
    "php-upload": {"technology_any": ["php", "laravel", "wordpress"], "required_surface": ["upload"], "threshold": .65, "capabilities": ["php-upload"], "selectors": [r"upload.*php", r"php.*upload"]},
    "php-deserialization": {"technology_any": ["php", "laravel", "wordpress"], "required_surface": ["deserialization"], "threshold": .70, "capabilities": ["php-deserialization", "laravel", "phpunit"], "selectors": [r"php.*deserial", r"laravel", r"phpunit"]},
    "java-upload": {"technology_any": ["java", "spring", "tomcat"], "required_surface": ["upload"], "threshold": .65, "capabilities": ["jsp-upload"], "selectors": [r"jsp.*upload", r"upload.*jsp"]},
    "java-framework-rce": {"technology_any": ["java", "spring", "tomcat"], "required_surface": ["input"], "threshold": .65, "capabilities": ["spring", "struts", "spel", "log4shell"], "selectors": [r"spring", r"struts", r"spel", r"log4"]},
    "java-deserialization": {"technology_any": ["java", "spring", "tomcat"], "required_surface": ["deserialization"], "threshold": .70, "capabilities": ["java-deserialization"], "selectors": [r"java.*deserial"]},
    "aspnet-viewstate": {"technology_any": ["asp.net", "iis"], "required_surface": ["viewstate"], "threshold": .65, "capabilities": ["viewstate"], "selectors": [r"viewstate"]},
    "aspnet-upload": {"technology_any": ["asp.net", "iis"], "required_surface": ["upload"], "threshold": .65, "capabilities": ["aspx-upload"], "selectors": [r"aspx.*upload", r"upload.*aspx"]},
    "aspnet-session": {"technology_any": ["asp.net", "iis"], "required_surface": ["authentication"], "threshold": .65, "capabilities": ["iis", "cookieless-session"], "selectors": [r"cookieless", r"asp\.net.*session"]},
    "node-prototype-pollution": {"technology_any": ["node.js", "express"], "required_surface": ["structured-input"], "threshold": .65, "capabilities": ["prototype-pollution", "express"], "selectors": [r"prototype.*pollution"]},
    "node-path-traversal": {"technology_any": ["node.js", "express"], "required_surface": ["file-input"], "threshold": .65, "capabilities": ["node-path-traversal"], "selectors": [r"node.*path.*travers", r"express.*travers"]},
    "python-framework": {"technology_any": ["python", "flask", "django"], "required_surface": ["input"], "threshold": .65, "capabilities": ["flask", "django", "werkzeug"], "selectors": [r"flask", r"django", r"werkzeug"]},
    "python-ssti": {"technology_any": ["python", "flask", "django"], "required_surface": ["template"], "threshold": .65, "capabilities": ["ssti"], "selectors": [r"ssti", r"template.*inject"]},
    "ruby-framework": {"technology_any": ["ruby", "rails"], "required_surface": ["input"], "threshold": .65, "capabilities": ["rails", "erb", "yaml"], "selectors": [r"rails", r"erb", r"ruby.*yaml"]},
    "go-framework": {"technology_any": ["go"], "required_surface": ["input"], "threshold": .65, "capabilities": ["gin", "fiber", "echo"], "selectors": [r"(?:gin|fiber|echo).*go", r"go.*(?:gin|fiber|echo)"]},
    "xxe": {"technology_any": [], "required_surface": ["xml"], "threshold": 0, "capabilities": ["xxe"], "selectors": [r"xxe", r"xml external"]},
    "ssti": {"technology_any": [], "required_surface": ["template"], "threshold": 0, "capabilities": ["ssti"], "selectors": [r"ssti", r"template.*inject"]},
    "deserialization": {"technology_any": [], "required_surface": ["deserialization"], "threshold": 0, "capabilities": ["deserialization"], "selectors": [r"deserial"]},
    "file-upload": {"technology_any": [], "required_surface": ["upload"], "threshold": 0, "capabilities": ["file-upload"], "selectors": [r"file.*upload", r"upload"]},
    "authenticated-privilege": {"technology_any": [], "required_surface": ["authentication"], "threshold": 0, "capabilities": ["authenticated-privilege"], "selectors": [r"privilege", r"idor", r"authorization"]},
    "graphql": {"technology_any": [], "required_surface": ["graphql"], "threshold": 0, "capabilities": ["graphql"], "selectors": [r"graphql"]},
    "websocket": {"technology_any": [], "required_surface": ["websocket"], "threshold": 0, "capabilities": ["websocket"], "selectors": [r"websocket"]},
    "sql-injection": {"technology_any": [], "required_surface": ["input"], "threshold": 0, "capabilities": ["sql-injection"], "selectors": [r"sql.?i", r"sql injection"]},
    "cross-site-scripting": {"technology_any": [], "required_surface": ["input"], "threshold": 0, "capabilities": ["xss"], "selectors": [r"cross.site scripting", r"\bxss\b"]},
}

# Application features and attack-surface requirements intentionally use the
# same factual vocabulary today, but remain separate schema fields so a future
# profile can require an application capability without requiring a URL marker.
for _profile in PAYLOAD_PROFILES.values():
    _profile["required_application_features"] = list(_profile["required_surface"])


@dataclass(frozen=True)
class Observation:
    technology: str
    confidence: float
    host: str
    port: str
    source: str
    evidence: str
    version: str


def _canon(name: str) -> str:
    value = str(name or "").lower()
    for canonical, profile in TECHNOLOGY_PROFILES.items():
        if value == canonical or value in profile["aliases"]:
            return canonical
    return value


def _confidence(source: str, evidence: str) -> float:
    text = (source + " " + evidence).lower()
    if "cookie" in text:
        return .95
    if "header:" in text or source in {"http_request", "http_probe", "headers_recon"}:
        return .90
    if source:
        return .80
    return .65


def technology_observations(inventory) -> list[Observation]:
    rows = []
    for host in sorted(inventory.hosts.values(), key=lambda item: item.host):
        for service in sorted(host.services.values(), key=lambda item: (item.port, item.scheme)):
            for item in service.tech_obs:
                rows.append(Observation(_canon(item.name), _confidence(item.source, item.evidence),
                    host.host, service.port, item.source, item.evidence, item.version))
    return sorted(rows, key=lambda row: (row.technology, row.host, row.port, row.source, row.evidence, row.version))


def attack_surface(inventory) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    patterns = {
        "upload": r"(?:upload|attachment|multipart|file)", "xml": r"(?:xml|soap|wsdl|saml)",
        "template": r"(?:template|render|preview|theme|view)",
        "deserialization": r"(?:deserialize|unserialize|marshal|pickle|object|viewstate)",
        "graphql": r"(?:graphql|graphiql)", "websocket": r"(?:websocket|socket\.io|\bws\b)",
        "viewstate": r"(?:__viewstate|viewstate)", "file-input": r"(?:file|path|dir|page|include|document|download|template)",
    }
    def add(feature, evidence):
        if evidence not in result.setdefault(feature, []):
            result[feature].append(evidence)
    for host in sorted(inventory.hosts.values(), key=lambda item: item.host):
        if host.auth_hints:
            add("authentication", {"host": host.host, "auth_hints": sorted(host.auth_hints)})
        for endpoint in sorted(host.endpoints.values(), key=lambda item: item.url):
            fields = " ".join([endpoint.url, *sorted(endpoint.params), *sorted(endpoint.api_operations)]).lower()
            if endpoint.params or any(method in {"POST", "PUT", "PATCH", "DELETE"} for method in endpoint.methods):
                add("input", {"url": endpoint.url, "methods": sorted(endpoint.methods), "parameters": sorted(endpoint.params)})
            if endpoint.api_operations or any(method in {"POST", "PUT", "PATCH"} for method in endpoint.methods):
                add("structured-input", {"url": endpoint.url, "methods": sorted(endpoint.methods)})
            if endpoint.auth_hints or endpoint.auth_observations:
                add("authentication", {"url": endpoint.url, "auth_hints": sorted(endpoint.auth_hints)})
            for feature, pattern in patterns.items():
                if re.search(pattern, fields, re.I):
                    add(feature, {"url": endpoint.url, "matched": pattern, "parameters": sorted(endpoint.params)})
    return {key: sorted(values, key=lambda item: json.dumps(item, sort_keys=True)) for key, values in sorted(result.items())}


class TechnologyCapabilityEngine:
    MODES = {"aggressive": {"LIKELY"}, "balanced": {"LIKELY", "POSSIBLE"},
             "thorough": {"LIKELY", "POSSIBLE", "UNLIKELY"}}

    def __init__(self, mode="balanced"):
        if mode not in self.MODES:
            raise ValueError("planner_mode must be aggressive, balanced or thorough")
        self.mode = mode

    def evaluate(self, inventory) -> tuple[dict, dict, dict]:
        started = time.perf_counter()
        observations = technology_observations(inventory)
        surface = attack_surface(inventory)
        scores: dict[str, float] = {}
        for row in observations:
            scores[row.technology] = max(scores.get(row.technology, 0), row.confidence)
            for parent in TECHNOLOGY_PROFILES.get(row.technology, {}).get("parents", []):
                scores[parent] = max(scores.get(parent, 0), round(row.confidence * .95, 3))
        decisions = []
        for family, profile in sorted(PAYLOAD_PROFILES.items()):
            matches = sorted(((tech, scores.get(tech, 0)) for tech in profile["technology_any"] if scores.get(tech, 0)), key=lambda row: (-row[1], row[0]))
            required = profile["required_surface"]
            present = [name for name in required if surface.get(name)]
            tech_ok = not profile["technology_any"] or any(score >= profile["threshold"] for _, score in matches)
            surface_ok = len(present) == len(required)
            if tech_ok and surface_ok:
                level = "LIKELY"
            elif matches or present or (not profile["technology_any"] and not required):
                level = "POSSIBLE"
            else:
                level = "UNLIKELY"
            selected = level in self.MODES[self.mode]
            missing = sorted(set(required) - set(present))
            reasons = []
            if matches:
                reasons.append("technology match: " + ", ".join(f"{t} ({c:.2f})" for t, c in matches))
            elif profile["technology_any"]:
                reasons.append("no supported technology was observed")
            if present:
                reasons.append("attack surface present: " + ", ".join(present))
            if missing:
                reasons.append("attack surface absent: " + ", ".join(missing))
            reasons.append(("selected" if selected else "skipped") + f" by {self.mode} mode ({level})")
            decisions.append({"payload_family": family, "decision": level, "selected": selected,
                "selected_capability_profile": family, "technology_observations": [asdict(row) for row in observations if row.technology in profile["technology_any"]],
                "confidence": max((score for _, score in matches), default=0),
                "attack_surface_evidence": {key: surface[key] for key in present},
                "required_attack_surface": required, "missing_attack_surface": missing,
                "supported_technologies": profile["technology_any"],
                "required_application_features": profile["required_application_features"],
                "confidence_threshold": profile["threshold"],
                "capabilities": profile["capabilities"],
                "reason_for_prioritizing": "; ".join(reasons) if selected else "",
                "reason_for_skipping": "; ".join(reasons) if not selected else ""})
        elapsed = (time.perf_counter() - started) * 1000
        selected = {row["payload_family"] for row in decisions if row["selected"]}
        tech_rows = []
        for technology in sorted(scores):
            supported = sorted(name for name, profile in PAYLOAD_PROFILES.items() if technology in profile["technology_any"])
            tech_rows.append({"technology": technology, "confidence": scores[technology],
                "capabilities": TECHNOLOGY_PROFILES.get(technology, {}).get("capabilities", []),
                "supported_payload_families": supported,
                "unsupported_payload_families": sorted(set(PAYLOAD_PROFILES) - set(supported)),
                "reasoning": [asdict(row) for row in observations
                    if row.technology == technology or technology in
                    TECHNOLOGY_PROFILES.get(row.technology, {}).get("parents", [])]})
        technologies = {"version": 1, "engine": "deterministic-profile-v1", "technologies": tech_rows}
        capabilities = {"version": 1, "mode": self.mode, "attack_surface": surface,
            "selected_payload_families": sorted(selected), "available_payload_families": sorted(PAYLOAD_PROFILES)}
        decision_report = {"version": 1, "mode": self.mode, "decisions": decisions,
            "benchmark": {"payload_families_before_optimization": len(decisions),
                "payload_families_after_optimization": len(selected),
                "skipped_payload_families": len(decisions) - len(selected),
                "executed_payload_families": 0, "average_planning_time_ms": round(elapsed, 3),
                "average_scan_duration_seconds": 0, "overall_scan_reduction_percent": round(100 * (len(decisions) - len(selected)) / len(decisions), 2) if decisions else 0}}
        return technologies, capabilities, decision_report

    @staticmethod
    def family_for_scanner_item(item: Any) -> str | None:
        if isinstance(item, dict):
            value = " ".join(str(item.get(key, "")) for key in ("id", "name", "category", "tags"))
        else:
            value = str(item)
        matches = [family for family, profile in PAYLOAD_PROFILES.items()
                   if any(re.search(pattern, value, re.I) for pattern in profile["selectors"])]
        return matches[0] if matches else None

    def filter_items(self, items, decision_report):
        decisions = {row["payload_family"]: row for row in decision_report["decisions"]}
        kept, skipped, executed = [], [], set()
        for item in items:
            family = self.family_for_scanner_item(item)
            if family is None or decisions[family]["selected"]:
                kept.append(item)
                if family:
                    executed.add(family)
            else:
                skipped.append({"item": item, "payload_family": family,
                    "reason": decisions[family]["reason_for_skipping"]})
        return kept, skipped, executed


def persist(directory, technologies, capabilities, decisions):
    paths = {}
    for name, value in (("technology-capabilities.json", technologies),
                        ("planner-capabilities.json", capabilities),
                        ("planner-decisions.json", decisions)):
        path = Path(directory) / name
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2))
        path.chmod(0o600)
        paths[name] = str(path)
    return paths
