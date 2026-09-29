"""Deterministic active-scan planning by attack surface and risk.

Unknown ZAP rules remain applicable.  This makes the optimiser conservative:
it removes a rule only when its catalog metadata clearly requires a surface
that the captured request does not have.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit


_INPUT_RULE = re.compile(
    r"sql|cross.?site scripting|\bxss\b|command injection|code injection|"
    r"remote code|server.?side template|\bssti\b|ldap|xpath|expression language|"
    r"path traversal|directory traversal|remote file|local file|open redirect|"
    r"parameter tamper|crlf|header injection", re.I)
_XML_RULE = re.compile(r"\bxml\b|\bxxe\b|xpath|soap", re.I)
_UPLOAD_RULE = re.compile(r"upload|multipart", re.I)
_PATH_RULE = re.compile(r"path traversal|directory traversal|local file|remote file|include", re.I)
_HEADER_RULE = re.compile(r"header|cookie|cors|csp|hsts|cache|content.?type|clickjack", re.I)
_RISKY_PATH = re.compile(
    r"(?:^|[/_.-])(admin|login|signin|auth|account|search|find|tim-?kiem|api|graphql|"
    r"upload|import|export|download|checkout|payment|order|delete|remove|update|save|"
    r"reset|confirm)(?:$|[/_.-])", re.I)
_RISKY_PARAM = re.compile(
    r"(?:^|[_-])(q|query|search|keyword|key|term|id|user|account|file|path|dir|page|"
    r"include|template|url|uri|redirect|return|callback|cmd|command|sort|filter)(?:$|[_-])",
    re.I)


def _rule_text(rule) -> str:
    if isinstance(rule, dict):
        return " ".join(str(rule.get(key, "")) for key in
                        ("id", "name", "category", "tags", "description"))
    return str(rule)


def request_surface(entry: dict) -> dict:
    request = (entry.get("_entry") or {}).get("request") or {}
    structure = entry.get("structure") or {}
    parsed = urlsplit(str(request.get("url") or entry.get("url") or ""))
    query_names = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    if structure.get("query"):
        query_names = [str(row[0]) for row in structure["query"]]
    body = structure.get("body") or []
    body_names = [str(row[0]) for row in body if isinstance(row, (list, tuple)) and row]
    post = request.get("postData") if isinstance(request.get("postData"), dict) else {}
    mime = str((post or {}).get("mimeType") or structure.get("body_type") or "").lower()
    headers = {str(row.get("name") or "").lower() for row in request.get("headers", [])
               if isinstance(row, dict)}
    names = query_names + body_names
    return {
        "method": str(request.get("method") or entry.get("method") or "GET").upper(),
        "path": parsed.path or "/", "query": query_names, "body": body_names,
        "has_input": bool(query_names or body_names), "mime": mime,
        "xml": "xml" in mime or "soap" in mime,
        "upload": "multipart/" in mime or any(re.search(r"file|upload|attachment", n, re.I) for n in names),
        "file_input": any(re.search(r"file|path|dir|page|include|document|download|template", n, re.I) for n in names),
        "headers": sorted(headers), "cookies": bool(request.get("cookies") or "cookie" in headers),
        "auth": entry.get("auth_context", "anonymous") != "anonymous",
    }


def applicable_rules(entry: dict, rules: list[dict]) -> tuple[list[int], list[dict]]:
    surface = request_surface(entry)
    kept, excluded = [], []
    for rule in rules:
        rule_id = int(rule["id"] if isinstance(rule, dict) else rule)
        text = _rule_text(rule)
        reason = ""
        if _XML_RULE.search(text) and not surface["xml"]:
            reason = "requires XML/SOAP input"
        elif _UPLOAD_RULE.search(text) and not surface["upload"]:
            reason = "requires multipart/file input"
        elif _PATH_RULE.search(text) and not surface["file_input"]:
            reason = "requires file/path-like input"
        elif _INPUT_RULE.search(text) and not surface["has_input"]:
            reason = "requires injectable query/body input"
        # Header/configuration rules and unknown third-party rules are retained.
        if reason and not _HEADER_RULE.search(text):
            excluded.append({"id": rule_id, "name": rule.get("name", "") if isinstance(rule, dict) else "",
                             "reason": reason})
        else:
            kept.append(rule_id)
    return sorted(set(kept)), excluded


def risk_score(entry: dict) -> tuple[int, list[str]]:
    surface = request_surface(entry)
    score, reasons = 0, []
    if surface["has_input"]:
        score += 35; reasons.append("query/body input")
    if surface["body"]:
        score += 15; reasons.append("request body")
    if surface["method"] not in ("GET", "HEAD", "OPTIONS"):
        score += 15; reasons.append("state-changing method")
    if surface["xml"] or "json" in surface["mime"] or surface["upload"]:
        score += 12; reasons.append("structured or upload body")
    if _RISKY_PATH.search(surface["path"]):
        score += 15; reasons.append("security-sensitive route")
    names = surface["query"] + surface["body"]
    if any(_RISKY_PARAM.search(name) for name in names):
        score += 15; reasons.append("security-sensitive parameter")
    if surface["auth"] or surface["cookies"]:
        score += 8; reasons.append("authenticated/session context")
    score += min(10, len(set(names)) * 2)
    return min(100, score), reasons


def plan_attack_points(entries, rules, apply_applicability=True):
    report = {"request_groups": len(entries), "rule_pairs_before": len(entries) * len(rules),
              "rule_pairs_after": 0, "excluded_pairs": 0,
              "applicability_mode": "surface-aware" if apply_applicability else "exhaustive-all-rules",
              "attack_points": []}
    for entry in entries:
        applicable, excluded = applicable_rules(entry, rules)
        if not apply_applicability:
            applicable = sorted({int(rule["id"] if isinstance(rule, dict) else rule) for rule in rules})
            excluded = []
        score, reasons = risk_score(entry)
        entry["_applicable_rules"] = applicable
        entry["risk_score"] = score
        entry["risk_reasons"] = reasons
        entry["rule_applicability_exclusions"] = excluded
        report["rule_pairs_after"] += len(applicable)
        report["excluded_pairs"] += len(excluded)
        report["attack_points"].append({"request_id": entry.get("request_id"),
            "url": entry.get("url"), "method": entry.get("method"), "risk_score": score,
            "risk_reasons": reasons, "applicable_rule_ids": applicable,
            "excluded_rules": excluded})
    report["attack_points"].sort(key=lambda row: (-row["risk_score"], row.get("url") or ""))
    return report
