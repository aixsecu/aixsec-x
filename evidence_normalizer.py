"""Normalize heterogeneous security-tool output without discarding raw artifacts."""
from __future__ import annotations

import hashlib
import json
import re
import time
from urllib.parse import urljoin

from capability_registry import Capability, registry
from http_engine import EvidenceRedactor


SCHEMA_FIELDS = (
    "tool", "tool_version", "capability", "category", "finding_id", "rule_id",
    "severity", "confidence", "verification_state", "url", "method", "parameter",
    "payload", "evidence", "request_reference", "response_reference", "auth_context",
    "timestamp", "coverage", "scan_scope",
)

SUPPORTED_TOOLS = {
    "zap_baseline", "zap_active_scan", "nuclei_scan", "sqlmap_runner",
    "sqlmap_check", "ffuf_dir", "http_request", "http_probe", "sql_error_verify",
}


def _stable(prefix, value):
    raw=json.dumps(value,sort_keys=True,default=str,separators=(",",":")).encode()
    return prefix+"-"+hashlib.sha256(raw).hexdigest()[:24]


def _capability(tool):
    explicit={
        "zap_baseline":Capability.PASSIVE_HTTP_ANALYSIS,
        "zap_active_scan":Capability.ACTIVE_WEB_SCAN,
        "nuclei_scan":Capability.TEMPLATE_SCAN,
        "sqlmap_runner":Capability.AUTOMATED_SQL_INJECTION_CONFIRMATION,
        "sqlmap_check":Capability.AUTOMATED_SQL_INJECTION_CONFIRMATION,
        "ffuf_dir":Capability.DIRECTORY_DISCOVERY,
        "http_request":Capability.HTTP_OBSERVATION,
        "http_probe":Capability.PASSIVE_HTTP_ANALYSIS,
        "sql_error_verify":Capability.SQL_INJECTION_VERIFICATION,
    }
    return explicit.get(tool) or registry().capability_for_tool(tool) or "unclassified"


def _rows(tool, result, args, data):
    if tool in {"zap_baseline","zap_active_scan","nuclei_scan","sql_error_verify"}:
        return data.get("alerts") or [], True
    if tool in {"sqlmap_runner","sqlmap_check"}:
        rows=[];output=str(result.get("output") or "")
        for parameter,method in re.findall(
                r"^Parameter:\s*(\S+)\s*\((GET|POST|URI|Cookie|HEADER)\)",output,re.M):
            if re.search(r"^\s+Type:\s*\S",output,re.M):
                rows.append({"category":"SQL Injection","rule_id":"sqli",
                    "url":args.get("url"),"parameter":parameter,"method":method,
                    "severity":"high","description":"Automated SQL injection provider reported an injection point; validation required."})
        return rows, True
    if tool == "ffuf_dir":
        return [{"category":"Directory Discovery","rule_id":"directory-discovery",
            "url":args.get("url"),"severity":"info","description":"Directory discovery execution observation."}],False
    if tool in {"http_request","http_probe"}:
        method=args.get("method","GET")
        return [{"category":"HTTP Observation","rule_id":"http-observation",
            "url":args.get("url"),"method":method,"severity":"info",
            "description":"Custom HTTP executor observation."}],False
    return [],False


def normalize(result, raw_result_reference=""):
    """Return normalized records. Private keys are retained only in memory."""
    tool=str(result.get("name") or "")
    if tool not in SUPPORTED_TOOLS:
        return []
    args=result.get("args") or {};data=result.get("data") or {}
    if not isinstance(data,dict): data={}
    coverage=data.get("coverage") if isinstance(data.get("coverage"),dict) else {}
    rows,candidates=_rows(tool,result,args,data)
    if not rows:
        rows=[{"category":"Execution Observation","rule_id":"execution",
            "url":args.get("url") or coverage.get("target"),"severity":"info",
            "description":"Security capability execution produced no finding record."}]
        candidates=False
    now=float(result.get("timestamp") or time.time())
    output=[]
    for source in rows:
        if not isinstance(source,dict): continue
        row=dict(source);url=EvidenceRedactor().redact_url(str(row.get("url") or args.get("url") or ""))
        if not url: continue
        method=str(row.get("method") or args.get("method") or "GET").upper()
        auth=str(row.get("auth_context") or args.get("auth_context") or "anonymous")
        category=str(row.get("category") or "Unclassified")
        severity=str(row.get("severity") or "info").lower()
        artifact=str(row.get("artifact_ref") or coverage.get("report_path") or
                     data.get("report_path") or raw_result_reference)
        request_hash=str(row.get("request_sha256") or "")
        response_hash=str(row.get("response_sha256") or "")
        request_ref=(artifact+("#request-sha256="+request_hash if request_hash else "")) if artifact else request_hash
        response_ref=(artifact+("#response-sha256="+response_hash if response_hash else "")) if artifact else response_hash
        capability=_capability(tool)
        key_category="sqli" if category.lower() in {"sql injection","sqli"} else category.lower()
        finding_id=_stable("finding",[key_category,url,method,str(row.get("parameter") or ""),auth]) if candidates else ""
        evidence_id=_stable("ev",[tool,row.get("scan_id"),row.get("rule_id"),url,method,
            row.get("parameter"),auth,request_hash,response_hash])
        confidence=row.get("confidence",row.get("scanner_confidence","unknown"))
        record={
            "tool":tool,"tool_version":str(row.get("tool_version") or coverage.get("version") or data.get("version") or ""),
            "capability":capability,"category":category,"finding_id":finding_id,
            "rule_id":str(row.get("rule_id") or ""),"severity":severity,
            "confidence":confidence,"verification_state":str(row.get("verification_state") or ("candidate" if candidates else "observed")),
            "url":url,"method":method,"parameter":str(row.get("parameter") or ""),
            "payload":str(row.get("payload") or ""),
            "evidence":str(row.get("description") or row.get("evidence") or ""),
            "request_reference":request_ref,"response_reference":response_ref,
            "auth_context":auth,"timestamp":now,"coverage":dict(coverage),
            "scan_scope":str(row.get("scan_scope") or coverage.get("scope") or data.get("scope") or coverage.get("target") or ""),
            # Compatibility/provenance fields.
            "evidence_id":evidence_id,"source_tool":tool,"artifact_ref":artifact,
            "description":str(row.get("description") or ""),"fix":str(row.get("fix") or ""),
            "scan_id":str(row.get("scan_id") or data.get("scan_id") or ""),
            "auth_state":str(row.get("auth_state") or coverage.get("auth_state") or ""),
            "request_sha256":request_hash,"response_sha256":response_hash,
            "raw_result_reference":raw_result_reference,"_candidate":candidates,
            "_normalized_schema":1,
            "_verification":{"response_header":row.get("_response_header") or "",
                "request_header":row.get("_request_header") or "",
                "url":row.get("_url") or row.get("url") or args.get("url") or "",
                "request_body":row.get("_request_body") or "",
                "body_sha256":row.get("_body_sha256") or ""},
        }
        for key,value in row.items():
            if key not in record and not key.startswith("_"):
                record[key]=value
        output.append(record)
    return output


def validate_schema(record):
    missing=[field for field in SCHEMA_FIELDS if field not in record]
    if missing: raise ValueError("Normalized evidence missing fields: "+", ".join(missing))
    return True
