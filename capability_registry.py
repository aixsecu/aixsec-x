"""Capability-to-tool resolution for planners and execution frontiers.

Capabilities describe security outcomes. Providers describe the existing tool
implementations. Planner code depends only on the former; the execution-facing
action shape remains backward compatible and still contains ``tool``.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable


class Capability:
    PASSIVE_HTTP_ANALYSIS = "passive_http_analysis"
    HEADER_AUDIT = "header_audit"
    COOKIE_AUDIT = "cookie_audit"
    TLS_ANALYSIS = "tls_analysis"
    DIRECTORY_DISCOVERY = "directory_discovery"
    TECHNOLOGY_FINGERPRINTING = "technology_fingerprinting"
    STATIC_FILE_DISCOVERY = "static_file_discovery"
    XSS_VERIFICATION = "xss_verification"
    SQL_INJECTION_VERIFICATION = "sql_injection_verification"
    BLIND_SQL_INJECTION = "blind_sql_injection"
    COMMAND_INJECTION = "command_injection"
    OPEN_REDIRECT = "open_redirect"
    CRLF_INJECTION = "crlf_injection"
    SSRF_VERIFICATION = "ssrf_verification"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD_VALIDATION = "file_upload_validation"
    AUTHORIZATION_REPLAY = "authorization_replay"
    AUTHORIZATION_ANALYSIS = "authorization_analysis"
    BUSINESS_LOGIC_VALIDATION = "business_logic_validation"
    CRAWLER = "crawler"
    API_DISCOVERY = "api_discovery"
    OPENAPI_IMPORT = "openapi_import"
    BROWSER_AUTOMATION = "browser_automation"
    CREDENTIAL_VALIDATION = "credential_validation"
    RATE_LIMIT_TESTING = "rate_limit_testing"
    HTTP_OBSERVATION = "http_observation"
    EVIDENCE_VALIDATION = "evidence_validation"
    EVIDENCE_REPLAY = "evidence_replay"
    EVIDENCE_STATUS = "evidence_status"
    SAST_DAST_CORRELATION = "sast_dast_correlation"
    DYNAMIC_PLANNING = "dynamic_planning"
    AUTH_CONTEXT_MANAGEMENT = "auth_context_management"
    AUTH_CONTEXT_INSPECTION = "auth_context_inspection"
    CREDENTIAL_LOGIN = "credential_login"
    BUSINESS_RULE_DECLARATION = "business_rule_declaration"
    BUSINESS_WORKFLOW_EXECUTION = "business_workflow_execution"
    AUTOMATED_SQL_INJECTION_CONFIRMATION = "automated_sql_injection_confirmation"
    ACTIVE_WEB_SCAN = "active_web_scan"
    TEMPLATE_SCAN = "template_scan"
    SAST = "sast"
    KNOWN_CVE_DETECTION = "known_cve_detection"


@dataclass(frozen=True)
class Provider:
    capability: str
    tool: str
    priority: int = 50
    cost: float = 1.0
    speed: float = 0.5
    accuracy: float = 0.5
    requires_auth: bool = False
    requires_browser: bool = False
    safe_mode: bool = False
    confirmation_only: bool = False
    coverage: float = 0.5
    confidence: float = 0.5

    def to_dict(self) -> dict:
        return asdict(self)


class CapabilityRegistry:
    def __init__(self, providers: Iterable[Provider] = ()) -> None:
        self._providers: dict[str, list[Provider]] = {}
        self._by_tool: dict[str, list[Provider]] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: Provider) -> None:
        if not provider.capability or not provider.tool:
            raise ValueError("capability and tool are required")
        if any(item.tool == provider.tool
               for item in self._providers.get(provider.capability, ())):
            raise ValueError(f"duplicate provider: {provider.capability}/{provider.tool}")
        self._providers.setdefault(provider.capability, []).append(provider)
        self._by_tool.setdefault(provider.tool, []).append(provider)

    def providers(self, capability: str) -> tuple[Provider, ...]:
        return tuple(sorted(self._providers.get(capability, ()), key=self._rank))

    def capabilities_for_tool(self, tool: str) -> tuple[str, ...]:
        return tuple(sorted({item.capability for item in self._by_tool.get(tool, ())}))

    def capabilities_for_observation(self, observation: dict) -> tuple[str, ...]:
        """Read capability-native observations and migrate legacy provider records."""
        capability = observation.get("capability")
        if capability:
            return (str(capability),)
        return self.capabilities_for_tool(str(observation.get("tool") or ""))

    def capability_for_tool(self, tool: str) -> str | None:
        values = self._by_tool.get(tool, ())
        return sorted(values, key=self._rank)[0].capability if values else None

    @staticmethod
    def _rank(provider: Provider) -> tuple:
        return (-provider.priority, provider.cost, -provider.accuracy,
                -provider.speed, provider.tool)

    def resolve(self, capability: str, available_tools: Iterable[str] | None = None,
                *, auth_available: bool = True, browser_available: bool = True,
                safe_mode: bool = False, confirmation: bool = False) -> Provider | None:
        available = None if available_tools is None else set(available_tools)
        if available is not None and capability in available:
            available = None  # Backward-compatible capability-set callers.
        candidates = []
        for provider in self._providers.get(capability, ()):
            if available is not None and provider.tool not in available:
                continue
            if provider.requires_auth and not auth_available:
                continue
            if provider.requires_browser and not browser_available:
                continue
            if safe_mode and not provider.safe_mode:
                continue
            if provider.confirmation_only and not confirmation:
                continue
            candidates.append(provider)
        return sorted(candidates, key=self._rank)[0] if candidates else None

    def tools_for(self, capabilities: Iterable[str], available_tools: Iterable[str] | None = None,
                  **requirements) -> set[str]:
        tools = set()
        for capability in capabilities:
            provider = self.resolve(capability, available_tools, **requirements)
            if provider:
                tools.add(provider.tool)
        return tools

    def describe(self, available_tools: Iterable[str] | None = None) -> list[dict]:
        rows = []
        for capability in sorted(self._providers):
            provider = self.resolve(capability, available_tools, confirmation=True)
            if provider:
                rows.append(provider.to_dict())
        return rows


def _provider(capability, tool, priority=50, cost=1, speed=.5, accuracy=.5,
              requires_auth=False, requires_browser=False, safe_mode=False,
              confirmation_only=False, coverage=.5, confidence=.5):
    return Provider(capability, tool, priority, cost, speed, accuracy,
                    requires_auth, requires_browser, safe_mode, confirmation_only,
                    coverage, confidence)


DEFAULT_REGISTRY = CapabilityRegistry([
    _provider(Capability.PASSIVE_HTTP_ANALYSIS, "zap_baseline", 90, 4, .3, .9, safe_mode=True),
    _provider(Capability.PASSIVE_HTTP_ANALYSIS, "http_probe", 50, 1, .9, .5, safe_mode=True),
    _provider(Capability.HEADER_AUDIT, "zap_baseline", 100, 4, .3, .9, safe_mode=True,
              coverage=.95, confidence=.9),
    _provider(Capability.HEADER_AUDIT, "headers_recon", 90, 1, .9, .9, safe_mode=True,
              coverage=.65, confidence=.85),
    _provider(Capability.COOKIE_AUDIT, "headers_recon", 80, 1, .9, .8, safe_mode=True),
    _provider(Capability.TLS_ANALYSIS, "headers_recon", 70, 1, .8, .7, safe_mode=True),
    _provider(Capability.DIRECTORY_DISCOVERY, "ffuf_dir", 90, 3, .8, .8),
    _provider(Capability.DIRECTORY_DISCOVERY, "crawler", 50, 2, .6, .6, safe_mode=True),
    _provider(Capability.TECHNOLOGY_FINGERPRINTING, "http_probe", 80, 1, .9, .7, safe_mode=True),
    _provider(Capability.TECHNOLOGY_FINGERPRINTING, "detect_cms", 70, 1, .8, .8, safe_mode=True),
    _provider(Capability.STATIC_FILE_DISCOVERY, "crawler", 80, 2, .7, .7, safe_mode=True),
    _provider(Capability.XSS_VERIFICATION, "zap_active_scan", 80, 4, .4, .8, confirmation_only=True),
    _provider(Capability.XSS_VERIFICATION, "wapiti_scan", 60, 5, .3, .7, confirmation_only=True),
    _provider(Capability.SQL_INJECTION_VERIFICATION, "sqli_manual_test", 90, 2, .7, .8, confirmation_only=True),
    _provider(Capability.SQL_INJECTION_VERIFICATION, "sqlmap_runner", 80, 5, .3, .95, confirmation_only=True),
    _provider(Capability.BLIND_SQL_INJECTION, "sqli_blind_extract", 90, 5, .2, .9, confirmation_only=True),
    _provider(Capability.BLIND_SQL_INJECTION, "sqlmap_runner", 100, 5, .3, .95,
              confirmation_only=True, coverage=.95, confidence=.95),
    _provider(Capability.COMMAND_INJECTION, "zap_active_scan", 70, 4, .4, .75, confirmation_only=True),
    _provider(Capability.OPEN_REDIRECT, "zap_active_scan", 80, 3, .5, .8, confirmation_only=True),
    _provider(Capability.CRLF_INJECTION, "zap_active_scan", 80, 3, .5, .8, confirmation_only=True),
    _provider(Capability.SSRF_VERIFICATION, "nuclei_scan", 80, 4, .5, .8, confirmation_only=True),
    _provider(Capability.PATH_TRAVERSAL, "zap_active_scan", 80, 4, .4, .8, confirmation_only=True),
    _provider(Capability.FILE_UPLOAD_VALIDATION, "http_request", 70, 2, .7, .7, confirmation_only=True),
    _provider(Capability.AUTHORIZATION_REPLAY, "auth_compare", 90, 2, .7, .9, requires_auth=True),
    _provider(Capability.AUTHORIZATION_ANALYSIS, "authorization_reason", 90, .1, 1, .8, safe_mode=True),
    _provider(Capability.BUSINESS_LOGIC_VALIDATION, "business_reason", 80, .1, 1, .7, safe_mode=True),
    _provider(Capability.BUSINESS_LOGIC_VALIDATION, "business_workflow_test", 70, 3, .5, .8, requires_auth=True),
    _provider(Capability.CRAWLER, "crawler", 90, 2, .7, .8, safe_mode=True),
    _provider(Capability.CRAWLER, "zap_baseline", 60, 4, .3, .9, safe_mode=True),
    _provider(Capability.API_DISCOVERY, "api_discovery", 90, 2, .7, .85, safe_mode=True),
    _provider(Capability.OPENAPI_IMPORT, "api_import", 90, 1, .9, .95, safe_mode=True),
    _provider(Capability.BROWSER_AUTOMATION, "zap_baseline", 90, 5, .2, .85, requires_browser=True),
    _provider(Capability.CREDENTIAL_VALIDATION, "auth_login", 90, 2, .6, .9, requires_auth=True),
    _provider(Capability.RATE_LIMIT_TESTING, "business_workflow_test", 80, 3, .5, .8, requires_auth=True),
    _provider(Capability.HTTP_OBSERVATION, "http_request", 90, 1, .9, .9),
    _provider(Capability.EVIDENCE_VALIDATION, "evidence_validate", 90, .1, 1, .95, safe_mode=True),
    _provider(Capability.EVIDENCE_REPLAY, "evidence_replay", 90, 1, .8, .9, confirmation_only=True),
    _provider(Capability.EVIDENCE_STATUS, "evidence_status", 90, .1, 1, .9, safe_mode=True),
    _provider(Capability.SAST_DAST_CORRELATION, "sast_dast_correlate", 90, .1, 1, .85, safe_mode=True),
    _provider(Capability.DYNAMIC_PLANNING, "dynamic_plan", 90, .1, 1, .9, safe_mode=True),
    _provider(Capability.AUTH_CONTEXT_MANAGEMENT, "auth_context_set", 90, .1, 1, .9, safe_mode=True),
    _provider(Capability.AUTH_CONTEXT_INSPECTION, "auth_context_list", 90, .1, 1, .9, safe_mode=True),
    _provider(Capability.CREDENTIAL_LOGIN, "auth_login", 90, 2, .6, .9, requires_auth=True),
    _provider(Capability.BUSINESS_RULE_DECLARATION, "business_rule_set", 90, .1, 1, .9, safe_mode=True),
    _provider(Capability.BUSINESS_WORKFLOW_EXECUTION, "business_workflow_test", 90, 3, .5, .8, requires_auth=True),
    _provider(Capability.AUTOMATED_SQL_INJECTION_CONFIRMATION, "sqlmap_runner", 90, 5, .3, .95, confirmation_only=True),
    _provider(Capability.ACTIVE_WEB_SCAN, "zap_active_scan", 90, 5, .3, .9, confirmation_only=True),
    _provider(Capability.TEMPLATE_SCAN, "nuclei_scan", 90, 4, .5, .85, confirmation_only=True),
    _provider(Capability.KNOWN_CVE_DETECTION, "nuclei_scan", 95, 4, .6, .9,
              confirmation_only=True, coverage=.9, confidence=.9),
    _provider(Capability.SAST, "sast_scan", 90, 3, .5, .85, safe_mode=True),
])


def registry() -> CapabilityRegistry:
    return DEFAULT_REGISTRY
