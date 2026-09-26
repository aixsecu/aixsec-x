"""Capability-driven provider selection and execution.

The planner-facing contract contains capabilities only. Concrete tool names are
kept inside orchestration records and never need to enter planner state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from capability_registry import Capability, CapabilityRegistry, Provider, registry


CAPABILITY_CHAINS = {
    Capability.BLIND_SQL_INJECTION: (Capability.SQL_INJECTION_VERIFICATION,),
    Capability.AUTHORIZATION_ANALYSIS: (Capability.AUTHORIZATION_REPLAY,),
    Capability.BUSINESS_LOGIC_VALIDATION: (Capability.HTTP_OBSERVATION,),
}

RETRYABLE_OUTCOMES = {"error", "timeout", "partial", "blocked", "unavailable"}


@dataclass(frozen=True)
class OrchestrationRequest:
    capability: str
    arguments: dict = field(default_factory=dict)
    confirmation: bool = False
    multiple_confirmation: bool = False
    auth_available: bool = True
    browser_available: bool = True
    safe_mode: bool = False
    min_coverage: float = 0.0
    min_accuracy: float = 0.0
    min_confidence: float = 0.0
    prefer_speed: bool = False
    max_cost: float | None = None


class ToolOrchestrator:
    def __init__(self, capabilities: CapabilityRegistry | None = None,
                 available_tools: Iterable[str] | None = None) -> None:
        self.registry = capabilities or registry()
        self.available_tools = None if available_tools is None else set(available_tools)

    @staticmethod
    def planner_schema(capabilities: Iterable[str]) -> dict:
        return {"type": "function", "function": {
            "name": "capability_request",
            "description": "Request a security outcome. Provider selection and fallback are handled by the orchestrator.",
            "parameters": {"type": "object", "properties": {
                "capability": {"type": "string", "enum": sorted(set(capabilities))},
                "arguments": {"type": "object"},
                "confirmation": {"type": "boolean"},
                "multiple_confirmation": {"type": "boolean"}},
                "required": ["capability", "arguments"]}}}

    def candidates(self, request: OrchestrationRequest) -> list[Provider]:
        candidates = []
        for provider in self.registry.providers(request.capability):
            if self.available_tools is not None and provider.tool not in self.available_tools:
                continue
            if provider.requires_auth and not request.auth_available:
                continue
            if provider.requires_browser and not request.browser_available:
                continue
            if request.safe_mode and not provider.safe_mode:
                continue
            if provider.confirmation_only and not request.confirmation:
                continue
            if provider.coverage < request.min_coverage or provider.accuracy < request.min_accuracy:
                continue
            if provider.confidence < request.min_confidence:
                continue
            if request.max_cost is not None and provider.cost > request.max_cost:
                continue
            candidates.append(provider)
        def score(provider):
            speed_weight = 3 if request.prefer_speed else 1
            return (-(provider.priority + provider.coverage * 20 + provider.accuracy * 20
                      + provider.confidence * 15 + provider.speed * 10 * speed_weight
                      - provider.cost * 5), provider.tool)
        return sorted(candidates, key=score)

    def chain(self, request: OrchestrationRequest) -> list[OrchestrationRequest]:
        prerequisites = [OrchestrationRequest(capability=value,
                         arguments=dict(request.arguments), confirmation=request.confirmation,
                         auth_available=request.auth_available,
                         browser_available=request.browser_available,
                         safe_mode=request.safe_mode)
                         for value in CAPABILITY_CHAINS.get(request.capability, ())]
        return prerequisites + [request]

    def execute(self, request: OrchestrationRequest,
                dispatch: Callable[[str, dict], dict]) -> dict:
        stages = []
        for stage in self.chain(request):
            attempts = []
            selected = self.candidates(stage)
            if not selected:
                return {"outcome": "blocked", "capability": request.capability,
                        "output": "No provider satisfies capability requirements",
                        "orchestration": stages + [{"capability": stage.capability,
                                                     "attempts": attempts}]}
            successes = []
            for provider in selected:
                result = dispatch(provider.tool, dict(stage.arguments))
                attempts.append({"provider": provider.tool,
                                 "outcome": result.get("outcome", "error")})
                if result.get("outcome") == "ok":
                    successes.append(result)
                    if not (stage.confirmation and stage.multiple_confirmation):
                        break
                elif result.get("outcome") not in RETRYABLE_OUTCOMES:
                    break
            stages.append({"capability": stage.capability, "attempts": attempts})
            if not successes:
                return {"outcome": attempts[-1]["outcome"] if attempts else "blocked",
                        "capability": request.capability,
                        "output": "All capability providers failed", "orchestration": stages}
        if len(successes) == 1:
            return {**successes[0], "capability": request.capability,
                    "orchestration": stages}
        return {"outcome": "ok", "capability": request.capability,
                "results": successes, "orchestration": stages,
                "output": f"Capability completed: {request.capability}"}


def request_from_action(action: dict) -> OrchestrationRequest:
    return OrchestrationRequest(
        capability=str(action.get("capability") or ""),
        arguments=dict(action.get("arguments") or {}),
        confirmation=bool(action.get("confirmation")),
        multiple_confirmation=bool(action.get("multiple_confirmation")),
        auth_available=bool(action.get("auth_available", True)),
        browser_available=bool(action.get("browser_available", True)),
        safe_mode=bool(action.get("safe_mode", False)),
        min_coverage=float(action.get("min_coverage", 0)),
        min_accuracy=float(action.get("min_accuracy", 0)),
        min_confidence=float(action.get("min_confidence", 0)),
        prefer_speed=bool(action.get("prefer_speed", False)),
        max_cost=float(action["max_cost"]) if action.get("max_cost") is not None else None)
