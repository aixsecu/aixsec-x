"""Planner action costs and consumable execution budgets."""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ActionCost:
    requests: int = 0
    seconds: float = 0.0
    risk: float = 0.0

    @property
    def weighted(self) -> float:
        return self.requests + self.seconds / 10.0 + self.risk * 5.0


class CostModel:
    """Estimates existing tools; it never introduces tools or payloads."""

    DEFAULTS = {
        "phase3_status": ActionCost(0, .01, 0),
        "authorization_reason": ActionCost(0, .05, 0),
        "business_reason": ActionCost(0, .05, 0),
        "sast_dast_correlate": ActionCost(0, .1, 0),
        "http_request": ActionCost(1, 1, .1),
        "auth_compare": ActionCost(2, 2, .2),
        "crawler": ActionCost(10, 15, .2),
        "api_discovery": ActionCost(12, 15, .2),
        "business_workflow_test": ActionCost(4, 4, .5),
        "sqli_manual_test": ActionCost(3, 4, .8),
    }

    def __init__(self, overrides: dict[str, ActionCost | dict] | None = None) -> None:
        self.profiles = dict(self.DEFAULTS)
        for name, value in (overrides or {}).items():
            self.profiles[name] = value if isinstance(value, ActionCost) else ActionCost(**value)

    def estimate(self, action: dict) -> ActionCost:
        return self.profiles.get(str(action.get("tool", "")), ActionCost(1, 2, .5))


@dataclass
class ExecutionBudget:
    max_actions: int = 100
    max_requests: int = 500
    max_seconds: float = 3600
    max_risk: float = 20.0
    actions_used: int = 0
    requests_used: int = 0
    seconds_used: float = 0.0
    risk_used: float = 0.0

    def permits(self, cost: ActionCost) -> bool:
        return (self.actions_used + 1 <= self.max_actions
                and self.requests_used + cost.requests <= self.max_requests
                and self.seconds_used + cost.seconds <= self.max_seconds
                and self.risk_used + cost.risk <= self.max_risk)

    def consume(self, cost: ActionCost, actual_seconds: float | None = None) -> None:
        if not self.permits(cost):
            raise RuntimeError("execution budget exhausted")
        self.actions_used += 1
        self.requests_used += cost.requests
        self.seconds_used += cost.seconds if actual_seconds is None else max(0, actual_seconds)
        self.risk_used += cost.risk

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "ExecutionBudget":
        return cls(**value)
