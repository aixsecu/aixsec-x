"""Goal-driven selection over graph knowledge, cost, risk, and memory."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .cost_model import CostModel, ExecutionBudget
from .knowledge_graph import KnowledgeGraph, NodeKind
from .planner_memory import PlannerMemory
from .workflow_model import WorkflowModel


def _id(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "action-" + hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Goal:
    objective: str = "coverage"
    target: str = ""
    success_condition: str = "knowledge_gap_closed"


class GoalDrivenPlanner:
    VALID_GOALS = {"coverage", "authorization", "business_logic", "sast_dast",
                   "workflow", "custom"}

    def __init__(self, graph: KnowledgeGraph, memory: PlannerMemory | None = None,
                 workflow: WorkflowModel | None = None, cost_model: CostModel | None = None,
                 capabilities: set[str] | None = None) -> None:
        self.graph = graph
        self.memory = memory or PlannerMemory()
        self.workflow = workflow or WorkflowModel()
        self.cost_model = cost_model or CostModel()
        self.capabilities = set(capabilities or ())

    def knowledge_gaps(self, goal: Goal) -> list[dict]:
        gaps: list[dict] = []
        endpoints = self.graph.query(NodeKind.ENDPOINT)
        for endpoint in endpoints:
            url = endpoint.attributes.get("url", "")
            observations = self.graph.neighbors(endpoint.node_id, "has_observation")
            direct = [item for item in observations if
                      item.attributes.get("context") is not None
                      or item.attributes.get("outcome") is not None
                      or item.attributes.get("state") == "observed"]
            if not direct and goal.objective in {"coverage", "authorization", "custom"}:
                gaps.append({"kind": "unobserved_endpoint", "url": url,
                             "methods": endpoint.attributes.get("methods") or ["GET"],
                             "information_gain": 1.0})
            discovery = [item for item in observations
                         if item.attributes.get("tool") in {"crawler", "api_discovery"}
                         or (item.attributes.get("tool") in {"zap_baseline", "zap_active_scan"}
                             and item.attributes.get("status") == "complete")]
            sources = endpoint.attributes.get("sources") or []
            root_candidate = ("configured_target" in sources
                              or urlparse(str(url)).path in {"", "/"})
            if direct and not discovery and root_candidate \
                    and goal.objective in {"coverage", "custom"}:
                gaps.append({"kind": "undiscovered_surface", "url": url,
                             "information_gain": 2.5})
            if endpoint.attributes.get("auth_hints") and goal.objective in {
                    "coverage", "authorization", "custom"}:
                auth_obs = [item for item in observations
                            if item.attributes.get("context") is not None]
                if len(auth_obs) < 2:
                    gaps.append({"kind": "missing_auth_comparison", "url": url,
                                 "information_gain": 2.0})
        if goal.objective in {"authorization", "custom"}:
            observed_urls = {node.attributes.get("url") for node in
                             self.graph.query(NodeKind.HYPOTHESIS)}
            for endpoint in endpoints:
                url = endpoint.attributes.get("url", "")
                observations = self.graph.neighbors(endpoint.node_id, "has_observation")
                if any(item.attributes.get("context") is not None
                       for item in observations) and url not in observed_urls:
                    gaps.append({"kind": "missing_authorization_reasoning", "url": url,
                                 "information_gain": 1.5})
        if goal.objective in {"sast_dast", "custom"}:
            hypotheses = self.graph.query(NodeKind.HYPOTHESIS)
            for finding in self.graph.query(NodeKind.SAST_FINDING):
                if not any(item.attributes.get("sast_finding_id") == finding.node_id
                           for item in hypotheses):
                    gaps.append({"kind": "uncorrelated_sast", "finding_id": finding.node_id,
                                 "information_gain": 1.5})
        if goal.objective in {"workflow", "business_logic", "custom"}:
            for state in sorted(self.workflow.states):
                if not self.workflow.next_steps(state):
                    gaps.append({"kind": "workflow_dead_end", "state": state,
                                 "information_gain": .8})
        return gaps

    def _candidate(self, gap: dict, goal: Goal) -> dict:
        kind = gap["kind"]
        if kind == "unobserved_endpoint":
            arguments = {"url": gap["url"], "method": str(gap["methods"][0]).lower()}
            tool, blockers = "http_request", []
            if str(gap['methods'][0]).upper() == 'UNKNOWN':
                blockers.append('observe_request_method_before_replay')
            if "{" in gap["url"]:
                blockers.append("substitute_observed_path_parameters")
        elif kind == "undiscovered_surface":
            tool, arguments, blockers = "crawler", {"url": gap["url"]}, []
        elif kind == "missing_auth_comparison":
            tool, arguments = "auth_compare", {"contexts": ["anonymous", "user_A"],
                "request": {"url": gap["url"], "method": "get"}}
            names = {item.attributes.get("name") for item in
                     self.graph.query(NodeKind.AUTH_CONTEXT)}
            missing = sorted({"anonymous", "user_A"} - names)
            blockers = (["configure_contexts:" + ",".join(missing)] if missing else [])
        elif kind == "missing_authorization_reasoning":
            tool, arguments, blockers = "authorization_reason", {"url": gap["url"]}, []
        elif kind == "uncorrelated_sast":
            tool, arguments, blockers = "sast_dast_correlate", {"max_results": 50}, []
        else:
            tool, arguments = "business_reason", {"workflow": gap.get("state", "")}
            blockers = ["observe_next_workflow_transition"]
        action = {"goal": goal.objective, "tool": tool, "arguments": arguments,
                  "reason": kind, "information_gain": gap["information_gain"],
                  "blocked_by": blockers}
        action["action_id"] = _id(action)
        return action

    def plan(self, goal: Goal | str = Goal(), budget: ExecutionBudget | None = None,
             max_actions: int = 12) -> dict:
        if isinstance(goal, str):
            goal = Goal(goal if goal in self.VALID_GOALS else "custom")
        candidates = []
        for gap in self.knowledge_gaps(goal):
            action = self._candidate(gap, goal)
            cost = self.cost_model.estimate(action)
            blockers = list(action["blocked_by"])
            if action["tool"] not in self.capabilities:
                blockers.append("tool_unavailable")
            if not self.memory.should_attempt(action):
                blockers.append("identical_strategy_failed")
            if budget is not None and not budget.permits(cost):
                blockers.append("budget_exceeded")
            action["blocked_by"] = sorted(set(blockers))
            action["state"] = "blocked" if blockers else "planned"
            action["estimated_cost"] = {"requests": cost.requests, "seconds": cost.seconds,
                                        "risk": cost.risk, "weighted": cost.weighted}
            action["score"] = round(action["information_gain"] / max(.1, cost.weighted)
                                    + self.memory.utility_adjustment(action), 6)
            candidates.append(action)
        candidates.sort(key=lambda item: (-item["score"], item["action_id"]))
        selected = candidates[:max(1, min(int(max_actions), 50))]
        return {"goal": goal.objective, "target": goal.target,
                "actions": selected, "gaps": len(candidates),
                "counts": {state: sum(item["state"] == state for item in selected)
                           for state in ("planned", "blocked")}}

    def next_action(self, goal: Goal | str, budget: ExecutionBudget) -> dict | None:
        for action in self.plan(goal, budget, 50)["actions"]:
            if action["state"] == "planned":
                return action
        return None
