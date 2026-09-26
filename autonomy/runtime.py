"""Checkpointable Observe → Reason → Plan → Execute → Learn runtime."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .cost_model import CostModel, ExecutionBudget
from .goal_planner import Goal, GoalDrivenPlanner
from .knowledge_graph import KnowledgeGraph, NodeKind
from .planner_memory import PlannerMemory
from .workflow_model import WorkflowModel


def _hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class RuntimeState:
    status: str = "ready"
    cycle: int = 0
    goal: dict = field(default_factory=lambda: {"objective": "coverage"})
    last_action_id: str = ""
    stop_reason: str = ""


class AutonomousRuntime:
    """Runs existing actions through a caller-provided, policy-aware executor.

    The runtime never bypasses scope or approval rules. Its executor must be the
    same dispatch boundary used by the interactive agent. Journaled results can
    be replayed without executing tools, preserving deterministic reproduction.
    """

    SCHEMA_VERSION = 1

    def __init__(self, graph: KnowledgeGraph | None = None,
                 memory: PlannerMemory | None = None,
                 workflow: WorkflowModel | None = None,
                 budget: ExecutionBudget | None = None,
                 cost_model: CostModel | None = None,
                 capabilities: set[str] | None = None,
                 executor: Callable[[dict], dict] | None = None) -> None:
        self.graph = graph or KnowledgeGraph()
        self.memory = memory or PlannerMemory()
        self.workflow = workflow or WorkflowModel()
        self.budget = budget or ExecutionBudget()
        self.cost_model = cost_model or CostModel()
        self.capabilities = set(capabilities or ())
        self.executor = executor
        self.state = RuntimeState()
        self.journal: list[dict] = []

    @property
    def planner(self) -> GoalDrivenPlanner:
        return GoalDrivenPlanner(self.graph, self.memory, self.workflow,
                                 self.cost_model, self.capabilities)

    def observe(self, inventory: Any, test_history: Any = None,
                auth_contexts: list[dict] | None = None) -> None:
        self.graph = KnowledgeGraph.from_phase_state(
            inventory, test_history, auth_contexts or [])
        analysis = getattr(inventory, "analysis", {}) or {}
        self.workflow.infer_from_runs(analysis.get("workflow_runs") or [])

    def _record_result(self, action: dict, result: dict, elapsed: float,
                       replayed: bool = False) -> None:
        outcome = str(result.get("outcome") or "error")
        success = outcome == "ok"
        gain = float(result.get("information_gain", 1.0 if success else 0.0))
        cost = self.cost_model.estimate(action)
        self.memory.learn(action, success, gain, cost.weighted,
                          str(result.get("error") or result.get("output") or ""))
        observation = self.graph.add_node(NodeKind.OBSERVATION, {
            "action_id": action["action_id"], "tool": action["tool"],
            "outcome": outcome, "channel": "execution", "result_hash": _hash(result),
        })
        arguments = action.get("arguments") or {}
        target = arguments.get("url")
        if not target and isinstance(arguments.get("request"), dict):
            target = arguments["request"].get("url")
        if target:
            endpoints = self.graph.query(NodeKind.ENDPOINT, url=target)
            if endpoints:
                self.graph.add_edge(endpoints[0].node_id, "has_observation", observation.node_id)
                data = result.get("data") or {}
                if action["tool"] == "auth_compare":
                    for value in data.get("observations") or []:
                        auth_observation = self.graph.add_node(
                            NodeKind.OBSERVATION, copy.deepcopy(value))
                        self.graph.add_edge(endpoints[0].node_id, "has_observation",
                                            auth_observation.node_id)
                        evidence = value.get("evidence")
                        if evidence is not None:
                            evidence_node = self.graph.add_node(NodeKind.EVIDENCE,
                                {"value": copy.deepcopy(evidence),
                                 "source": "auth_compare"})
                            self.graph.add_edge(auth_observation.node_id, "supported_by",
                                                evidence_node.node_id)
        data = result.get("data") or {}
        if success and action["tool"] in {"crawler", "api_discovery", "api_import"}:
            discovered: list[tuple[str, list[str]]] = []
            for page in data.get("pages") or []:
                if isinstance(page, dict) and page.get("url"):
                    discovered.append((str(page["url"]), ["GET"]))
            for link in data.get("links") or []:
                if isinstance(link, str):
                    discovered.append((link, ["GET"]))
            for operation in data.get("operations") or []:
                if isinstance(operation, dict) and operation.get("url"):
                    discovered.append((str(operation["url"]),
                                       [str(operation.get("method") or "GET").upper()]))
            for hint in data.get("js_hints") or []:
                if isinstance(hint, dict) and hint.get("url") and hint.get("in_scope", True):
                    methods = [] if hint.get("method") == "UNKNOWN" else [
                        str(hint.get("method") or "GET").upper()]
                    discovered.append((str(hint["url"]), methods))
            for url, methods in discovered:
                if not self.graph.query(NodeKind.ENDPOINT, url=url):
                    self.graph.add_node(NodeKind.ENDPOINT, {
                        "url": url, "methods": methods, "auth_hints": [],
                        "sources": [action["tool"]]})
        for value in data.get("hypotheses") or []:
            if isinstance(value, dict):
                self.graph.add_node(NodeKind.HYPOTHESIS, copy.deepcopy(value),
                                    value.get("hypothesis_id"))
        entry = {"sequence": len(self.journal) + 1, "action": copy.deepcopy(action),
                 "result": copy.deepcopy(result), "result_hash": _hash(result),
                 "elapsed": round(elapsed, 6)}
        self.journal.append(entry)
        self.state.last_action_id = action["action_id"]
        self.state.cycle += 1

    def step(self, goal: Goal | str) -> dict:
        action = self.planner.next_action(goal, self.budget)
        if action is None:
            self.state.status = "complete"
            self.state.stop_reason = "no_executable_knowledge_gap"
            return {"status": "complete", "reason": self.state.stop_reason}
        if self.executor is None:
            raise RuntimeError("autonomous runtime has no executor")
        cost = self.cost_model.estimate(action)
        started = time.monotonic()
        result = self.executor(copy.deepcopy(action))
        elapsed = time.monotonic() - started
        if not isinstance(result, dict):
            result = {"outcome": "error", "error": "executor returned non-object"}
        self.budget.consume(cost, elapsed)
        self._record_result(action, result, elapsed)
        return {"status": "executed", "action": action, "result": result}

    def run(self, goal: Goal | str = "coverage", max_cycles: int | None = None,
            checkpoint_path: str | Path | None = None,
            checkpoint_every: int = 1,
            should_stop: Callable[[], bool] | None = None) -> dict:
        objective = goal if isinstance(goal, Goal) else Goal(str(goal))
        self.state.goal = {"objective": objective.objective, "target": objective.target,
                           "success_condition": objective.success_condition}
        self.state.status = "running"
        limit = max_cycles if max_cycles is not None else self.budget.max_actions
        while self.state.status == "running" and self.state.cycle < limit:
            if should_stop and should_stop():
                self.state.status, self.state.stop_reason = "paused", "interrupted"
                break
            value = self.step(objective)
            if checkpoint_path and (self.state.cycle % max(1, checkpoint_every) == 0
                                    or self.state.status != "running"):
                self.checkpoint(checkpoint_path)
            if value["status"] == "complete":
                break
        if self.state.status == "running":
            self.state.status, self.state.stop_reason = "paused", "cycle_limit"
        if checkpoint_path:
            self.checkpoint(checkpoint_path)
        return self.status()

    def replay(self, journal: list[dict] | None = None) -> None:
        entries = copy.deepcopy(self.journal if journal is None else journal)
        self.journal = []
        for entry in entries:
            if _hash(entry["result"]) != entry["result_hash"]:
                raise ValueError("replay journal result hash mismatch")
            action = entry["action"]
            cost = self.cost_model.estimate(action)
            self.budget.consume(cost, float(entry.get("elapsed", cost.seconds)))
            self._record_result(action, entry["result"], float(entry.get("elapsed", 0)), True)

    def status(self) -> dict:
        return {"status": self.state.status, "cycle": self.state.cycle,
                "goal": copy.deepcopy(self.state.goal),
                "last_action_id": self.state.last_action_id,
                "stop_reason": self.state.stop_reason,
                "budget": self.budget.to_dict(), "journal_entries": len(self.journal)}

    def to_dict(self) -> dict:
        return {"schema_version": self.SCHEMA_VERSION, "state": vars(self.state),
                "graph": self.graph.to_dict(), "memory": self.memory.to_dict(),
                "workflow": self.workflow.to_dict(), "budget": self.budget.to_dict(),
                "capabilities": sorted(self.capabilities),
                "journal": copy.deepcopy(self.journal)}

    def checkpoint(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".tmp")
        temporary.write_text(json.dumps(self.to_dict(), sort_keys=True, indent=2,
                                        ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temporary, destination)

    @classmethod
    def from_dict(cls, data: dict, executor: Callable[[dict], dict] | None = None,
                  cost_model: CostModel | None = None) -> "AutonomousRuntime":
        if int(data.get("schema_version", 0)) != cls.SCHEMA_VERSION:
            raise ValueError("unsupported autonomy checkpoint schema")
        runtime = cls(KnowledgeGraph.from_dict(data["graph"]),
                      PlannerMemory.from_dict(data["memory"]),
                      WorkflowModel.from_dict(data["workflow"]),
                      ExecutionBudget.from_dict(data["budget"]), cost_model,
                      set(data.get("capabilities") or []), executor)
        runtime.state = RuntimeState(**data.get("state", {}))
        runtime.journal = copy.deepcopy(data.get("journal") or [])
        return runtime

    @classmethod
    def resume(cls, path: str | Path, executor: Callable[[dict], dict] | None = None,
               cost_model: CostModel | None = None) -> "AutonomousRuntime":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        runtime = cls.from_dict(data, executor, cost_model)
        if runtime.state.status in {"paused", "running"}:
            runtime.state.status = "ready"
            runtime.state.stop_reason = ""
        return runtime
