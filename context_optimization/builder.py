"""Build bounded action context from Phase 1-4 state."""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass

from autonomy import KnowledgeGraph, PlannerMemory

from .metrics import RuntimeMetrics
from .retrievers import ContextRetriever, EvidenceRetriever, PlannerMemoryRetriever
from .summarizer import ContextSummarizer


@dataclass(frozen=True)
class ContextLimits:
    max_graph_nodes: int = 40
    max_observations: int = 12
    max_hypotheses: int = 6
    max_history: int = 12
    max_evidence: int = 8
    max_memory_successes: int = 4
    max_memory_failures: int = 4


@dataclass(frozen=True)
class ContextRequest:
    goal: str
    endpoint: str = ""
    auth_context: str = ""
    workflow: str = ""
    hypothesis_id: str = ""
    parameter: str = ""


class ContextBuilder:
    def __init__(self, graph: KnowledgeGraph, memory: PlannerMemory | None = None,
                 limits: ContextLimits | None = None,
                 summarizer: ContextSummarizer | None = None) -> None:
        self.graph = graph
        self.memory = memory or PlannerMemory()
        self.limits = limits or ContextLimits()
        self.summarizer = summarizer or ContextSummarizer()

    def build(self, request: ContextRequest, history: list[dict] | None = None,
              metrics: RuntimeMetrics | None = None) -> dict:
        started = time.perf_counter()
        nodes = ContextRetriever(self.graph).retrieve(
            endpoint=request.endpoint, workflow=request.workflow,
            auth_context=request.auth_context, hypothesis_id=request.hypothesis_id,
            max_nodes=self.limits.max_graph_nodes,
            max_observations=self.limits.max_observations,
            max_hypotheses=self.limits.max_hypotheses)
        evidence = EvidenceRetriever(self.graph).retrieve(
            request.hypothesis_id, endpoint=request.endpoint,
            parameter=request.parameter, auth_context=request.auth_context,
            workflow=request.workflow, limit=self.limits.max_evidence)
        memory = PlannerMemoryRetriever(self.memory).retrieve(
            endpoint=request.endpoint, workflow=request.workflow,
            success_limit=self.limits.max_memory_successes,
            failure_limit=self.limits.max_memory_failures)
        ordered_history = list(history or [])
        recent = ordered_history[-self.limits.max_history:]
        old = ordered_history[:-self.limits.max_history]
        context = {
            "protected": {"goal": request.goal, "endpoint": request.endpoint,
                          "auth_context": request.auth_context,
                          "workflow": request.workflow,
                          "hypothesis_id": request.hypothesis_id,
                          "parameter": request.parameter},
            "graph_nodes": [node.to_dict() for node in nodes
                            if node.kind not in {"observation", "evidence"}],
            "observations": [node.to_dict() for node in nodes
                             if node.kind == "observation"],
            "evidence": [node.to_dict() for node in evidence],
            "planner_memory": copy.deepcopy(memory),
            "recent_history": copy.deepcopy(recent),
            "history_summary": self.summarizer.summarize_history(old) if old else {},
        }
        if metrics is not None:
            metrics.retrieved_graph_nodes = len(nodes)
            metrics.retrieved_observations = len(context["observations"])
            metrics.retrieved_evidence = len(context["evidence"])
            metrics.retrieved_planner_memory = len(memory)
            metrics.context_build_ms = round((time.perf_counter() - started) * 1000, 3)
        return context
