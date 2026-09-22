"""Ranked, bounded retrieval from graph, evidence, and planner memory."""
from __future__ import annotations

from typing import Any

from autonomy import KnowledgeGraph, Node, NodeKind, PlannerMemory


def _matches(attributes: dict, value: str, keys: tuple[str, ...]) -> bool:
    return bool(value) and any(str(attributes.get(key) or "") == value for key in keys)


class ContextRetriever:
    """Returns a relevant subgraph; it has no API for dumping the whole graph."""

    def __init__(self, graph: KnowledgeGraph) -> None:
        self.graph = graph

    def retrieve(self, *, endpoint: str = "", workflow: str = "",
                 auth_context: str = "", hypothesis_id: str = "",
                 max_nodes: int = 40, max_observations: int = 12,
                 max_hypotheses: int = 6) -> list[Node]:
        ranked: dict[str, tuple[int, Node]] = {}

        def add(node: Node, score: int) -> None:
            old = ranked.get(node.node_id)
            if old is None or score > old[0]:
                ranked[node.node_id] = (score, node)

        seeds: list[Node] = []
        for node in self.graph.query():
            attrs = node.attributes
            score = 0
            if _matches(attrs, endpoint, ("url", "endpoint")):
                score = 100
            elif _matches(attrs, workflow, ("workflow", "name")):
                score = 90
            elif _matches(attrs, auth_context, ("context", "name", "auth_context")):
                score = 80
            elif node.node_id == hypothesis_id or attrs.get("hypothesis_id") == hypothesis_id:
                score = 70
            if score:
                add(node, score); seeds.append(node)
        for seed in sorted(seeds, key=lambda item: item.node_id):
            for node in self.graph.neighbors(seed.node_id, direction="both"):
                add(node, 60 if node.kind == NodeKind.OBSERVATION.value else 50)
                if node.kind == NodeKind.OBSERVATION.value:
                    for evidence in self.graph.neighbors(node.node_id, "supported_by"):
                        add(evidence, 45)
        observations = 0
        hypotheses = 0
        selected = []
        for _, node in sorted(ranked.values(), key=lambda item: (-item[0], item[1].node_id)):
            if node.kind == NodeKind.OBSERVATION.value:
                if observations >= max_observations:
                    continue
                observations += 1
            if node.kind == NodeKind.HYPOTHESIS.value:
                if hypotheses >= max_hypotheses:
                    continue
                hypotheses += 1
            selected.append(node)
            if len(selected) >= max_nodes:
                break
        return selected


class EvidenceRetriever:
    def __init__(self, graph: KnowledgeGraph) -> None:
        self.graph = graph

    def retrieve(self, hypothesis_id: str, *, endpoint: str = "", parameter: str = "",
                 auth_context: str = "", workflow: str = "", limit: int = 8) -> list[Node]:
        hypothesis = self.graph.get(hypothesis_id) if hypothesis_id else None
        candidates: dict[str, Node] = {}
        if hypothesis:
            for related in self.graph.neighbors(hypothesis.node_id, direction="both"):
                if related.kind == NodeKind.EVIDENCE.value:
                    candidates[related.node_id] = related
                for evidence in self.graph.neighbors(related.node_id, "supported_by"):
                    if evidence.kind == NodeKind.EVIDENCE.value:
                        candidates[evidence.node_id] = evidence
        def rank(node: Node) -> tuple:
            attrs = node.attributes
            score = (50 * _matches(attrs, endpoint, ("url", "endpoint"))
                     + 40 * _matches(attrs, parameter, ("parameter", "param"))
                     + 30 * _matches(attrs, auth_context, ("context", "auth_context"))
                     + 20 * _matches(attrs, workflow, ("workflow",)))
            recency = float(attrs.get("ts") or attrs.get("created_at") or 0)
            return (-score, -recency, node.node_id)
        return sorted(candidates.values(), key=rank)[:max(0, limit)]


class PlannerMemoryRetriever:
    def __init__(self, memory: PlannerMemory) -> None:
        self.memory = memory

    def retrieve(self, *, endpoint: str = "", workflow: str = "",
                 success_limit: int = 4, failure_limit: int = 4) -> list[dict]:
        records = list(self.memory.records.values())
        related = [item for item in records if
                   (endpoint and item.get("endpoint") == endpoint)
                   or (workflow and item.get("workflow") == workflow)]
        pool = related or records
        successes = sorted((item for item in pool if item.get("successes", 0) > 0),
            key=lambda item: (-item.get("successes", 0),
                              -item.get("information_gain", 0), item["strategy_id"]))
        failures = sorted((item for item in pool if item.get("failures", 0) > 0),
            key=lambda item: (-item.get("failures", 0), item["strategy_id"]))
        return [dict(item) for item in successes[:success_limit] + failures[:failure_limit]]
