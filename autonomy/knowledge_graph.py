"""Serializable, deterministic knowledge graph for security observations."""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


class NodeKind(str, Enum):
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    AUTH_CONTEXT = "auth_context"
    OBSERVATION = "observation"
    EVIDENCE = "evidence"
    TEST_RESULT = "test_result"
    BUSINESS_RULE = "business_rule"
    HYPOTHESIS = "hypothesis"
    SAST_FINDING = "sast_finding"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def _stable_id(prefix: str, value: Any) -> str:
    return f"{prefix}-" + hashlib.sha256(_canonical(value).encode()).hexdigest()[:20]


@dataclass(frozen=True)
class Node:
    node_id: str
    kind: str
    attributes: dict[str, Any]

    def to_dict(self) -> dict:
        return {"id": self.node_id, "kind": self.kind,
                "attributes": copy.deepcopy(self.attributes)}


@dataclass(frozen=True)
class Edge:
    edge_id: str
    source: str
    relation: str
    target: str
    attributes: dict[str, Any]

    def to_dict(self) -> dict:
        return {"id": self.edge_id, "source": self.source,
                "relation": self.relation, "target": self.target,
                "attributes": copy.deepcopy(self.attributes)}


class KnowledgeGraph:
    """Small dependency-free graph with append-only evidence nodes.

    Node and edge IDs are content-derived when omitted, so rebuilding from the
    same Phase 1-3 state produces the same graph and deterministic replay input.
    """

    SCHEMA_VERSION = 1

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: dict[str, Edge] = {}

    def add_node(self, kind: NodeKind | str, attributes: dict[str, Any],
                 node_id: str | None = None) -> Node:
        kind_value = kind.value if isinstance(kind, NodeKind) else str(kind)
        if kind_value not in {item.value for item in NodeKind}:
            raise ValueError(f"unsupported node kind: {kind_value}")
        attrs = copy.deepcopy(attributes)
        identity = node_id or _stable_id(kind_value, attrs)
        existing = self._nodes.get(identity)
        if existing:
            if existing.kind != kind_value:
                raise ValueError(f"node kind conflict for {identity}")
            if kind_value == NodeKind.EVIDENCE.value and existing.attributes != attrs:
                raise ValueError("evidence nodes are immutable")
            if existing.attributes == attrs:
                return Node(existing.node_id, existing.kind, copy.deepcopy(existing.attributes))
        node = Node(identity, kind_value, attrs)
        self._nodes[identity] = node
        return Node(node.node_id, node.kind, copy.deepcopy(node.attributes))

    def add_edge(self, source: str, relation: str, target: str,
                 attributes: dict[str, Any] | None = None) -> Edge:
        if source not in self._nodes or target not in self._nodes:
            raise KeyError("both edge endpoints must exist")
        attrs = copy.deepcopy(attributes or {})
        identity = _stable_id("edge", [source, relation, target, attrs])
        edge = Edge(identity, source, str(relation), target, attrs)
        self._edges.setdefault(identity, edge)
        return self._edges[identity]

    def get(self, node_id: str) -> Node | None:
        node = self._nodes.get(node_id)
        return None if node is None else Node(node.node_id, node.kind,
                                              copy.deepcopy(node.attributes))

    def query(self, kind: NodeKind | str | None = None, **attributes: Any) -> list[Node]:
        kind_value = kind.value if isinstance(kind, NodeKind) else kind
        values = [node for node in self._nodes.values()
                  if (kind_value is None or node.kind == kind_value)
                  and all(node.attributes.get(key) == value
                          for key, value in attributes.items())]
        return [Node(node.node_id, node.kind, copy.deepcopy(node.attributes))
                for node in sorted(values, key=lambda node: node.node_id)]

    def neighbors(self, node_id: str, relation: str | None = None,
                  direction: str = "out") -> list[Node]:
        if direction not in {"in", "out", "both"}:
            raise ValueError("direction must be in, out, or both")
        ids: set[str] = set()
        for edge in self._edges.values():
            if relation is not None and edge.relation != relation:
                continue
            if direction in {"out", "both"} and edge.source == node_id:
                ids.add(edge.target)
            if direction in {"in", "both"} and edge.target == node_id:
                ids.add(edge.source)
        return [Node(self._nodes[item].node_id, self._nodes[item].kind,
                     copy.deepcopy(self._nodes[item].attributes)) for item in sorted(ids)]

    def edges(self, relation: str | None = None) -> list[Edge]:
        return sorted((edge for edge in self._edges.values()
                       if relation is None or edge.relation == relation),
                      key=lambda edge: edge.edge_id)

    def to_dict(self) -> dict:
        return {"schema_version": self.SCHEMA_VERSION,
                "nodes": [self._nodes[key].to_dict() for key in sorted(self._nodes)],
                "edges": [self._edges[key].to_dict() for key in sorted(self._edges)]}

    @classmethod
    def from_dict(cls, data: dict) -> "KnowledgeGraph":
        if int(data.get("schema_version", 0)) != cls.SCHEMA_VERSION:
            raise ValueError("unsupported knowledge graph schema")
        graph = cls()
        for value in data.get("nodes") or []:
            graph.add_node(value["kind"], value.get("attributes") or {}, value["id"])
        for value in data.get("edges") or []:
            edge = graph.add_edge(value["source"], value["relation"], value["target"],
                                  value.get("attributes") or {})
            if value.get("id") != edge.edge_id:
                raise ValueError("non-deterministic edge id in serialized graph")
        return graph

    def save(self, path: str | Path) -> None:
        Path(path).write_text(_canonical(self.to_dict()) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "KnowledgeGraph":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def from_phase_state(cls, inventory: Any, test_history: Any = None,
                         auth_contexts: Iterable[dict] = ()) -> "KnowledgeGraph":
        graph = cls()
        endpoint_nodes: dict[str, Node] = {}
        for host in sorted(getattr(inventory, "hosts", {}).values(), key=lambda x: x.host):
            for endpoint in sorted(host.endpoints.values(), key=lambda x: x.url):
                enode = graph.add_node(NodeKind.ENDPOINT, {
                    "url": endpoint.url, "methods": sorted(endpoint.methods),
                    "auth_hints": sorted(endpoint.auth_hints),
                    "sources": sorted(endpoint.sources),
                }, _stable_id("endpoint", endpoint.url))
                endpoint_nodes[endpoint.url] = enode
                for name in sorted(endpoint.params):
                    pnode = graph.add_node(NodeKind.PARAMETER,
                        {"name": name, "endpoint": endpoint.url},
                        _stable_id("parameter", [endpoint.url, name]))
                    graph.add_edge(enode.node_id, "accepts", pnode.node_id)
                for index, observation in enumerate(endpoint.auth_observations):
                    onode = graph.add_node(NodeKind.OBSERVATION, copy.deepcopy(observation),
                        _stable_id("observation", [endpoint.url, index, observation]))
                    graph.add_edge(enode.node_id, "has_observation", onode.node_id)
                    evidence = observation.get("evidence")
                    if evidence is not None:
                        evnode = graph.add_node(NodeKind.EVIDENCE,
                            {"value": copy.deepcopy(evidence), "source": "auth_observation"})
                        graph.add_edge(onode.node_id, "supported_by", evnode.node_id)
                for method, operation in sorted(endpoint.api_operations.items()):
                    for index, observation in enumerate(operation.get("observations") or []):
                        value = {"method": method, "channel": "api_discovery",
                                 **copy.deepcopy(observation)}
                        onode = graph.add_node(NodeKind.OBSERVATION, value,
                            _stable_id("api_observation",
                                       [endpoint.url, method, index, observation]))
                        graph.add_edge(enode.node_id, "has_observation", onode.node_id)
        for context in sorted(auth_contexts, key=lambda x: str(x.get("name", ""))):
            safe = {key: copy.deepcopy(value) for key, value in context.items()
                    if key not in {"password", "token", "secret", "headers", "cookies"}}
            graph.add_node(NodeKind.AUTH_CONTEXT, safe,
                           _stable_id("auth_context", safe.get("name", safe)))
        analysis = getattr(inventory, "analysis", {}) or {}
        for workflow, rules in sorted((analysis.get("business_rules") or {}).items()):
            for rule in rules:
                graph.add_node(NodeKind.BUSINESS_RULE,
                               {"workflow": workflow, **copy.deepcopy(rule)})
        for group in ("authorization_hypotheses", "business_hypotheses"):
            for hypothesis in analysis.get(group) or []:
                hypothesis_node = graph.add_node(
                    NodeKind.HYPOTHESIS, copy.deepcopy(hypothesis),
                    hypothesis.get("hypothesis_id"))
                for index, evidence_value in enumerate(hypothesis.get("evidence") or []):
                    evidence_node = graph.add_node(NodeKind.EVIDENCE, {
                        "value": copy.deepcopy(evidence_value),
                        "source": group, "url": hypothesis.get("url", "")},
                        _stable_id("hypothesis_evidence", [hypothesis_node.node_id,
                                                           index, evidence_value]))
                    graph.add_edge(hypothesis_node.node_id, "supported_by",
                                   evidence_node.node_id)
        for finding in analysis.get("sast_findings") or []:
            graph.add_node(NodeKind.SAST_FINDING, copy.deepcopy(finding))
        records = getattr(test_history, "records", []) if test_history else []
        if isinstance(records, dict):
            records = records.values()
        for record in records or []:
            value = record if isinstance(record, dict) else vars(record)
            node = graph.add_node(NodeKind.TEST_RESULT, copy.deepcopy(value))
            endpoint = endpoint_nodes.get(str(value.get("endpoint") or value.get("url") or ""))
            if endpoint:
                graph.add_edge(endpoint.node_id, "has_test_result", node.node_id)
            evidence_id = str(value.get("evidence_id") or "")
            if evidence_id:
                evidence = graph.add_node(NodeKind.EVIDENCE,
                    {"evidence_id": evidence_id, "source": "test_history"}, evidence_id)
                graph.add_edge(node.node_id, "supported_by", evidence.node_id)
        return graph
