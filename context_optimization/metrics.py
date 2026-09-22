"""Runtime metrics emitted by context preparation and LLM calls."""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class RuntimeMetrics:
    prompt_chars: int = 0
    estimated_tokens: int = 0
    retrieved_graph_nodes: int = 0
    retrieved_observations: int = 0
    retrieved_evidence: int = 0
    retrieved_planner_memory: int = 0
    context_build_ms: float = 0.0
    prompt_build_ms: float = 0.0
    llm_latency_ms: float = 0.0
    first_token_latency_ms: float = 0.0
    completion_latency_ms: float = 0.0
    pruned_items: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

