"""Deterministic token estimation and ordered context pruning."""
from __future__ import annotations

import copy
import json
import math
from typing import Any


def estimate_tokens(value: Any) -> int:
    """Conservative tokenizer-independent estimate, stable across platforms."""
    text = value if isinstance(value, str) else json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    if not text:
        return 0
    # UTF-8 bytes covers Vietnamese and JSON punctuation more safely than chars/4.
    return max(1, math.ceil(len(text.encode("utf-8")) / 3.5))


class TokenBudgetManager:
    def __init__(self, max_prompt_tokens: int = 12000,
                 reserved_completion_tokens: int = 2048) -> None:
        if max_prompt_tokens <= reserved_completion_tokens:
            raise ValueError("max_prompt_tokens must exceed reserved completion tokens")
        self.max_prompt_tokens = int(max_prompt_tokens)
        self.reserved_completion_tokens = int(reserved_completion_tokens)

    @property
    def context_budget(self) -> int:
        return self.max_prompt_tokens - self.reserved_completion_tokens

    def estimate_context(self, context: dict) -> int:
        return estimate_tokens(context)

    def fit_context(self, context: dict, fixed_prompt: Any = "") -> tuple[dict, int]:
        value = copy.deepcopy(context)
        removed = 0
        def over() -> bool:
            return estimate_tokens(fixed_prompt) + estimate_tokens(value) > self.context_budget
        # Required pruning order: old observations, old memory, irrelevant nodes,
        # duplicate evidence. Lists are ranked best-first, so remove from the end.
        for key in ("recent_history", "observations", "planner_memory", "graph_nodes"):
            while over() and value.get(key):
                value[key].pop(); removed += 1
        if over() and value.get("history_summary"):
            value["history_summary"] = {}; removed += 1
        if value.get("evidence"):
            seen = set(); deduped = []
            for evidence in value["evidence"]:
                marker = json.dumps(evidence.get("attributes", evidence), sort_keys=True,
                                    separators=(",", ":"), default=str)
                if marker not in seen:
                    seen.add(marker); deduped.append(evidence)
                else:
                    removed += 1
            value["evidence"] = deduped
        while over() and len(value.get("evidence", [])) > 1:
            value["evidence"].pop(); removed += 1
        # protected is intentionally never truncated, even if the caller sets an
        # impossibly small budget. The caller can inspect the final estimate.
        return value, removed
