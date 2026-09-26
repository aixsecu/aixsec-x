"""Composable prompt parts instead of a growing conversation transcript."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

from .metrics import RuntimeMetrics
from .token_budget import TokenBudgetManager, estimate_tokens


@dataclass(frozen=True)
class PromptParts:
    system: str
    planner: dict | None = None
    tool: str = ""
    policy: str = ""
    reasoning: str = ""


class PromptComposer:
    def __init__(self, budget: TokenBudgetManager) -> None:
        self.budget = budget

    def compose(self, parts: PromptParts, metrics: RuntimeMetrics | None = None) -> list[dict]:
        started = time.perf_counter()
        fixed = {"system": parts.system, "policy": parts.policy,
                 "tool": parts.tool, "reasoning": parts.reasoning}
        planner, removed = self.budget.fit_context(parts.planner or {}, fixed)
        messages = [{"role": "system", "content": parts.system}]
        if parts.policy:
            messages.append({"role": "user", "content": "[POLICY]\n" + parts.policy})
        if planner:
            messages.append({"role": "user", "content": "[PLANNER CONTEXT]\n" +
                             json.dumps(planner, ensure_ascii=False, sort_keys=True,
                                        separators=(",", ":"))})
        if parts.tool:
            messages.append({"role": "user", "content": "[TOOL CONTEXT]\n" + parts.tool})
        if parts.reasoning:
            messages.append({"role": "user", "content": "[CURRENT TASK]\n" + parts.reasoning})
        if metrics is not None:
            joined = json.dumps(messages, ensure_ascii=False, separators=(",", ":"))
            metrics.prompt_chars = len(joined)
            metrics.estimated_tokens = estimate_tokens(joined)
            metrics.pruned_items = removed
            metrics.prompt_build_ms = round((time.perf_counter() - started) * 1000, 3)
        return messages
