"""Fact-only deterministic summaries for old execution observations."""
from __future__ import annotations

from collections import Counter


class ContextSummarizer:
    def summarize_observations(self, observations: list[dict]) -> dict:
        tools = Counter(str(item.get("tool") or item.get("name") or "unknown")
                        for item in observations)
        outcomes = Counter(str(item.get("outcome") or "unknown")
                           for item in observations)
        endpoints = sorted({str(item.get("url") or item.get("endpoint") or "")
                            for item in observations
                            if item.get("url") or item.get("endpoint")})
        return {"observation_count": len(observations),
                "tools": dict(sorted(tools.items())),
                "outcomes": dict(sorted(outcomes.items())),
                "endpoints": endpoints}

    def summarize_history(self, history: list[dict]) -> dict:
        return self.summarize_observations(history)
