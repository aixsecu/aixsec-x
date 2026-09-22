"""Inference and navigation of application workflows from observed traffic."""
from __future__ import annotations

import copy
from collections import defaultdict, deque
from urllib.parse import urlparse


def _label(observation: dict) -> str:
    explicit = observation.get("action") or observation.get("name")
    if explicit:
        return str(explicit).lower()
    path = urlparse(str(observation.get("url") or "")).path.lower()
    for name in ("login", "cart", "checkout", "payment", "logout", "register"):
        if name in path:
            return name
    parts = [part for part in path.split("/") if part]
    return parts[-1] if parts else "root"


class WorkflowModel:
    SCHEMA_VERSION = 1

    def __init__(self) -> None:
        self.states: dict[str, dict] = {}
        self.transitions: dict[tuple[str, str], dict] = {}

    def observe_sequence(self, observations: list[dict], workflow: str = "default") -> None:
        labels = [_label(item) for item in observations]
        for label in labels:
            state = self.states.setdefault(label, {"name": label, "observations": 0,
                                                   "workflows": []})
            state["observations"] += 1
            if workflow not in state["workflows"]:
                state["workflows"].append(workflow)
                state["workflows"].sort()
        for left, right in zip(labels, labels[1:]):
            key = (left, right)
            transition = self.transitions.setdefault(key, {"from": left, "to": right,
                                                            "count": 0, "successes": 0})
            transition["count"] += 1
            transition["successes"] += 1

    def infer_from_runs(self, runs: list[dict]) -> None:
        for run in runs:
            steps = run.get("steps") or run.get("observations") or []
            if isinstance(steps, list):
                self.observe_sequence(steps, str(run.get("workflow") or "default"))

    def next_steps(self, current: str) -> list[dict]:
        values = []
        for (source, _), transition in self.transitions.items():
            if source == current:
                value = copy.deepcopy(transition)
                value["confidence"] = transition["successes"] / max(1, transition["count"])
                values.append(value)
        return sorted(values, key=lambda item: (-item["confidence"], -item["count"], item["to"]))

    def find_path(self, start: str, goal: str) -> list[str]:
        queue = deque([(start, [start])])
        seen = {start}
        adjacency: dict[str, list[str]] = defaultdict(list)
        for source, target in self.transitions:
            adjacency[source].append(target)
        while queue:
            current, path = queue.popleft()
            if current == goal:
                return path
            for target in sorted(adjacency[current]):
                if target not in seen:
                    seen.add(target); queue.append((target, path + [target]))
        return []

    def to_dict(self) -> dict:
        return {"schema_version": self.SCHEMA_VERSION,
                "states": [copy.deepcopy(self.states[key]) for key in sorted(self.states)],
                "transitions": [copy.deepcopy(self.transitions[key])
                                for key in sorted(self.transitions)]}

    @classmethod
    def from_dict(cls, data: dict) -> "WorkflowModel":
        if int(data.get("schema_version", 0)) != cls.SCHEMA_VERSION:
            raise ValueError("unsupported workflow schema")
        model = cls()
        model.states = {item["name"]: dict(item) for item in data.get("states") or []}
        model.transitions = {(item["from"], item["to"]): dict(item)
                             for item in data.get("transitions") or []}
        return model
