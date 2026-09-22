"""Persisted planner learning, intentionally separate from target evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def strategy_fingerprint(action: dict) -> str:
    args = action.get("arguments") or {}
    # Values can contain credentials; only stable argument shape and target are retained.
    safe = {"tool": action.get("tool"), "goal": action.get("goal"),
            "hypothesis_id": action.get("hypothesis_id"),
            "argument_keys": sorted(args),
            "target": args.get("url") or args.get("target") or ""}
    raw = json.dumps(safe, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


class PlannerMemory:
    SCHEMA_VERSION = 1

    def __init__(self, records: dict[str, dict] | None = None) -> None:
        self.records = records or {}

    def learn(self, action: dict, success: bool, information_gain: float = 0.0,
              cost: float = 0.0, reason: str = "") -> dict:
        key = strategy_fingerprint(action)
        record = self.records.setdefault(key, {"strategy_id": key,
            "tool": action.get("tool", ""), "attempts": 0, "successes": 0,
            "failures": 0, "information_gain": 0.0, "cost": 0.0,
            "last_failure_reason": "",
            "endpoint": str((action.get("arguments") or {}).get("url") or
                            ((action.get("arguments") or {}).get("request") or {}).get("url") or ""),
            "workflow": str(action.get("workflow") or "")})
        record["attempts"] += 1
        record["successes" if success else "failures"] += 1
        record["information_gain"] += max(0.0, float(information_gain))
        record["cost"] += max(0.0, float(cost))
        if not success:
            record["last_failure_reason"] = str(reason)[:240]
        return dict(record)

    def should_attempt(self, action: dict, retry_failed: bool = False) -> bool:
        record = self.records.get(strategy_fingerprint(action))
        return not record or record["failures"] == 0 or record["successes"] > 0 or retry_failed

    def utility_adjustment(self, action: dict) -> float:
        record = self.records.get(strategy_fingerprint(action))
        if not record:
            return 0.0
        if record["attempts"] == 0:
            return 0.0
        return (record["successes"] - record["failures"]) / record["attempts"]

    def to_dict(self) -> dict:
        return {"schema_version": self.SCHEMA_VERSION,
                "records": {key: dict(self.records[key]) for key in sorted(self.records)}}

    @classmethod
    def from_dict(cls, data: dict) -> "PlannerMemory":
        if int(data.get("schema_version", 0)) != cls.SCHEMA_VERSION:
            raise ValueError("unsupported planner memory schema")
        return cls({str(k): dict(v) for k, v in (data.get("records") or {}).items()})

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), sort_keys=True, indent=2) + "\n",
                              encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "PlannerMemory":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
