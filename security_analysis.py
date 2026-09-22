"""Adaptive security planning and evidence-bound reasoning runtime.

The LLM may request these primitives, but cannot promote a hypothesis to a
confirmed vulnerability. This module plans and correlates; active observations
come from existing HTTP/auth tools or the bounded workflow executor below.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

import auth_context
import http_engine as he
from autonomy import (ExecutionBudget, Goal, GoalDrivenPlanner, KnowledgeGraph,
                      PlannerMemory, WorkflowModel)

SUCCESS = range(200, 300)
MAX_RULES = 100
MAX_WORKFLOW_STEPS = 20


def _id(prefix: str, value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()
    return prefix + "-" + hashlib.sha256(raw).hexdigest()[:12]


def _category(name: str) -> str:
    value = name.lower()
    mappings = (
        ("sql", "sqli"), ("xss", "xss"), ("cross-site", "xss"),
        ("command", "command_injection"), ("rce", "rce"),
        ("ssrf", "ssrf"), ("lfi", "path_traversal"),
        ("file", "path_traversal"), ("deserial", "deserialization"),
        ("ssti", "ssti"), ("upload", "file_upload"),
    )
    return next((category for marker, category in mappings if marker in value), "other")


def _success(status: Any) -> bool:
    return isinstance(status, int) and status in SUCCESS


@dataclass
class SecurityAnalysisState:
    inventory: Any = None
    test_history: Any = None
    ledger: Any = None
    capabilities: set[str] = field(default_factory=set)
    rules: dict[str, list[dict]] = field(default_factory=dict)
    workflow_runs: list[dict] = field(default_factory=list)
    sast_findings: list[dict] = field(default_factory=list)
    planner_memory: PlannerMemory = field(default_factory=PlannerMemory)
    workflow_model: WorkflowModel = field(default_factory=WorkflowModel)

    def reset(self) -> None:
        self.inventory = self.test_history = self.ledger = None
        self.capabilities = set()
        self.rules = {}
        self.workflow_runs = []
        self.sast_findings = []
        self.planner_memory = PlannerMemory()
        self.workflow_model = WorkflowModel()

    def bind(self, inventory, test_history, ledger, capabilities=None) -> None:
        self.inventory, self.test_history, self.ledger = inventory, test_history, ledger
        self.capabilities = set(capabilities or ())
        persisted = getattr(inventory, "analysis", {}) if inventory else {}
        self.rules = dict(persisted.get("business_rules") or {})
        self.workflow_runs = list(persisted.get("workflow_runs") or [])
        self.sast_findings = list(persisted.get("sast_findings") or [])
        memory = persisted.get("planner_memory")
        self.planner_memory = PlannerMemory.from_dict(memory) if memory else PlannerMemory()
        self.workflow_model = WorkflowModel()
        self.workflow_model.infer_from_runs(self.workflow_runs)

    def _sync(self, key: str, value: Any) -> None:
        if self.inventory is not None:
            self.inventory.analysis[key] = value

    def ingest_tool_result(self, result: dict) -> None:
        if result.get("outcome") != "ok" or result.get("name") != "sast_scan":
            return
        data = result.get("data") or {}
        for finding in data.get("findings") or []:
            if isinstance(finding, dict) and finding not in self.sast_findings:
                self.sast_findings.append(finding)
        self._sync("sast_findings", self.sast_findings)

    # ── dynamic planner ──
    def plan(self, goal: str = "coverage", max_actions: int = 12) -> dict:
        if self.inventory is None or self.test_history is None:
            raise ValueError("Phase 3 planner is not bound to an agent session")
        goal = goal if goal in {"coverage", "authorization", "business_logic",
                                "sast_dast"} else "custom"
        max_actions = max(1, min(int(max_actions), 50))
        actions = []

        def add(priority, tool, args, reason, hypothesis="", blocked_by=None):
            if tool not in self.capabilities:
                state = "blocked"
                blocked = ["tool_unavailable"]
            else:
                state = "planned"
                blocked = list(blocked_by or [])
                if blocked:
                    state = "blocked"
            endpoint = str(args.get("url") or "")
            param = str(args.get("param") or "")
            vuln = {"auth_compare": "authorization", "authorization_reason": "authorization",
                    "sqli_manual_test": "sqli", "http_request": "recon",
                    "api_discovery": "recon"}.get(tool, "")
            if endpoint and self.test_history.already_tested(endpoint, param, vuln):
                state, blocked = "completed", ["already_tested"]
            action = {"priority": priority, "tool": tool, "arguments": args,
                      "reason": reason, "hypothesis_id": hypothesis,
                      "state": state, "blocked_by": blocked}
            action["action_id"] = _id("act", action)
            actions.append(action)

        for operation in self.inventory.api_inventory():
            url, method = operation["url"], operation["method"]
            observations = operation.get("observations") or []
            declared_security = any((o.get("metadata") or {}).get("security")
                                    for o in observations)
            endpoint = self.inventory.host(url).endpoints.get(url)
            if declared_security and endpoint and not endpoint.auth_observations:
                configured = {item["name"] for item in auth_context.manager().list()}
                missing = [name for name in ("anonymous", "user_A")
                           if name not in configured]
                add(95, "auth_compare", {"contexts": ["anonymous", "user_A"],
                    "request": {"url": url, "method": method}},
                    "Protected API operation has no cross-context observation yet",
                    blocked_by=(["configure_contexts:" + ",".join(missing)] if missing else []))
            parameters = sorted(endpoint.params) if endpoint else []
            if parameters and method in ("GET", "POST"):
                for parameter in parameters[:3]:
                    blockers = []
                    if method == "POST":
                        blockers.append("provide_control_form_or_json_body")
                    if "{" in url:
                        blockers.append("substitute_observed_path_parameters")
                    add(55, "sqli_manual_test", {"url": url, "param": parameter,
                        "method": method.lower()},
                        "Discovered input has no SQL injection validation record",
                        blocked_by=blockers)
            if not any(o.get("state") == "observed" for o in observations):
                blockers = ["substitute_observed_path_parameters"] if "{" in url else []
                add(35, "http_request", {"url": url, "method": method.lower()},
                    "Declared/candidate operation has not been directly observed",
                    blocked_by=blockers)

        for host in self.inventory.hosts.values():
            for endpoint in host.endpoints.values():
                if endpoint.auth_observations:
                    hid = _id("hyp", [endpoint.url, "authorization"])
                    add(100, "authorization_reason", {"url": endpoint.url},
                        "Authorization observations are ready for evidence-bound reasoning", hid)

        for correlation in self.correlate(max_results=50)["correlations"]:
            validation = correlation.get("validation") or {}
            if validation.get("tool"):
                add(85, validation["tool"], validation.get("arguments") or {},
                    "SAST sink correlates with a discovered DAST operation",
                    correlation["correlation_id"], validation.get("blocked_by"))

        # Phase 4 chooses knowledge gaps by expected information gain and cost.
        # Legacy validation candidates remain in the returned shape so Phase 3
        # callers keep their API and already-tested semantics.
        graph = KnowledgeGraph.from_phase_state(
            self.inventory, self.test_history, auth_context.manager().list())
        budget = ExecutionBudget(max_actions=max_actions, max_requests=500,
                                 max_seconds=3600, max_risk=20)
        intelligent = GoalDrivenPlanner(
            graph, self.planner_memory, self.workflow_model,
            capabilities=self.capabilities).plan(Goal(goal), budget, max_actions=50)
        known = {(item["tool"], json.dumps(item["arguments"], sort_keys=True,
                                           default=str)) for item in actions}
        for candidate in intelligent["actions"]:
            key = (candidate["tool"], json.dumps(candidate["arguments"],
                                                  sort_keys=True, default=str))
            if key not in known:
                candidate["priority"] = int(candidate["score"] * 10)
                candidate["hypothesis_id"] = ""
                actions.append(candidate)
                known.add(key)
        actions.sort(key=lambda item: (-item.get("score", item.get("priority", 0) / 100),
                                       item["action_id"]))
        selected = actions[:max_actions]
        result = {"plan_id": _id("plan", [goal, selected]), "goal": goal,
                  "generated_at": round(time.time(), 2), "actions": selected,
                  "counts": {state: sum(a["state"] == state for a in selected)
                             for state in ("planned", "blocked", "completed")}}
        self._sync("latest_plan", result)
        self._sync("planner_memory", self.planner_memory.to_dict())
        return result

    # ── authorization reasoning ──
    def reason_authorization(self, url: str = "", resource_owner: str = "",
                             expected_allowed_contexts=None) -> dict:
        if self.inventory is None:
            raise ValueError("Phase 3 reasoner is not bound to an agent session")
        expected = set(expected_allowed_contexts or [])
        records = [x for x in self.inventory.auth_inventory()
                   if not url or x.get("url") == url]
        hypotheses = []
        for record in records:
            by_context = {o.get("context"): o for o in record.get("observations", [])}
            for context, observation in by_context.items():
                status = (observation.get("response") or {}).get("status")
                if context == "anonymous" and _success(status):
                    hypotheses.append(self._hypothesis(
                        "unauthenticated_access", record["url"], "supported",
                        .75, [f"anonymous received HTTP {status}"],
                        ["Confirm endpoint is intended to require authentication"]))
                if expected and context not in expected and _success(status):
                    hypotheses.append(self._hypothesis(
                        "unexpected_context_access", record["url"], "supported",
                        .85, [f"{context} received HTTP {status}",
                              f"declared allowed contexts: {sorted(expected)}"],
                        ["Verify declared policy and resource ownership independently"]))
                if resource_owner and context != resource_owner and context != "anonymous" \
                        and _success(status):
                    hypotheses.append(self._hypothesis(
                        "cross_subject_object_access", record["url"], "supported",
                        .9, [f"declared owner={resource_owner}",
                             f"observer={context} received HTTP {status}"],
                        ["Repeat with a control object owned by the observer",
                         "Confirm response represents the protected object, not a generic envelope"]))
            for pair in record.get("comparisons", []):
                left, right = pair.get("left"), pair.get("right")
                if left != "anonymous" and right != "anonymous" \
                        and pair.get("same_status") and pair.get("same_body_hash"):
                    statuses = [(by_context.get(x, {}).get("response") or {}).get("status")
                                for x in (left, right)]
                    if all(_success(status) for status in statuses):
                        hypotheses.append(self._hypothesis(
                            "cross_context_equivalent_response", record["url"], "testable",
                            .55, [f"{left} and {right} received identical successful bodies"],
                            ["Provide declared resource owner to evaluate horizontal authorization"]))
        result = {"hypotheses": self._dedupe_hypotheses(hypotheses),
                  "basis": "structured_auth_observations", "verdicts": False}
        self._sync("authorization_hypotheses", result["hypotheses"])
        return result

    @staticmethod
    def _hypothesis(kind, url, status, confidence, evidence, gaps):
        value = {"kind": kind, "url": url, "status": status,
                 "confidence": confidence, "evidence": evidence,
                 "evidence_gaps": gaps, "verdict": False}
        value["hypothesis_id"] = _id("hyp", [kind, url, evidence])
        return value

    @staticmethod
    def _dedupe_hypotheses(values):
        output = []
        seen = set()
        for value in values:
            key = (value["kind"], value["url"], tuple(value["evidence"]))
            if key not in seen:
                seen.add(key); output.append(value)
        return output

    # ── business workflow ──
    def set_rule(self, workflow: str, rule: dict) -> dict:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", workflow or ""):
            raise ValueError("invalid workflow name")
        if not isinstance(rule, dict) or rule.get("type") not in {
                "required_before", "max_successes", "numeric_bound", "state_transition"}:
            raise ValueError("unsupported business rule type")
        kind = rule["type"]
        if kind == "required_before" and not all(
                isinstance(rule.get(key), str) and rule.get(key)
                for key in ("before", "action")):
            raise ValueError("required_before needs before and action")
        if kind == "max_successes" and (not isinstance(rule.get("action"), str)
                or not isinstance(rule.get("max"), int) or rule["max"] < 1):
            raise ValueError("max_successes needs action and integer max >= 1")
        if kind == "numeric_bound" and (not isinstance(rule.get("field"), str)
                or not any(isinstance(rule.get(key), (int, float))
                           for key in ("min", "max"))):
            raise ValueError("numeric_bound needs field and numeric min or max")
        if kind == "state_transition":
            allowed = rule.get("allowed")
            if not isinstance(allowed, list) or not allowed or not all(
                    isinstance(pair, list) and len(pair) == 2
                    and all(isinstance(value, str) and value for value in pair)
                    for pair in allowed):
                raise ValueError("state_transition needs non-empty string pairs in allowed")
        if sum(len(values) for values in self.rules.values()) >= MAX_RULES:
            raise ValueError("too many business rules")
        value = dict(rule)
        value["rule_id"] = _id("rule", [workflow, value])
        bucket = self.rules.setdefault(workflow, [])
        if value not in bucket:
            bucket.append(value)
        self._sync("business_rules", self.rules)
        return value

    def execute_workflow(self, workflow: str, context_name: str, steps: list[dict]) -> dict:
        if workflow not in self.rules:
            raise ValueError("workflow has no declared rules")
        if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_WORKFLOW_STEPS:
            raise ValueError(f"workflow requires 1..{MAX_WORKFLOW_STEPS} steps")
        context = auth_context.manager().get(context_name)
        observations = []
        for index, step in enumerate(steps):
            if not isinstance(step, dict) or not step.get("action") \
                    or not isinstance(step.get("request"), dict):
                raise ValueError("each workflow step needs action and request")
            response, record = context._request(step["request"], record=True)
            evidence = context.evidence(record)
            observations.append({
                "index": index, "action": str(step["action"]),
                "resource": str(step.get("resource") or ""),
                "inputs": he.EvidenceRedactor().redact_json(
                    dict(step.get("inputs") or {})),
                "from_state": str(step.get("from_state") or ""),
                "to_state": str(step.get("to_state") or ""),
                "status": response.status_code,
                "response": {"final_url": evidence.get("final_url", ""),
                             "body_sha256": hashlib.sha256(response.content).hexdigest(),
                             "length": len(response.content)},
                "evidence": evidence,
            })
        run = {"run_id": _id("run", [workflow, context_name, observations]),
               "workflow": workflow, "context": context_name,
               "observations": observations, "created_at": round(time.time(), 2)}
        self.workflow_runs.append(run)
        self._sync("workflow_runs", self.workflow_runs)
        return run

    def reason_business(self, workflow: str) -> dict:
        rules = self.rules.get(workflow) or []
        runs = [run for run in self.workflow_runs if run["workflow"] == workflow]
        hypotheses = []
        for run in runs:
            successful = [o for o in run["observations"] if _success(o["status"])]
            for rule in rules:
                kind = rule["type"]
                if kind == "required_before":
                    before, action = rule.get("before"), rule.get("action")
                    seen = False
                    for observation in run["observations"]:
                        if observation["action"] == before and _success(observation["status"]):
                            seen = True
                        if observation["action"] == action and _success(observation["status"]) and not seen:
                            hypotheses.append(self._business_hypothesis(rule, run, observation,
                                f"{action} succeeded before required {before}"))
                elif kind == "max_successes":
                    matches = [o for o in successful if o["action"] == rule.get("action")]
                    if len(matches) > int(rule.get("max", 1)):
                        hypotheses.append(self._business_hypothesis(rule, run, matches[-1],
                            f"successful executions={len(matches)} exceeds max={rule.get('max', 1)}"))
                elif kind == "numeric_bound":
                    for observation in successful:
                        value = observation["inputs"].get(rule.get("field"))
                        if isinstance(value, (int, float)) and (
                                (rule.get("min") is not None and value < rule["min"]) or
                                (rule.get("max") is not None and value > rule["max"])):
                            hypotheses.append(self._business_hypothesis(rule, run, observation,
                                f"accepted {rule.get('field')}={value} outside declared bound"))
                elif kind == "state_transition":
                    allowed = {tuple(x) for x in rule.get("allowed") or [] if len(x) == 2}
                    for observation in successful:
                        pair = (observation["from_state"], observation["to_state"])
                        if all(pair) and pair not in allowed:
                            hypotheses.append(self._business_hypothesis(rule, run, observation,
                                f"accepted undeclared transition {pair[0]} -> {pair[1]}"))
        result = {"workflow": workflow, "rules": rules, "runs": len(runs),
                  "hypotheses": self._dedupe_hypotheses(hypotheses),
                  "verdicts": False}
        self._sync("business_hypotheses", result["hypotheses"])
        return result

    def _business_hypothesis(self, rule, run, observation, evidence):
        value = self._hypothesis("business_rule_deviation",
                                 observation["response"]["final_url"], "supported",
                                 .8, [evidence, f"HTTP {observation['status']}",
                                     f"rule_id={rule['rule_id']}", f"run_id={run['run_id']}"],
                                 ["Confirm server-side state changed as represented by the response"])
        value["rule_id"], value["run_id"] = rule["rule_id"], run["run_id"]
        return value

    # ── SAST -> DAST ──
    def correlate(self, max_results: int = 30) -> dict:
        max_results = max(1, min(int(max_results), 200))
        operations = self.inventory.api_inventory() if self.inventory is not None else []
        correlations = []
        for finding in self.sast_findings:
            category = finding.get("category") or _category(str(finding.get("name") or ""))
            if category == "other" or finding.get("secret"):
                continue
            for operation in operations:
                score, reasons = .0, []
                path = str(operation.get("url") or "")
                route = str(finding.get("route") or "")
                if route and route in path:
                    score += .55; reasons.append("route_match")
                params = set(finding.get("parameters") or [])
                endpoint = self.inventory.host(path).endpoints.get(path)
                common = params & set(endpoint.params if endpoint else [])
                if common:
                    score += .3; reasons.append("parameter_match:" + ",".join(sorted(common)))
                filename = str(finding.get("file") or "").rsplit("/", 1)[-1].split(".", 1)[0].lower()
                if filename and filename in path.lower():
                    score += .1; reasons.append("filename_path_hint")
                if not route and not params:
                    score += .1; reasons.append("category_only")
                if score < .25:
                    continue
                validation = self._validation(category, path, operation.get("method"), sorted(common))
                value = {"sast_finding": finding, "operation": {"url": path,
                         "method": operation.get("method")}, "category": category,
                         "score": round(min(score, 1.), 2), "reasons": reasons,
                         "validation": validation, "verdict": False}
                value["correlation_id"] = _id("corr", [finding, path, category])
                correlations.append(value)
        correlations.sort(key=lambda x: (-x["score"], x["correlation_id"]))
        result = {"correlations": correlations[:max_results],
                  "sast_findings": len(self.sast_findings),
                  "api_operations": len(operations), "verdicts": False}
        self._sync("sast_dast_correlations", result["correlations"])
        return result

    @staticmethod
    def _validation(category, url, method, parameters):
        parameter = parameters[0] if parameters else ""
        if category == "sqli" and parameter:
            return {"tool": "sqli_manual_test", "arguments": {
                    "url": url, "method": str(method or "GET").lower(), "param": parameter},
                    "blocked_by": []}
        return {"tool": "http_request", "arguments": {
                "url": url, "method": str(method or "GET").lower()},
                "blocked_by": ["manual_payload_and_control_required"],
                "note": "Correlation is a lead; preserve a control/payload pair and do not infer exploitability from SAST alone"}

    def status(self) -> dict:
        return {"bound": self.inventory is not None, "rules": sum(map(len, self.rules.values())),
                "workflow_runs": len(self.workflow_runs),
                "sast_findings": len(self.sast_findings),
                "analysis_keys": sorted((self.inventory.analysis if self.inventory else {}).keys())}


_state = SecurityAnalysisState()


def manager() -> SecurityAnalysisState:
    return _state


def reset() -> None:
    _state.reset()
