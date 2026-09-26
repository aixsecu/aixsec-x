"""Phase 3 planner, reasoning, workflow and SAST→DAST tests."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import auth_context
import security_analysis
import tools
from inventory import Inventory, TestHistory
from ledger import Ledger


def api_data(url):
    return {"operations": [{
        "url": url, "method": "GET", "source": "openapi", "confidence": 1,
        "state": "declared", "metadata": {
            "security": [{"bearer": []}],
            "parameters": [{"name": "id", "in": "query"}]}}]}


class WorkflowHandler(BaseHTTPRequestHandler):
    def _reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path in ("/pay", "/refund"):
            self._reply(200, {"accepted": True})
        else:
            self._reply(404, {})

    def log_message(self, *_args):
        pass


class SecurityAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), WorkflowHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def setUp(self):
        auth_context.reset_contexts(); security_analysis.reset()
        self.inventory, self.history, self.ledger = Inventory(), TestHistory(), Ledger()
        security_analysis.manager().bind(
            self.inventory, self.history, self.ledger,
            {spec.name for spec in tools.TOOL_REGISTRY})

    def test_dynamic_plan_replans_from_history_and_capabilities(self):
        url = self.origin + "/api/orders"
        self.inventory.ingest([{"name": "api_import", "outcome": "ok",
                                "data": api_data(url)}])
        first = security_analysis.manager().plan(max_actions=20)
        auth = next(a for a in first["actions"] if a["capability"] == "authorization_replay")
        self.assertEqual(auth["state"], "blocked")
        self.assertIn("configure_contexts", auth["blocked_by"][0])
        sql = next(a for a in first["actions"] if a["capability"] == "sql_injection_verification")
        self.assertEqual(sql["state"], "planned")
        self.history.add(url, "id", "sqli", "sqli_manual_test", "ok")
        second = security_analysis.manager().plan(max_actions=20)
        sql2 = next(a for a in second["actions"] if a["capability"] == "sql_injection_verification")
        self.assertEqual(sql2["state"], "completed")
        self.assertNotEqual(first["plan_id"], second["plan_id"])
        self.assertEqual(self.inventory.analysis["latest_plan"], second)

    def test_planner_blocks_template_and_post_without_body(self):
        url = self.origin + "/api/orders/{id}"
        data = api_data(url); data["operations"][0]["method"] = "POST"
        self.inventory.ingest([{"name": "api_import", "outcome": "ok", "data": data}])
        plan = security_analysis.manager().plan(max_actions=20)
        sql = next(a for a in plan["actions"] if a["capability"] == "sql_injection_verification")
        self.assertEqual(sql["state"], "blocked")
        self.assertEqual(set(sql["blocked_by"]),
                         {"provide_control_form_or_json_body", "substitute_observed_path_parameters"})

    def test_authorization_reasoning_with_declared_owner(self):
        url = self.origin + "/objects/2"
        observations = {
            "url": url, "method": "GET", "contexts": ["anonymous", "user_A", "user_B"],
            "observations": [
                {"context": "anonymous", "response": {"status": 401}},
                {"context": "user_A", "response": {"status": 200}},
                {"context": "user_B", "response": {"status": 200}}],
            "comparisons": [{"left": "user_A", "right": "user_B",
                             "same_status": True, "same_body_hash": True}],
        }
        self.inventory.ingest([{"name": "auth_compare", "outcome": "ok",
                                "data": observations}])
        result = security_analysis.manager().reason_authorization(
            url, resource_owner="user_B", expected_allowed_contexts=["user_B"])
        kinds = {item["kind"] for item in result["hypotheses"]}
        self.assertIn("cross_subject_object_access", kinds)
        self.assertIn("unexpected_context_access", kinds)
        self.assertIn("cross_context_equivalent_response", kinds)
        self.assertFalse(result["verdicts"])
        self.assertTrue(all(not item["verdict"] for item in result["hypotheses"]))

    def test_anonymous_success_is_hypothesis_not_verdict(self):
        url = self.origin + "/public-or-private"
        self.inventory.ingest([{"name": "auth_compare", "outcome": "ok", "data": {
            "url": url, "method": "GET", "contexts": ["anonymous", "user_A"],
            "observations": [{"context": "anonymous", "response": {"status": 200}},
                             {"context": "user_A", "response": {"status": 200}}],
            "comparisons": []}}])
        hypothesis = security_analysis.manager().reason_authorization(url)["hypotheses"][0]
        self.assertEqual(hypothesis["kind"], "unauthenticated_access")
        self.assertTrue(hypothesis["evidence_gaps"])

    def test_business_sequence_numeric_and_replay_reasoning(self):
        auth_context.manager().configure("user_A", self.origin)
        state = security_analysis.manager()
        state.set_rule("checkout", {"type": "required_before", "before": "approve",
                                    "action": "pay"})
        state.set_rule("checkout", {"type": "numeric_bound", "field": "amount", "min": 0})
        state.set_rule("checkout", {"type": "max_successes", "action": "pay", "max": 1})
        run = state.execute_workflow("checkout", "user_A", [
            {"action": "pay", "inputs": {"amount": -10},
             "request": {"method": "POST", "url": self.origin + "/pay"}},
            {"action": "pay", "inputs": {"amount": 5},
             "request": {"method": "POST", "url": self.origin + "/pay"}}])
        self.assertEqual([o["status"] for o in run["observations"]], [200, 200])
        result = state.reason_business("checkout")
        evidence = " ".join(e for h in result["hypotheses"] for e in h["evidence"])
        self.assertIn("before required", evidence)
        self.assertIn("outside declared bound", evidence)
        self.assertIn("exceeds max", evidence)
        self.assertFalse(result["verdicts"])

    def test_business_transition(self):
        auth_context.manager().configure("user_A", self.origin)
        security_analysis.manager().set_rule(
            "refund", {"type": "state_transition", "allowed": [["paid", "refunded"]]})
        security_analysis.manager().execute_workflow("refund", "user_A", [{
            "action": "refund", "from_state": "created", "to_state": "refunded",
            "request": {"method": "POST", "url": self.origin + "/refund"}}])
        result = security_analysis.manager().reason_business("refund")
        self.assertEqual(len(result["hypotheses"]), 1)
        self.assertIn("undeclared transition", result["hypotheses"][0]["evidence"][0])

    def test_invalid_business_rules_rejected(self):
        for rule in ({"type": "required_before", "action": "pay"},
                     {"type": "max_successes", "action": "pay", "max": 0},
                     {"type": "numeric_bound", "field": "amount"},
                     {"type": "state_transition", "allowed": []}):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                security_analysis.manager().set_rule("checkout", rule)

    def test_sast_structured_output_and_correlation(self):
        url = self.origin + "/api/users"
        self.inventory.ingest([{"name": "api_import", "outcome": "ok",
                                "data": api_data(url)}])
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "users.py"
            source.write_text("cursor.execute(f\"/api/users SELECT {request.args.get('id')}\")\n")
            output, data = tools._sast_scan(src_path=str(source), engine="patterns")
        self.assertIn("SQLi", output)
        self.assertEqual(data["findings"][0]["category"], "sqli")
        self.assertNotIn("SELECT", json.dumps(data))
        security_analysis.manager().ingest_tool_result(
            {"name": "sast_scan", "outcome": "ok", "data": data})
        result = security_analysis.manager().correlate()
        correlation = result["correlations"][0]
        self.assertGreaterEqual(correlation["score"], .8)
        self.assertEqual(correlation["validation"]["capability"], "sql_injection_verification")
        self.assertNotIn("tool", correlation["validation"])
        self.assertEqual(correlation["validation"]["arguments"]["param"], "id")
        self.assertFalse(correlation["verdict"])

    def test_secret_sast_findings_never_correlate(self):
        self.inventory.ingest([{"name": "api_import", "outcome": "ok",
                                "data": api_data(self.origin + "/api/users")}])
        security_analysis.manager().sast_findings = [{"name": "Hardcoded credential",
            "category": "other", "secret": True, "file": "x.py", "line": 1}]
        self.assertEqual(security_analysis.manager().correlate()["correlations"], [])

    def test_analysis_persistence_and_status(self):
        security_analysis.manager().set_rule(
            "checkout", {"type": "max_successes", "action": "pay", "max": 1})
        security_analysis.manager().plan(max_actions=1)
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / "inventory.json")
            self.inventory.save(path)
            loaded = Inventory.load(path)
        self.assertIn("business_rules", loaded.analysis)
        self.assertIn("latest_plan", loaded.analysis)

    def test_tool_wrappers_and_registry(self):
        names = {spec.name for spec in tools.TOOL_REGISTRY}
        expected = {"dynamic_plan", "authorization_reason", "business_rule_set",
                    "business_workflow_test", "business_reason",
                    "sast_dast_correlate", "phase3_status"}
        self.assertTrue(expected <= names)
        text, data = tools._phase3_status()
        self.assertFalse(text.startswith("[!]")); self.assertTrue(data["bound"])


if __name__ == "__main__":
    unittest.main()
