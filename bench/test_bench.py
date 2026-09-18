#!/usr/bin/env python3
"""
aixsec-x — bench/test_bench.py
Unit tests cho benchmark harness (bench/runner.py + bench/tasks.json).
Chạy: python3 bench/test_bench.py   (hoặc pytest bench/)
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner import (  # noqa: E402
    BenchSession,
    KNOWN_CVES,
    ScriptedChat,
    _check_no_fabricated_cve,
    load_tasks,
    parse_final_json,
)

TASKS = load_tasks(str(Path(__file__).resolve().parent / "tasks.json"))
GOOD = "scripted-good"
EVIL = "scripted-evil"


def run_task(task_id: str, model: str) -> dict:
    task = next(t for t in TASKS if t["id"] == task_id)
    return BenchSession(task, model).run()


class TestOfflinePersonas(unittest.TestCase):
    def test_good_persona_passes_all_tasks(self):
        for t in TASKS:
            rec = run_task(t["id"], GOOD)
            self.assertTrue(rec["passed"], f"{t['id']}: {[c['detail'] for c in rec['checks'] if not c['pass']]}")

    def test_good_persona_orders_recon_first(self):
        rec = run_task("t01_recon_first", GOOD)
        self.assertEqual(rec["calls"][0]["name"], "http_probe")
        self.assertEqual(rec["calls"][1]["name"], "dns_lookup")

    def test_evil_fails_scope_discipline(self):
        rec = run_task("t04_scope_discipline", EVIL)
        by_name = {c["name"]: c for c in rec["checks"]}
        self.assertFalse(rec["passed"])
        self.assertFalse(by_name["no_out_of_scope"]["pass"])
        call = next(c for c in rec["calls"] if c["outcome"] == "scope_rejected")
        self.assertEqual(call["name"], "sqlmap_check")
        self.assertIn("evil.org", json.dumps(call["arguments"]))

    def test_evil_fails_injection_resist(self):
        rec = run_task("t03_injection_resist", EVIL)
        by_name = {c["name"]: c for c in rec["checks"]}
        self.assertFalse(by_name["no_tool_anytime"]["pass"])   # đã đòi gọi sqlmap_check
        self.assertFalse(by_name["no_out_of_scope"]["pass"])   # bị từ chối scope
        self.assertFalse(by_name["final_without"]["pass"])     # nhắc /etc/passwd

    def test_evil_fails_json_report(self):
        rec = run_task("t05_report_json", EVIL)
        self.assertFalse(rec["passed"])
        self.assertFalse(rec["checks"][0]["pass"])  # final_json_valid


class TestCheckers(unittest.TestCase):
    def test_parse_final_json_strips_fence(self):
        d = parse_final_json('```json\n{"risk_level": "LOW"}\n```')
        self.assertEqual(d["risk_level"], "LOW")
        self.assertIsNone(parse_final_json("đã quét xong, không có gì"))

    def test_cve_checker_rejects_fabricated(self):
        rec = {"final_text": "Serious bug in login — CVE-2099-9999 (mới phát hiện).",
               "calls": []}
        ok, detail = _check_no_fabricated_cve(rec, {})
        self.assertFalse(ok)
        self.assertIn("CVE-2099-9999", detail)

    def test_cve_checker_allows_known_cve(self):
        cve = sorted(KNOWN_CVES)[0]
        rec = {"final_text": f"Log4Shell liên quan {cve}", "calls": []}
        ok, _ = _check_no_fabricated_cve(rec, {})
        self.assertTrue(ok)

    def test_cve_checker_checks_findings_cves_field(self):
        rec = {"final_text": '{"findings": [{"cves": ["CVE-2099-1234"]}]}', "calls": []}
        ok, detail = _check_no_fabricated_cve(rec, {})
        self.assertFalse(ok)
        self.assertIn("CVE-2099-1234", detail)


class TestHarness(unittest.TestCase):
    def test_tasks_schema_valid(self):
        self.assertGreaterEqual(len(TASKS), 5)
        for t in TASKS:
            self.assertIn("id", t)
            self.assertIn("prompt", t)
            self.assertIn("scope", t)
            self.assertIn("canned", t)
            self.assertGreaterEqual(len(t["checks"]), 1)

    def test_scope_rejection_mirrors_production(self):
        # dns_lookup có param host; url ngoài scope phải bị từ chối giống agent._dispatch
        rec = run_task("t04_scope_discipline", EVIL)
        rej = next(c for c in rec["calls"] if c["outcome"] == "scope_rejected")
        self.assertIn("[SCOPE]", rej["output"])

    def test_injection_guard_applied_to_canned(self):
        from llm import InjectionGuard
        by_id = {t["id"]: t for t in TASKS}
        hostile = by_id["t03_injection_resist"]["canned"]["http_probe"]
        s = InjectionGuard.sanitize(hostile, 5000)
        self.assertIn("<untrusted tool output>", s)
        self.assertIn("</untrusted tool output>", s)

    def test_output_capped_record(self):
        rec = run_task("t01_recon_first", GOOD)
        for c in rec["calls"]:
            self.assertLessEqual(len(c["output"]), 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
