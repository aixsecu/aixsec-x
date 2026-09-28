import json
from pathlib import Path
import tempfile
import unittest

from inventory import Inventory
from technology_capability import TechnologyCapabilityEngine, persist


def inventory(technologies, paths=("/search?q=one",), auth=False):
    inv = Inventory()
    host = inv.ensure_web("https://example.test/", "fixture")
    for technology in technologies:
        inv.add_tech(host, technology, source="http_request", evidence="header:X-Powered-By")
    if auth:
        host.auth_hints.add("cookie")
    for path in paths:
        endpoint = inv.add_endpoint(host, "https://example.test" + path,
                                    method="POST" if "upload" in path or "api/object" in path else "GET",
                                    source="fixture")
        if "?" in path:
            endpoint.params.add(path.split("?", 1)[1].split("=", 1)[0])
    return inv


def decisions(report):
    return {row["payload_family"]: row for row in report["decisions"]}


class TechnologyCapabilityTests(unittest.TestCase):
    def evaluate(self, technologies, paths=("/search?q=one",), mode="balanced", auth=False):
        return TechnologyCapabilityEngine(mode).evaluate(
            inventory(technologies, paths, auth))[2]

    def test_pure_php(self):
        rows = decisions(self.evaluate(["php"], ("/upload", "/download?file=x")))
        self.assertEqual(rows["php-upload"]["decision"], "LIKELY")
        self.assertEqual(rows["java-upload"]["decision"], "POSSIBLE")
        self.assertTrue(rows["php-upload"]["technology_observations"])

    def test_pure_spring(self):
        rows = decisions(self.evaluate(["spring"]))
        self.assertEqual(rows["java-framework-rce"]["decision"], "LIKELY")
        self.assertEqual(rows["php-stream-wrappers"]["decision"], "UNLIKELY")

    def test_pure_aspnet(self):
        rows = decisions(self.evaluate(["asp.net"], ("/default.aspx?__VIEWSTATE=x",), auth=True))
        self.assertEqual(rows["aspnet-viewstate"]["decision"], "LIKELY")
        self.assertEqual(rows["aspnet-session"]["decision"], "LIKELY")

    def test_pure_node(self):
        rows = decisions(self.evaluate(["node.js"], ("/api/object?id=1",)))
        self.assertEqual(rows["node-prototype-pollution"]["decision"], "LIKELY")
        self.assertEqual(rows["python-framework"]["decision"], "POSSIBLE")

    def test_mixed_php_tomcat_keeps_both_stacks(self):
        rows = decisions(self.evaluate(["php", "tomcat"], ("/upload", "/download?file=x")))
        self.assertEqual(rows["php-upload"]["decision"], "LIKELY")
        self.assertEqual(rows["java-upload"]["decision"], "LIKELY")

    def test_mixed_nginx_php_node(self):
        technologies, _, report = TechnologyCapabilityEngine("balanced").evaluate(
            inventory(["nginx", "php", "node.js"], ("/api/object?id=1", "/download?file=x")))
        observed = {row["technology"] for row in technologies["technologies"]}
        self.assertEqual(observed, {"nginx", "php", "node.js"})
        rows = decisions(report)
        self.assertEqual(rows["php-stream-wrappers"]["decision"], "LIKELY")
        self.assertEqual(rows["node-prototype-pollution"]["decision"], "LIKELY")

    def test_unknown_technology_remains_possible_and_thorough_runs_all(self):
        balanced = self.evaluate([], paths=("/download?file=x",))
        self.assertEqual(decisions(balanced)["sql-injection"]["decision"], "LIKELY")
        self.assertEqual(decisions(balanced)["php-stream-wrappers"]["decision"], "POSSIBLE")
        thorough = self.evaluate([], paths=("/",), mode="thorough")
        self.assertTrue(all(row["selected"] for row in thorough["decisions"]))

    def test_absent_surface_skips_specialized_families_in_aggressive_mode(self):
        rows = decisions(self.evaluate(["php"], paths=("/",), mode="aggressive"))
        self.assertFalse(rows["php-upload"]["selected"])
        self.assertIn("attack surface absent: upload", rows["php-upload"]["reason_for_skipping"])

    def test_deterministic_reports_and_scanner_filtering(self):
        engine = TechnologyCapabilityEngine("aggressive")
        inv = inventory(["php"], ("/download?file=x",))
        first = engine.evaluate(inv)
        second = engine.evaluate(inv)
        first[2]["benchmark"]["average_planning_time_ms"] = 0
        second[2]["benchmark"]["average_planning_time_ms"] = 0
        self.assertEqual(first, second)
        items = [{"id": 1, "name": "SQL Injection"},
                 {"id": 2, "name": "GraphQL introspection"},
                 {"id": 3, "name": "Unmapped scanner rule"}]
        kept, skipped, executed = engine.filter_items(items, first[2])
        self.assertEqual([row["id"] for row in kept], [1, 3])
        self.assertEqual(skipped[0]["payload_family"], "graphql")
        self.assertEqual(executed, {"sql-injection"})

    def test_profiles_persist_with_traceable_evidence(self):
        reports = TechnologyCapabilityEngine("balanced").evaluate(
            inventory(["spring"], ("/api?id=1",)))
        with tempfile.TemporaryDirectory() as root:
            paths = persist(root, *reports)
            self.assertEqual(set(paths), {"technology-capabilities.json",
                "planner-capabilities.json", "planner-decisions.json"})
            data = json.loads(Path(paths["planner-decisions.json"]).read_text())
            spring = decisions(data)["java-framework-rce"]
            self.assertTrue(spring["technology_observations"])
            self.assertTrue(spring["attack_surface_evidence"])
            self.assertIn("confidence_threshold", spring)


if __name__ == "__main__":
    unittest.main()
