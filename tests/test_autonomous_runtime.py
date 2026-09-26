import tempfile
import unittest
from pathlib import Path

from autonomy import (AutonomousRuntime, ExecutionBudget, KnowledgeGraph,
                      NodeKind)


class AutonomousRuntimeTests(unittest.TestCase):
    def runtime(self, executor):
        graph = KnowledgeGraph()
        graph.add_node(NodeKind.ENDPOINT, {"url": "https://example.test/a",
                                           "methods": ["GET"], "auth_hints": []})
        return AutonomousRuntime(graph=graph, budget=ExecutionBudget(max_actions=5),
                                 capabilities={"http_request"}, executor=executor)

    def test_loop_checkpoints_and_resumes(self):
        calls = []
        runtime = self.runtime(lambda action: calls.append(action) or
                               {"outcome": "ok", "data": {"status": 200}})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            result = runtime.run("coverage", checkpoint_path=path)
            self.assertEqual(result["status"], "complete")
            self.assertEqual([item["tool"] for item in calls], ["http_request"])
            self.assertTrue(all(item["capability"] == "http_observation" for item in calls))
            resumed = AutonomousRuntime.resume(path, lambda action: {"outcome": "ok"})
            self.assertEqual(resumed.graph.to_dict(), runtime.graph.to_dict())
            self.assertEqual(resumed.journal, runtime.journal)

    def test_replay_does_not_call_executor(self):
        calls = []
        original = self.runtime(lambda action: calls.append(action) or {"outcome": "ok"})
        original.step("coverage")
        replay_calls = []
        replayed = self.runtime(lambda action: replay_calls.append(action))
        replayed.replay(original.journal)
        self.assertEqual(replay_calls, [])
        self.assertEqual(replayed.graph.to_dict(), original.graph.to_dict())

    def test_interrupt_pauses_before_execution(self):
        runtime = self.runtime(lambda action: {"outcome": "ok"})
        result = runtime.run("coverage", should_stop=lambda: True)
        self.assertEqual(result["status"], "paused")
        self.assertEqual(result["stop_reason"], "interrupted")

    def test_discovery_updates_graph_and_replans_for_new_endpoint(self):
        graph = KnowledgeGraph()
        graph.add_node(NodeKind.ENDPOINT, {"url": "https://example.test/",
            "methods": ["GET"], "auth_hints": [], "sources": ["configured_target"]})
        calls = []
        def execute(action):
            calls.append(action["tool"])
            if action["tool"] == "crawler":
                return {"outcome": "ok", "data": {
                    "pages": [{"url": "https://example.test/child", "status": 200}],
                    "links": ["https://example.test/child"]}}
            return {"outcome": "ok"}
        runtime = AutonomousRuntime(graph=graph, budget=ExecutionBudget(max_actions=6),
            capabilities={"http_request", "crawler"}, executor=execute)
        result = runtime.run("coverage")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(calls, ["http_request", "crawler", "http_request"])
        self.assertEqual(len(runtime.graph.query(
            NodeKind.ENDPOINT, url="https://example.test/child")), 1)


if __name__ == "__main__":
    unittest.main()
