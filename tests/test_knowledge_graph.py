import tempfile
import unittest
from pathlib import Path

from autonomy import KnowledgeGraph, NodeKind
from inventory import Inventory


class KnowledgeGraphTests(unittest.TestCase):
    def test_queries_edges_serialization_and_evidence_immutability(self):
        graph = KnowledgeGraph()
        endpoint = graph.add_node(NodeKind.ENDPOINT, {"url": "https://example.test/a"})
        evidence = graph.add_node(NodeKind.EVIDENCE, {"status": 200}, "evidence-one")
        graph.add_edge(endpoint.node_id, "supported_by", evidence.node_id)
        evidence.attributes["status"] = 500
        self.assertEqual(graph.get("evidence-one").attributes["status"], 200)
        with self.assertRaises(ValueError):
            graph.add_node(NodeKind.EVIDENCE, {"status": 500}, "evidence-one")
        self.assertEqual(graph.neighbors(endpoint.node_id)[0].node_id, "evidence-one")
        restored = KnowledgeGraph.from_dict(graph.to_dict())
        self.assertEqual(restored.to_dict(), graph.to_dict())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "graph.json"
            graph.save(path)
            self.assertEqual(KnowledgeGraph.load(path).to_dict(), graph.to_dict())

    def test_builds_endpoint_parameter_and_auth_observation(self):
        inventory = Inventory()
        endpoint = inventory.ensure_web("https://example.test/a").add_endpoint(
            "https://example.test/a")
        endpoint.methods.add("GET"); endpoint.params.add("id")
        endpoint.auth_observations.append({"context": "anonymous", "status": 401,
                                           "evidence": {"digest": "abc"}})
        graph = KnowledgeGraph.from_phase_state(inventory, auth_contexts=[{"name": "anonymous"}])
        self.assertEqual(len(graph.query(NodeKind.ENDPOINT)), 1)
        self.assertEqual(len(graph.query(NodeKind.PARAMETER)), 1)
        self.assertEqual(len(graph.query(NodeKind.AUTH_CONTEXT)), 1)
        self.assertEqual(len(graph.query(NodeKind.EVIDENCE)), 1)


if __name__ == "__main__":
    unittest.main()
