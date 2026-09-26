import unittest

from autonomy import (ActionCost, CostModel, ExecutionBudget, Goal,
                      GoalDrivenPlanner, KnowledgeGraph, NodeKind, PlannerMemory,
                      WorkflowModel)


class GoalPlannerTests(unittest.TestCase):
    def graph(self):
        graph = KnowledgeGraph()
        graph.add_node(NodeKind.ENDPOINT, {"url": "https://example.test/a",
                                           "methods": ["GET"], "auth_hints": []})
        return graph

    def test_selects_gap_and_suppresses_identical_failed_strategy(self):
        graph, memory = self.graph(), PlannerMemory()
        planner = GoalDrivenPlanner(graph, memory, capabilities={"http_request"})
        budget = ExecutionBudget()
        action = planner.next_action(Goal("coverage"), budget)
        self.assertEqual(action["capability"], "http_observation")
        self.assertNotIn("tool", action)
        memory.learn(action, False, reason="network error")
        plan = planner.plan("coverage", budget)
        self.assertIn("identical_strategy_failed", plan["actions"][0]["blocked_by"])

    def test_budget_blocks_action_and_cost_is_configurable(self):
        planner = GoalDrivenPlanner(self.graph(), capabilities={"http_request"},
            cost_model=CostModel({"http_observation": ActionCost(2, 1, .1)}))
        plan = planner.plan("coverage", ExecutionBudget(max_requests=1))
        self.assertEqual(plan["actions"][0]["state"], "blocked")
        self.assertIn("budget_exceeded", plan["actions"][0]["blocked_by"])

    def test_workflow_inference_and_navigation(self):
        workflow = WorkflowModel()
        workflow.observe_sequence([{"url": "/login"}, {"url": "/cart"},
                                   {"url": "/checkout"}, {"url": "/payment"}])
        self.assertEqual(workflow.find_path("login", "payment"),
                         ["login", "cart", "checkout", "payment"])
        self.assertEqual(workflow.next_steps("cart")[0]["to"], "checkout")
        self.assertEqual(WorkflowModel.from_dict(workflow.to_dict()).to_dict(),
                         workflow.to_dict())

    def test_unverified_evidence_requests_validation_not_rescan(self):
        graph = KnowledgeGraph()
        endpoint = graph.add_node(NodeKind.ENDPOINT, {"url": "https://example.test/a",
            "methods": ["GET"], "auth_hints": []})
        evidence = graph.add_node(NodeKind.EVIDENCE, {"evidence_id": "ev-1",
            "category": "SQL Injection", "verification_state": "candidate",
            "confidence": .45, "response_reference": "raw/report.json"}, "ev-1")
        graph.add_edge(endpoint.node_id, "has_evidence", evidence.node_id)
        action = GoalDrivenPlanner(graph, capabilities={"evidence_validate"}).next_action(
            Goal("coverage"), ExecutionBudget())
        self.assertEqual(action["capability"], "evidence_validation")
        self.assertFalse(action["confirmation"])
        self.assertGreater(action["confidence_gain"], 0)

    def test_confirmed_evidence_and_complete_coverage_stop(self):
        graph = KnowledgeGraph()
        endpoint = graph.add_node(NodeKind.ENDPOINT, {"url": "https://example.test/",
            "methods": ["GET"], "auth_hints": [], "sources": ["configured_target"]})
        observation = graph.add_node(NodeKind.OBSERVATION, {"capability": "crawler",
            "outcome": "ok", "state": "observed", "status": "complete"})
        graph.add_edge(endpoint.node_id, "has_observation", observation.node_id)
        evidence = graph.add_node(NodeKind.EVIDENCE, {"evidence_id": "ev-1",
            "category": "Header Audit", "verification_state": "confirmed",
            "confidence": .95, "response_reference": "raw/report.json"}, "ev-1")
        graph.add_edge(endpoint.node_id, "has_evidence", evidence.node_id)
        plan = GoalDrivenPlanner(graph, capabilities={"crawler"}).plan("coverage")
        self.assertEqual(plan["actions"], [])
        self.assertEqual(plan["stop_reason"], "evidence_sufficient")

    def test_successful_capability_strategy_is_not_repeated(self):
        graph, memory = self.graph(), PlannerMemory()
        planner = GoalDrivenPlanner(graph, memory, capabilities={"http_request"})
        action = planner.next_action("coverage", ExecutionBudget())
        memory.learn(action, True, information_gain=1, cost=1)
        repeated = planner.plan("coverage", ExecutionBudget())["actions"][0]
        self.assertIn("identical_strategy_failed", repeated["blocked_by"])

    def test_unsupported_attack_graph_hypothesis_requests_targeted_observation(self):
        graph = KnowledgeGraph()
        graph.add_node(NodeKind.ENDPOINT, {"url": "https://example.test/a",
            "methods": ["GET"], "auth_hints": []})
        graph.add_node(NodeKind.HYPOTHESIS, {"url": "https://example.test/a",
            "category": "authorization"}, "hyp-1")
        plan = GoalDrivenPlanner(graph, capabilities={"http_request"}).plan("coverage")
        targeted = [row for row in plan["actions"] if row["reason"] == "unsupported_hypothesis"]
        self.assertEqual(targeted[0]["capability"], "http_observation")
        self.assertNotIn("tool", targeted[0])


if __name__ == "__main__":
    unittest.main()
