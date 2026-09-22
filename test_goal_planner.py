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
        self.assertEqual(action["tool"], "http_request")
        memory.learn(action, False, reason="network error")
        plan = planner.plan("coverage", budget)
        self.assertIn("identical_strategy_failed", plan["actions"][0]["blocked_by"])

    def test_budget_blocks_action_and_cost_is_configurable(self):
        planner = GoalDrivenPlanner(self.graph(), capabilities={"http_request"},
            cost_model=CostModel({"http_request": ActionCost(2, 1, .1)}))
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


if __name__ == "__main__":
    unittest.main()
