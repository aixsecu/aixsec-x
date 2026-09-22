import json
import unittest

from autonomy import KnowledgeGraph, NodeKind, PlannerMemory
from context_optimization import (ContextBuilder, ContextLimits, ContextRequest,
    ContextRetriever, ContextSummarizer, EvidenceRetriever, PlannerMemoryRetriever,
    PromptComposer, PromptParts, RuntimeMetrics, TokenBudgetManager, estimate_tokens)


class ContextRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.graph = KnowledgeGraph()
        self.current = self.graph.add_node(NodeKind.ENDPOINT,
            {"url": "https://example.test/current"}, "endpoint-current")
        self.other = self.graph.add_node(NodeKind.ENDPOINT,
            {"url": "https://example.test/other"}, "endpoint-other")
        self.hypothesis = self.graph.add_node(NodeKind.HYPOTHESIS,
            {"hypothesis_id": "hyp-one", "url": "https://example.test/current"}, "hyp-one")
        self.observation = self.graph.add_node(NodeKind.OBSERVATION,
            {"url": "https://example.test/current", "context": "user_A"}, "obs-one")
        self.evidence = self.graph.add_node(NodeKind.EVIDENCE,
            {"url": "https://example.test/current", "parameter": "id", "ts": 2}, "ev-one")
        self.graph.add_edge(self.current.node_id, "has_observation", self.observation.node_id)
        self.graph.add_edge(self.hypothesis.node_id, "based_on", self.observation.node_id)
        self.graph.add_edge(self.observation.node_id, "supported_by", self.evidence.node_id)

    def test_relevant_subgraph_excludes_unrelated_endpoint(self):
        nodes = ContextRetriever(self.graph).retrieve(
            endpoint="https://example.test/current", max_nodes=10)
        ids = {node.node_id for node in nodes}
        self.assertIn("endpoint-current", ids)
        self.assertIn("obs-one", ids)
        self.assertNotIn("endpoint-other", ids)

    def test_evidence_is_directly_bound_to_hypothesis(self):
        values = EvidenceRetriever(self.graph).retrieve(
            "hyp-one", endpoint="https://example.test/current", parameter="id")
        self.assertEqual([item.node_id for item in values], ["ev-one"])

    def test_builder_limits_and_metrics(self):
        metrics = RuntimeMetrics()
        context = ContextBuilder(self.graph, limits=ContextLimits(
            max_graph_nodes=3, max_observations=1, max_history=2)).build(
                ContextRequest("authorization", "https://example.test/current",
                               hypothesis_id="hyp-one"),
                [{"tool": "a", "outcome": "ok"},
                 {"tool": "b", "outcome": "error"},
                 {"tool": "c", "outcome": "ok"}], metrics)
        self.assertEqual(context["protected"]["goal"], "authorization")
        self.assertLessEqual(metrics.retrieved_graph_nodes, 3)
        self.assertEqual(len(context["recent_history"]), 2)
        self.assertEqual(context["history_summary"]["observation_count"], 1)


class MemorySummaryBudgetTests(unittest.TestCase):
    def test_memory_retrieval_prefers_related_success_then_failure(self):
        memory = PlannerMemory()
        good = {"tool": "http_request", "arguments": {"url": "https://x/a"}}
        bad = {"tool": "crawler", "arguments": {"url": "https://x/a"}}
        unrelated = {"tool": "http_request", "arguments": {"url": "https://x/b"}}
        memory.learn(good, True, 2); memory.learn(bad, False); memory.learn(unrelated, True, 9)
        values = PlannerMemoryRetriever(memory).retrieve(endpoint="https://x/a")
        self.assertEqual([item["tool"] for item in values], ["http_request", "crawler"])

    def test_summary_is_deterministic_and_fact_only(self):
        values = [{"tool": "crawler", "outcome": "ok", "url": "/a"},
                  {"tool": "crawler", "outcome": "error", "url": "/b"}]
        summarizer = ContextSummarizer()
        self.assertEqual(summarizer.summarize_observations(values),
                         summarizer.summarize_observations(list(values)))
        self.assertEqual(summarizer.summarize_observations(values)["tools"], {"crawler": 2})

    def test_budget_prunes_optional_data_and_never_protected(self):
        context = {"protected": {"goal": "coverage", "endpoint": "/current",
                                  "auth_context": "user_A", "hypothesis_id": "h"},
                   "recent_history": [{"x": "z" * 500} for _ in range(5)],
                   "observations": [{"x": "z" * 500} for _ in range(5)],
                   "planner_memory": [{"x": "z" * 500} for _ in range(5)],
                   "graph_nodes": [{"x": "z" * 500} for _ in range(5)],
                   "evidence": [{"attributes": {"digest": "same"}},
                                {"attributes": {"digest": "same"}}],
                   "history_summary": {"count": 10}}
        fitted, removed = TokenBudgetManager(1000, 300).fit_context(context, "fixed")
        self.assertEqual(fitted["protected"], context["protected"])
        self.assertGreater(removed, 0)
        self.assertEqual(len(fitted["evidence"]), 1)

    def test_prompt_composition_and_metrics(self):
        metrics = RuntimeMetrics()
        messages = PromptComposer(TokenBudgetManager(2000, 400)).compose(
            PromptParts("system", {"protected": {"goal": "g"}},
                        "tool facts", "scope", "next action"), metrics)
        self.assertEqual([item["role"] for item in messages],
                         ["system", "user", "user", "user", "user"])
        self.assertGreater(metrics.estimated_tokens, 0)
        self.assertEqual(metrics.estimated_tokens,
                         estimate_tokens(json.dumps(messages, ensure_ascii=False,
                                                    separators=(",", ":"))))


class ContextIntegrationTests(unittest.TestCase):
    def test_agent_rebuilds_smaller_deterministic_prompt(self):
        from agent import WebXAgent
        class Chat:
            def __init__(self): self.messages = None; self.tools = None
            def __call__(self, messages, tools=None, **kwargs):
                self.messages, self.tools = messages, tools
                return {"content": "{}", "tool_calls": []}
        chat = Chat()
        config = {"ollama_url": "http://x", "model": "m", "max_rounds": 1,
            "tool_timeout": 10, "output_cap": 5000,
            "targets": ["https://example.test/"], "src_dirs": [],
            "auto_exec": "all", "temperature": .1, "num_ctx": 4096, "db": {},
            "context_optimization": True, "max_prompt_tokens": 3000,
            "reserved_completion_tokens": 500, "context_max_tools": 8}
        agent = WebXAgent(config=config, chat=chat)
        original = [{"role": "system", "content": "old" * 10000}]
        original.extend({"role": "user", "content": "history" * 3000}
                        for _ in range(10))
        first = agent._prepare_llm_messages(original, "cover current endpoint", [])
        second = agent._prepare_llm_messages(original, "cover current endpoint", [])
        self.assertEqual(first, second)
        self.assertLess(len(json.dumps(first)), len(json.dumps(original)) // 10)
        self.assertIn("cover current endpoint", json.dumps(first))
        self.assertIn("https://example.test/", json.dumps(first))
        agent._chat_contextual(original, "cover current endpoint", tools=[])
        self.assertLessEqual(len(chat.tools), 8)
        self.assertGreater(agent.context_runtime_metrics()["estimated_tokens"], 0)


if __name__ == "__main__":
    unittest.main()
