import unittest

from capability_registry import Capability, CapabilityRegistry, Provider, registry
from tool_orchestrator import OrchestrationRequest, ToolOrchestrator


class ToolOrchestratorTests(unittest.TestCase):
    def test_selection_uses_all_constraints(self):
        providers = CapabilityRegistry([
            Provider('audit', 'broad', priority=50, cost=4, speed=.3, accuracy=.95,
                     coverage=.95, confidence=.9),
            Provider('audit', 'fast', priority=50, cost=1, speed=.9, accuracy=.8,
                     coverage=.7, confidence=.8),
            Provider('audit', 'browser', priority=100, requires_browser=True,
                     coverage=1, confidence=1),
        ])
        value = ToolOrchestrator(providers, {'broad', 'fast', 'browser'})
        selected = value.candidates(OrchestrationRequest('audit', browser_available=False,
                                    min_coverage=.8, min_confidence=.85))
        self.assertEqual([item.tool for item in selected], ['broad'])

    def test_fallback_uses_next_provider(self):
        providers = CapabilityRegistry([
            Provider('audit', 'first', priority=100),
            Provider('audit', 'second', priority=50),
        ])
        calls = []
        result = ToolOrchestrator(providers).execute(OrchestrationRequest('audit'),
            lambda tool, args: calls.append(tool) or {'outcome': 'error' if tool == 'first' else 'ok'})
        self.assertEqual(calls, ['first', 'second'])
        self.assertEqual(result['outcome'], 'ok')

    def test_multiple_confirmation_runs_all_providers(self):
        providers = CapabilityRegistry([
            Provider('confirm', 'one', confirmation_only=True),
            Provider('confirm', 'two', confirmation_only=True),
        ])
        calls = []
        result = ToolOrchestrator(providers).execute(OrchestrationRequest(
            'confirm', confirmation=True, multiple_confirmation=True),
            lambda tool, args: calls.append(tool) or {'outcome': 'ok', 'name': tool})
        self.assertEqual(set(calls), {'one', 'two'})
        self.assertEqual(len(result['results']), 2)

    def test_capability_chain_runs_prerequisite_first(self):
        calls = []
        result = ToolOrchestrator(registry(), {'sqli_manual_test', 'sqli_blind_extract'}).execute(
            OrchestrationRequest(Capability.BLIND_SQL_INJECTION, {'url': 'https://example.test',
                                 'param': 'id'}, confirmation=True),
            lambda tool, args: calls.append(tool) or {'outcome': 'ok'})
        self.assertEqual(calls, ['sqli_manual_test', 'sqli_blind_extract'])
        self.assertEqual(result['outcome'], 'ok')

    def test_planner_schema_contains_no_tool_names(self):
        schema = ToolOrchestrator.planner_schema({Capability.HEADER_AUDIT,
                                                  Capability.KNOWN_CVE_DETECTION})
        rendered = str(schema)
        self.assertIn('capability_request', rendered)
        self.assertNotIn('zap_baseline', rendered)
        self.assertNotIn('nuclei_scan', rendered)

    def test_default_example_provider_selection(self):
        value = ToolOrchestrator(registry(), {'zap_baseline', 'sqlmap_runner',
                                 'sqli_blind_extract', 'ffuf_dir', 'nuclei_scan'})
        cases = {
            Capability.HEADER_AUDIT: 'zap_baseline',
            Capability.BLIND_SQL_INJECTION: 'sqlmap_runner',
            Capability.DIRECTORY_DISCOVERY: 'ffuf_dir',
            Capability.KNOWN_CVE_DETECTION: 'nuclei_scan',
        }
        for capability, expected in cases.items():
            with self.subTest(capability=capability):
                request = OrchestrationRequest(capability, confirmation=True)
                self.assertEqual(value.candidates(request)[0].tool, expected)


if __name__ == '__main__':
    unittest.main()
