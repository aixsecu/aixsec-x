import unittest

from capability_registry import Capability, CapabilityRegistry, Provider, registry
from autonomy import Goal, GoalDrivenPlanner, KnowledgeGraph, NodeKind


class CapabilityRegistryTests(unittest.TestCase):
    def test_priority_and_availability_choose_provider(self):
        value=CapabilityRegistry([
            Provider('audit','slow',priority=10,cost=5,speed=.2,accuracy=.9,
                     safe_mode=True),
            Provider('audit','fast',priority=20,cost=1,speed=.9,accuracy=.8,
                     safe_mode=True),
        ])
        self.assertEqual(value.resolve('audit').tool,'fast')
        self.assertEqual(value.resolve('audit',{'slow'}).tool,'slow')

    def test_requirements_are_enforced(self):
        value=CapabilityRegistry([
            Provider('auth','auth-tool',requires_auth=True),
            Provider('browser','browser-tool',requires_browser=True),
            Provider('confirm','confirm-tool',confirmation_only=True),
            Provider('safe','safe-tool',safe_mode=True),
        ])
        self.assertIsNone(value.resolve('auth',auth_available=False))
        self.assertIsNone(value.resolve('browser',browser_available=False))
        self.assertIsNone(value.resolve('confirm'))
        self.assertEqual(value.resolve('confirm',confirmation=True).tool,'confirm-tool')
        self.assertEqual(value.resolve('safe',safe_mode=True).tool,'safe-tool')

    def test_registry_contains_required_capability_metadata(self):
        required={Capability.PASSIVE_HTTP_ANALYSIS,Capability.HEADER_AUDIT,
            Capability.COOKIE_AUDIT,Capability.TLS_ANALYSIS,
            Capability.DIRECTORY_DISCOVERY,Capability.TECHNOLOGY_FINGERPRINTING,
            Capability.STATIC_FILE_DISCOVERY,Capability.XSS_VERIFICATION,
            Capability.SQL_INJECTION_VERIFICATION,Capability.BLIND_SQL_INJECTION,
            Capability.COMMAND_INJECTION,Capability.OPEN_REDIRECT,
            Capability.CRLF_INJECTION,Capability.SSRF_VERIFICATION,
            Capability.PATH_TRAVERSAL,Capability.FILE_UPLOAD_VALIDATION,
            Capability.AUTHORIZATION_REPLAY,Capability.BUSINESS_LOGIC_VALIDATION,
            Capability.CRAWLER,Capability.API_DISCOVERY,Capability.OPENAPI_IMPORT,
            Capability.BROWSER_AUTOMATION,Capability.CREDENTIAL_VALIDATION,
            Capability.RATE_LIMIT_TESTING}
        rows=registry().describe()
        self.assertTrue(required <= {row['capability'] for row in rows})
        for row in rows:
            self.assertTrue({'priority','cost','speed','accuracy','requires_auth',
                'requires_browser','safe_mode','confirmation_only'} <= set(row))

    def test_planner_requests_capability_without_provider_identity(self):
        graph=KnowledgeGraph()
        graph.add_node(NodeKind.ENDPOINT,{'url':'https://example.test/a',
            'methods':['GET'],'auth_hints':[]})
        action=GoalDrivenPlanner(graph,capabilities={Capability.HTTP_OBSERVATION}).next_action(
            Goal('coverage'),__import__('autonomy').ExecutionBudget())
        self.assertEqual(action['capability'],Capability.HTTP_OBSERVATION)
        self.assertNotIn('tool',action)


if __name__ == '__main__':
    unittest.main()
