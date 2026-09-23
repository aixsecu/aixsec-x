"""Offline ZAP contract/integration tests. Never scan an external target."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent import WebXAgent
from config import load_config
from evidence import EvidenceStore
from execution_policy import check_action
from inventory import Inventory, TestHistory
from ledger import Ledger
from pipeline import record_result
from scope import ScopePolicy
from tools import TOOL_INDEX
from zap_adapter import build_plan, parse_report, run_scan, within

URL = 'https://example.test/'


def report(rule='40018', risk='3', confidence='4'):
    return {'@version': 'test-fixture', 'site': [{'@name': URL.rstrip('/'), 'alerts': [{
        'pluginid': rule, 'name': 'SQL Injection' if rule == '40018' else 'Content Security Policy (CSP) Header Not Set',
        'riskcode': risk, 'confidence': confidence, 'cweid': '89',
        'instances': [{'uri': URL, 'method': 'GET', 'param': 'id' if rule == '40018' else '',
            'request-header': 'GET / HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer VERY_SECRET\r\n',
            'response-header': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=SECRET\r\n\r\n',
            'response-body': '<html>hello</html>', 'request-body': ''}]}]}]}


def config(directory, **updates):
    value = load_config()
    value.update(targets=[URL], scan_backend='zap', auto_exec='all', evidence_dir=str(directory),
                 zap_executable='/fake/zap', planner_enabled=False, max_rounds=2,
                 zap_allowed_rules=[40018], allow_active_scan=True)
    value.update(updates)
    return value


def scanner_data(directory, fixture=None):
    path = Path(directory) / 'report.json'
    path.write_text(json.dumps(fixture or report()))
    rows, _ = parse_report(path, URL, 'scan-1')
    return {'target': URL, 'alerts': rows, 'endpoints': [URL],
            'coverage': {'tool': 'zap_baseline', 'target': URL, 'status': 'complete', 'auth_context': 'anonymous'}}


class ZapPlanTests(unittest.TestCase):
    def test_baseline_jobs_and_no_active_scan(self):
        with tempfile.TemporaryDirectory() as root:
            plan = build_plan(config(root), URL, root, ajax=True)
            kinds = [j['type'] for j in plan['jobs']]
            self.assertIn('spiderAjax', kinds)
            self.assertIn('passiveScan-wait', kinds)
            self.assertNotIn('activeScan', kinds)
            context = plan['env']['contexts'][0]
            import re
            self.assertIsNotNone(re.fullmatch(context['includePaths'][0], URL))
            self.assertIsNone(re.fullmatch(context['includePaths'][0], 'https://example.test.evil/'))

    def test_active_requires_allowlist_and_disables_other_rules(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = config(root)
            with self.assertRaises(ValueError):
                build_plan(cfg, URL, root, active=True, rule_ids=[999])
            plan = build_plan(cfg, URL, root, active=True, rule_ids=[40018])
            policy = next(j['policyDefinition'] for j in plan['jobs'] if j['type'] == 'activeScan-policy')
            self.assertEqual(policy['defaultThreshold'], 'Off')
            self.assertEqual([r['id'] for r in policy['rules']], [40018])

    def test_external_openapi_reference_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as root:
            spec = Path(root) / 'api.json'
            spec.write_text(json.dumps({'openapi': '3.0.0', 'components': {'$ref': 'https://evil.test/spec'}}))
            with self.assertRaisesRegex(ValueError, 'External OpenAPI'):
                build_plan(config(root, zap_openapi_file=str(spec)), URL, root)

    def test_openapi_local_import_and_cross_origin_servers(self):
        with tempfile.TemporaryDirectory() as root:
            spec = Path(root) / 'source.json'
            spec.write_text(json.dumps({'openapi': '3.0.0', 'paths': {}}))
            cfg = config(root, zap_openapi_file=str(spec))
            self.assertIn('openapi', [j['type'] for j in build_plan(cfg, URL, root)['jobs']])
            job = next(j for j in build_plan(cfg, URL, root)['jobs'] if j['type'] == 'openapi')
            self.assertNotIn('maxMessages', job['parameters'])
            spec.write_text(json.dumps({'openapi': '3.0.0', 'servers': [{'url': 'https://evil.test'}]}))
            with self.assertRaises(ValueError):
                build_plan(cfg, URL, root)

    def test_auth_requires_operator_profile_and_verification(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, 'AUTH_FILE'):
                build_plan(config(root), URL, root, auth_context='user_A')
            profile = Path(root) / 'auth.json'
            profile.write_text(json.dumps({'user_A': {'origin': URL,
                'authentication': {'method': 'form', 'parameters': {'loginRequestUrl': URL + 'login'},
                    'verification': {'method': 'response', 'loggedInRegex': 'logout', 'loggedOutRegex': 'login'}},
                'credential_env': {'username': 'TEST_ZAP_USER', 'password': 'TEST_ZAP_PASS'}}}))
            with patch.dict(os.environ, {'TEST_ZAP_USER': 'alice', 'TEST_ZAP_PASS': 'private'}):
                plan = build_plan(config(root, zap_auth_file=str(profile)), URL, root, auth_context='user_A')
            context = plan['env']['contexts'][0]
            self.assertEqual(context['users'][0]['credentials']['password'], 'private')
            spider = next(j for j in plan['jobs'] if j['type'] == 'spider')
            self.assertEqual(spider['parameters']['user'], 'user_A')

    def test_default_ports_and_credentials(self):
        self.assertTrue(within('https://example.test:443/a', URL))
        self.assertFalse(within('https://example.test:444/a', URL))
        self.assertFalse(within('https://user:password@example.test/', URL))


class ZapEvidenceTests(unittest.TestCase):
    def test_scanner_confidence_cannot_confirm_sqli(self):
        with tempfile.TemporaryDirectory() as root:
            store = EvidenceStore(Ledger(), root)
            store.ingest({'name': 'zap_baseline', 'outcome': 'ok', 'data': scanner_data(root)})
            eid = next(iter(store.records))
            self.assertEqual(store.validate(eid)['status'], 'needs_validation')
            result = store.finish()
            self.assertEqual(result['risk_level'], 'UNKNOWN')
            self.assertEqual(result['candidate_risk_level'], 'HIGH')
            saved = Path(result['evidence_path']).read_text()
            self.assertNotIn('VERY_SECRET', saved)
            self.assertNotIn('_response_header', saved)

    def test_missing_header_has_deterministic_validator(self):
        with tempfile.TemporaryDirectory() as root:
            store = EvidenceStore(Ledger())
            store.ingest({'name': 'zap_baseline', 'outcome': 'ok', 'data': scanner_data(root, report('10038', '2'))})
            store.validate(next(iter(store.records)))
            self.assertEqual(store.finish()['risk_level'], 'MEDIUM')
            self.assertEqual(store.finish()['findings'][0]['status'], 'confirmed')

    def test_existing_header_or_login_redirect_does_not_confirm(self):
        for header in ('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Security-Policy: default-src self\r\n',
                       'HTTP/1.1 302 Found\r\nContent-Type: text/html\r\n'):
            with tempfile.TemporaryDirectory() as root:
                fixture = report('10038', '2')
                fixture['site'][0]['alerts'][0]['instances'][0]['response-header'] = header
                store = EvidenceStore(Ledger())
                store.ingest({'name': 'zap_baseline', 'outcome': 'ok', 'data': scanner_data(root, fixture)})
                store.validate(next(iter(store.records)))
                self.assertEqual(store.finish()['risk_level'], 'UNKNOWN')

    def test_duplicates_do_not_confirm_and_auth_contexts_stay_separate(self):
        with tempfile.TemporaryDirectory() as root:
            data = scanner_data(root)
            store = EvidenceStore(Ledger())
            for _ in range(2):
                store.ingest({'name': 'zap_baseline', 'outcome': 'ok', 'data': data})
            self.assertEqual(len(store.candidates), 1)
            self.assertEqual(len(store.records), 1)
            other = copy.deepcopy(data)
            other['alerts'][0]['auth_context'] = 'user_B'
            store.ingest({'name': 'zap_baseline', 'outcome': 'ok', 'data': other})
            self.assertEqual(len(store.candidates), 2)
            self.assertTrue(all(f.status == 'candidate' for f in store.candidates.values()))

    def test_bad_report_and_cross_origin_alerts(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'report.json'
            path.write_text('{}')
            with self.assertRaises(ValueError):
                parse_report(path, URL, 'scan')
            fixture = report()
            fixture['site'][0]['alerts'][0]['instances'][0]['uri'] = 'https://evil.test/'
            path.write_text(json.dumps(fixture))
            rows, metadata = parse_report(path, URL, 'scan')
            self.assertEqual(rows, [])
            self.assertEqual(metadata['rejected_out_of_origin'], 1)

    def test_private_arguments_and_sqlmap_policy(self):
        self.assertIsNotNone(check_action({}, 'zap_baseline', {'_config': {}}, None))
        self.assertIsNotNone(check_action({'allow_sqlmap': True}, 'sqlmap_runner', {'url': URL}, EvidenceStore(Ledger())))
        self.assertIsNotNone(check_action({}, 'sqli_blind_extract', {'action': 'dump'}))
        self.assertIsNotNone(check_action({'allow_content_discovery': False}, 'ffuf_dir', {}))

    def test_replay_rejects_unknown_id_and_changed_scope(self):
        with tempfile.TemporaryDirectory() as root:
            store = EvidenceStore(Ledger())
            with self.assertRaises(ValueError):
                store.replay('fake', ScopePolicy([URL]))
            store.ingest({'name': 'zap_baseline', 'outcome': 'ok', 'data': scanner_data(root)})
            with self.assertRaisesRegex(ValueError, 'outside current scope'):
                store.replay(next(iter(store.records)), ScopePolicy(['https://other.test']))


class ZapPipelineTests(unittest.TestCase):
    def test_baseline_runs_before_model_and_model_cannot_invent_finding(self):
        events = []
        with tempfile.TemporaryDirectory() as root:
            data = {'target': URL, 'alerts': [], 'endpoints': [URL], 'coverage': {
                    'tool': 'zap_baseline', 'target': URL, 'status': 'complete'}}
            def baseline(**kwargs):
                events.append('baseline')
                return 'zero alerts', data
            def model(*args, **kwargs):
                events.append('model')
                return {'content': json.dumps({'risk_level': 'CRITICAL', 'findings': [
                    {'name': 'ZAP Domain Scan', 'severity': 'critical'}]}), 'tool_calls': []}
            agent = WebXAgent(config(root, planner_enabled=True), chat=model)
            with patch.object(TOOL_INDEX['zap_baseline'], 'exec_fn', baseline), contextlib.redirect_stdout(io.StringIO()):
                result = agent.run('scan')
            self.assertEqual(events, ['baseline', 'model'])
            self.assertEqual(result['findings'], [])
            self.assertEqual(agent.ledger.all(), [])
            self.assertEqual(result['risk_level'], 'UNKNOWN')
            self.assertEqual(len(result['coverage']), 1)

    def test_model_timeout_preserves_scanner_evidence_and_graph(self):
        with tempfile.TemporaryDirectory() as root:
            data = scanner_data(root)
            model = MagicMock(return_value={'content': '[!] Ollama first-token timeout.', 'tool_calls': []})
            agent = WebXAgent(config(root, planner_enabled=True), chat=model)
            with patch.object(TOOL_INDEX['zap_baseline'], 'exec_fn', return_value=('scan', data)), contextlib.redirect_stdout(io.StringIO()):
                result = agent.run('scan')
            self.assertTrue(result['llm_down'])
            self.assertEqual(len(result['findings']), 1)
            self.assertEqual(result['risk_level'], 'UNKNOWN')
            self.assertEqual(model.call_count, 2)
            graph = json.dumps(agent.inventory.analysis['knowledge_graph'])
            self.assertIn('supported_by', graph)
            self.assertNotIn('VERY_SECRET', graph)

    def test_baseline_only_never_calls_model_and_denial_is_coverage(self):
        with tempfile.TemporaryDirectory() as root:
            model = MagicMock()
            agent = WebXAgent(config(root, auto_exec='safe'), chat=model)
            with contextlib.redirect_stdout(io.StringIO()):
                result = agent.run('scan')
            model.assert_not_called()
            self.assertEqual(result['coverage'][0]['status'], 'denied')
            self.assertEqual(result['findings'], [])

    def test_partial_scan_not_reported_as_complete(self):
        with tempfile.TemporaryDirectory() as root:
            data = scanner_data(root)
            data['coverage']['status'] = 'timeout'
            agent = WebXAgent(config(root))
            with patch.object(TOOL_INDEX['zap_baseline'], 'exec_fn', return_value=('timeout', data)), contextlib.redirect_stdout(io.StringIO()):
                result = agent.run('scan')
            self.assertEqual(result['coverage'][0]['status'], 'timeout')
            self.assertEqual(len(result['findings']), 1)

    def test_action_budget_limits_multiple_targets(self):
        with tempfile.TemporaryDirectory() as root:
            agent = WebXAgent(config(root, targets=[URL, 'https://other.test'], pipeline_max_actions=1))
            with patch.object(TOOL_INDEX['zap_baseline'], 'exec_fn', return_value=('scan', scanner_data(root))) as tool, contextlib.redirect_stdout(io.StringIO()):
                result = agent.run('scan')
            self.assertEqual(tool.call_count, 1)
            self.assertEqual(result['budget']['actions'], 1)
            self.assertEqual(result['coverage'][-1]['status'], 'blocked')


class ZapExecutorTests(unittest.TestCase):
    def test_process_report_lifecycle_and_secret_plan_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            def launch(argv, **kwargs):
                plan_path = Path(argv[-1])
                plan = json.loads(plan_path.read_text())
                dest = plan_path.parent
                (dest / 'report.json').write_text(json.dumps(report()))
                (dest / 'urls.txt').write_text(URL + '\n')
                (dest / 'traffic.har').write_text(json.dumps({'log': {'entries': []}}))
                self.assertTrue(kwargs['start_new_session'])
                self.assertNotIn('activeScan', [j['type'] for j in plan['jobs']])
                process = MagicMock()
                process.wait.return_value = 0
                return process
            with patch('zap_adapter.executable', return_value='/fake/zap'), patch('zap_adapter.subprocess.Popen', side_effect=launch):
                text, data = run_scan(config(root), URL)
            self.assertEqual(data['coverage']['status'], 'complete')
            self.assertEqual(len(data['alerts']), 1)
            self.assertEqual(list(Path(root).glob('*/plan.yaml')), [])
            self.assertEqual(Path(data['coverage']['report_path']).stat().st_mode & 0o777, 0o600)

    def test_timeout_stops_owned_process_and_keeps_partial_report(self):
        import subprocess
        with tempfile.TemporaryDirectory() as root:
            proc = MagicMock(pid=12345, returncode=-15)
            proc.wait.side_effect = [subprocess.TimeoutExpired('zap', 1), -15]
            def launch(argv, **kwargs):
                dest = Path(argv[-1]).parent
                (dest / 'report.json').write_text(json.dumps(report()))
                return proc
            with patch('zap_adapter.executable', return_value='/fake/zap'), patch('zap_adapter.subprocess.Popen', side_effect=launch), patch('zap_adapter.os.killpg') as kill:
                _, data = run_scan(config(root), URL, timeout=1)
            kill.assert_called_once()
            self.assertEqual(data['coverage']['status'], 'timeout')
            self.assertEqual(len(data['alerts']), 1)


class ZapAdditionalContracts(unittest.TestCase):
    def test_malformed_rule_ids_are_blocked_instead_of_crashing_dispatch(self):
        for value in ([[40018]], '40018', [True], [None]):
            self.assertIsNotNone(check_action({'allow_active_scan': True, 'zap_allowed_rules': [40018]},
                'zap_active_scan', {'rule_ids': value}))

    def test_false_positive_alert_is_not_a_candidate(self):
        with tempfile.TemporaryDirectory() as root:
            data = scanner_data(root, report(confidence='0'))
            self.assertEqual(data['alerts'], [])

    def test_http_fallback_does_not_imply_full_scan_coverage(self):
        with tempfile.TemporaryDirectory() as root:
            agent = WebXAgent(config(root, scan_backend='auto'))
            with patch('pipeline.executable', return_value=None), patch.object(TOOL_INDEX['http_request'], 'exec_fn',
                    return_value=('HTTP 200', {'url': URL, 'status': 200})), contextlib.redirect_stdout(io.StringIO()):
                result = agent.run('scan')
            self.assertEqual(result['coverage'][0]['status'], 'partial')
            self.assertEqual(result['findings'], [])

    def test_unverified_auth_prevents_complete_coverage(self):
        with tempfile.TemporaryDirectory() as root:
            def launch(argv, **kwargs):
                dest = Path(argv[-1]).parent
                (dest / 'report.json').write_text(json.dumps(report()))
                (dest / 'urls.txt').write_text(URL)
                return MagicMock(wait=MagicMock(return_value=0))
            with patch('zap_adapter.executable', return_value='/fake/zap'), patch('zap_adapter.build_plan', return_value={'env': {}, 'jobs': []}), patch('zap_adapter.subprocess.Popen', side_effect=launch):
                _, data = run_scan(config(root), URL, auth_context='user_A')
            self.assertEqual(data['coverage']['auth_state'], 'unverified')
            self.assertEqual(data['coverage']['status'], 'partial')
            self.assertEqual(data['alerts'][0]['auth_state'], 'unverified')

    def test_actual_replay_isolated_and_does_not_confirm_sql_injection(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(dict(self.headers))
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<html>hello</html>')
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            url = f'http://127.0.0.1:{server.server_port}/'
            with tempfile.TemporaryDirectory() as root:
                fixture = report()
                fixture['site'][0]['@name'] = url.rstrip('/')
                fixture['site'][0]['alerts'][0]['instances'][0]['uri'] = url
                path = Path(root) / 'report.json'
                path.write_text(json.dumps(fixture))
                rows, _ = parse_report(path, url, 'scan')
                store = EvidenceStore(Ledger())
                store.ingest({'name': 'zap_baseline', 'outcome': 'ok', 'data': {'alerts': rows}})
                eid = next(iter(store.records))
                result = store.replay(eid, ScopePolicy([url]))
                self.assertTrue(result['body_matches_capture'])
                self.assertFalse(result['verdict'])
                self.assertNotIn('Authorization', received[0])
                self.assertNotIn('Cookie', received[0])
                self.assertEqual(store.finish()['risk_level'], 'UNKNOWN')
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


class MacLauncherTests(unittest.TestCase):
    def test_default_launcher_discovers_application_bundle(self):
        from zap_adapter import executable
        with patch('zap_adapter.sys.platform', 'darwin'), patch('zap_adapter.shutil.which', return_value=None), patch('zap_adapter.Path.is_file', side_effect=lambda: True), patch('zap_adapter.os.access', side_effect=lambda p, mode: str(p).startswith('/Applications/')):
            self.assertEqual(executable({}), '/Applications/ZAP.app/Contents/MacOS/ZAP.sh')

    def test_explicit_missing_launcher_does_not_silently_fallback(self):
        from zap_adapter import executable
        with patch('zap_adapter.sys.platform', 'darwin'), patch('zap_adapter.shutil.which', return_value=None), patch('zap_adapter.Path.is_file', return_value=False):
            self.assertIsNone(executable({'zap_executable': '/missing/custom-zap'}))


class MacCliCommandTests(unittest.TestCase):
    def test_app_bundle_uses_bundled_java_and_jar(self):
        from zap_adapter import launch_command
        with tempfile.TemporaryDirectory() as root:
            contents = Path(root) / 'ZAP.app' / 'Contents'
            (contents / 'MacOS').mkdir(parents=True)
            (contents / 'Java').mkdir()
            java = contents / 'PlugIns' / 'jre' / 'Contents' / 'Home' / 'bin' / 'java'
            java.parent.mkdir(parents=True)
            java.touch()
            java.chmod(0o700)
            jar = contents / 'Java' / 'zap-2.17.0.jar'
            jar.touch()
            with patch('zap_adapter.sys.platform', 'darwin'):
                cmd = launch_command(str(contents / 'MacOS' / 'ZAP.sh'))
            self.assertEqual(cmd[0], str(java))
            self.assertEqual(cmd[-2:], ['-jar', str(jar)])
            self.assertIn('-Djava.awt.headless=true', cmd)

    def test_non_bundle_launcher_is_unchanged(self):
        from zap_adapter import launch_command
        self.assertEqual(launch_command('/opt/zap.sh'), ['/opt/zap.sh'])


class LinuxLauncherTests(unittest.TestCase):
    def test_kali_prefers_zaproxy_on_path(self):
        from zap_adapter import executable, launch_command
        with patch('zap_adapter.sys.platform', 'linux'), patch('zap_adapter.shutil.which', side_effect=lambda name: '/usr/bin/' + name):
            self.assertEqual(executable({}), '/usr/bin/zaproxy')
            self.assertEqual(launch_command(executable({})), ['/usr/bin/zaproxy'])

    def test_upstream_launcher_on_path(self):
        from zap_adapter import executable
        with patch('zap_adapter.sys.platform', 'linux'), patch('zap_adapter.shutil.which', side_effect=lambda name: '/opt/ZAP/zap.sh' if name == 'zap.sh' else None):
            self.assertEqual(executable({}), '/opt/ZAP/zap.sh')

    def test_kali_launcher_outside_path(self):
        from zap_adapter import executable
        with patch('zap_adapter.sys.platform', 'linux'), patch('zap_adapter.shutil.which', return_value=None), patch('zap_adapter.Path.is_file', return_value=True), patch('zap_adapter.os.access', side_effect=lambda path, mode: path == '/usr/share/zaproxy/zap.sh'):
            self.assertEqual(executable({}), '/usr/share/zaproxy/zap.sh')

    def test_explicit_missing_override_is_not_replaced(self):
        from zap_adapter import executable
        with patch('zap_adapter.sys.platform', 'linux'), patch('zap_adapter.shutil.which', side_effect=lambda name: '/usr/bin/zaproxy' if name == 'zaproxy' else None), patch('zap_adapter.Path.is_file', return_value=False):
            self.assertIsNone(executable({'zap_executable': '/Applications/ZAP.app/Contents/MacOS/ZAP.sh'}))

    def test_explicit_custom_launcher_wins(self):
        from zap_adapter import executable
        with patch('zap_adapter.sys.platform', 'linux'), patch('zap_adapter.shutil.which', return_value=None), patch('zap_adapter.Path.is_file', return_value=True), patch('zap_adapter.os.access', return_value=True):
            self.assertEqual(executable({'zap_executable': '/opt/custom/zap.sh'}), '/opt/custom/zap.sh')

    def test_no_installation_returns_none(self):
        from zap_adapter import executable
        with patch('zap_adapter.sys.platform', 'linux'), patch('zap_adapter.shutil.which', return_value=None), patch('zap_adapter.Path.is_file', return_value=False):
            self.assertIsNone(executable({}))
