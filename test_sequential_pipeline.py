"""Offline scheduling/checkpoint tests: no scanner or external target is contacted."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from agent import WebXAgent
from config import load_config
from tools import TOOL_INDEX
from scan_state import ScannerHistory, RunLock

URL = 'https://example.test/'
TEMPLATE = {'id':'fixture', 'sha256':'abcd', 'path':'/unused/template.yaml', 'scope':'origin'}


def config(root, **updates):
    cfg = load_config()
    cfg.update(targets=[URL], scan_backend='zap', evidence_dir=root, auto_exec='all', planner_enabled=False,
               nuclei_enabled=True, allow_active_scan=True, zap_allowed_rules=[40018])
    cfg.update(updates)
    return cfg


def baseline(root):
    path = Path(root)/'seed-source.har'
    path.write_text(json.dumps({'log':{'entries':[
        {'request':{'url':URL+'search?q=one','method':'GET','headers':[]},
         'response':{'status':200,'content':{'text':'ok'}}},
        {'request':{'url':URL+'search?q=two','method':'GET','headers':[]},
         'response':{'status':200,'content':{'text':'ok'}}}]}}))
    return ('baseline', {'coverage':{'tool':'zap_baseline','target':URL,'status':'complete',
             'har_path':str(path),'auth_context':'anonymous'}, 'alerts':[],
             'active_rules':[{'id':40018,'name':'SQLi'}]})


class SequentialTests(unittest.TestCase):
    def test_sequence_continues_after_zap_timeout_and_ignores_total_budgets(self):
        with tempfile.TemporaryDirectory() as root:
            order=[]
            def active(**kw):
                order.append('zap')
                return 'timeout', {'coverage':{'status':'timeout'},'alerts':[]}
            def nuclei(**kw):
                order.append('nuclei')
                self.assertEqual(kw['_templates'], [TEMPLATE])
                return 'nuclei', {'coverage':{'status':'complete'}, 'alerts':[]}
            agent=WebXAgent(config(root,pipeline_max_actions=1,pipeline_max_seconds=1,pipeline_max_requests=1))
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=baseline(root)), \
                 patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',side_effect=active), \
                 patch.object(TOOL_INDEX['nuclei_scan'],'exec_fn',side_effect=nuclei), \
                 patch('adapters.nuclei.catalog',return_value=([TEMPLATE],{'status':'complete'})), \
                 contextlib.redirect_stdout(io.StringIO()):
                result=agent.run('scan')
            self.assertEqual(order,['zap','nuclei'])
            self.assertEqual(result['progress']['stages']['zap_active']['status'],'partial')
            self.assertEqual(result['progress']['stages']['nuclei']['status'],'complete')
            self.assertIsNone(result['budget']['max_seconds'])

    def test_resume_completed_actions_restores_candidates_without_network(self):
        with tempfile.TemporaryDirectory() as root:
            cfg=config(root)
            report={'coverage':{'status':'complete'},'alerts':[{'rule_id':'nuclei:fixture','category':'Fixture exposure',
                'severity':'medium','url':URL,'method':'GET','scan_id':'fixture'}]}
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=baseline(root)) as b, \
                 patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',return_value=('ok',{'coverage':{'status':'complete'}})) as z, \
                 patch.object(TOOL_INDEX['nuclei_scan'],'exec_fn',return_value=('matched',report)) as n, \
                 patch('adapters.nuclei.catalog',return_value=([TEMPLATE],{'status':'complete'})), \
                 contextlib.redirect_stdout(io.StringIO()):
                first=WebXAgent(cfg).run('scan')
                cfg={**cfg,'resume_session':str(Path(first['progress']['path']).parent)}
                second=WebXAgent(cfg).run('continue')
            self.assertEqual((b.call_count,z.call_count,n.call_count),(1,1,1))
            self.assertEqual(len(second['findings']),1)
            self.assertNotEqual(second['findings'][0]['status'],'confirmed')
            self.assertEqual(second['calls'],0)

    def test_interrupt_resumes_active_action_without_repeating_discovery(self):
        with tempfile.TemporaryDirectory() as root:
            cfg=config(root,nuclei_enabled=False)
            agent=WebXAgent(cfg)
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=baseline(root)) as b, \
                 patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',side_effect=KeyboardInterrupt), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt): agent.run('scan')
            resume=str(agent.evidence_store.directory)
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn') as b, \
                 patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',return_value=('ok',{'coverage':{'status':'complete'}})) as z, \
                 contextlib.redirect_stdout(io.StringIO()):
                result=WebXAgent({**cfg,'resume_session':resume}).run('continue')
            b.assert_not_called(); self.assertEqual(z.call_count,1)
            self.assertEqual(result['progress']['status'],'complete')

    def test_history_distinguishes_scanners_rules_and_auth_family(self):
        with tempfile.TemporaryDirectory() as root:
            h=ScannerHistory(root,'default')
            h.finish('zap','anonymous-family',['40018'],'complete')
            self.assertEqual(h.remaining('nuclei','anonymous-family',['40018']),['40018'])
            self.assertEqual(h.remaining('zap','other-user-family',['40018']),['40018'])
            self.assertEqual(h.remaining('zap','anonymous-family',['40018','40012']),['40012'])

    def test_same_namespace_concurrent_run_rejected(self):
        with tempfile.TemporaryDirectory() as root, RunLock(root,'same'):
            with self.assertRaises(ValueError):
                with RunLock(root,'same'): pass

    def test_missing_nuclei_is_explicit_and_report_still_finishes(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=baseline(root)), \
                 patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',return_value=('ok',{})), \
                 patch('adapters.nuclei.catalog',return_value=([],{'status':'skipped','reason':'Nuclei executable unavailable'})), \
                 contextlib.redirect_stdout(io.StringIO()):
                result=WebXAgent(config(root)).run('scan')
            self.assertEqual(result['progress']['stages']['nuclei']['status'],'skipped')
            self.assertIn('unavailable',result['progress']['stages']['nuclei']['reason'])


@unittest.skipUnless(__import__('os').environ.get('WEBX_TEST_LIVE_SEQUENTIAL') == '1', 'opt-in local ZAP + Nuclei integration')
class LiveSequentialTests(unittest.TestCase):
    def test_real_scanners_candidates_and_resume(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from urllib.parse import unquote
        import threading
        from test_nuclei_adapter import TEMPLATE as YAML
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.split('?')[0] not in ('/', '/search', '/fixture'):
                    self.send_error(404); return
                if self.path.startswith('/search') and "'" in unquote(self.path):
                    body=b'syntax error: select id FROM products'
                else:
                    body=b'<html><a href="/search?q=abc">Search</a> local-marker</html>'
                self.send_response(200); self.send_header('Content-Type','text/html')
                self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
        try:
            with tempfile.TemporaryDirectory() as root:
                template=Path(root)/'fixture.yaml'; template.write_text(YAML.replace('{{BaseURL}}','{{RootURL}}'))
                cfg=config(root,targets=[f'http://127.0.0.1:{server.server_port}/search?q=abc'],nuclei_templates=str(template),
                           zap_ajax=False,zap_max_urls=5,zap_spider_depth=3,zap_spider_children=20,
                           zap_phase_minutes=1,zap_timeout=180,nuclei_timeout=60,allow_sqlmap=False)
                first=WebXAgent(cfg).run('Scan local fixture')
                self.assertEqual(first['progress']['stages']['nuclei']['status'],'complete',first['progress'])
                self.assertTrue(any('nuclei_scan' in f.get('sources',[]) for f in first['findings']),first['findings'])
                self.assertTrue(any('sql_error_verify' in f.get('sources',[]) for f in first['findings']),first['findings'])
                cfg['resume_session']=str(Path(first['progress']['path']).parent)
                with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',side_effect=AssertionError('discovery repeated')), \
                     patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',side_effect=AssertionError('ZAP repeated')), \
                     patch.object(TOOL_INDEX['nuclei_scan'],'exec_fn',side_effect=AssertionError('Nuclei repeated')), \
                     patch.object(TOOL_INDEX['sql_error_verify'],'exec_fn',side_effect=AssertionError('verification repeated')):
                    resumed=WebXAgent(cfg).run('Continue local fixture')
                self.assertEqual(resumed['calls'],0)
                self.assertEqual(len(resumed['findings']),len(first['findings']))
        finally:
            server.shutdown(); server.server_close(); worker.join()


class ResumeFailureTests(unittest.TestCase):
    def test_failed_task_requires_explicit_retry(self):
        with tempfile.TemporaryDirectory() as root:
            cfg=config(root,nuclei_enabled=False)
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=baseline(root)) as b, \
                 patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',return_value=('timeout',{'coverage':{'status':'timeout'}})) as z, \
                 contextlib.redirect_stdout(io.StringIO()):
                first=WebXAgent(cfg).run('scan')
                resume={**cfg,'resume_session':str(Path(first['progress']['path']).parent)}
                second=WebXAgent(resume).run('continue')
                self.assertEqual(z.call_count,1)
                self.assertEqual(second['progress']['stages']['zap_active']['status'],'partial')
                third=WebXAgent({**resume,'retry_incomplete':True}).run('retry')
                self.assertEqual(z.call_count,2)
                self.assertEqual(b.call_count,1)

    def test_resume_different_target_rejected_before_dispatch(self):
        with tempfile.TemporaryDirectory() as root:
            cfg=config(root,nuclei_enabled=False)
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=baseline(root)), \
                 patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',return_value=('ok',{})), \
                 contextlib.redirect_stdout(io.StringIO()):
                first=WebXAgent(cfg).run('scan')
            new={**cfg,'resume_session':str(Path(first['progress']['path']).parent),'targets':['https://other.test/']}
            with patch.object(WebXAgent,'_dispatch') as dispatch:
                with self.assertRaisesRegex(ValueError,'configuration differs'):
                    WebXAgent(new).run('continue')
            dispatch.assert_not_called()

    def test_new_session_deduplicates_nuclei_and_changed_template_runs(self):
        with tempfile.TemporaryDirectory() as root:
            cfg=config(root)
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=baseline(root)), \
                 patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',return_value=('ok',{})), \
                 patch.object(TOOL_INDEX['nuclei_scan'],'exec_fn',return_value=('ok',{'coverage':{'status':'complete'}})) as n, \
                 patch('adapters.nuclei.catalog',return_value=([TEMPLATE],{'status':'complete'})) as catalog, \
                 contextlib.redirect_stdout(io.StringIO()):
                WebXAgent(cfg).run('scan'); WebXAgent(cfg).run('scan')
                self.assertEqual(n.call_count,1)
                catalog.return_value=([{**TEMPLATE,'sha256':'new-revision'}],{'status':'complete'})
                WebXAgent(cfg).run('scan')
                self.assertEqual(n.call_count,2)
