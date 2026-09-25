"""Concurrency, isolation, route grouping and resume regressions (offline)."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from zap_workers import drive, parallel_safe
from zap_schedule import ScanSchedule
from test_sequential_pipeline import config, baseline, URL
from tools import TOOL_INDEX
from agent import WebXAgent
from scan_state import Journal


def entry(path, method='GET', headers=None):
    return {'auth_context':'anonymous', '_entry':{'request':{'url':URL+path,
            'method':method, 'headers':headers or []}}}


class WorkersTests(unittest.TestCase):
    def test_overlap_and_serial_barrier_and_owner_thread(self):
        main = threading.get_ident()
        barrier = threading.Barrier(2)
        active = set()
        guard = threading.Lock()
        results = []
        jobs = [entry('a'),entry('b'),entry('write', 'POST'),entry('c'),entry('d')]
        def start(job, cancelled):
            self.assertEqual(threading.get_ident(), main)
            path = job['_entry']['request']['url']
            def work():
                with guard:
                    if path.endswith('write'):
                        self.assertFalse(active)
                    active.add(path)
                if not path.endswith('write'):
                    barrier.wait(timeout=3)
                time.sleep(.01)
                with guard:
                    active.remove(path)
                return path
            result = yield work
            self.assertEqual(threading.get_ident(), main)
            results.append(result)
        drive(jobs, start, 2)
        self.assertEqual(len(results),5)
        self.assertEqual(results[2],URL+'write')

    def test_denial_stops_queue_and_preserves_reason(self):
        started=[]
        def start(job,cancelled):
            started.append(job)
            result = yield lambda: {'outcome':'denied','output':'Operator denied'}
            return result
        reason=drive([entry('a'),entry('b')],start,1)
        self.assertEqual(len(started),1)
        self.assertEqual(reason,'Operator denied')

    def test_cookie_and_auth_serialized(self):
        self.assertFalse(parallel_safe(entry('a',headers=[{'name':'Cookie','value':'private'}])))
        self.assertFalse(parallel_safe(entry('a','PATCH')))
        job=entry('a');job['auth_context']='member'
        self.assertFalse(parallel_safe(job))

    def test_failure_cancels_other_worker(self):
        stopped=threading.Event()
        barrier=threading.Barrier(2)
        def start(job,cancelled):
            def call():
                barrier.wait(timeout=3)
                if job['_entry']['request']['url'].endswith('a'):
                    raise KeyboardInterrupt()
                self.assertTrue(cancelled.wait(3))
                stopped.set()
                return {}
            yield call
        with self.assertRaises(KeyboardInterrupt):
            drive([entry('a'),entry('b')],start,2)
        self.assertTrue(stopped.is_set())

    def test_pipeline_seeds_are_isolated_and_resume_avoids_scans(self):
        with tempfile.TemporaryDirectory() as root:
            seed=baseline(root)
            har=Path(root)/'seed-source.har'
            rows=json.loads(har.read_text())
            rows['log']['entries'][1]['request']['url']=URL+'other?q=two'
            har.write_text(json.dumps(rows))
            barrier=threading.Barrier(2)
            seen=[]
            def active(**kw):
                self.assertEqual(kw['url'],kw['_config']['_zap_seed_entry']['request']['url'])
                barrier.wait(3)
                seen.append(kw['url'])
                return 'ok',{'coverage':{'status':'complete'}}
            cfg=config(root,nuclei_enabled=False,zap_workers=2)
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=seed),patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',side_effect=active):
                result=WebXAgent(cfg).run('scan')
            self.assertEqual(len(seen),2)
            cfg['resume_session']=str(Path(result['progress']['path']).parent)
            with patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',side_effect=AssertionError('repeated')):
                result=WebXAgent(cfg).run('scan')
            self.assertEqual(result['progress']['stages']['zap_active']['status'],'complete')

    def test_operator_slug_groups_preserve_method_query_and_origin(self):
        with tempfile.TemporaryDirectory() as root:
            routes=Path(root)/'routes.json'
            routes.write_text(json.dumps([{'origin':URL.rstrip('/'),'group':'products','paths':['/cooler-*']}]))
            har=Path(root)/'traffic.har'
            requests=[entry('cooler-a'),entry('cooler-b'),entry('login'),entry('cooler-c?q=1'),entry('cooler-d','POST')]
            har.write_text(json.dumps({'log':{'entries':[j['_entry'] | {'response':{'status':200}} for j in requests]}}))
            schedule=ScanSchedule(root,route_groups_file=str(routes))
            schedule.collect({'target':URL,'har_path':str(har)})
            self.assertEqual(len(schedule.entries),4)
            grouped=[v for v in schedule.entries.values() if v['equivalent_requests']==2]
            self.assertEqual(len(grouped),1)
            fid=grouped[0]['request_id']
            self.assertEqual(schedule.claim(fid,[40018]),[40018])
            self.assertEqual(schedule.claim(fid,[40018]),[])
            other=ScanSchedule(root,namespace='new',route_groups_file=str(routes))
            self.assertEqual(other.claim(fid,[40018]),[40018])

    def test_route_file_change_invalidates_resume(self):
        with tempfile.TemporaryDirectory() as root:
            routes=Path(root)/'routes.json';routes.write_text('[]')
            cfg={'zap_route_groups_file':str(routes)}
            Journal(root,cfg)
            routes.write_text('[ ]')
            with self.assertRaisesRegex(ValueError,'profile changed'):
                Journal(root,cfg)


@unittest.skipUnless(__import__('os').environ.get('WEBX_TEST_LIVE_ZAP_WORKERS') == '1',
                     'opt-in two real localhost ZAP JVMs')
class LiveWorkerTests(unittest.TestCase):
    def test_two_jvms_complete_with_shared_request_pacing(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from concurrent.futures import ThreadPoolExecutor
        from adapters.zap import run_scan
        from config import load_config
        times=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get('X-ZAP-Scan-ID'):
                    times.append(time.monotonic())
                body=b'syntax error: select id FROM products' if '%27' in self.path or "'" in self.path else b'ok'
                self.send_response(200)
                self.send_header('Content-Type','text/html')
                self.send_header('Content-Length',str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as root:
                def work(path):
                    url=f'http://127.0.0.1:{server.server_port}/{path}?q=test'
                    captured={'request':{'url':url,'method':'GET','httpVersion':'HTTP/1.1',
                        'headers':[],'queryString':[{'name':'q','value':'test'}],'cookies':[],
                        'headersSize':-1,'bodySize':0},
                        'response':{'status':200,'statusText':'OK','httpVersion':'HTTP/1.1',
                        'headers':[{'name':'Content-Type','value':'text/html'}],
                        'content':{'text':'ok','size':2,'mimeType':'text/html'},'cookies':[],
                        'redirectURL':'','headersSize':-1,'bodySize':2},
                        'startedDateTime':'2026-09-25T00:00:00Z','time':1,
                        'timings':{'send':0,'wait':1,'receive':0},'cache':{}}
                    cfg=load_config()
                    cfg.update(evidence_dir=root,zap_allowed_rules=[40018],zap_phase_minutes=1,
                        zap_timeout=150,zap_delay_ms=200,_zap_rate_root=root,
                        _zap_cancelled=threading.Event(),_zap_seed_entry=captured)
                    return run_scan(cfg,url,active=True,rule_ids=[40018])
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results=list(pool.map(work,['search','other']))
                for output,data in results:
                    self.assertEqual(data['coverage']['status'],'complete',output)
                    self.assertTrue(data['coverage']['active_evidence']['rules_with_evidence'],output)
                self.assertGreater(len(times),10)
                gaps=[b-a for a,b in zip(sorted(times),sorted(times)[1:])]
                self.assertGreater(min(gaps),.15)  # allow local scheduling/network jitter
        finally:
            server.shutdown();server.server_close();thread.join()
