"""Automatic trial policy, fresh controls, persistent backoff and concurrency caps."""
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from zap_auto import AutoConcurrency, controls
from zap_concurrency import ConcurrencyPolicy
from zap_workers import drive, scheduling_reasons
from test_zap_workers import entry


def job(path):
    value=entry(path,headers=[{'name':'Cookie','value':'sid=private'}])
    value['request_id']=path
    value['_entry']['response']={'status':200}
    return value


class AutoTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.policy=ConcurrencyPolicy()
    def controller(self,jobs):return AutoConcurrency({'zap_delay_ms':0},self.root,jobs,self.policy)
    def result(self,status=200,**changes):
        path=self.root/'observer.jsonl';path.write_text(json.dumps({'status':status,**changes})+'\n')
        return {'outcome':'ok','data':{'coverage':{'active_requests_path':str(path)}}}
    def test_warmup_promotes_then_backoff_persists(self):
        item=job('catalog');auto=self.controller([item])
        with patch('zap_auto.controls',return_value={'stable':True,'observations':[{'elapsed':.1}]}): auto.prepare(item)
        self.assertEqual(auto.limit('https://example.test'),1)
        auto.observe(item,self.result());self.assertEqual(auto.limit('https://example.test'),2)
        auto.observe(item,self.result(429));self.assertEqual(auto.limit('https://example.test'),1)
        restored=self.controller([item]);self.assertEqual(restored.limit('https://example.test'),1)
        with patch('zap_auto.controls',side_effect=AssertionError('backoff reprobed')):restored.prepare(item)
        self.assertIn('auto_origin_backoff',item['_auto_reasons'])
    def test_unknown_auth_and_workflow_not_probed(self):
        items=[job('checkout'),job('products')];items[1]['auth_context']='member'
        auto=self.controller(items)
        with patch('zap_auto.controls',side_effect=AssertionError('unsafe control')):
            for item in items:
                self.assertTrue(scheduling_reasons(item,'auto',self.policy));auto.prepare(item)
    def test_fresh_controls_and_cookie_preservation(self):
        item=job('products');fake=SimpleNamespace(status_code=200,text='ok',content=b'ok',headers={})
        with patch('http_engine.HttpSession') as session:
            session.return_value.request.return_value=(fake,None)
            result=controls({'zap_delay_ms':0},item,self.root)
            self.assertTrue(result['stable']);self.assertEqual(session.return_value.request.call_count,2)
            kw=session.return_value.request.call_args.kwargs
            self.assertEqual(kw['headers']['Cookie'],'sid=private');self.assertFalse(kw['follow_redirects'])
            fake.headers={'Set-Cookie':'secret=changed'}
            self.assertFalse(controls({'zap_delay_ms':0},item,self.root)['stable'])
    def test_timeout_and_session_signals_reduce_parallelism(self):
        for result in ({'outcome':'timeout'},self.result(200,set_cookie=True),self.result(200,redirect=True)):
            item=job('products');auto=self.controller([item]);auto.observe(item,result)
            self.assertEqual(auto.limit('https://example.test'),1)
            self.assertTrue(auto.data['origins']['https://example.test']['backoff'])
    def test_two_worker_trial_after_first_success(self):
        items=[job('a'),job('b'),job('c')];auto=self.controller(items)
        barrier=threading.Barrier(2);started=[]
        good=self.result()
        def start(item,cancelled):
            auto.prepare(item)
            def work():
                started.append(item['request_id'])
                if item['request_id']!='a':barrier.wait(3)
                return good
            result=yield work
            auto.observe(item,result)
        with patch('zap_auto.controls',return_value={'stable':True}):
            drive(items,start,workers=4,cookie_mode='auto',policy=self.policy,auto=auto)
        self.assertEqual(started[0],'a');self.assertEqual(len(started),3)
    def test_changed_controls_downgrade_without_skipping_scan(self):
        items=[job('a'),job('b')];auto=self.controller(items);called=[]
        def start(item,cancelled):
            auto.prepare(item)
            result=yield lambda: called.append(item['request_id']) or {'outcome':'ok'}
            auto.observe(item,result)
        with patch('zap_auto.controls',return_value={'stable':False,'reason':'control_changed_or_slow'}):
            drive(items,start,cookie_mode='auto',policy=self.policy,auto=auto)
        self.assertEqual(called,['a','b']);self.assertEqual(auto.limit('https://example.test'),1)


@unittest.skipUnless(__import__('os').environ.get('WEBX_TEST_LIVE_AUTO')=='1','opt-in localhost control requests')
class LocalControlTests(unittest.TestCase):
    def test_real_controls_preserve_cookie_and_do_not_follow_redirects(self):
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        requests=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path,self.headers.get('Cookie')))
                self.send_response(302 if self.path=='/redirect' else 200)
                if self.path=='/redirect':self.send_header('Location','/must-not-follow')
                self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as root:
                item=job('products');item['_entry']['request']['url']=f'http://127.0.0.1:{server.server_port}/products'
                self.assertTrue(controls({'zap_delay_ms':0},item,root)['stable'])
                self.assertEqual(requests,[('/products','sid=private')]*2)
                item['_entry']['request']['url']=f'http://127.0.0.1:{server.server_port}/redirect'
                self.assertFalse(controls({'zap_delay_ms':0},item,root)['stable'])
                self.assertEqual(requests[-1][0],'/redirect')
        finally:server.shutdown();server.server_close();thread.join()

class AutoPipelineTests(unittest.TestCase):
    def test_controls_are_not_repeated_on_resume(self):
        from test_sequential_pipeline import baseline,config
        from tools import TOOL_INDEX
        from agent import WebXAgent
        with tempfile.TemporaryDirectory() as root:
            seed=baseline(root)
            path=Path(root)/'observer.jsonl';path.write_text('{"status":200}\n')
            cfg=config(root,nuclei_enabled=False,zap_cookie_parallel='auto')
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=seed),patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',return_value=('ok',{'coverage':{'status':'complete','active_requests_path':str(path)}})),patch('zap_auto.controls',return_value={'stable':True}) as control:
                result=WebXAgent(cfg).run('scan')
                self.assertEqual(control.call_count,1)
            self.assertEqual(result['progress']['stages']['zap_active']['automatic']['stable_controls'],1)
            cfg['resume_session']=str(Path(result['progress']['path']).parent)
            with patch('zap_auto.controls',side_effect=AssertionError('restored result reprobed')),patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',side_effect=AssertionError('restored result rescanned')):
                result=WebXAgent(cfg).run('resume')
            self.assertEqual(result['calls'],0)
