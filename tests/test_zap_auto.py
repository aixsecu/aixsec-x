"""Automatic trial policy, fresh controls, persistent backoff and concurrency caps."""
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from zap_auto import AutoConcurrency, bootstrap_eligible, controls, classify_cookies, classify_redirect
from zap_concurrency import ConcurrencyPolicy
from zap_workers import drive, scheduling_reasons
from tests.test_zap_workers import entry


def job(path):
    value=entry(path,headers=[{'name':'Cookie','value':'sid=private'}])
    value['request_id']=path
    value['_entry']['response']={'status':200}
    return value


def bootstrap_job(path, method='GET', headers=None):
    value=entry(path,method=method,headers=headers)
    value['request_id']=path
    value['_entry']['response']={'status':200}
    return value


class AutoTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.policy=ConcurrencyPolicy()
    def controller(self,jobs,**config):return AutoConcurrency({'zap_delay_ms':0,'zap_workers':4,**config},self.root,jobs,self.policy)
    def result(self,status=200,**changes):
        path=self.root/'observer.jsonl';path.write_text(json.dumps({'status':status,**changes})+'\n')
        return {'outcome':'ok','data':{'coverage':{'active_requests_path':str(path)}}}
    def test_gradual_promotion_temporary_backoff_and_recovery(self):
        items=[job(str(v)) for v in range(12)];auto=self.controller(items)
        item=items[0]
        auto.data['origins']['https://example.test']['mode']='steady'
        with patch('zap_auto.controls',return_value={'stable':True,'observations':[{'elapsed':.1}]}): auto.prepare(item)
        self.assertEqual(auto.limit('https://example.test',item),1)
        for clean in items[:4]: auto.observe(clean,self.result())
        self.assertEqual(auto.limit('https://example.test'),2)
        auto.observe(items[4],self.result(429));auto.observe(items[5],self.result(403))
        self.assertEqual(auto.limit('https://example.test'),2)
        auto.observe(items[6],self.result(500));self.assertEqual(auto.limit('https://example.test'),1)
        for clean in items[7:11]: auto.observe(clean,self.result())
        self.assertEqual(auto.limit('https://example.test'),2)
        restored=self.controller([item]);self.assertEqual(restored.limit('https://example.test'),2)

    def test_bootstrap_eligibility_is_strictly_low_risk(self):
        self.assertTrue(bootstrap_eligible(bootstrap_job('products')))
        self.assertTrue(bootstrap_eligible(bootstrap_job('products',method='HEAD')))
        cases=[bootstrap_job('products',method='POST'),
               bootstrap_job('products',headers=[{'name':'Cookie','value':'sid=x'}]),
               bootstrap_job('products',headers=[{'name':'Authorization','value':'Bearer x'}]),
               bootstrap_job('products',headers=[{'name':'X-CSRF-Token','value':'x'}]),
               bootstrap_job('products?session=x'),bootstrap_job('checkout')]
        body=bootstrap_job('products');body['_entry']['request']['postData']={'text':'x'};cases.append(body)
        authenticated=bootstrap_job('products');authenticated['auth_context']='member';cases.append(authenticated)
        for item in cases:
            self.assertFalse(bootstrap_eligible(item),item['request_id'])

    def test_two_clean_bootstrap_groups_run_together_and_promote(self):
        items=[bootstrap_job('public-a'),bootstrap_job('public-b')]
        auto=self.controller(items);barrier=threading.Barrier(2);started=[]
        good=self.result()
        def start(item,cancelled):
            auto.prepare(item)
            def work():
                started.append(item['request_id']);barrier.wait(3);return good
            result=yield work
            auto.observe(item,result)
        with patch('zap_auto.controls',return_value={'stable':True}):
            drive(items,start,workers=4,cookie_mode='auto',policy=self.policy,auto=auto)
        state=auto.data['origins']['https://example.test']
        self.assertCountEqual(started,['public-a','public-b'])
        self.assertEqual((state['mode'],state['level'],state['bootstrap_result']),('steady',2,'clean'))

    def test_one_unstable_bootstrap_group_falls_back_to_one(self):
        items=[bootstrap_job('public-a'),bootstrap_job('public-b')];auto=self.controller(items)
        with patch('zap_auto.controls',return_value={'stable':False,'reason':'control_changed_or_slow'}):
            auto.prepare(items[0])
        state=auto.data['origins']['https://example.test']
        self.assertEqual((state['mode'],auto.limit('https://example.test'),state['bootstrap_result']),
                         ('steady',1,'unstable'))

    def test_eligible_serial_eligible_continues_bootstrap(self):
        first=bootstrap_job('public-a');serial=bootstrap_job('checkout');last=bootstrap_job('public-b')
        auto=self.controller([first,serial,last])
        auto.observe(first,self.result())
        before=json.loads(json.dumps(auto.data['origins']['https://example.test']))
        auto.observe(serial,{'outcome':'error','data':{}})
        after=auto.data['origins']['https://example.test']
        self.assertEqual(after,before)
        auto.observe(last,self.result())
        self.assertEqual((after['mode'],after['level'],after['bootstrap_result']),('steady',2,'clean'))
        self.assertEqual(after['bootstrap_groups'],{'public-a':'clean','public-b':'clean'})

    def test_serial_only_application_stays_neutral_and_serial(self):
        items=[bootstrap_job('checkout'),bootstrap_job('save',method='POST')]
        authenticated=bootstrap_job('account');authenticated['auth_context']='member';items.append(authenticated)
        auto=self.controller(items);active=0;maximum=0;guard=threading.Lock()
        def start(item,cancelled):
            def work():
                nonlocal active,maximum
                with guard: active+=1;maximum=max(maximum,active)
                time.sleep(.01)
                with guard: active-=1
                return {'outcome':'ok'}
            result=yield work
            auto.observe(item,result)
        drive(items,start,workers=4,cookie_mode='auto',policy=self.policy,auto=auto)
        state=auto.data['origins']['https://example.test']
        self.assertEqual(maximum,1)
        self.assertEqual((state['mode'],state['level'],state['bootstrap_groups']),('bootstrap',1,{}))
        self.assertEqual((state['score'],state['stable_groups'],state['groups_since_change']),(0,0,0))

    def test_one_eligible_group_preserves_progress_across_resume(self):
        eligible=bootstrap_job('public');serial=bootstrap_job('checkout')
        auto=self.controller([eligible,serial]);auto.observe(eligible,self.result());auto.observe(serial,self.result(500))
        restored=self.controller([eligible,serial]);state=restored.data['origins']['https://example.test']
        self.assertEqual((state['mode'],state['level']),('bootstrap',1))
        self.assertEqual(state['bootstrap_groups'],{'public':'clean'})
        self.assertEqual(state['score'],0)

    def test_unknown_capture_is_neutral_to_bootstrap(self):
        eligible=bootstrap_job('public');unknown=bootstrap_job('unknown')
        unknown['_entry']['response']={'status':0}
        auto=self.controller([eligible,unknown]);auto.observe(eligible,self.result())
        before=json.loads(json.dumps(auto.data['origins']['https://example.test']))
        auto.observe(unknown,{'outcome':'error','data':{}})
        self.assertEqual(auto.data['origins']['https://example.test'],before)

    def test_mixed_workflow_then_reads_resume_two_worker_bootstrap(self):
        workflow=bootstrap_job('checkout');reads=[bootstrap_job('public-a'),bootstrap_job('public-b')]
        items=[workflow,*reads];auto=self.controller(items);barrier=threading.Barrier(2);overlapped=[]
        good=self.result()
        def start(item,cancelled):
            auto.prepare(item)
            def work():
                if item in reads:
                    overlapped.append(item['request_id']);barrier.wait(3)
                return good
            result=yield work
            auto.observe(item,result)
        with patch('zap_auto.controls',return_value={'stable':True}):
            drive(items,start,workers=4,cookie_mode='auto',policy=self.policy,auto=auto)
        state=auto.data['origins']['https://example.test']
        self.assertCountEqual(overlapped,['public-a','public-b'])
        self.assertEqual((state['mode'],state['level']),('steady',2))

    def test_pre_bootstrap_persisted_origin_remains_steady(self):
        path=self.root/'auto-concurrency.json'
        path.write_text(json.dumps({'version':2,'origins':{'https://example.test':{
            'level':4,'score':9,'stable_groups':1,'unstable_groups':{},'groups_since_change':2}},
            'groups':{},'decisions':{}}))
        auto=self.controller([bootstrap_job('public')])
        state=auto.data['origins']['https://example.test']
        self.assertEqual((state['mode'],auto.limit('https://example.test')),('steady',4))
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
            fake.headers={'Set-Cookie':'PHPSESSID=changed'}
            self.assertFalse(controls({'zap_delay_ms':0},item,self.root)['stable'])
            fake.status_code=301;fake.headers={'Location':'/products/'}
            self.assertTrue(controls({'zap_delay_ms':0},item,self.root)['stable'])
    def test_group_local_quarantine_then_origin_escalation(self):
        items=[job('products'),job('orders')];auto=self.controller(items)
        auto.data['origins']['https://example.test']={'level':4,'score':8,'stable_groups':0,
            'unstable_groups':{},'groups_since_change':3}
        auto.observe(items[0],self.result(302,redirect=True,location='/login'))
        self.assertEqual(auto.limit('https://example.test'),4)
        self.assertTrue(auto.data['groups']['products']['quarantined'])
        auto.observe(items[1],self.result(302,redirect=True,location='/login'))
        self.assertEqual(auto.limit('https://example.test'),2)
    def test_two_worker_trial_after_first_success(self):
        items=[job(v) for v in ('a','b','c','d','e','f')];auto=self.controller(items)
        auto.data['origins']['https://example.test']['mode']='steady'
        barrier=threading.Barrier(2);started=[]
        good=self.result()
        def start(item,cancelled):
            auto.prepare(item)
            def work():
                started.append(item['request_id'])
                if item['request_id'] in ('e','f'):barrier.wait(3)
                return good
            result=yield work
            auto.observe(item,result)
        with patch('zap_auto.controls',return_value={'stable':True}):
            drive(items,start,workers=4,cookie_mode='auto',policy=self.policy,auto=auto)
        self.assertEqual(started[:4],['a','b','c','d']);self.assertEqual(len(started),6)
    def test_changed_controls_downgrade_without_skipping_scan(self):
        items=[bootstrap_job('a'),bootstrap_job('b')];auto=self.controller(items);called=[]
        def start(item,cancelled):
            auto.prepare(item)
            result=yield lambda: called.append(item['request_id']) or {'outcome':'ok'}
            auto.observe(item,result)
        with patch('zap_auto.controls',return_value={'stable':False,'reason':'control_changed_or_slow'}):
            drive(items,start,cookie_mode='auto',policy=self.policy,auto=auto)
        self.assertEqual(called,['a','b']);self.assertEqual(auto.limit('https://example.test'),1)

    def test_redirect_classification(self):
        base={'status':302,'redirect':True,'url':'http://example.test/products'}
        cases=[('/products/',('canonical',0)),('/login',('login',-4)),('/logout',('logout',-4)),
               ('/cart',('same_origin',0)),('https://other.test/x',('cross_origin',-3)),
               ('https://example.test/products',('http_to_https',0)),('/en/products',('language',0))]
        for location,expected in cases:
            self.assertEqual(classify_redirect({**base,'location':location}),expected)
        self.assertEqual(classify_redirect({**base,'status':200,'location':'/login'}),('none',0))

    def test_captured_canonical_redirect_remains_parallel_candidate(self):
        item=job('products');item['_entry']['response']={'status':308,
            'headers':[{'name':'Location','value':'/products/'}]}
        auto=self.controller([item])
        self.assertEqual(item['_auto_reasons'],[])
        self.assertFalse(scheduling_reasons(item,'auto',self.policy))

    def test_cookie_classification(self):
        self.assertEqual(classify_cookies({'set_cookie_names':['sid'],'request_cookie_names':['sid']}),('session_refresh',-1))
        self.assertEqual(classify_cookies({'set_cookie_names':['XSRF-TOKEN']}),('csrf_rotation',-1))
        self.assertEqual(classify_cookies({'set_cookie_names':['AWSALB']}),('affinity',0))
        self.assertEqual(classify_cookies({'set_cookie_names':['_ga']}),('analytics',0))

    def test_benign_cookie_and_redirect_do_not_quarantine(self):
        item=job('products');auto=self.controller([item])
        auto.observe(item,self.result(301,url='https://example.test/products',redirect=True,location='/products/',set_cookie=True,
            set_cookie_names=['AWSALB'],request_cookie_names=['sid']))
        self.assertNotIn('products',auto.data['groups'])

    def test_alternating_workload_is_damped(self):
        items=[job(str(v)) for v in range(8)];auto=self.controller(items)
        auto.data['origins']['https://example.test']={'level':2,'score':6,'stable_groups':0,
            'unstable_groups':{},'groups_since_change':0}
        for index,item in enumerate(items):
            auto.observe(item,self.result(429) if index%2 == 0 else self.result())
        self.assertEqual(auto.limit('https://example.test'),2)


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
        from tests.test_sequential_pipeline import baseline,config
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
