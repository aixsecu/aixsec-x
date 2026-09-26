import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from request_inputs import inputs, mutate
from captured_auth import preflight
from adapters.nuclei import template_info, run_scan

RAW='''id: captured-json-fixture
info:
  name: Captured JSON fixture
  author: aixsec
  severity: info
http:
  - raw:
      - |
        POST {{AIXSECPath}} HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {{AIXSECBody}}
    matchers:
      - type: word
        words: [logged-in-marker]
'''

class CapturedInputTests(unittest.TestCase):
    def test_duplicate_query_and_form_each_change_only_one_occurrence(self):
        entry={'request':{'url':'https://example.test/?q=a+space&q=two', 'method':'POST',
                         'postData':{'mimeType':'application/x-www-form-urlencoded','text':'q=three&csrf=keep%2f'}}}
        selections=inputs(entry,'q')
        self.assertEqual(len(selections),3)
        values=[mutate(entry,s) for s in selections]
        self.assertEqual(values[0][0],'https://example.test/?q=a+space%27&q=two')
        self.assertEqual(values[1][0],'https://example.test/?q=a+space&q=two%27')
        self.assertEqual(values[2][1],'q=three%27&csrf=keep%2f')

    def test_json_pointer_nested_arrays_and_duplicate_key_rejected(self):
        entry={'request':{'url':'https://example.test/','method':'POST','postData':{'mimeType':'application/json',
                'text':'{"items":[{"q":"one"},{"q":"two"}],"count":2}'}}}
        self.assertEqual(len(inputs(entry,'q')),2)
        selection=inputs(entry,'/items/1/q')[0]
        obj=json.loads(mutate(entry,selection)[1])
        self.assertEqual(obj['items'][0]['q'],'one')
        self.assertEqual(obj['items'][1]['q'],"two'")
        self.assertEqual(obj['count'],2)
        entry['request']['postData']['text']='{"q":"one","q":"two"}'
        with self.assertRaisesRegex(ValueError,'Duplicate JSON'): inputs(entry,'q')

    def test_raw_template_acceptance_and_host_framing_rejection(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'raw.yaml';p.write_text(RAW)
            info=template_info(p)
            self.assertEqual(info['scope'],'captured');self.assertEqual(info['methods'],['POST'])
            for text in (RAW.replace('{{Hostname}}','external.test'),
                         RAW.replace('Content-Type: application/json','Content-Length: 20'),
                         RAW.replace('{{AIXSECPath}}','https://external.test/')):
                p.write_text(text)
                with self.assertRaises(ValueError): template_info(p)

    def test_expired_authenticated_capture_stops_before_payload(self):
        from verification import paired
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as root:
            profile=Path(root)/'auth.json'
            profile.write_text(json.dumps({'user_A':{'origin':'https://example.test/', 'authentication':{
                'verification':{'loggedInRegex':'logged-in-marker','loggedOutRegex':'expired'}}}}))
            entry={'request':{'url':'https://example.test/?q=abc','method':'GET','headers':[{'name':'Cookie','value':'sid=old'}]}}
            with patch('http_engine.HttpSession') as session:
                session.return_value.request.return_value=(SimpleNamespace(status_code=200,text='expired',content=b'expired'),{})
                _, data=paired({'evidence_dir':root,'zap_auth_file':str(profile)},entry,'q',
                              {'url':entry['request']['url'],'auth_context':'user_A'})
            self.assertEqual(session.return_value.request.call_count,1)
            self.assertEqual(data['coverage']['status'],'partial')
            self.assertFalse(data['verification']['reproduced_error'])


@unittest.skipUnless(os.environ.get('WEBX_TEST_LIVE_CAPTURE')=='1','opt-in Nuclei/auth/JSON localhost test')
class LiveCaptureTests(unittest.TestCase):
    def test_authenticated_json_nuclei_and_paired_verification(self):
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        from urllib.parse import urlsplit
        import threading
        from verification import paired
        received=[]
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body=self.rfile.read(int(self.headers.get('Content-Length',0))).decode()
                received.append((self.path,self.headers.get('Cookie'),self.headers.get('X-CSRF-Token'),body))
                valid=self.headers.get('Cookie')=='sid=LOCAL' and self.headers.get('X-CSRF-Token')=='csrf-local'
                content=('logged-in-marker syntax error: select id FROM products' if "'" in body else 'logged-in-marker local-json') if valid else 'expired'
                self.send_response(200);self.send_header('Content-Length',str(len(content)));self.end_headers();self.wfile.write(content.encode())
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            with tempfile.TemporaryDirectory() as root:
                url=f'http://127.0.0.1:{server.server_port}/search'
                entry={'request':{'url':url,'method':'POST',
                    'headers':[{'name':'Cookie','value':'sid=LOCAL'},{'name':'X-CSRF-Token','value':'csrf-local'}],
                    'postData':{'mimeType':'application/json','text':'{"search":{"q":"abc"}}'}}}
                profile=Path(root)/'auth.json';profile.write_text(json.dumps({'user_A':{'origin':url,'authentication':{
                    'verification':{'loggedInRegex':'logged-in-marker','loggedOutRegex':'expired'}}}}))
                cfg={'evidence_dir':root,'zap_auth_file':str(profile),'nuclei_timeout':45}
                template=Path(root)/'raw.yaml';template.write_text(RAW)
                _,data=run_scan(cfg,url,[template_info(template)],entry=entry,auth_context='user_A')
                self.assertEqual(data['coverage']['status'],'complete',data)
                self.assertEqual(len(data['alerts']),1,data)
                self.assertEqual(data['alerts'][0]['auth_context'],'user_A')
                self.assertEqual(data['coverage']['auth_state'],'verified')
                self.assertTrue(all(r[0]=='/search' and r[1]=='sid=LOCAL' and r[2]=='csrf-local' for r in received))
                self.assertTrue(any(json.loads(r[3])=={'search':{'q':'abc'}} for r in received))
                _,check=paired(cfg,entry,'/search/q',{'url':url,'auth_context':'user_A'})
                self.assertTrue(check['verification']['reproduced_error'],check)
                self.assertFalse(check['verification']['confirmed_sqli'])
        finally:
            server.shutdown();server.server_close();worker.join()


class ResumeAndOfflineTests(unittest.TestCase):
    def test_auth_profile_change_rejected_on_resume(self):
        from scan_state import Journal
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'auth.json';path.write_text('{}')
            cfg={'zap_auth_file':str(path)}
            Journal(root,cfg)
            path.write_text('{"user_A": {}}')
            with self.assertRaisesRegex(ValueError,'auth profile changed'): Journal(root,cfg)

    def test_offline_json_sql_error_candidate_keeps_json_pointer(self):
        from zap_active_evidence import analyze
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);url='https://example.test/search'
            seed={'request':{'url':url,'method':'POST','postData':{'mimeType':'application/json','text':'{"search":{"q":"abc"}}'}},
                  'response':{'status':200,'content':{'text':'ok'}}}
            (p/'seed.har').write_text(json.dumps({'log':{'entries':[seed]}}))
            row={'rule_id':'40018','request_url':url,'method':'POST','status':200,
                 'request_body':json.dumps({'search':{'q':"abc'"}}),'response_body':'syntax error: select id'}
            (p/'active-evidence.jsonl').write_text(json.dumps(row)+'\n')
            _,alerts=analyze(p,url,[40018],'anonymous','test')
            self.assertEqual(alerts[0]['parameter'],'/search/q')

    def test_pipeline_binds_authenticated_post_to_matching_template(self):
        from test_sequential_pipeline import config
        from agent import WebXAgent
        from tools import TOOL_INDEX
        import contextlib,io
        with tempfile.TemporaryDirectory() as root:
            url='https://example.test/search'
            entry={'request':{'url':url,'method':'POST','headers':[{'name':'Cookie','value':'sid=LOCAL'}],
                'postData':{'mimeType':'application/json','text':'{"q":"abc"}'}},'response':{'status':200,'content':{'text':'ok'}}}
            har=Path(root)/'seed.har';har.write_text(json.dumps({'log':{'entries':[entry]}}))
            data={'coverage':{'tool':'zap_baseline','target':url,'status':'complete','har_path':str(har),
                              'auth_context':'user_A','auth_state':'verified'},'alerts':[]}
            template={'id':'captured','path':'/unused','sha256':'hash','scope':'captured','methods':['POST']}
            cfg=config(root,zap_auto_active=False)
            def scan(**kw):
                self.assertEqual(kw['_entry']['request'],entry['request'])
                self.assertEqual(kw['auth_context'],'user_A')
                return 'ok',{'coverage':{'status':'complete'}}
            with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=('ok',data)), \
                 patch('adapters.nuclei.catalog',return_value=([template],{'status':'complete'})), \
                 patch.object(TOOL_INDEX['nuclei_scan'],'exec_fn',side_effect=scan) as scanner, \
                 contextlib.redirect_stdout(io.StringIO()):
                WebXAgent(cfg).run('scan')
            self.assertEqual(scanner.call_count,1)
