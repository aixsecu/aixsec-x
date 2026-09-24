"""Opt-in ZAP/browser integration test against an isolated localhost fixture.

Run on Kali: WEBX_TEST_LIVE_ZAP=1 python3 -m unittest test_zap_live -v
No external site is scanned. Uses WEBX_ZAP_BROWSER (default firefox-headless).
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest

from config import load_config
from zap_adapter import run_scan


@unittest.skipUnless(os.environ.get('WEBX_TEST_LIVE_ZAP') == '1', 'opt-in real ZAP/browser test')
class LiveZapTests(unittest.TestCase):
    def test_ajax_form_and_active_parameter_requests(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(('GET', self.path))
                if self.path == '/':
                    body = b'''<!doctype html><html><head><title>Local AJAX fixture</title></head><body>
                    <form action="/form" method="post"><input name="query"><button type="submit">Search</button></form>
                    <input name="keyword" id="keyword" onkeyup="fetch('/api/search?q='+this.value)">
                    <button onclick="fetch('/api/item?id=1').then(r=>r.text()).then(t=>document.getElementById('result').textContent=t)">Load</button>
                    <div id="result"></div></body></html>'''
                    mime = 'text/html'
                elif self.path.startswith('/api/'):
                    body, mime = b'{"result":"fixture"}', 'application/json'
                else:
                    self.send_error(404); return
                self.send_response(200); self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                received.append(('POST', self.path))
                self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
                self.wfile.write(b'<html>Search complete</html>')
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        try:
            with tempfile.TemporaryDirectory() as root:
                url = f'http://127.0.0.1:{server.server_port}/'
                cfg = load_config()
                cfg.update(evidence_dir=root, zap_phase_minutes=1, zap_timeout=180,
                           zap_allowed_rules=[40018], zap_openapi_file='', zap_auth_context='anonymous')
                _, baseline = run_scan(cfg, url, ajax=True)
                self.assertEqual(baseline['coverage']['status'], 'complete', baseline['coverage']['gaps'])
                self.assertTrue(any(method == 'GET' and path.startswith('/api/item?') for method,path in received),
                                'AJAX click did not produce a request')
                self.assertTrue(any(method == 'POST' and path == '/form' for method,path in received),
                                'Form submission did not produce POST')
                self.assertTrue(baseline['discovery']['forms'])
                # A separate targeted active scan must retain the captured POST body.
                cfg['_zap_seed_har'] = baseline['coverage']['har_path']
                _, active = run_scan(cfg, url+'form', active=True, rule_ids=[40018])
                self.assertGreater(active['coverage']['active_test_requests'], 0, active['coverage']['gaps'])
                self.assertTrue(any(e['method']=='POST' and e['tested'] for e in active['discovery']['endpoints']))
        finally:
            server.shutdown(); server.server_close(); worker.join()

@unittest.skipUnless(os.environ.get('WEBX_TEST_LIVE_EVIDENCE') == '1', 'opt-in real ZAP evidence test')
class LiveEvidenceTests(unittest.TestCase):
    def test_active_transcript_and_differential_candidate(self):
        from urllib.parse import unquote
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                # Synthetic error oracle; no database, browser or external target.
                body = (b'syntax error: select id FROM products' if "'" in unquote(self.path)
                        else b'Search complete')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as root:
                url = f'http://127.0.0.1:{server.server_port}/search?q=abc'
                seed = {'startedDateTime': '2026-01-01T00:00:00Z', 'time': 0,
                        'request': {'method': 'GET', 'url': url, 'httpVersion': 'HTTP/1.1',
                                    'headers': [], 'queryString': [{'name':'q','value':'abc'}],
                                    'cookies': [], 'headersSize': -1, 'bodySize': 0},
                        'response': {'status': 200, 'statusText': 'OK', 'httpVersion':'HTTP/1.1',
                                     'headers':[{'name':'Content-Type','value':'text/html'}], 'cookies':[],
                                     'content':{'size':15,'mimeType':'text/html','text':'Search complete'},
                                     'redirectURL':'','headersSize':-1,'bodySize':15},
                        'cache':{}, 'timings':{'send':0,'wait':0,'receive':0}}
                cfg = load_config()
                cfg.update(evidence_dir=root, zap_phase_minutes=1, zap_timeout=180,
                           zap_allowed_rules=[40018], zap_openapi_file='', _zap_seed_entry=seed)
                _, data = run_scan(cfg, url, active=True, rule_ids=[40018])
                detail = data['coverage']['active_evidence']
                self.assertGreater(detail['records'], 0, data['coverage'])
                self.assertIn(40018, detail['rules_with_evidence'])
                self.assertTrue(any(r['rule_id']=='aixsec-sql-error-differential' for r in data['alerts']), data['alerts'])
                records = [json.loads(s) for s in Path(detail['artifact_ref']).read_text().splitlines()]
                self.assertTrue(any("'" in unquote(r['request_url']) for r in records))
                self.assertTrue(all('elapsed_ms' in r and 'response_sha256' in r for r in records))
        finally:
            server.shutdown(); server.server_close(); worker.join()
