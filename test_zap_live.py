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
