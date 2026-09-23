"""Request-backed discovery tests; fixtures never contact an external host."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from zap_discovery import Discovery
from zap_adapter import build_plan, run_scan
from evidence import EvidenceStore
from ledger import Ledger
from inventory import Inventory

URL = 'http://example.test/'


def entry(path='/', body='', mime='text/html', method='GET', post=None, rule=None, status=200):
    return {'request': {'url': URL + path.lstrip('/'), 'method': method,
            'headers': [{'name': 'X-ZAP-Scan-ID', 'value': str(rule)}] if rule else [],
            'postData': post or {}},
            'response': {'status': status, 'content': {'mimeType': mime, 'text': body}}}


def write_har(root, entries):
    path = Path(root) / 'traffic.har'
    path.write_text(json.dumps({'log': {'entries': entries}}))
    return path


class DiscoveryTests(unittest.TestCase):
    def test_form_and_standalone_input_without_alerts(self):
        with tempfile.TemporaryDirectory() as root:
            d = Discovery(URL)
            d.har(write_har(root, [entry(body='<form action="/send" method="POST"><input name="email" value="SECRET"></form><input id="keyword"><script>$("#r").load("ajax/search.php?q="+q)</script>')]))
            result = d.result()
            form = result['forms'][0]
            self.assertEqual(form['parameters'], ['email'])
            self.assertEqual(form['state'], 'discovered')
            self.assertEqual(result['inputs'][1]['name'], 'keyword')
            self.assertFalse(result['inputs'][1]['in_form'])
            ajax = next(e for e in result['endpoints'] if e['url'].endswith('/ajax/search.php'))
            self.assertEqual(ajax['parameters'], ['q'])
            self.assertFalse(ajax['requested'])
            self.assertNotIn('SECRET', json.dumps(result))

    def test_captured_post_promotes_form_but_not_to_tested(self):
        with tempfile.TemporaryDirectory() as root:
            d = Discovery(URL)
            d.har(write_har(root, [entry(body='<form action="/send" method="post"><input name="email"></form>'),
                entry('/send', method='POST', mime='application/json', post={'mimeType':'application/x-www-form-urlencoded', 'text':'email=SECRET'})]))
            result = d.result()
            self.assertEqual(result['forms'][0]['state'], 'requested')
            self.assertEqual(result['test_request_count'], 0)
            self.assertNotIn('SECRET', json.dumps(result))

    def test_method_and_auth_context_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            d = Discovery(URL, 'alice')
            d.har(write_har(root, [entry('/same?q=1'), entry('/same', method='POST', post={'mimeType':'application/json','text':'{"q":"secret"}'})]))
            self.assertEqual({e['method'] for e in d.result()['endpoints']}, {'GET','POST'})
            self.assertEqual({e['auth_context'] for e in d.result()['endpoints']}, {'alice'})

    def test_only_attributed_successful_request_counts_as_test(self):
        with tempfile.TemporaryDirectory() as root:
            d = Discovery(URL, allowed_rules=[40018])
            d.har(write_har(root, [entry('/a?q=x', rule=40018), entry('/b?q=x', rule=999), entry('/c?q=x', rule=40018, status=0)]))
            result = d.result()
            self.assertEqual(result['test_request_count'], 1)
            self.assertEqual(result['summary']['tested'], 1)
            self.assertFalse(next(e for e in result['endpoints'] if e['url'].endswith('/c'))['requested'])

    def test_relative_external_script_resolves_against_document(self):
        with tempfile.TemporaryDirectory() as root:
            d = Discovery(URL)
            d.har(write_har(root, [entry('/js/app.js', body="$.post('ajax/cart.php', {})", mime='application/javascript'),
                entry('/shop/', body='<script src="/js/app.js"></script>')]))
            self.assertIn(URL+'shop/ajax/cart.php', [e['url'] for e in d.result()['endpoints']])
            self.assertNotIn(URL+'js/ajax/cart.php', [e['url'] for e in d.result()['endpoints']])

    def test_ajax_options_and_off_origin_exclusion(self):
        d = Discovery(URL)
        d.page(URL, "$.ajax({type:'post',url:'ajax/cart.php',data:{id:id,soluong:1},success:function(x){}}); fetch('https://outside.test/api')", 'text/html')
        rows = d.result()['endpoints']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['method'], 'POST')
        self.assertEqual(rows[0]['parameters'], ['id','soluong'])

    def test_inventory_reaches_final_report_and_existing_inventory(self):
        d = Discovery(URL)
        d.add(URL+'search?q=', 'GET', ['q'], 'javascript_literal')
        data = {'discovery':d.result(), 'scan_id':'scan-1'}
        result = {'name':'zap_baseline','outcome':'ok','data':data}
        store = EvidenceStore(Ledger())
        store.ingest(result)
        self.assertEqual(store.finish()['discovery'][0]['summary']['discovered_only'], 1)
        inv = Inventory()
        inv.ingest([result])
        self.assertIn('q', json.dumps(inv.to_dict()))

    def test_seed_import_filters_origin_and_endpoint_and_does_not_replay(self):
        with tempfile.TemporaryDirectory() as root:
            bad = entry('/api'); bad['request']['url']='https://outside.test/api'
            har = write_har(root,[entry('/api',method='POST'),entry('/other'),bad])
            plan = build_plan({'_zap_seed_har':str(har),'zap_allowed_rules':[40018]}, URL+'api',root,active=True,rule_ids=[40018])
            job = next(j for j in plan['jobs'] if j['type']=='import')
            self.assertFalse(job['parameters'].get('sendRequests', False))
            scan = next(j for j in plan['jobs'] if j['type']=='activeScan')
            self.assertNotIn('url', scan['parameters'])
            import re
            scope = plan['env']['contexts'][0]['includePaths'][0]
            self.assertTrue(re.fullmatch(scope, URL+'api?q=1'))
            self.assertFalse(re.fullmatch(scope, URL+'other'))
            entries = json.loads(Path(job['parameters']['fileName']).read_text())['log']['entries']
            self.assertEqual(len(entries),1)
            self.assertEqual(entries[0]['request']['method'],'POST')

    def test_browser_failure_cannot_report_complete_even_if_zap_exits_zero(self):
        with tempfile.TemporaryDirectory() as root:
            def launch(argv, **kwargs):
                dest = Path(argv[-1]).parent
                (dest/'report.json').write_text(json.dumps({'site':[{'@name':URL,'alerts':[]}]}))
                (dest/'urls.txt').write_text(URL)
                write_har(dest,[entry()])
                (dest/'home'/'zap.log').write_text('Failed to start browser firefox-headless')
                kwargs['stdout'].write('Job spiderAjax started\nJob spiderAjax finished\n')
                kwargs['stdout'].flush()
                return MagicMock(wait=MagicMock(return_value=0))
            with patch('zap_adapter.executable',return_value='/fake/zap'),patch('zap_adapter.subprocess.Popen',side_effect=launch):
                _, data = run_scan({'evidence_dir':root}, URL, ajax=True)
            self.assertEqual(data['coverage']['status'],'partial')
            self.assertEqual(data['coverage']['phases']['spiderAjax'],'failed')

    def test_active_observer_tracks_post_without_har_or_alert(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'active.jsonl'
            rows=[{'url':URL+'form','method':'POST','parameters':['query'],'rule_id':'40018','status':200},
                  {'url':'https://outside.test/form','method':'POST','parameters':['q'],'rule_id':'40018','status':200},
                  {'url':URL+'form','method':'POST','parameters':['query'],'rule_id':'999','status':200}]
            path.write_text('\n'.join(json.dumps(r) for r in rows))
            d=Discovery(URL,allowed_rules=[40018]); d.active_records(path)
            result=d.result()
            self.assertEqual(result['test_request_count'],1)
            self.assertEqual(result['endpoints'][0]['state'],'tested')
            self.assertEqual(result['endpoints'][0]['method'],'POST')
