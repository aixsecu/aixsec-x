import json
import tempfile
import unittest
from pathlib import Path
from zap_active_evidence import analyze

URL = 'https://example.test/search?q=abc'
class ActiveEvidenceTests(unittest.TestCase):
    def run_case(self, body='syntax error: select id FROM products', control='ok', **changes):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            seed = {'request': {'url': URL, 'method': 'GET'}, 'response': {'status': 200, 'content': {'text': control}}}
            row = dict(rule_id='40018', request_url=URL+'%27', method='GET', status=200,
                       request_body='', response_body=body, request_sha256='a', response_sha256='b')
            row.update(changes)
            (p/'seed.har').write_text(json.dumps({'log': {'entries': [seed]}}))
            (p/'active-evidence.jsonl').write_text(json.dumps(row)+'\n')
            return analyze(p, URL, [40018], 'anonymous', 'test')

    def test_custom_error_becomes_candidate_without_raw_body(self):
        summary, rows = self.run_case()
        self.assertEqual(summary['rules_with_evidence'], [40018])
        self.assertEqual(rows[0]['parameter'], 'q')
        self.assertNotIn('FROM products', json.dumps(rows))
        self.assertNotIn('confirmed', rows[0])

    def test_preexisting_error_is_not_new_finding(self):
        self.assertEqual(self.run_case(control='syntax error: select id')[1], [])

    def test_generic_error_is_not_sql_evidence(self):
        self.assertEqual(self.run_case(body='syntax error: invalid input')[1], [])

    def test_wrong_origin_rule_method_and_unchanged_input(self):
        for changes in ({'request_url':'https://other.test/search?q=x'}, {'rule_id':'40012'},
                        {'method':'POST'}, {'request_url':URL}):
            with self.subTest(changes=changes):
                self.assertEqual(self.run_case(**changes)[1], [])

    def test_missing_capture_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary, rows = analyze(tmp, URL, [40018], 'anonymous', 'test')
            self.assertTrue(summary['gaps'])
            self.assertEqual(rows, [])

    def test_truncation_is_not_silently_complete(self):
        summary, _ = self.run_case(response_truncated=True)
        self.assertIn('Some request/response bodies truncated', summary['gaps'])

    def test_post_form_comparison_and_missing_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            req = {'url': 'https://example.test/search', 'method': 'POST',
                   'postData': {'mimeType':'application/x-www-form-urlencoded', 'text':'q=abc&csrf=secret'}}
            control = {'request':req, 'response':{'status':200,'content':{'text':'ok'}}}
            (p/'seed.har').write_text(json.dumps({'log':{'entries':[control]}}))
            row = {'rule_id':'40018', 'request_url':req['url'], 'method':'POST', 'status':200,
                   'request_body':'q=abc%27&csrf=<redacted>', 'response_body':'syntax error: select id FROM products'}
            (p/'active-evidence.jsonl').write_text(json.dumps(row)+'\n')
            _, rows = analyze(p, req['url'], [40018], 'anonymous', 'test')
            self.assertEqual(rows[0]['parameter'], 'q')
            control['response']['content'].pop('text')
            (p/'seed.har').write_text(json.dumps({'log':{'entries':[control]}}))
            self.assertEqual(analyze(p, req['url'], [40018], 'anonymous', 'test')[1], [])

    def test_malformed_record_and_byte_limit_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'active-evidence.jsonl').write_text('{broken')
            (p/'active-evidence-truncated').write_text('true')
            summary, rows = analyze(p, URL, [40018], 'anonymous', 'test')
            self.assertEqual(rows, [])
            self.assertIn('Malformed evidence records skipped', summary['gaps'])
            self.assertTrue(any('byte limit' in gap for gap in summary['gaps']))
