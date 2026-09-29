import tempfile
import unittest
import json
from pathlib import Path

from request_templates import build_templates, coverage_report, hydrate_from_har
from zap_schedule import ScanSchedule

BASE='https://example.test/'


class RequestTemplateTests(unittest.TestCase):
    def test_get_inputs_are_seeded_without_route_name_heuristics(self):
        discovery={'forms':[{'page':BASE,'action':BASE+'x7','method':'GET',
                    'parameters':['product_code','csrf_token'],'state':'discovered'}]}
        templates=build_templates(BASE,discovery)
        self.assertEqual(len(templates),1)
        entry=templates[0].seed_entry()
        self.assertEqual(entry['request']['method'],'GET')
        self.assertIn('product_code=aixsec-test',entry['request']['url'])
        self.assertNotIn('csrf_token=',entry['request']['url'])
        report=coverage_report(templates)
        self.assertTrue(report['summary']['ready'])
        self.assertEqual(report['summary']['discovered_inputs'],2)
        self.assertEqual(report['summary']['seeded'],1)
        self.assertEqual(report['summary']['skipped_by_policy'],1)

    def test_uncaptured_post_is_visible_and_policy_skipped(self):
        templates=build_templates(BASE,{'forms':[{'page':BASE,'action':BASE+'order',
            'method':'POST','parameters':['product_id','quantity'],'state':'discovered'}]})
        self.assertIsNone(templates[0].seed_entry())
        report=coverage_report(templates)
        self.assertTrue(report['summary']['ready'])
        self.assertEqual(report['summary']['skipped_by_policy'],2)
        self.assertEqual(report['inputs'][0]['reason'],'uncaptured write request')

    def test_safe_post_search_seed_has_form_body(self):
        templates=build_templates(BASE,{'forms':[{'page':BASE,'action':BASE+'lookup',
            'method':'POST','parameters':['keyword','category'],'state':'discovered'}]})
        entry=templates[0].seed_entry(allow_safe_post=True)
        self.assertEqual(templates[0].side_effect_class,'likely_safe_write')
        self.assertEqual(entry['request']['method'],'POST')
        self.assertEqual(entry['request']['postData']['mimeType'],
                         'application/x-www-form-urlencoded')
        self.assertIn('keyword=aixsec-test',entry['request']['postData']['text'])

    def test_dynamic_token_blocks_uncaptured_post_seed(self):
        templates=build_templates(BASE,{'forms':[{'page':BASE,'action':BASE+'lookup',
            'method':'POST','parameters':['keyword','csrf_token'],'state':'discovered'}]})
        self.assertIsNone(templates[0].seed_entry(allow_safe_post=True))
        report=coverage_report(templates)
        self.assertTrue(report['summary']['ready'])
        self.assertEqual(report['summary']['blocked_by_csrf'],1)
        self.assertEqual(report['summary']['skipped_by_policy'],1)

    def test_private_har_hydrates_csrf_and_cookie_without_report_leak(self):
        secret='csrf-SECRET-value'
        discovery={'forms':[{'page':BASE,'action':BASE+'lookup','method':'POST',
                    'parameters':['keyword','csrf_token'],'state':'discovered'}]}
        templates=build_templates(BASE,discovery)
        with tempfile.TemporaryDirectory() as root:
            har=Path(root)/'traffic.har'
            har.write_text(json.dumps({'log':{'entries':[{
                'request':{'url':BASE,'method':'GET','headers':[{'name':'Cookie','value':'sid=PRIVATE'}]},
                'response':{'status':200,'content':{'mimeType':'text/html','text':
                    '<form action="/lookup" method="post"><input name="keyword">'
                    f'<input type="hidden" name="csrf_token" value="{secret}"></form>'}}}]}}))
            hydrate_from_har(templates,har)
            entry=templates[0].seed_entry(allow_safe_post=True)
        self.assertIn('csrf_token=csrf-SECRET-value',entry['request']['postData']['text'])
        self.assertIn({'name':'Cookie','value':'sid=PRIVATE'},entry['request']['headers'])
        public=json.dumps(coverage_report(templates))
        self.assertNotIn(secret,public)
        self.assertNotIn('sid=PRIVATE',public)

    def test_seed_enters_schedule_before_family_reduction(self):
        templates=build_templates(BASE,{'endpoints':[{'url':BASE+'catalog','method':'GET',
            'parameters':['id'],'sources':['javascript_literal'],'state':'discovered'}]})
        entry=templates[0].seed_entry()
        with tempfile.TemporaryDirectory() as root:
            schedule=ScanSchedule(root)
            row=schedule.collect_seed(templates[0],entry)
            self.assertEqual(row['coverage_state'],'seeded')
            self.assertTrue(row['structure']['query'])
            self.assertEqual(row['_entry']['request']['url'],BASE+'catalog?id=aixsec-test')

    def test_duplicate_sources_do_not_duplicate_input_identity(self):
        discovery={'endpoints':[{'url':BASE+'items','method':'GET','parameters':['id'],
                    'sources':['javascript_literal'],'state':'discovered'}],
                   'forms':[{'page':BASE,'action':BASE+'items','method':'GET',
                    'parameters':['id'],'state':'discovered'}]}
        self.assertEqual(len(build_templates(BASE,discovery)),1)


if __name__ == '__main__':
    unittest.main()
