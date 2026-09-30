import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from zap_schedule import family, ScanSchedule
from adapters.zap import build_plan
from config import load_config
from agent import WebXAgent
from tools import TOOL_INDEX
from attack_planning import applicable_rules, risk_score

BASE='https://example.test/'
def request(url=BASE+'item?id=1',method='GET',post=None):
    return {'url':url,'method':method,'headers':[],'postData':post or {}}
def entry(req):
    return {'request':req, 'response':{'status':200}}

class FamilyTests(unittest.TestCase):
    def test_values_order_and_numeric_ids_group(self):
        self.assertEqual(family(request(BASE+'users/12?x=1&y=a')),family(request(BASE+'users/99?y=b&x=2')))
    def test_routes_and_methods_do_not_group(self):
        a=family(request(BASE+'api?act=search&q=x'))
        self.assertNotEqual(a,family(request(BASE+'api?act=delete&q=x')))
        self.assertNotEqual(a,family(request(BASE+'api?act=search&q=x','POST')))
        self.assertNotEqual(a,family(request(BASE+'other?act=search&q=x')))
        self.assertNotEqual(a,family(request(BASE+'api?act=search&q=x'),'alice'))
    def test_json_schema_body_location_and_route_values(self):
        a=request(post={'mimeType':'application/json','text':'{"id":1,"filter":{"q":"a"}}'})
        b=request(post={'mimeType':'application/json','text':'{"filter":{"q":"b"},"id":2}'})
        self.assertEqual(family(a),family(b))
        b['postData']['text']='{"id":2,"filter":{"sort":"b"}}'
        self.assertNotEqual(family(a),family(b))
        self.assertNotEqual(family(request(BASE+'api?id=1')),family(request(BASE+'api',post={'mimeType':'application/x-www-form-urlencoded','text':'id=1'})))
    def test_slugs_stay_distinct_and_uuids_group(self):
        self.assertNotEqual(family(request(BASE+'products/camera')),family(request(BASE+'products/laptop')))
        self.assertEqual(family(request(BASE+'users/12345678-1234-1234-1234-123456789012')),
                         family(request(BASE+'users/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')))

class ScheduleTests(unittest.TestCase):
    def test_rule_applicability_is_per_request_and_conservative(self):
        plain={'url':BASE+'plain','method':'GET','auth_context':'anonymous',
               'structure':{'query':[],'body':[]},'_entry':entry(request(BASE+'plain'))}
        search={'url':BASE+'tim-kiem.html?keyword=a','method':'GET','auth_context':'anonymous',
                'structure':{'query':[('keyword','')],'body':[]},
                '_entry':entry(request(BASE+'tim-kiem.html?keyword=a'))}
        rules=[{'id':40018,'name':'SQL Injection'},{'id':40012,'name':'Cross Site Scripting'},
               {'id':10001,'name':'Unknown third-party check'}]
        kept,excluded=applicable_rules(plain,rules)
        self.assertEqual(kept,[10001])
        self.assertEqual({row['id'] for row in excluded},{40012,40018})
        self.assertEqual(applicable_rules(search,rules)[0],[10001,40012,40018])
        self.assertGreater(risk_score(search)[0],risk_score(plain)[0])

    def test_deferred_budget_is_reported_without_persistent_claim(self):
        with tempfile.TemporaryDirectory() as root:
            schedule=ScanSchedule(root);schedule.entries['f']={'request_id':'f','url':BASE,'method':'GET'}
            schedule.defer('f',[40018],'deferred_by_budget')
            row=schedule.summary([40018])['families'][0]['rules'][0]
            self.assertEqual(row['state'],'deferred_by_budget')
            self.assertEqual(schedule.remaining('f',[40018]),[40018])

    def test_malformed_har_downgrades_coverage_without_crashing(self):
        with tempfile.TemporaryDirectory() as root:
            har = Path(root) / 'traffic.har'
            har.write_text('{"log":{"entries":[{"broken": true}')
            coverage = {'har_path': str(har), 'target': BASE,
                        'auth_context': 'anonymous', 'status': 'complete'}
            schedule = ScanSchedule(root)
            self.assertEqual(schedule.collect(coverage), 0)
            self.assertEqual(coverage['status'], 'partial')
            self.assertEqual(coverage['har_import']['status'], 'error')
            self.assertIn('HAR import failed', schedule.stop_reason)
            self.assertEqual(len(schedule.import_errors), 1)
            self.assertEqual(schedule.entries, {})

    def test_har_with_invalid_schema_is_reported_as_partial(self):
        with tempfile.TemporaryDirectory() as root:
            har = Path(root) / 'traffic.har'
            har.write_text(json.dumps({'log': {'entries': {}}}))
            coverage = {'har_path': str(har), 'target': BASE,
                        'auth_context': 'anonymous', 'status': 'complete'}
            schedule = ScanSchedule(root)
            self.assertEqual(schedule.collect(coverage), 0)
            self.assertIn('log.entries must be an array',
                          coverage['har_import']['reason'])

    def test_active_limit_prioritizes_parameterized_and_body_shapes(self):
        with tempfile.TemporaryDirectory() as root:
            har=Path(root)/'traffic.har'
            har.write_text(json.dumps({'log':{'entries':[
                entry(request(BASE+'plain')),
                entry(request(BASE+'search?q=a')),
                entry(request(BASE+'submit','POST',{'mimeType':'application/json','text':'{"q":"a"}'})),
            ]}}))
            schedule=ScanSchedule(root);schedule.collect({'har_path':str(har),'target':BASE})
            report=schedule.limit(2)
            self.assertEqual(report,{'configured':2,'before':3,'after':2,'dropped':1})
            self.assertTrue(all(row['structure']['query'] or row['structure']['body']
                                for row in schedule.entries.values()))
            self.assertEqual(schedule.summary([])['active_input_limit'],report)

    def test_recorded_responses_remain_deduplicated(self):
        with tempfile.TemporaryDirectory() as root:
            schedule = ScanSchedule(root)
            schedule.claim('family', [40018])
            schedule.finish('family', [40018], {'outcome': 'ok', 'data': {
                'discovery': {'endpoints': [{'tested_rule_ids': ['40018']}]},
                'coverage': {'active_evidence': {'rules_with_evidence': [40018]}}}})
            self.assertEqual(ScanSchedule(root).remaining('family', [40018]), [])
            with schedule.connection() as db:
                self.assertEqual(db.execute('SELECT state FROM attempts').fetchone()[0], 'responses_recorded')

    def test_auth_expired_attempt_is_retryable_and_keeps_generation_ledger(self):
        with tempfile.TemporaryDirectory() as root:
            schedule=ScanSchedule(root); schedule.claim('family',[40018])
            schedule.finish('family',[40018],{'outcome':'ok','data':{'coverage':{
                'status':'partial','auth_generation':3,'auth_disposition':'deferred_auth_expired'}}})
            self.assertEqual(schedule.remaining('family',[40018]),[40018])
            summary=schedule.summary([40018])
            self.assertEqual(summary['auth_retry_ledger'][0]['auth_generation'],3)
            self.assertEqual(summary['families'],[])  # ledger survives even before a new HAR entry is collected


    def test_persistent_per_rule_reservation_and_denial_release(self):
        with tempfile.TemporaryDirectory() as root:
            s=ScanSchedule(root)
            self.assertEqual(s.claim('f',[40018,40012]),[40018,40012])
            other=ScanSchedule(root)
            self.assertEqual(other.remaining('f',[40018,40012,6]),[6])
            s.finish('f',[40018],{'outcome':'denied'})
            self.assertEqual(other.remaining('f',[40018,40012]),[40018])
            self.assertEqual(ScanSchedule(root,'new-deployment').remaining('f',[40012]),[40012])
    def test_capture_grouping_drops_external_and_static(self):
        with tempfile.TemporaryDirectory() as root:
            har=Path(root)/'traffic.har'
            har.write_text(json.dumps({'log':{'entries':[entry(request(BASE+'search?q=a')),entry(request(BASE+'search?q=b')),
                entry(request('https://outside.test/search?q=b')),entry(request(BASE+'main.js'))]}}))
            s=ScanSchedule(root);s.collect({'har_path':str(har),'target':BASE})
            self.assertEqual(len(s.entries),1)
            row=next(iter(s.entries.values()))
            self.assertEqual(row['equivalent_requests'],2)
            self.assertEqual(s.skipped_static,1)
    def test_exact_seed_skips_crawl_and_other_methods(self):
        with tempfile.TemporaryDirectory() as root:
            cfg={'_zap_seed_entry':entry(request(BASE+'search?q=a')),'zap_allowed_rules':[40018,40012]}
            plan=build_plan(cfg,BASE+'search?q=a',root,active=True,rule_ids=[40018,40012])
            self.assertNotIn('spider',[j['type'] for j in plan['jobs']])
            self.assertEqual(len(json.loads((Path(root)/'seed.har').read_text())['log']['entries']),1)
            policy=next(j for j in plan['jobs'] if j['type']=='activeScan-policy')
            self.assertEqual({r['id'] for r in policy['policyDefinition']['rules']},{40018,40012})
    def test_pipeline_schedules_all_installed_rules_without_llm_and_skips_next_run(self):
        with tempfile.TemporaryDirectory() as root:
            har=Path(root)/'traffic.har'
            har.write_text(json.dumps({'log':{'entries':[entry(request(BASE+'search?q=a')),entry(request(BASE+'search?q=b'))]}}))
            cfg=load_config();cfg.update(nuclei_enabled=False, targets=[BASE],evidence_dir=root,scan_backend='zap',planner_enabled=False,
                allow_active_scan=True,zap_auto_active=True,zap_allowed_rules='all',auto_exec='all')
            baseline={'target':BASE,'coverage':{'target':BASE,'har_path':str(har),'auth_context':'anonymous','status':'complete'},
                      'active_rules':[{'id':40018,'name':'SQLi'},{'id':40012,'name':'XSS'}], 'alerts':[]}
            calls=[]
            def active(**kw):
                calls.append(kw)
                self.assertEqual(kw['_config']['_zap_seed_entry']['request']['url'],BASE+'search?q=a')
                return 'done',{'alerts':[],'discovery':{'endpoints':[{'tested_rule_ids':['40012','40018']}]}}
            for _ in range(2):
                agent=WebXAgent(cfg)
                agent.available.update({'zap_baseline','zap_active_scan'})
                with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=('baseline',copy.deepcopy(baseline))),patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',side_effect=active):
                    result=agent.run('scan all supported categories')
            self.assertEqual(len(calls),1)
            self.assertEqual(set(calls[0]['rule_ids']),{40012,40018})
            self.assertTrue(Path(result['family_evidence_path']).is_file())
            self.assertEqual(json.loads(Path(result['family_evidence_path']).read_text())['finding_count'],0)
            self.assertTrue((Path(result['evidence_path']).parent/'confidence.json').is_file())
            self.assertTrue((Path(result['evidence_path']).parent/'family-ai-hypotheses.json').is_file())
            states=result['active_schedule']['families'][0]['rules']
            self.assertTrue(all(s['state']=='requests_observed' for s in states))
