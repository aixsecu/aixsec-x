"""Operator policy scope, authentication independence and per-origin barriers."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from zap_concurrency import ConcurrencyPolicy
from zap_workers import drive, parallel_safe, scheduling_summary
from tests.test_zap_workers import entry
from scan_state import Journal


def rule(**changes):
    return dict(id='catalog',origin='https://example.test',auth_context='member',
                paths=['/catalog/*'],mode='parallel_read',**changes) if not changes else {
        **rule(),**changes}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'policy.json'
    def policy(self,*rules):
        self.path.write_text(json.dumps({'version':1,'rules':list(rules)}))
        return ConcurrencyPolicy(str(self.path))
    def member(self,path='catalog/a'):
        job=entry(path,headers=[{'name':'Authorization','value':'Bearer private'},
                               {'name':'Cookie','value':'session=private'}])
        job['auth_context']='member'
        return job
    def test_scoped_authenticated_reads_preserve_requests(self):
        policy=self.policy(rule())
        job=self.member();original=copy.deepcopy(job)
        self.assertFalse(parallel_safe(job))
        self.assertTrue(parallel_safe(job,policy=policy))
        self.assertEqual(job,original)
        for changed in ('context','path','origin','port'):
            other=copy.deepcopy(job)
            if changed=='context':other['auth_context']='administrator'
            elif changed=='path':other['_entry']['request']['url']='https://example.test/profile'
            elif changed=='origin':other['_entry']['request']['url']='https://other.test/catalog/a'
            else:other['_entry']['request']['url']='https://example.test:8443/catalog/a'
            self.assertFalse(parallel_safe(other,policy=policy),changed)
        self.assertNotIn('private',json.dumps(scheduling_summary([job],policy=policy)))
    def test_serial_override_and_hard_constraints(self):
        policy=self.policy(rule(),rule(id='deny',auth_context='*',paths=['/catalog/logout'],mode='serial'))
        self.assertFalse(parallel_safe(self.member('catalog/logout'),policy=policy))
        for changes in ({'method':'POST'}, {'postData':{'text':'{}'}},
                        {'headers':[{'name':'X-CSRF-Token','value':'secret'}]},
                        {'url':'https://example.test/catalog/a?session=secret'}):
            job=self.member();job['_entry']['request'].update(changes)
            self.assertFalse(parallel_safe(job,policy=policy))
    def test_invalid_policy_and_ambiguous_matches(self):
        for bad in (rule(auth_context='*'),rule(origin='https://example.test/path'),
                    rule(origin='https://user:pass@example.test'),rule(mode='unknown')):
            with self.assertRaises(ValueError):self.policy(bad)
        policy=self.policy(rule(),rule(id='duplicate'))
        with self.assertRaises(ValueError):policy.match(self.member())
    def test_concurrency_file_change_rejects_resume(self):
        self.policy(rule())
        cfg={'zap_concurrency_file':str(self.path)}
        Journal(self.temp.name,cfg)
        self.policy(rule(mode='serial'))
        with self.assertRaisesRegex(ValueError,'concurrency profile changed'):
            Journal(self.temp.name,cfg)
    def test_authenticated_policy_reads_overlap(self):
        policy=self.policy(rule())
        barrier=threading.Barrier(2)
        def start(job,cancelled):
            def work():
                self.assertEqual(job['_entry']['request']['headers'][0]['value'],'Bearer private')
                barrier.wait(3)
                return {'outcome':'ok'}
            yield work
        drive([self.member('catalog/a'),self.member('catalog/b')],start,2,policy=policy)
    def test_serial_origin_does_not_block_other_origin_or_reorder_same_origin(self):
        first=entry('write','POST')
        blocked=entry('next')
        independent=entry('write','POST');independent['_entry']['request']['url']='https://other.test/write'
        barrier=threading.Barrier(2)
        finished=threading.Event()
        order=[]
        def start(job,cancelled):
            url=job['_entry']['request']['url']
            order.append(url)
            def work():
                if url.endswith('/next'):
                    self.assertTrue(finished.is_set())
                else:
                    barrier.wait(3)
                    if url=='https://example.test/write':finished.set()
                return {'outcome':'ok'}
            yield work
        drive([first,blocked,independent],start,2)
        self.assertEqual(order[:2],['https://example.test/write','https://other.test/write'])
    def test_pipeline_uses_policy_and_retains_stage_diagnostics(self):
        from unittest.mock import patch
        from test_sequential_pipeline import baseline,config
        from tools import TOOL_INDEX
        from agent import WebXAgent
        self.policy(rule(auth_context='anonymous',paths=['/*']))
        root=self.temp.name
        seed=baseline(root)
        har=Path(root)/'seed-source.har'
        content=json.loads(har.read_text())
        content['log']['entries'][1]['request']['url']='https://example.test/other?q=two'
        for captured in content['log']['entries']:
            captured['request']['headers']=[{'name':'Cookie','value':'sid=private'}]
        har.write_text(json.dumps(content))
        barrier=threading.Barrier(2)
        def active(**kw):
            self.assertEqual(kw['_config']['_zap_seed_entry']['request']['headers'][0]['value'],'sid=private')
            barrier.wait(3)
            return 'ok',{'coverage':{'status':'complete'}}
        cfg=config(root,nuclei_enabled=False,zap_concurrency_file=str(self.path))
        with patch.object(TOOL_INDEX['zap_baseline'],'exec_fn',return_value=seed),patch.object(TOOL_INDEX['zap_active_scan'],'exec_fn',side_effect=active):
            result=WebXAgent(cfg).run('scan')
        stats=result['progress']['stages']['zap_active']['scheduling']
        self.assertEqual(stats['parallel_eligible'],2)
        self.assertEqual(stats['policy_matches'],{'catalog':2})
