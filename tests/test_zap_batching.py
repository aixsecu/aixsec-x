"""Offline regressions for safe ZAP active-scan batching and metrics."""
import json
from pathlib import Path
import tempfile
import unittest

from adapters.zap import build_plan
from zap_workers import batch_jobs


BASE = 'https://example.test/'


def captured(path, auth='anonymous', method='GET', headers=None):
    return {'request_id': path, 'auth_context': auth,
            '_entry': {'request': {'url': BASE + path, 'method': method,
                                    'headers': headers or []},
                       'response': {'status': 200}}}


class ZapBatchingTests(unittest.TestCase):
    def test_discovery_plan_uses_distinct_phase_budgets_and_checkpoints(self):
        with tempfile.TemporaryDirectory() as root:
            config = {'zap_spider_minutes': 2, 'zap_ajax_minutes': 4,
                      'zap_passive_minutes': 1}
            plan = build_plan(config, BASE, root, ajax=True)
            spider = next(job for job in plan['jobs'] if job['type'] == 'spider')
            ajax = next(job for job in plan['jobs'] if job['type'] == 'spiderAjax')
            passive = next(job for job in plan['jobs'] if job['type'] == 'passiveScan-wait')
            self.assertEqual(spider['parameters']['maxDuration'], 2)
            self.assertEqual(ajax['parameters']['maxDuration'], 4)
            self.assertEqual(passive['parameters']['maxDuration'], 1)
            exports = [job['parameters']['fileName'] for job in plan['jobs']
                       if job['type'] == 'export']
            self.assertTrue(any(name.endswith('traffic-spider.har') for name in exports))
            self.assertTrue(any(name.endswith('traffic-ajax.har') for name in exports))

    def test_safe_groups_batch_by_origin_and_auth(self):
        jobs = [captured('a'), captured('b'), captured('c', auth='member')]
        batches = batch_jobs(jobs, 8, 'guest')
        self.assertEqual([len(row['_batch_members']) for row in batches], [2, 1])

    def test_unsafe_and_auto_unassessed_groups_remain_isolated(self):
        post = captured('write', method='POST')
        cookie = captured('private', headers=[{'name': 'Cookie', 'value': 'sid=secret'}])
        self.assertEqual(len(batch_jobs([post, post.copy()], 8, 'guest')), 2)
        auto = [captured('a'), captured('b')]
        for row in auto:
            row['_auto_reasons'] = []
        self.assertEqual(len(batch_jobs(auto, 8, 'auto')), 2)
        self.assertEqual(len(batch_jobs([cookie, captured('public')], 8, 'strict')), 2)

    def test_batch_plan_imports_once_and_exports_once(self):
        with tempfile.TemporaryDirectory() as root:
            entries = [captured('a')['_entry'], captured('b')['_entry']]
            config = {'zap_allowed_rules': [40018], '_zap_seed_entries': entries,
                      'zap_phase_minutes': 1, 'zap_strength': 'Medium'}
            plan = build_plan(config, BASE + 'a', root, active=True, rule_ids=[40018])
            types = [job['type'] for job in plan['jobs']]
            self.assertEqual(types.count('import'), 1)
            self.assertEqual(types.count('activeScan'), 1)
            self.assertEqual(types.count('report'), 1)
            seed = json.loads((Path(root) / 'seed.har').read_text())
            self.assertEqual(len(seed['log']['entries']), 2)
            self.assertEqual(len(plan['env']['contexts'][0]['includePaths']), 2)

    def test_batch_rejects_cross_origin_seed(self):
        with tempfile.TemporaryDirectory() as root:
            foreign = captured('a')['_entry']
            foreign['request']['url'] = 'https://outside.test/a'
            with self.assertRaisesRegex(ValueError, 'one origin'):
                build_plan({'zap_allowed_rules': [40018], '_zap_seed_entries': [foreign]},
                           BASE, root, active=True, rule_ids=[40018])


if __name__ == '__main__':
    unittest.main()
