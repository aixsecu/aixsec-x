import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch
from agent import WebXAgent
from config import load_config
from tools import TOOL_INDEX
from planner_progress import facts
from evidence import EvidenceStore
from ledger import Ledger

class PlannerProgressTests(unittest.TestCase):
    def test_success_without_new_facts_stops_planner(self):
        with tempfile.TemporaryDirectory() as root:
            cfg=load_config();cfg.update(evidence_dir=root,scan_backend='none',targets=['https://example.test/'],
                                       planner_enabled=True,nuclei_enabled=False,auto_exec='all',max_rounds=8)
            calls=[]
            def model(*args,**kw):
                calls.append(1)
                return {'content':'','tool_calls':[{'name':'evidence_status','arguments':{}}]}
            with contextlib.redirect_stdout(io.StringIO()):
                result=WebXAgent(cfg,chat=model).run('scan')
            self.assertEqual(len(calls),1)
            self.assertIn('No new',result['progress']['stages']['planner']['reason'])

    def test_scan_ids_and_hashes_alone_are_not_new_facts(self):
        from inventory import Inventory
        from types import SimpleNamespace
        store=EvidenceStore(Ledger())
        agent=SimpleNamespace(evidence_store=store,inventory=Inventory(),transcript=[])
        row={'category':'SQL Injection','url':'https://example.test/','method':'GET','parameter':'q','auth_context':'anonymous'}
        store.records['one']={**row,'scan_id':'one','response_sha256':'first'}
        before=facts(agent)
        store.records['two']={**row,'scan_id':'two','response_sha256':'changed-clock'}
        self.assertEqual(facts(agent),before)
        store.records['two']['validation']={'status':'needs_validation','reason':'paired error reproduced'}
        self.assertTrue(facts(agent)-before)
