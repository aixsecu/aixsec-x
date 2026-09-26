import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from adapters.nuclei import template_info, parse_report, run_scan
from evidence import EvidenceStore
from ledger import Ledger

TEMPLATE = '''id: local-fixture
info:
  name: Fixture
  author: aixsec
  severity: medium
http:
  - method: GET
    path: ['{{BaseURL}}/fixture']
    matchers:
      - type: word
        words: [local-marker]
'''
URL='https://example.test/'

class NucleiTests(unittest.TestCase):
    def test_template_scope_and_external_template_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'template.yaml'; p.write_text(TEMPLATE)
            self.assertEqual(template_info(p)['scope'],'request_family')
            p.write_text(TEMPLATE.replace('{{BaseURL}}','{{RootURL}}'))
            self.assertEqual(template_info(p)['scope'],'origin')
            p.write_text(TEMPLATE.replace('{{BaseURL}}','https://external.test'))
            with self.assertRaises(ValueError): template_info(p)
            p.write_text(TEMPLATE + '\nvariables:\n  RootURL: https://external.test\n')
            with self.assertRaises(ValueError): template_info(p)

    def test_jsonl_scope_malformed_and_evidence_candidate(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'report.jsonl'
            item={'template-id':'local-fixture','matched-at':URL+'fixture',
                  'info':{'name':'Fixture','severity':'high'},'request':'GET /fixture HTTP/1.1\r\nCookie: SECRET',
                  'response':'HTTP/1.1 200 OK\r\n\r\nSECRET'}
            p.write_text(json.dumps(item)+'\n'+json.dumps({**item,'matched-at':'https://external.test/'})+'\n{broken\n')
            rows, errors, rejected=parse_report(p,URL,[{'id':'local-fixture'}],'test')
            self.assertEqual((len(rows),errors,rejected),(1,1,1))
            self.assertNotIn('SECRET',json.dumps(rows))
            store=EvidenceStore(Ledger(),root)
            store.ingest({'name':'nuclei_scan','outcome':'ok','args':{'url':URL},'data':{'alerts':rows}})
            result=store.finish(False)
            self.assertEqual(len(result['findings']),1)
            self.assertNotEqual(result['findings'][0]['status'],'confirmed')

    def test_changed_template_is_not_executed(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'template.yaml'; p.write_text(TEMPLATE)
            info=template_info(p); p.write_text(TEMPLATE+'\n# new revision\n')
            with patch('adapters.nuclei.executable',return_value='/fake/nuclei'), patch('adapters.nuclei.subprocess.Popen') as process:
                with self.assertRaises(ValueError): run_scan({'evidence_dir':root},URL,[info])
            process.assert_not_called()

    def test_timeout_terminates_process_and_preserves_partial_results(self):
        import subprocess
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'template.yaml'; p.write_text(TEMPLATE)
            info=template_info(p)
            with patch('adapters.nuclei.executable',return_value='/fake/nuclei'), \
                 patch('adapters.nuclei.subprocess.Popen') as popen, patch('adapters.nuclei.os.killpg') as kill:
                popen.return_value.wait.side_effect=[subprocess.TimeoutExpired('nuclei',1),0]
                popen.return_value.pid=1234
                _, data=run_scan({'evidence_dir':root},URL,[info],timeout=1)
            kill.assert_called_once()
            self.assertEqual(data['coverage']['status'],'timeout')
