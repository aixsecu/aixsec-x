import json
from pathlib import Path
import tempfile
import unittest

from family_evidence import FamilyEvidenceStore


class FamilyEvidenceStoreTests(unittest.TestCase):
    def record(self,**updates):
        value={'tool':'zap_active_scan','_candidate':True,'family_id':'rf-one',
            'representative_id':'request-one','representative_url':'https://example.test/orders/1',
            'member_urls':['https://example.test/orders/1','https://example.test/orders/2'],
            'member_count':2,'finding_id':'finding-one','evidence_id':'evidence-one',
            'rule_id':'40018','rule_ids':['40018','40019'],'category':'SQL Injection',
            'severity':'high','url':'https://example.test/orders/1','method':'GET','parameter':'id',
            'raw_result_reference':'/evidence/tool-1.json','artifact_ref':'/evidence/zap-report.json',
            'request_reference':'/evidence/zap-report.json#request-sha256=a',
            'response_reference':'/evidence/zap-report.json#response-sha256=b',
            'evidence':'scanner candidate'}
        value.update(updates);return value

    def test_candidate_finding_contains_complete_family_provenance(self):
        result=FamilyEvidenceStore().build([self.record()])
        self.assertEqual(result['verification_policy'],'candidate_only_no_validation')
        finding=result['findings'][0]
        self.assertEqual(finding['verification_state'],'candidate')
        for field in ('family_id','representative_id','representative_url','member_urls',
                      'rule_ids','raw_evidence'):
            self.assertIn(field,finding)
        self.assertEqual(finding['member_count'],2)
        self.assertEqual(finding['rule_ids'],['40018'])
        self.assertEqual(finding['raw_evidence'][0]['raw_result_reference'],'/evidence/tool-1.json')

    def test_only_representative_zap_candidates_are_stored(self):
        rows=[self.record(tool='zap_baseline'),self.record(_candidate=False),
              self.record(family_id=''),self.record(evidence_id='kept')]
        result=FamilyEvidenceStore().build(rows)
        self.assertEqual(result['finding_count'],1)

    def test_persisted_artifact_is_private(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'family-evidence.json'
            FamilyEvidenceStore().write([self.record()],path)
            self.assertEqual(json.loads(path.read_text())['finding_count'],1)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)


if __name__=='__main__':unittest.main()
