from pathlib import Path
import tempfile
import unittest

from divergence import DivergenceDetector


def record(evidence_id,member='',parameter='id',status='200',evidence='candidate'):
    return {'tool':'zap_active_scan','_candidate':True,'evidence_id':evidence_id,
        'family_id':'rf-one','representative_id':'r1','divergence_member_id':member,
        'rule_id':'40018','parameter':parameter,'category':'SQL Injection','evidence':evidence,
        'method':'GET','_verification':{'response_header':
            f'HTTP/1.1 {status} OK\r\nContent-Type: text/html\r\nX-Test: yes\r\n'}}


def fixtures():
    family={'version':1,'family_count':1,'families':[{'family_id':'rf-one','fingerprint':'abc',
        'structure':{},'representative_candidates':['r1'],'members':[
            {'request_id':'r1','url':'https://example.test/orders/1'},
            {'request_id':'m2','url':'https://example.test/orders/2'},
            {'request_id':'m3','url':'https://example.test/orders/3'}]}]}
    evidence={'findings':[{'finding_id':'f1','family_id':'rf-one','representative_id':'r1',
        'member_count':3,'rule_ids':['40018'],'raw_evidence':[{'evidence_id':'e1'}]}]}
    return family,evidence


class DivergenceTests(unittest.TestCase):
    def test_plan_is_deterministic_and_bounded(self):
        family,evidence=fixtures();plans=DivergenceDetector(samples=1).plan(family,evidence)
        self.assertEqual([row['member_id'] for row in plans],['m2'])
        self.assertEqual(plans[0]['rule_ids'],['40018'])

    def test_confidence_gate_controls_whether_replay_is_planned(self):
        family,evidence=fixtures();detector=DivergenceDetector()
        self.assertEqual(detector.plan(family,evidence,required_families=set()),[])
        self.assertEqual(len(detector.plan(family,evidence,required_families={'rf-one'})),2)

    def test_matching_replays_confirm_family(self):
        family,evidence=fixtures();detector=DivergenceDetector();plans=detector.plan(family,evidence)
        records=[record('e1'),record('e2','m2'),record('e3','m3')]
        result=detector.analyze(family,evidence,records,plans,3,1)
        self.assertEqual(result['findings'][0]['status'],'family_confirmed')
        self.assertEqual(result['family_confirmation_rate'],100.0)
        self.assertEqual(result['extra_scans'],2)
        self.assertEqual(result['avoided_scans'],0)

    def test_mismatch_splits_family_deterministically(self):
        family,evidence=fixtures();detector=DivergenceDetector();plans=detector.plan(family,evidence)
        records=[record('e1'),record('e2','m2'),record('e3','m3',parameter='other')]
        result=detector.analyze(family,evidence,records,plans,100,1)
        self.assertEqual(result['findings'][0]['status'],'split_family')
        self.assertEqual(result['avoided_scans'],97)
        self.assertEqual(len(result['splits']),1)
        detector.apply_splits(family,result)
        self.assertEqual(family['family_count'],2)
        self.assertEqual(family['families'][1]['members'][0]['request_id'],'m3')

    def test_persists_private_artifact(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'divergence.json';DivergenceDetector.write({'findings':[]},path)
            self.assertTrue(path.is_file());self.assertEqual(path.stat().st_mode & 0o777,0o600)


if __name__=='__main__':unittest.main()
