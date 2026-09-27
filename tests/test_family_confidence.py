from pathlib import Path
import tempfile
import unittest

from family_confidence import FamilyConfidence


def report(size=5):
    return {'families':[{'family_id':'rf-one','representative_candidates':['r1'],
        'members':[{'request_id':f'r{index}'} for index in range(1,size+1)]}]}


class FamilyConfidenceTests(unittest.TestCase):
    def test_each_family_contains_required_confidence_fields(self):
        result=FamilyConfidence().build(report(),{'r2','r3'})
        family=result['families'][0]
        self.assertEqual(family['coverage_score'],60.0)
        self.assertEqual(family['representative_ratio'],0.2)
        self.assertEqual(family['confidence'],0.52)
        self.assertEqual(family['validated_members'],['r1','r2','r3'])
        self.assertTrue(family['additional_replay_required'])

    def test_confidence_stops_additional_replay_at_threshold(self):
        result=FamilyConfidence().build(report(),{'r2','r3','r4'})
        family=result['families'][0]
        self.assertEqual(family['confidence'],0.68)
        self.assertFalse(family['additional_replay_required'])
        self.assertEqual(result['families_requiring_replay'],[])

    def test_single_member_family_is_fully_confident(self):
        family=FamilyConfidence().build(report(1))['families'][0]
        self.assertEqual(family['coverage_score'],100.0)
        self.assertEqual(family['confidence'],1.0)
        self.assertFalse(family['additional_replay_required'])

    def test_persisted_artifact_is_private(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'confidence.json';FamilyConfidence.write(FamilyConfidence().build(report()),path)
            self.assertTrue(path.is_file());self.assertEqual(path.stat().st_mode & 0o777,0o600)


if __name__=='__main__':unittest.main()
