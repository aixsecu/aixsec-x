import copy
from pathlib import Path
import tempfile
import unittest

from family_ai import FamilyAIAssistant


def reports(low=True):
    confidence={'family_count':2,'families_requiring_replay':['rf-low'] if low else [],'families':[
        {'family_id':'rf-low','confidence':0.2,'validated_members':['r1'],
         'representative_ratio':0.2,'coverage_score':20,'additional_replay_required':low},
        {'family_id':'rf-high','confidence':1.0,'validated_members':['r9'],
         'representative_ratio':1.0,'coverage_score':100,'additional_replay_required':False}]}
    family={'families':[{'family_id':'rf-low','fingerprint':'a','representative_candidates':['r1'],
        'members':[{'request_id':'r1'},{'request_id':'r2'}]},
        {'family_id':'rf-high','fingerprint':'b','representative_candidates':['r9'],
         'members':[{'request_id':'r9'}]}]}
    return confidence,family


class FamilyAITests(unittest.TestCase):
    def test_ai_is_never_called_without_low_confidence_family(self):
        confidence,family=reports(False)
        result=FamilyAIAssistant(True).assist(confidence,family,
            lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError('must not call')))
        self.assertEqual(result['ai_invocations'],0);self.assertEqual(result['hypotheses'],[])

    def test_only_allowed_hypotheses_are_retained_and_never_applied(self):
        confidence,family=reports();original=copy.deepcopy(family)
        content='{"suggestions":[' \
            '{"action":"suggest_split","family_id":"rf-low","member_ids":["r2"],"reason":"different shape"},' \
            '{"action":"suggest_merge","family_id":"rf-low","target_family_id":"rf-high","member_ids":[]},' \
            '{"action":"finding","family_id":"rf-low","severity":"critical"},' \
            '{"action":"suggest_additional_replay","family_id":"rf-low","member_ids":["unknown"]}]}'
        result=FamilyAIAssistant(True).assist(confidence,family,
            lambda *args,**kwargs:{'content':content})
        self.assertEqual(result['ai_invocations'],1);self.assertEqual(len(result['hypotheses']),2)
        self.assertTrue(all(row['status']=='hypothesis' and not row['applied'] and row['evidence_precedence']
                            for row in result['hypotheses']))
        self.assertEqual(family,original)

    def test_disabled_assistance_does_not_call_model(self):
        confidence,family=reports()
        result=FamilyAIAssistant(False).assist(confidence,family,
            lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError('must not call')))
        self.assertEqual(result['ai_invocations'],0)

    def test_benchmark_metrics(self):
        metrics=FamilyAIAssistant.benchmark(10,2,1,1)
        self.assertEqual(metrics['ai_usage_rate'],20.0)
        self.assertEqual(metrics['manual_validation_reduction'],50.0)

    def test_persisted_hypotheses_are_private(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'family-ai-hypotheses.json';FamilyAIAssistant.write({'hypotheses':[]},path)
            self.assertTrue(path.is_file());self.assertEqual(path.stat().st_mode & 0o777,0o600)


if __name__=='__main__':unittest.main()
