from pathlib import Path
import tempfile
import unittest

from divergence import DivergenceDetector
from family_history import FamilyHistory
from route_family import RepresentativeSelector,RouteFamilyBuilder


def rows(count=5):
    result={}
    for index in range(count):
        request_id=f'r{index+1}';url=f'https://example.test/orders/{index+1}'
        captured={'request':{'url':url,'method':'GET','headers':[]},
            'response':{'status':200,'headers':[],
                        'content':{'mimeType':'text/html','text':'<html><body>order</body></html>'}}}
        result[request_id]={'request_id':request_id,'url':url,'method':'GET',
                            'auth_context':'anonymous','_entry':captured}
    return result


class FamilyHistoryTests(unittest.TestCase):
    def test_split_rebuilds_representatives_and_preserves_history(self):
        entries=rows();family=RouteFamilyBuilder().build(entries)
        RepresentativeSelector().select(entries,family)
        parent=family['families'][0]['family_id'];history=FamilyHistory(5)
        history.observe_plans([{'family_id':parent,'member_id':'r2'}])
        divergence={'splits':[{'source_family_id':parent,'family_id':'rf-div-child',
            'member_id':'r2','member_url':entries['r2']['url']}]}
        selection,event=history.rebuild(family,divergence,entries,RepresentativeSelector(),1)
        self.assertEqual(event['before']['families'],1)
        self.assertEqual(event['after']['families'],2)
        self.assertEqual(selection['scan_groups_after'],2)
        self.assertEqual(entries['r2']['route_family_id'],'rf-div-child')
        snapshot=history.snapshot(family,2)
        self.assertEqual(snapshot['generations'],1)
        self.assertEqual(snapshot['events'][0]['splits'][0]['member_id'],'r2')

    def test_recursive_plan_skips_members_already_tested_in_parent(self):
        entries=rows();family=RouteFamilyBuilder().build(entries);RepresentativeSelector().select(entries,family)
        family_id=family['families'][0]['family_id'];evidence={'findings':[{'family_id':family_id,
            'representative_id':'r1','rule_ids':['40018']}]}
        plans=DivergenceDetector(samples=2).plan(family,evidence,{(family_id,'r2')})
        self.assertEqual([plan['member_id'] for plan in plans],['r3','r4'])

    def test_history_artifact_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'family-history.json';FamilyHistory.write({'events':[]},path)
            self.assertTrue(path.is_file());self.assertEqual(path.stat().st_mode & 0o777,0o600)


if __name__=='__main__':unittest.main()
