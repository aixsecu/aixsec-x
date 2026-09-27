"""Deterministic confidence scores for Route Family sampling coverage."""
from __future__ import annotations

import json
from pathlib import Path


class FamilyConfidence:
    def __init__(self,threshold=0.6):
        self.threshold=min(1.0,max(0.0,float(threshold)))

    def build(self,family_report,tested_members=()):
        tested={str(value) for value in tested_members};families=[]
        for family in sorted(family_report.get('families',[]),key=lambda row:row['family_id']):
            members=[str(row['request_id']) for row in family.get('members',[])]
            representatives={str(value) for value in family.get('representative_candidates',[])}
            validated=sorted(set(members)&(tested|representatives));count=len(members)
            coverage=(len(validated)/count) if count else 1.0
            representative_ratio=(len(representatives)/count) if count else 1.0
            # Replays carry most weight; representatives provide the initial prior.
            confidence=min(1.0,0.8*coverage+0.2*representative_ratio)
            unvalidated=sorted(set(members)-set(validated))
            families.append({'family_id':family['family_id'],'member_count':count,
                'coverage_score':round(coverage*100,2),'confidence':round(confidence,4),
                'validated_members':validated,'representative_ratio':round(representative_ratio,4),
                'additional_replay_required':bool(unvalidated and confidence<self.threshold),
                'unvalidated_members':unvalidated})
        required=[row['family_id'] for row in families if row['additional_replay_required']]
        return {'version':1,'algorithm':'deterministic-family-confidence-v1',
                'threshold':self.threshold,'family_count':len(families),
                'families_requiring_replay':required,'families':families}

    @staticmethod
    def write(result,path):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);temporary=path.with_suffix(path.suffix+'.tmp')
        temporary.write_text(json.dumps(result,ensure_ascii=False,indent=2));temporary.chmod(0o600);temporary.replace(path)
        return result
