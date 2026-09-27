"""Durable history for recursive deterministic Route Family splits."""
from __future__ import annotations

import json
from pathlib import Path

from route_family import RepresentativeSelector


class FamilyHistory:
    def __init__(self,original_groups):
        self.original_groups=int(original_groups);self.tested=set();self.validated=set();self.events=[]

    def observe_plans(self,plans,validated_members=None):
        self.tested.update((plan['family_id'],plan['member_id']) for plan in plans)
        self.validated.update(str(value) for value in
                              (validated_members if validated_members is not None else [p['member_id'] for p in plans]))

    def rebuild(self,family_report,divergence,entries,selector=None,generation=1):
        from divergence import DivergenceDetector
        selector=selector or RepresentativeSelector()
        before={'families':family_report.get('family_count',len(family_report.get('families',[]))),
                'representatives':sum(len(f.get('representative_candidates',[])) for f in family_report.get('families',[]))}
        parents={split['source_family_id'] for split in divergence.get('splits',[])}
        DivergenceDetector.apply_splits(family_report,divergence)
        for row in entries.values():
            row.pop('representative_id',None)
        selection=selector.select(entries,family_report)
        member_to_family={member['request_id']:family for family in family_report.get('families',[])
                          for member in family.get('members',[])}
        for request_id,row in entries.items():
            family=member_to_family.get(request_id)
            if family:row['route_family_id']=family['family_id']
        after={'families':family_report['family_count'],'representatives':selection['scan_groups_after']}
        event={'generation':generation,'parent_family_ids':sorted(parents),
               'splits':list(divergence.get('splits',[])),'before':before,'after':after,
               'tested_members':len(self.tested),'validated_members':len(self.validated),
               'coverage_percent':round(100*min(self.original_groups,len(self.validated)+after['representatives'])/
                                        self.original_groups,2) if self.original_groups else 100.0}
        self.events.append(event)
        return selection,event

    def snapshot(self,family_report,representative_count):
        return {'version':1,'original_groups':self.original_groups,'generations':len(self.events),
                'final_families':family_report.get('family_count',0),
                'final_representatives':int(representative_count),'tested_members':len(self.tested),
                'validated_members':len(self.validated),
                'coverage_percent':round(100*min(self.original_groups,len(self.validated)+int(representative_count)) /
                                         self.original_groups,2) if self.original_groups else 100.0,
                'events':self.events}

    @staticmethod
    def write(result,path):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);temporary=path.with_suffix(path.suffix+'.tmp')
        temporary.write_text(json.dumps(result,ensure_ascii=False,indent=2));temporary.chmod(0o600);temporary.replace(path)
        return result
