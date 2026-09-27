#!/usr/bin/env python3
"""CPU-only planning benchmark for deterministic family divergence sampling."""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from divergence import DivergenceDetector  # noqa: E402


def run(groups=10000,families=100,samples=2):
    per=max(1,groups//families);family_rows=[];findings=[];records=[]
    for family_index in range(families):
        family_id=f'rf-{family_index}';members=[{'request_id':f'{family_index}-{i}',
            'url':f'https://example.test/route-{family_index}/{i}'} for i in range(per)]
        family_rows.append({'family_id':family_id,'fingerprint':str(family_index),'structure':{},
            'members':members,'representative_candidates':[members[0]['request_id']]})
        evidence_id=f'e-{family_index}'
        findings.append({'finding_id':f'f-{family_index}','family_id':family_id,
            'representative_id':members[0]['request_id'],'member_count':len(members),
            'rule_ids':['40018'],'raw_evidence':[{'evidence_id':evidence_id}]})
        records.append({'evidence_id':evidence_id,'family_id':family_id,'rule_id':'40018',
            'parameter':'id','category':'SQL Injection','evidence':'candidate','method':'GET',
            '_verification':{'response_header':'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'}})
    detector=DivergenceDetector(samples);report={'families':family_rows};evidence={'findings':findings}
    began=time.perf_counter_ns();plans=detector.plan(report,evidence)
    for plan in plans:
        records.append({'evidence_id':'replay-'+plan['member_id'],'family_id':plan['family_id'],
            'divergence_member_id':plan['member_id'],'rule_id':'40018','parameter':'id',
            'category':'SQL Injection','evidence':'candidate','method':'GET',
            '_verification':{'response_header':'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'}})
    result=detector.analyze(report,evidence,records,plans,groups,families)
    split_fixture={'splits':[{'source_family_id':family['family_id'],
        'family_id':'rf-div-'+family['family_id'],'member_id':family['members'][1]['request_id'],
        'member_url':family['members'][1]['url']} for family in family_rows if len(family['members'])>1]}
    families_before=len(report['families']);detector.apply_splits(report,split_fixture)
    families_after=len(report['families']);representatives_after=families_after
    elapsed=(time.perf_counter_ns()-began)/1_000_000
    representative_count=families;extra=len(plans)
    return {'original_scans':groups,'representative_scans':representative_count,
        'extra_scans':extra,'avoided_scans':result['avoided_scans'],
        'family_confirmation_rate':result['family_confirmation_rate'],
        'families_before_split':families_before,'families_after_split':families_after,
        'representatives_before_split':representative_count,
        'representatives_after_split':representatives_after,
        'coverage_percent':round(100*min(groups,extra+representatives_after)/groups,2),
        'planning_and_comparison_elapsed_ms':round(elapsed,3)}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--groups',type=int,default=10000)
    parser.add_argument('--families',type=int,default=100);parser.add_argument('--samples',type=int,default=2)
    args=parser.parse_args();print(json.dumps(run(args.groups,args.families,args.samples),indent=2))
