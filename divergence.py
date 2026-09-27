"""Deterministic validation of representative evidence across Route Families."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re


def _response_signature(row):
    private=row.get('_verification') or {};header=str(private.get('response_header') or '')
    lines=header.splitlines();status='';names=[];content_type=''
    if lines:
        match=re.match(r'HTTP/\S+\s+(\d{3})',lines[0]);status=match.group(1) if match else ''
    for line in lines[1:]:
        if ':' not in line:continue
        name,value=line.split(':',1);name=name.strip().lower();names.append(name)
        if name=='content-type':content_type=value.split(';',1)[0].strip().lower()
    return {'status':status,'content_type':content_type,'header_names':sorted(set(names)),
            'method':str(row.get('method') or 'GET').upper()}


def _evidence_signature(row):
    return {'rule_id':str(row.get('rule_id') or ''),'parameter':str(row.get('parameter') or ''),
            'category':str(row.get('category') or '').strip().lower(),
            'evidence':re.sub(r'\s+',' ',str(row.get('evidence') or '').strip().lower())}


class DivergenceDetector:
    def __init__(self,samples=2):
        self.samples=max(1,int(samples))

    def plan(self,family_report,family_evidence,tested=None,required_families=None):
        tested=set(tested or ())
        required_families=None if required_families is None else set(required_families)
        findings=family_evidence.get('findings',[]);by_family={}
        for finding in findings:by_family.setdefault(finding['family_id'],[]).append(finding)
        plans=[]
        for family in family_report.get('families',[]):
            if required_families is not None and family['family_id'] not in required_families:continue
            family_findings=by_family.get(family['family_id'],[])
            if not family_findings:continue
            representatives=set(family.get('representative_candidates') or [])
            candidates=sorted((m for m in family.get('members',[]) if m['request_id'] not in representatives
                               and (family['family_id'],m['request_id']) not in tested),
                              key=lambda m:m['request_id'])[:self.samples]
            rules=sorted({rule for finding in family_findings for rule in finding.get('rule_ids',[])})
            representative_id=sorted(representatives)[0] if representatives else family_findings[0]['representative_id']
            member_urls=sorted({str(m.get('url') or '') for m in family.get('members',[]) if m.get('url')})
            for member in candidates:
                plans.append({'family_id':family['family_id'],'representative_id':representative_id,
                    'member_id':member['request_id'],'member_url':member.get('url',''),
                    'member_count':len(family.get('members',[])),'member_urls':member_urls,'rule_ids':rules})
        return plans

    def analyze(self,family_report,family_evidence,records,plans,original_groups,representative_count):
        indexed={str(row.get('evidence_id')):row for row in records if isinstance(row,dict)}
        replays={}
        for row in records:
            if isinstance(row,dict) and row.get('divergence_member_id'):
                replays.setdefault((str(row.get('family_id')),str(row.get('divergence_member_id'))),[]).append(row)
        plan_by_family={}
        for plan in plans:plan_by_family.setdefault(plan['family_id'],[]).append(plan)
        results=[];splits=[]
        for finding in family_evidence.get('findings',[]):
            primary=[indexed.get(raw.get('evidence_id')) for raw in finding.get('raw_evidence',[])]
            primary=[row for row in primary if row]
            comparisons=[]
            for plan in plan_by_family.get(finding['family_id'],[]):
                rows=replays.get((finding['family_id'],plan['member_id']),[]);matched=False;details=[]
                for original in primary:
                    expected_evidence=_evidence_signature(original);expected_response=_response_signature(original)
                    same=[row for row in rows if _evidence_signature(row)==expected_evidence]
                    response_match=any(_response_signature(row)==expected_response for row in same)
                    details.append({'rule_id':expected_evidence['rule_id'],
                        'affected_parameter':expected_evidence['parameter'],
                        'vulnerability_evidence_match':bool(same),
                        'response_structure_match':response_match})
                    matched=matched or bool(same and response_match)
                comparisons.append({'member_id':plan['member_id'],'member_url':plan['member_url'],
                                    'matched':matched,'comparisons':details})
            confirmed=(finding.get('member_count',1)<=1) or bool(comparisons and all(v['matched'] for v in comparisons))
            status='family_confirmed' if confirmed else 'split_family'
            split_ids=[]
            if not confirmed:
                for comparison in comparisons:
                    if comparison['matched']:continue
                    seed=finding['family_id']+':'+comparison['member_id']
                    split_id='rf-div-'+hashlib.sha256(seed.encode()).hexdigest()[:20]
                    split={'source_family_id':finding['family_id'],'family_id':split_id,
                           'member_id':comparison['member_id'],'member_url':comparison['member_url']}
                    if split not in splits:splits.append(split)
                    split_ids.append(split_id)
            results.append({'finding_id':finding['finding_id'],'family_id':finding['family_id'],
                'representative_id':finding['representative_id'],'status':status,
                'rule_ids':finding['rule_ids'],'comparisons':comparisons,'split_family_ids':split_ids})
        confirmed=sum(1 for row in results if row['status']=='family_confirmed');total=len(results)
        extra=len(plans);avoided=max(0,int(original_groups)-int(representative_count)-extra)
        return {'version':1,'algorithm':'deterministic-family-divergence-v1',
            'extra_scans':extra,'avoided_scans':avoided,
            'family_confirmation_rate':round(100*confirmed/total,2) if total else 0.0,
            'confirmed_findings':confirmed,'finding_count':total,'findings':results,'splits':splits}

    @staticmethod
    def apply_splits(family_report,divergence):
        families={family['family_id']:family for family in family_report.get('families',[])}
        for split in divergence.get('splits',[]):
            source=families.get(split['source_family_id'])
            if not source:continue
            members=[m for m in source['members'] if m['request_id']==split['member_id']]
            if not members:continue
            source['members']=[m for m in source['members'] if m['request_id']!=split['member_id']]
            families[split['family_id']]={'family_id':split['family_id'],
                'fingerprint':source['fingerprint']+':divergent:'+split['member_id'],
                'structure':source['structure'],'members':members,
                'representative_candidates':[split['member_id']]}
        family_report['families']=[family for family in families.values() if family['members']]
        family_report['family_count']=len(family_report['families'])
        return family_report

    @staticmethod
    def write(result,path):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);temporary=path.with_suffix(path.suffix+'.tmp')
        temporary.write_text(json.dumps(result,ensure_ascii=False,indent=2));temporary.chmod(0o600);temporary.replace(path)
        return result
