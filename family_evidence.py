"""Candidate-only evidence grouped by deterministic Route Family representatives."""
from __future__ import annotations

import json
from pathlib import Path


class FamilyEvidenceStore:
    """Persist provenance for representative scans without validating findings."""

    def build(self,records):
        findings={}
        for row in records:
            if (not isinstance(row,dict) or row.get('tool')!='zap_active_scan'
                    or not row.get('family_id') or not row.get('_candidate')):
                continue
            key=(str(row.get('family_id')),str(row.get('representative_id')),
                 str(row.get('finding_id') or row.get('evidence_id')))
            finding=findings.setdefault(key,{
                'finding_id':str(row.get('finding_id') or row.get('evidence_id') or ''),
                'verification_state':'candidate',
                'family_id':str(row.get('family_id') or ''),
                'representative_id':str(row.get('representative_id') or ''),
                'representative_url':str(row.get('representative_url') or row.get('url') or ''),
                'member_urls':sorted({str(value) for value in row.get('member_urls',[]) if value}),
                'member_count':max(1,int(row.get('member_count') or 1)),
                'rule_ids':[],
                'category':str(row.get('category') or ''),
                'severity':str(row.get('severity') or 'info'),
                'url':str(row.get('url') or ''),
                'method':str(row.get('method') or 'GET'),
                'parameter':str(row.get('parameter') or ''),
                'raw_evidence':[]})
            finding['member_urls']=sorted(set(finding['member_urls'])|
                                          {str(value) for value in row.get('member_urls',[]) if value})
            finding['member_count']=max(finding['member_count'],int(row.get('member_count') or 1),
                                        len(finding['member_urls']))
            finding_rules=({str(row.get('rule_id'))} if row.get('rule_id') else
                           {str(value) for value in row.get('rule_ids',[]) if value})
            finding['rule_ids']=sorted(set(finding['rule_ids'])|finding_rules)
            evidence={'evidence_id':str(row.get('evidence_id') or ''),
                'raw_result_reference':str(row.get('raw_result_reference') or ''),
                'artifact_reference':str(row.get('artifact_ref') or ''),
                'request_reference':str(row.get('request_reference') or ''),
                'response_reference':str(row.get('response_reference') or ''),
                'scanner_evidence':str(row.get('evidence') or '')}
            if evidence not in finding['raw_evidence']:
                finding['raw_evidence'].append(evidence)
        ordered=sorted(findings.values(),key=lambda row:(row['family_id'],row['representative_id'],row['finding_id']))
        return {'version':1,'verification_policy':'candidate_only_no_validation',
                'finding_count':len(ordered),'findings':ordered}

    def write(self,records,path):
        result=self.build(records);path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        temporary=path.with_suffix(path.suffix+'.tmp')
        temporary.write_text(json.dumps(result,ensure_ascii=False,indent=2));temporary.chmod(0o600)
        temporary.replace(path)
        return result
