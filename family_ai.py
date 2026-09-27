"""Constrained AI hypotheses for low-confidence Route Families."""
from __future__ import annotations

import json
from pathlib import Path


ALLOWED_ACTIONS={'suggest_merge','suggest_split','suggest_additional_replay'}


class FamilyAIAssistant:
    def __init__(self,enabled=False,max_families=20):
        self.enabled=bool(enabled);self.max_families=max(1,int(max_families))

    def eligible(self,confidence_report):
        required=set(confidence_report.get('families_requiring_replay',[]))
        return [row for row in confidence_report.get('families',[]) if row.get('family_id') in required]

    def assist(self,confidence_report,family_report,chat,config=None):
        eligible=self.eligible(confidence_report)
        base={'version':1,'policy':'hypotheses_only_evidence_wins','enabled':self.enabled,
              'eligible_families':len(eligible),'ai_invocations':0,'hypotheses':[],'errors':[]}
        if not self.enabled or not eligible:return base
        structures={row['family_id']:{'family_id':row['family_id'],'fingerprint':row.get('fingerprint',''),
            'member_ids':[member.get('request_id') for member in row.get('members',[])],
            'representative_ids':row.get('representative_candidates',[])}
            for row in family_report.get('families',[])}
        payload=[]
        for confidence in eligible[:self.max_families]:
            payload.append({'confidence':confidence,'family':structures.get(confidence['family_id'],{})})
        prompt=('You are assisting deterministic route-family classification. Do not identify vulnerabilities, '
            'make findings, assign severity, or claim confirmation. Return JSON only: '
            '{"suggestions":[{"action":"suggest_merge|suggest_split|suggest_additional_replay",'
            '"family_id":"...","target_family_id":"optional","member_ids":[],"reason":"..."}]}. '
            'Suggestions are untrusted hypotheses and evidence always wins. Input: '+json.dumps(payload,separators=(',',':')))
        try:
            response=chat([{'role':'system','content':'Family classification assistance only; never decide findings.'},
                           {'role':'user','content':prompt}],tools=[],config=dict(config or {}))
            base['ai_invocations']=1
            parsed=json.loads(str((response or {}).get('content') or '{}'))
            suggestions=parsed.get('suggestions',[]) if isinstance(parsed,dict) else []
            eligible_ids={row['family_id'] for row in eligible};member_ids={row['family_id']:set(
                structures.get(row['family_id'],{}).get('member_ids',[])) for row in eligible}
            for suggestion in suggestions:
                if not isinstance(suggestion,dict):continue
                action=str(suggestion.get('action') or '');family_id=str(suggestion.get('family_id') or '')
                members=sorted({str(value) for value in suggestion.get('member_ids',[]) if value})
                if action not in ALLOWED_ACTIONS or family_id not in eligible_ids:continue
                if any(member not in member_ids[family_id] for member in members):continue
                target=str(suggestion.get('target_family_id') or '')
                if action=='suggest_merge' and target not in structures:continue
                base['hypotheses'].append({'hypothesis_id':f'aih-{len(base["hypotheses"])+1:04d}',
                    'status':'hypothesis','action':action,'family_id':family_id,
                    'target_family_id':target,'member_ids':members,
                    'reason':str(suggestion.get('reason') or '')[:500],
                    'applied':False,'evidence_precedence':True})
        except Exception as exc:
            base['errors'].append(type(exc).__name__+': '+str(exc)[:300])
        return base

    @staticmethod
    def benchmark(total_families,eligible_families,ai_invocations,evidence_resolved):
        total=max(0,int(total_families));eligible=max(0,int(eligible_families))
        assisted=eligible if int(ai_invocations)>0 else 0
        return {'ai_usage_rate':round(100*assisted/total,2) if total else 0.0,
                'eligible_family_rate':round(100*eligible/total,2) if total else 0.0,
                'manual_validation_reduction':round(100*min(eligible,max(0,int(evidence_resolved)))/eligible,2)
                                              if eligible else 0.0}

    @staticmethod
    def write(result,path):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);temporary=path.with_suffix(path.suffix+'.tmp')
        temporary.write_text(json.dumps(result,ensure_ascii=False,indent=2));temporary.chmod(0o600);temporary.replace(path)
        return result
