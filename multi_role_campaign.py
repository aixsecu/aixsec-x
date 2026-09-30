"""Bounded automatic differential authorization campaign; candidates only."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from urllib.parse import urlsplit


def _id(value):
    return 'authz-'+hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()[:20]


def run(manifest, manager, entries, target, maximum=20):
    origin=(urlsplit(target).scheme+'://'+urlsplit(target).netloc).lower()
    contexts=[name for name,row in (manifest.get('contexts') or {}).items()
              if str(row.get('origin') or '').rstrip('/').lower()==origin
              and all(os.environ.get(env) for env in (row.get('credential_env') or {}).values())
              and not ((row.get('operator_pause') or {}).get('ready_env') and
                       not os.environ.get((row.get('operator_pause') or {}).get('ready_env')))]
    if not contexts:
        return {'version':1,'contexts':[],'requests':0,'comparisons':[],
                'candidates':[],'reason':'No configured role contexts for target origin'}
    try:manager.get('anonymous')
    except ValueError:manager.configure('anonymous',origin,replace=True)
    names=['anonymous']+contexts[:7]
    declarations={name:(manifest['contexts'][name].get('authorization') or {}) for name in contexts}
    selected=[]
    for entry in entries:
        request=(entry.get('_entry') or {}).get('request') or {}
        if str(request.get('method') or 'GET').upper() not in ('GET','HEAD'):continue
        url=str(request.get('url') or '')
        if url and url not in {row['url'] for row in selected}:
            selected.append({'url':url,'method':request.get('method','GET'),'follow_redirects':False})
        if len(selected)>=max(1,min(int(maximum),100)):break
    comparisons=[];candidates=[];errors=[]
    for request in selected:
        try:result=manager.compare(names,request)
        except (ValueError,TypeError) as exc:
            errors.append({'url':request['url'],'error':str(exc)[:300]});continue
        comparisons.append(result)
        path=urlsplit(request['url']).path or '/'
        protected=any(fnmatch.fnmatchcase(path,pattern) for declaration in declarations.values()
                      for pattern in declaration.get('protected_paths',[]))
        observations={row['context']:row for row in result['observations']}
        anonymous=observations.get('anonymous',{}).get('response') or {}
        authenticated=[row for name,row in observations.items() if name!='anonymous']
        if protected and 200 <= int(anonymous.get('status') or 0)<300 and any(
                200 <= int((row.get('response') or {}).get('status') or 0)<300 for row in authenticated):
            candidates.append({'candidate_id':_id(['anonymous',request['url']]),
                'kind':'unauthenticated_protected_access','severity':'high','url':request['url'],
                'contexts':['anonymous']+contexts,'status':'candidate','verdict':False,
                'evidence':['operator-declared protected path','anonymous successful response'],
                'evidence_gaps':['Confirm response contains protected data, not a generic envelope']})
        for owner,declaration in declarations.items():
            if not any(fnmatch.fnmatchcase(path,pattern) for pattern in declaration.get('owned_paths',[])):
                continue
            owner_response=(observations.get(owner,{}).get('response') or {})
            for observer in contexts:
                if observer==owner:continue
                response=(observations.get(observer,{}).get('response') or {})
                pair=next((pair for pair in result['comparisons'] if
                    {pair['left'],pair['right']}=={owner,observer}),{})
                if (200 <= int(owner_response.get('status') or 0)<300 and
                        200 <= int(response.get('status') or 0)<300 and pair.get('same_body_hash')):
                    candidates.append({'candidate_id':_id([owner,observer,request['url']]),
                        'kind':'cross_subject_object_access','severity':'high','url':request['url'],
                        'contexts':[owner,observer],'status':'candidate','verdict':False,
                        'evidence':[f'operator-declared owner={owner}',
                                    'non-owner received identical successful response'],
                        'evidence_gaps':['Confirm object identity and intended authorization policy']})
    unique={row['candidate_id']:row for row in candidates}
    return {'version':1,'contexts':names,'requests':len(selected),
            'comparisons':comparisons,'candidates':list(unique.values()),
            'errors':errors,
            'interpretation':'candidate_only_no_automatic_verdict'}
