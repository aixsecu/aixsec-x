"""Progress means new observed facts, not a successful call or a fresh scan ID."""
from scan_state import digest


def facts(agent):
    result=set()
    def add(kind,value): result.add(digest([kind,value]))
    for host in agent.inventory.hosts.values():
        for endpoint in host.endpoints.values():
            add('endpoint',[endpoint.url,sorted(endpoint.methods),sorted(endpoint.params)])
            for observation in endpoint.auth_observations:
                add('auth',{k:observation.get(k) for k in ('url','method','context','auth_context','status','status_code','allowed','body_matches')})
    for row in agent.evidence_store.records.values():
        identity=[row.get(k) for k in ('category','url','method','parameter','auth_context')]
        add('evidence',identity)
        if row.get('input_selectors'):
            add('paired-input',[identity,row['input_selectors']])
        if row.get('validation'):
            add('validation',[identity,row['validation'].get('status'),row['validation'].get('reason')])
        for replay in row.get('replays',[]):
            add('replay',[identity,replay.get('status'),replay.get('body_matches_capture')])
    for discovery in agent.evidence_store.discovery:
        for endpoint in discovery.get('endpoints',[]):
            add('discovery',{k:endpoint.get(k) for k in ('url','method','parameters','requested','tested','tested_rule_ids')})
    for turn in agent.transcript:
        for call in turn.get('calls',[]):
            if call.get('outcome') not in ('ok','partial'): continue
            data=call.get('data') or {}
            if isinstance(data,dict):
                if data.get('url') and 'status' in data:
                    add('http',[data['url'],data.get('method'),data['status']])
                for observation in data.get('observations',[]) if isinstance(data.get('observations'),list) else []:
                    if isinstance(observation,dict) and 'status' in observation:
                        add('observed-step',{k:observation.get(k) for k in ('url','method','context','state','step','status','allowed','owner')})
    import auth_context
    for context in auth_context.manager().list():
        add('context',[context.get('name'),context.get('state')])
    return result
