"""Phase 5 coverage accounting for advanced web security surfaces.

This module never invents credentials, schemas, OAST callbacks or vulnerability
verdicts. It connects discovered facts to existing executors and makes missing
prerequisites explicit.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit


def _surface(name, state, evidence=None, blockers=None, executor=''):
    return {'surface':name,'state':state,'executor':executor,
            'evidence':list(evidence or []),'blockers':list(blockers or [])}


def evaluate(templates, discoveries, coverages, auth_contexts, analysis, config):
    urls=[template.request_url for template in templates]
    text=' '.join(urls).lower()
    endpoints=[row for discovery in discoveries for row in discovery.get('endpoints',[])]
    forms=[row for discovery in discoveries for row in discovery.get('forms',[])]
    inputs=[row for discovery in discoveries for row in discovery.get('inputs',[])]
    sources={source for row in endpoints for source in row.get('sources',[])}

    contexts=[row for row in auth_contexts if row.get('state')=='authenticated']
    names=sorted({str(row.get('name') or row.get('context') or '') for row in contexts if row.get('name') or row.get('context')})
    auth_evidence=[{'contexts':names,'request_templates':sum(t.auth_context!='anonymous' for t in templates)}]
    if len(names)>=2:
        authorization=_surface('multi_role_authorization','ready',auth_evidence,
            executor='auth_compare + authorization_reason')
    else:
        authorization=_surface('multi_role_authorization','blocked',auth_evidence,
            ['configure and authenticate at least two isolated user contexts'],
            'auth_compare + authorization_reason')

    ajax_completed=any(((coverage.get('phases') or {}).get('spiderAjax')=='completed')
                       for coverage in coverages)
    dom_evidence=[]
    standalone=sum(not row.get('in_form') for row in inputs)
    if standalone:dom_evidence.append({'standalone_inputs':standalone})
    if 'javascript_literal' in sources:dom_evidence.append({'javascript_endpoints':True})
    dom=(_surface('dom_browser','tested' if ajax_completed else 'blocked',dom_evidence,
                  [] if ajax_completed else ['AJAX Spider/browser phase did not complete'],
                  'ZAP AJAX Spider + passive DOM rules'))

    graphql=[url for url in urls if re.search(r'/graphql(?:/|$)|/graphiql(?:/|$)',url,re.I)]
    graphql += [str(row.get('url') or '') for row in endpoints
                if 'graphql' in ' '.join(row.get('sources',[])).lower()]
    graphql=sorted(set(filter(None,graphql)))
    protocols=[]
    if graphql:
        protocols.append(_surface('graphql','discovered',[{'endpoints':graphql}],
            ['provide captured operation or schema before active mutation testing'],
            'api_discovery + captured-request ZAP scan'))
    else:protocols.append(_surface('graphql','not_discovered'))

    soap=sorted({url for url in urls if re.search(r'(?:\.asmx|\.svc|/soap|wsdl)',url,re.I)})
    xml_templates=[t.request_url for t in templates if 'xml' in t.body_type.lower()]
    soap=sorted(set(soap+xml_templates))
    protocols.append(_surface('soap_xml','discovered' if soap else 'not_discovered',
        [{'endpoints':soap}] if soap else [],
        ['provide captured XML/SOAP request or WSDL'] if soap else [],
        'captured-request ZAP XML/XXE rules' if soap else ''))

    websocket=sorted({url for url in urls if urlsplit(url).scheme in ('ws','wss')
                      or re.search(r'(?:socket\.io|websocket)',url,re.I)})
    protocols.append(_surface('websocket','discovered' if websocket else 'not_discovered',
        [{'endpoints':websocket}] if websocket else [],
        ['WebSocket frame capture/executor is not configured'] if websocket else [],
        'ZAP WebSocket add-on' if websocket else ''))

    callback=str(config.get('oast_callback_url') or '')
    oast_enabled=bool(config.get('allow_oast'))
    callback_parts=urlsplit(callback)
    callback_valid=callback_parts.scheme in ('http','https') and bool(callback_parts.hostname)
    if oast_enabled and callback_valid:
        oast=_surface('oast','ready',[{'callback_origin':urlsplit(callback).netloc}],
                      executor='OAST-capable scanner rules')
    else:
        blockers=[]
        if not oast_enabled:blockers.append('WEBX_ALLOW_OAST is disabled')
        if not callback_valid:blockers.append('WEBX_OAST_CALLBACK_URL is missing or invalid')
        oast=_surface('oast','blocked',blockers=blockers,executor='OAST-capable scanner rules')

    rules=analysis.get('business_rules') or {}
    runs=analysis.get('workflow_runs') or []
    workflow_evidence=[{'declared_workflows':sorted(rules),'observed_runs':len(runs)}]
    if rules and runs:
        workflows=_surface('business_workflows','tested',workflow_evidence,
                            executor='business_workflow_test + business_reason')
    elif rules:
        workflows=_surface('business_workflows','ready',workflow_evidence,
                            ['execute declared workflow controls'],
                            'business_workflow_test + business_reason')
    else:
        workflows=_surface('business_workflows','blocked',workflow_evidence,
                            ['declare business invariants before workflow testing'],
                            'business_rule_set + business_workflow_test')

    surfaces=[authorization,dom,*protocols,oast,workflows]
    counts={state:sum(row['state']==state for row in surfaces)
            for state in ('tested','ready','discovered','blocked','not_discovered','unsupported')}
    return {'version':1,'surfaces':surfaces,'summary':counts,
            'interpretation':'Blocked/not_discovered advanced surfaces are coverage gaps, not evidence of safety.'}
