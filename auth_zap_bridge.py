"""Prepare runtime/browser/cookie/OAuth authentication for ZAP in memory."""
from __future__ import annotations

import re


def prepare(manifest, context_name, manager, timeout=15):
    if context_name == 'anonymous': return None
    row=(manifest.get('contexts') or {}).get(context_name)
    if not row: raise ValueError('Selected authentication context is missing from manifest')
    method=((row.get('zap') or {}).get('authentication') or {}).get('method')
    if method in ('form','json','http'):
        return None
    context=manager.get(context_name)
    context.login()
    material=context.zap_material()
    if not material['headers'] and not material['cookies']:
        raise ValueError('Browser/runtime ZAP authentication requires imported cookies or headers')
    verification=(row.get('runtime') or {}).get('verification') or {}
    verification_url=str(verification.get('url') or row.get('origin') or '')
    response,_=context.request({'url':verification_url,'method':'GET','follow_redirects':False,
                                'timeout':timeout},record=True)
    text=response.text[:2_000_000]
    logged_in=str(verification.get('loggedInRegex') or '')
    logged_out=str(verification.get('loggedOutRegex') or '')
    verified=(200 <= response.status_code < 400 and
              (not logged_in or bool(re.search(logged_in,text))) and
              (not logged_out or not re.search(logged_out,text)))
    if not verified: raise ValueError('Runtime authentication preflight did not verify')
    return {**material,'context':context_name,'verified':True,
            'verification_status':response.status_code}


def public(material):
    if not material:return None
    return {'context':material['context'],'verified':material['verified'],
            'generation':material.get('generation',0),
            'header_names':material.get('header_names',[]),
            'cookie_names':material.get('cookie_names',[]),
            'verification_status':material.get('verification_status')}
