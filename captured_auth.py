"""Fresh, same-origin checks before reusing a captured authenticated context."""
import json
from pathlib import Path
import re
from adapters.zap import within


def headers(request):
    denied={'host','content-length','transfer-encoding','connection','proxy-connection',
            'proxy-authorization','upgrade','te','trailer','accept-encoding','x-zap-scan-id'}
    out={}
    for item in request.get('headers',[]):
        key,value=str(item.get('name','')),str(item.get('value',''))
        if not key or key.lower() in denied or key.startswith(':'): continue
        if any(c in key+value for c in ('\r','\n')): raise ValueError('Invalid captured header')
        out[key]=value
    mime=(request.get('postData') or {}).get('mimeType')
    if mime and not any(k.lower()=='content-type' for k in out): out['Content-Type']=mime
    return out


def credentialed(entry):
    return any(k.lower() in ('cookie','authorization') for k in headers(entry['request']))


def oracle(config, context, url):
    if context=='anonymous': return None
    path=config.get('zap_auth_file')
    if not path: raise ValueError('Authenticated replay requires an operator auth profile')
    profile=json.loads(Path(path).read_text()).get(context) or {}
    if not within(url,profile.get('origin','')): raise ValueError('Auth profile origin mismatch')
    check=(profile.get('authentication') or {}).get('verification') or {}
    if not check.get('loggedInRegex') or not check.get('loggedOutRegex'):
        raise ValueError('Auth profile requires logged-in and logged-out markers')
    return re.compile(check['loggedInRegex']),re.compile(check['loggedOutRegex'])


def accepted(check, status, text):
    return 200 <= status < 300 and (check is None or
        (bool(check[0].search(text)) and not check[1].search(text)))


def preflight(config, entry, context, timeout=15):
    import http_engine as he
    req=entry['request']; check=oracle(config,context,req['url'])
    session=he.HttpSession('captured-auth-preflight',proxies=he.get_proxies())
    try:
        response,_=session.request(req['method'],req['url'],headers=headers(req),
            body=(req.get('postData') or {}).get('text') or None,follow_redirects=False,
            timeout=timeout,max_response_bytes=65536)
        if not accepted(check,response.status_code,response.text):
            raise ValueError('Captured authentication is expired or unverified; refresh discovery/login')
    finally: session.s.close()
    return 'verified' if check else 'captured_unverified' if credentialed(entry) else 'anonymous'
