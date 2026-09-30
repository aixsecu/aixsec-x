"""Fresh, same-origin checks before reusing a captured authenticated context."""
import json
from pathlib import Path
import re
from adapters.zap import within
from urllib.parse import urlsplit


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


def artifact_expired(config, context, path):
    """Detect an explicit logged-out marker in bounded active evidence."""
    if context=='anonymous' or not path or not Path(path).is_file(): return False
    profile=json.loads(Path(config['zap_auth_file']).read_text()).get(context) or {}
    verification=(profile.get('authentication') or {}).get('verification') or {}
    marker=verification.get('loggedOutRegex')
    if not marker: return True
    pattern=re.compile(marker)
    try:
        with Path(path).open(errors='replace') as stream:
            for index,line in enumerate(stream):
                if index>=10000: break
                try: body=str(json.loads(line).get('response_body') or '')
                except (ValueError,TypeError): continue
                if pattern.search(body): return True
    except OSError: return True
    return False


def artifact_expired_pairs(config, context, path, request_pairs):
    """Attribute explicit logged-out responses to request/rule pairs.

    Returns ``(pairs, complete)``. ``complete=False`` tells callers to fall
    back to quarantining the whole job because the artifact could not be
    interpreted safely.
    """
    if context == 'anonymous':
        return [], True
    if not path or not Path(path).is_file():
        return [], False
    try:
        profile=json.loads(Path(config['zap_auth_file']).read_text()).get(context) or {}
        verification=(profile.get('authentication') or {}).get('verification') or {}
        marker=verification.get('loggedOutRegex')
        if not marker:
            return [], False
        pattern=re.compile(marker)
    except (OSError, ValueError, TypeError, re.error, KeyError):
        return [], False

    def identity(url, method):
        parsed=urlsplit(str(url or ''))
        return (parsed.scheme.lower(), parsed.hostname,
                parsed.port or (443 if parsed.scheme.lower() == 'https' else 80),
                parsed.path or '/', str(method or 'GET').upper())

    references=[]
    for pair in request_pairs or []:
        if not isinstance(pair,dict) or not pair.get('request_id'):
            continue
        references.append((identity(pair.get('url'),pair.get('method')),
                           str(pair['request_id']),
                           {int(rule) for rule in pair.get('rule_ids',[]) if str(rule).isdigit()}))
    affected=set()
    try:
        with Path(path).open(errors='replace') as stream:
            for index,line in enumerate(stream):
                if index >= 10000:
                    return [], False
                try:
                    row=json.loads(line)
                    if not pattern.search(str(row.get('response_body') or '')):
                        continue
                    rule=int(row.get('rule_id'))
                    row_identity=identity(row.get('request_url'),row.get('method'))
                except (ValueError,TypeError,AttributeError):
                    continue
                matches=[(request_id,rules) for reference,request_id,rules in references
                         if reference == row_identity and rule in rules]
                if not matches:
                    return [], False
                for request_id,_ in matches:
                    affected.add((request_id,rule))
    except OSError:
        return [], False
    return [{'request_id':request_id,'rule_id':rule,
             'auth_disposition':'deferred_auth_expired'}
            for request_id,rule in sorted(affected)], True


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
