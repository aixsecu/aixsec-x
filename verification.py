"""Fresh paired SQL error observations from captured requests; no extraction."""
import hashlib
import os
import re
from pathlib import Path
import subprocess
import signal
import tempfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from zap_active_evidence import SQL_ERROR
from scan_state import atomic


def discovered_get_probe(config, endpoint, timeout=45):
    """Bounded quote-parity check for read-like JS-discovered GET endpoints.

    This closes the gap where a JavaScript literal names an endpoint and
    parameter but no browser interaction captured a request for ZAP to seed.
    It creates a candidate only; it never extracts data.
    """
    import time
    import http_engine as he
    from adapters.zap import within
    from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
    url=str(endpoint.get('url') or '')
    parameters=[str(v) for v in endpoint.get('parameters') or [] if str(v)]
    if endpoint.get('method') not in ('GET','UNKNOWN') or not parameters or not within(url,url):
        raise ValueError('Discovered GET probe requires a same-origin GET-like endpoint with parameters')
    sensitive=re.compile(r'csrf|xsrf|token|session|password|secret|api.?key',re.I)
    parameters=[v for v in parameters if not sensitive.search(v)]
    if not parameters: raise ValueError('Only sensitive discovered parameters were present')
    root=Path(config.get('evidence_dir','.aixsec-evidence')).resolve()
    directory=Path(tempfile.mkdtemp(prefix='discovered-get-',dir=root));path=directory/'pairs.json'
    session=he.HttpSession('discovered-get-probe',proxies=he.get_proxies())
    deadline=time.monotonic()+max(5,int(timeout));rows=[];alerts=[]
    def request(parameter,value,kind):
        template=str(endpoint.get('request_template') or '')
        if template and endpoint.get('template_parameter') == parameter and '{value}' in template:
            from urllib.parse import quote
            target=template.replace('{value}',quote(value,safe=''))
        else:
            p=urlsplit(url);query=parse_qsl(p.query,keep_blank_values=True);query.append((parameter,value))
            target=urlunsplit((p.scheme,p.netloc,p.path,urlencode(query),''))
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('Discovered GET probe timed out')
        response,_=session.request('GET',target,headers={'User-Agent':'Mozilla/5.0'},
            follow_redirects=False,timeout=min(15,max(1,remaining)),max_response_bytes=65536)
        body=response.content
        row={'kind':kind,'parameter':parameter,'status':response.status_code,'length':len(body),
             'sha256':hashlib.sha256(body).hexdigest(),'sql_error':bool(SQL_ERROR.search(response.text))}
        rows.append(row);atomic(path,rows);return row
    try:
        for parameter in parameters:
            control1=request(parameter,'test','control');payload1=request(parameter,"test'",'payload')
            control2=request(parameter,'test','control');payload2=request(parameter,"test'",'payload')
            escaped=request(parameter,"test''",'escaped')
            def equivalent(left,right,ratio=.03,floor=64):
                tolerance=max(floor,int(max(left['length'],right['length'])*ratio))
                return left['status']==right['status'] and abs(left['length']-right['length'])<=tolerance
            stable_controls=equivalent(control1,control2)
            stable_payloads=equivalent(payload1,payload2)
            payload_diff=(payload1['status']!=control1['status']
                          or abs(payload1['length']-control1['length'])
                             > max(128,int(max(payload1['length'],control1['length'])*.20))
                          or payload1['sql_error'] != control1['sql_error'])
            escaped_matches=equivalent(escaped,control1,ratio=.05,floor=128)
            if stable_controls and stable_payloads and payload_diff and escaped_matches:
                alerts.append({'category':'SQL Injection','rule_id':'aixsec-quote-differential',
                    'severity':'high','url':url,'method':'GET','parameter':parameter,
                    'auth_context':'anonymous','artifact_ref':str(path),
                    'description':'Stable quote differential reproduced twice and escaped quote matched controls. Candidate only; no data extraction was attempted.',
                    'response_sha256':payload1['sha256']})
    finally:
        session.s.close();atomic(path,rows)
    return {'alerts':alerts,'coverage':{'tool':'discovered_get_probe','target':url,
        'status':'complete','requests':len(rows),'report_path':str(path),'auth_context':'anonymous'}}


def discovered_search_form_probe(config, form, timeout=45):
    """Bounded check for a GET form or an anonymous POST search form."""
    import time
    import http_engine as he
    from adapters.zap import within
    url=str(form.get('action') or '')
    method=str(form.get('method') or '').upper()
    parameters=[str(v) for v in form.get('parameters') or [] if str(v)]
    if method not in ('GET','POST') or not parameters or not within(url,url):
        raise ValueError('Discovered form probe requires a same-origin GET/POST form with parameters')
    search=re.compile(r'(?:^|[_-])(q|query|search|keyword|key|term)(?:$|[_-])|timkiem|txt.?key',re.I)
    sensitive=re.compile(r'csrf|xsrf|token|session|password|secret|api.?key',re.I)
    candidates=[v for v in parameters
                if not sensitive.search(v) and (method == 'GET' or search.search(v))]
    if not candidates:
        raise ValueError('Discovered form has no safely probeable parameters')
    root=Path(config.get('evidence_dir','.aixsec-evidence')).resolve()
    directory=Path(tempfile.mkdtemp(prefix='discovered-form-',dir=root));path=directory/'pairs.json'
    session=he.HttpSession('discovered-form-probe',proxies=he.get_proxies())
    deadline=time.monotonic()+max(5,int(timeout));rows=[];alerts=[]
    def request(parameter,value,kind):
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('Discovered form probe timed out')
        body={name:'' for name in parameters};body[parameter]=value
        target=url
        kwargs={'headers':{'User-Agent':'Mozilla/5.0'},'follow_redirects':False,
                'timeout':min(15,max(1,remaining)),'max_response_bytes':65536}
        if method == 'GET':
            from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
            parsed=urlsplit(url)
            query=parse_qsl(parsed.query,keep_blank_values=True)
            supplied=set(body)
            query=[(name,existing) for name,existing in query if name not in supplied]
            query.extend(body.items())
            target=urlunsplit((parsed.scheme,parsed.netloc,parsed.path,urlencode(query),''))
        else:
            kwargs['form']=body
        response,_=session.request(method,target,**kwargs)
        content=response.content
        row={'kind':kind,'parameter':parameter,'status':response.status_code,'length':len(content),
             'sha256':hashlib.sha256(content).hexdigest(),'sql_error':bool(SQL_ERROR.search(response.text))}
        rows.append(row);atomic(path,rows);return row
    try:
        for parameter in candidates:
            control1=request(parameter,'test','control');payload1=request(parameter,"test'",'payload')
            control2=request(parameter,'test','control');payload2=request(parameter,"test'",'payload')
            escaped=request(parameter,"test''",'escaped')
            def equivalent(left,right,ratio=.03,floor=64):
                tolerance=max(floor,int(max(left['length'],right['length'])*ratio))
                return left['status']==right['status'] and abs(left['length']-right['length'])<=tolerance
            stable_controls=equivalent(control1,control2)
            stable_payloads=equivalent(payload1,payload2)
            payload_diff=(payload1['status']!=control1['status']
                          or abs(payload1['length']-control1['length'])
                             > max(128,int(max(payload1['length'],control1['length'])*.20))
                          or payload1['sql_error'] != control1['sql_error'])
            escaped_matches=equivalent(escaped,control1,ratio=.05,floor=128)
            blocked=payload1['status'] in (401,403) or control1['status'] in (401,403)
            if stable_controls and stable_payloads and payload_diff and escaped_matches and not blocked:
                alerts.append({'category':'SQL Injection','rule_id':'aixsec-form-quote-differential',
                    'severity':'high','url':url,'method':method,'parameter':parameter,
                    'auth_context':'anonymous','artifact_ref':str(path),
                    'description':'Stable search-form quote differential reproduced twice and escaped quote matched controls. Candidate only; no data extraction was attempted.',
                    'response_sha256':payload1['sha256']})
    finally:
        session.s.close();atomic(path,rows)
    return {'alerts':alerts,'coverage':{'tool':'discovered_search_form_probe','target':url,
        'status':'complete','requests':len(rows),'report_path':str(path),'auth_context':'anonymous'}}


def variants(entry, parameter, selector=None):
    from request_inputs import inputs, mutate
    req=entry['request']
    if req['method'].upper() not in ('GET','POST','PUT','PATCH'):
        raise ValueError('Unsupported captured method')
    selections=inputs(entry,parameter)
    if selector is None:
        if len(selections)!=1: raise ValueError('Ambiguous parameter; select an occurrence')
        selector=selections[0]
    if selector not in selections: raise ValueError('Unknown captured input selector')
    control=(req['url'],(req.get('postData') or {}).get('text',''))
    return [control,mutate(entry,selector)]*2


from captured_auth import headers


def paired(config, entry, parameter, record, timeout=60):
    import time
    import http_engine as he
    from adapters.zap import within
    root = Path(config.get('evidence_dir','.aixsec-evidence')).resolve()
    directory = Path(tempfile.mkdtemp(prefix='verify-', dir=root))
    path = directory/'pairs.json'
    from request_inputs import inputs
    from captured_auth import oracle, accepted, credentialed
    req = entry['request']; rows = []; deadline = time.monotonic() + max(1,timeout)
    context=record.get('auth_context','anonymous')
    session = he.HttpSession('sql-error-verification', proxies=he.get_proxies())
    state = 'complete'; reason = ''; reproduced_inputs=[]; auth_state='unverified'
    try:
        check=oracle(config,context,req['url'])
        for selection in inputs(entry,parameter):
            observations=[]
            for index, (url, body) in enumerate(variants(entry,parameter,selection)):
                if not within(url, req['url']): raise ValueError('Request outside captured origin')
                remaining=deadline-time.monotonic()
                if remaining<=0: state='timeout'; break
                response,_=session.request(req['method'],url,headers=headers(req),body=body or None,
                    follow_redirects=False,timeout=min(15,max(1,remaining)),max_response_bytes=65536)
                text=response.text
                auth_ok=accepted(check,response.status_code,text)
                observation={'kind':'control' if index%2==0 else 'payload','input':selection,
                    'url':url,'status':response.status_code,'sql_error':bool(SQL_ERROR.search(text)),
                    'auth_valid':auth_ok,'response_sha256':hashlib.sha256(response.content).hexdigest(),
                    'body':text[:65536]}
                observations.append(observation); rows.append(observation); atomic(path,rows)
                if index%2==0 and not auth_ok:
                    state='partial';reason='Control failed or authentication expired; refresh discovery/login';break
                auth_state='verified' if check else 'captured_unverified' if credentialed(entry) else 'anonymous'
                if index<3: time.sleep(0.2)
            reproduced=len(observations)==4 and all(r['auth_valid'] and not r['sql_error'] for r in observations[::2]) and all(r['sql_error'] and r['status'] not in (301,302,303,307,308,401,403) for r in observations[1::2])
            if reproduced: reproduced_inputs.append(selection)
            if state!='complete': break
    except Exception as exc:
        state,reason='partial',str(exc) if isinstance(exc,ValueError) else type(exc).__name__
    finally: session.s.close()
    atomic(path,rows)
    alerts=[]
    if reproduced_inputs:
        alerts.append({'category':'SQL Injection','rule_id':'sql-error-paired','severity':'high',
            'url':record['url'],'method':req['method'],'parameter':parameter,'auth_context':context,
            'artifact_ref':str(path),'input_selectors':reproduced_inputs,
            'description':'SQL error reproduced in two fresh control/payload pairs per selected input. Candidate only; exploitability is not established.',
            'response_sha256':next(r['response_sha256'] for r in rows if r['kind']=='payload' and r['input'] in reproduced_inputs)})
    return f'SQL error verification {state}: reproduced={bool(reproduced_inputs)}; candidate only', {
        'alerts':alerts,'verification':{'reproduced_error':bool(reproduced_inputs),'confirmed_sqli':False,
            'input_selectors':reproduced_inputs,'artifact_ref':str(path)},
        'coverage':{'tool':'sql_error_verify','target':record['url'],'status':state,'reason':reason,
            'auth_context':context,'auth_state':auth_state,'report_path':str(path),'requests':len(rows)}}


def sqlmap_probe(config, entry, parameter, timeout=240):
    import shutil
    binary = shutil.which('sqlmap')
    if not binary: raise ValueError('sqlmap executable unavailable')
    variants(entry, parameter)  # Ambiguous duplicate selectors are not delegated to sqlmap.
    from request_inputs import inputs
    selection=inputs(entry,parameter)[0]
    sqlmap_parameter=selection['name']
    if len(inputs(entry,sqlmap_parameter))!=1:
        raise ValueError('sqlmap requires an unambiguous parameter name; use paired verification for individual occurrences')
    from captured_auth import preflight
    preflight(config, entry, config.get('_verification_auth_context', 'anonymous'))
    req = entry['request']; p = urlsplit(req['url'])
    root = Path(config.get('evidence_dir','.aixsec-evidence')).resolve()
    directory = Path(tempfile.mkdtemp(prefix='sqlmap-', dir=root))
    request_path, log = directory/'request.txt', directory/'sqlmap.log'
    head = headers(req); head['Host'] = p.netloc
    body = (req.get('postData') or {}).get('text','')
    request_path.write_text(req['method'] + ' ' + (p.path or '/') + ('?'+p.query if p.query else '') + ' HTTP/1.1\r\n' +
        '\r\n'.join(k + ': ' + v for k,v in head.items()) + '\r\n\r\n' + body)
    request_path.chmod(0o600)
    command = [binary,'-r',str(request_path),'-p',sqlmap_parameter,'--batch','--technique=BE','--level=1','--risk=1',
        '--threads=1','--timeout=10','--retries=0','--disable-coloring','--output-dir='+str(directory/'output')]
    if p.scheme=='https': command.append('--force-ssl')
    state = 'complete'
    with log.open('w') as stream:
        log.chmod(0o600)
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=max(1,timeout))
            if code: state='error'
        except subprocess.TimeoutExpired:
            state='timeout'
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
        except BaseException:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(); raise
    text = log.read_text(errors='replace')
    # Keep raw request, payloads and server output private; emit only parser fields.
    import re
    observations = '\n'.join(line for line in text.splitlines() if re.match(r'^(?:Parameter:|\s+Type:)',line))
    from http_engine import EvidenceRedactor
    return observations or f'sqlmap {state}: no structured injection observation', {
        'coverage':{'tool':'sqlmap_runner','target':EvidenceRedactor().redact_url(req['url']),'status':state,'report_path':str(log)},
        'report_path':str(log)}
