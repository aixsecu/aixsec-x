"""Fresh paired SQL error observations from captured requests; no extraction."""
import hashlib
import os
from pathlib import Path
import subprocess
import signal
import tempfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from zap_active_evidence import SQL_ERROR
from scan_state import atomic


def variants(entry, parameter):
    request = entry['request']
    method = request['method'].upper()
    if method not in ('GET', 'POST'):
        raise ValueError('Paired SQL error verification supports captured GET/POST only')
    p = urlsplit(request['url'])
    query = parse_qsl(p.query, keep_blank_values=True)
    post = request.get('postData') or {}
    body = post.get('text', '')
    if body and post.get('mimeType','').split(';')[0] != 'application/x-www-form-urlencoded':
        raise ValueError('Verification requires a URL-encoded form body')
    form = parse_qsl(body, keep_blank_values=True)
    if sum(k == parameter for k,v in query + form) != 1:
        raise ValueError('Captured parameter must occur exactly once')
    def changed(pairs):
        return [(k, v + "'" if k == parameter else v) for k,v in pairs]
    payload_url = urlunsplit((p.scheme,p.netloc,p.path,urlencode(changed(query)),''))
    payload_body = urlencode(changed(form)) if form else body
    return [(request['url'], body), (payload_url, payload_body)] * 2


def headers(request):
    # Captured credentials remain private and are used only on the same origin.
    return {h['name']:h['value'] for h in request.get('headers', []) if h.get('name','').lower()
            in ('accept','content-type','x-requested-with','referer','cookie','authorization')}


def paired(config, entry, parameter, record, timeout=60):
    import time
    import http_engine as he
    from adapters.zap import within
    root = Path(config.get('evidence_dir','.aixsec-evidence')).resolve()
    directory = Path(tempfile.mkdtemp(prefix='verify-', dir=root))
    path = directory/'pairs.json'
    req = entry['request']; rows = []; deadline = time.monotonic() + max(1,timeout)
    session = he.HttpSession('sql-error-verification', proxies=he.get_proxies())
    state = 'complete'; reason = ''
    try:
        for index, (url, body) in enumerate(variants(entry,parameter)):
            if not within(url, req['url']):
                raise ValueError('Paired request outside captured origin')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                state = 'timeout'; break
            # A local per-request timeout/rate remains even without session budgets.
            response, _ = session.request(req['method'], url, headers=headers(req), body=body or None,
                follow_redirects=False, timeout=min(15,max(1,remaining)), max_response_bytes=65536)
            text = response.text
            rows.append({'kind':'control' if index % 2 == 0 else 'payload', 'url':url,
                         'status':response.status_code, 'sql_error':bool(SQL_ERROR.search(text)),
                         'response_sha256':hashlib.sha256(response.content).hexdigest(), 'body':text[:65536]})
            atomic(path, rows)
            if index < 3: time.sleep(0.2)
    except Exception as exc:
        state, reason = 'partial', type(exc).__name__
    finally:
        session.s.close()
    reproduced = len(rows)==4 and all(200 <= row['status'] < 300 and not row['sql_error'] for row in rows[::2]) and all(row['sql_error'] for row in rows[1::2])
    atomic(path, rows)
    alerts = []
    if reproduced:
        alerts.append({'category':'SQL Injection','rule_id':'sql-error-paired','severity':'high',
            'url':record['url'],'method':req['method'],'parameter':parameter,
            'auth_context':record.get('auth_context','anonymous'),'artifact_ref':str(path),
            'description':'SQL error reproduced in two fresh control/payload pairs. Candidate only; exploitability is not established.',
            'response_sha256':rows[1]['response_sha256']})
    return f'SQL error verification {state}: reproduced={reproduced}; candidate only', {
        'alerts':alerts, 'verification':{'reproduced_error':reproduced, 'confirmed_sqli':False, 'artifact_ref':str(path)},
        'coverage':{'tool':'sql_error_verify','target':record['url'],'status':state, 'reason':reason,
                    'report_path':str(path), 'requests':len(rows)}}


def sqlmap_probe(config, entry, parameter, timeout=240):
    import shutil
    binary = shutil.which('sqlmap')
    if not binary: raise ValueError('sqlmap executable unavailable')
    variants(entry, parameter)  # Validate unique parameter and supported method/body.
    req = entry['request']; p = urlsplit(req['url'])
    root = Path(config.get('evidence_dir','.aixsec-evidence')).resolve()
    directory = Path(tempfile.mkdtemp(prefix='sqlmap-', dir=root))
    request_path, log = directory/'request.txt', directory/'sqlmap.log'
    head = headers(req); head['Host'] = p.netloc
    body = (req.get('postData') or {}).get('text','')
    request_path.write_text(req['method'] + ' ' + (p.path or '/') + ('?'+p.query if p.query else '') + ' HTTP/1.1\r\n' +
        '\r\n'.join(k + ': ' + v for k,v in head.items()) + '\r\n\r\n' + body)
    request_path.chmod(0o600)
    command = [binary,'-r',str(request_path),'-p',parameter,'--batch','--technique=BE','--level=1','--risk=1',
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
