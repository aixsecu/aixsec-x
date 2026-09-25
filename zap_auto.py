"""Bounded automatic concurrency trials; observations never prove independence."""
import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit, unquote, parse_qsl
from adapters.zap import origin
from scan_state import atomic
from captured_auth import headers, oracle, accepted

# Deliberately conservative for workflows even when their seed method is GET.
WORKFLOW = re.compile(r'(?:^|[/_.\-])(login|logout|signin|signout|auth|account|profile|admin|cart|basket|checkout|payment|order|delete|remove|update|save|upload|subscribe|reset|confirm|activate)(?:$|[/_.\-])', re.I)


def candidate_reasons(entry, config):
    req = entry['_entry']['request']
    parsed = urlsplit(req['url'])
    reasons = []
    if WORKFLOW.search(unquote(parsed.path)):
        reasons.append('auto_workflow_route')
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in ('action','act','task','operation','op') and WORKFLOW.search('/'+value):
            reasons.append('auto_workflow_action'); break
    captured = entry['_entry'].get('response') or {}
    if not 200 <= int(captured.get('status') or 0) < 300:
        reasons.append('auto_no_successful_capture')
    names = {h.get('name','').lower() for h in req.get('headers', [])}
    context = entry.get('auth_context','anonymous')
    if context != 'anonymous':
        try:
            oracle(config, context, req['url'])
        except (ValueError, OSError, KeyError, TypeError, re.error):
            reasons.append('auto_missing_auth_oracle')
    elif any(re.search(r'authorization|api.?key|token|secret|auth', name) for name in names):
        reasons.append('auto_unlabelled_credentials')
    if req.get('cookies') and 'cookie' not in names:
        reasons.append('auto_cookie_header_missing')
    return reasons


def pace(root, url, delay_ms):
    # Java FileChannel locks and POSIX record locks coordinate across JVM/Python.
    import fcntl
    import os
    import struct
    path=Path(root)/('zap-rate-'+hashlib.sha256(origin(url).encode()).hexdigest()+'.lock')
    with path.open('a+b') as stream:
        os.chmod(path,0o600)
        fcntl.lockf(stream,fcntl.LOCK_EX)
        try:
            stream.seek(0); raw=stream.read(8)
            last=struct.unpack('>q',raw)[0] if len(raw)==8 else 0
            pause=max(0,(last+delay_ms)/1000-time.time())
            if pause: time.sleep(pause)
            # a+b forces append: truncate before writing the single timestamp.
            stream.seek(0);stream.truncate()
            stream.write(struct.pack('>q',int(time.time()*1000)));stream.flush()
        finally: fcntl.lockf(stream,fcntl.LOCK_UN)


def controls(config, entry, root):
    import http_engine as he
    req=entry['_entry']['request']; context=entry.get('auth_context','anonymous')
    check=oracle(config,context,req['url'])
    observations=[]
    for _ in range(2):
        pace(root,req['url'],max(0,int(config.get('zap_delay_ms',200))))
        session=he.HttpSession('zap-auto-control',proxies=he.get_proxies())
        started=time.monotonic()
        try:
            response,meta=session.request(req.get('method','GET'),req['url'],headers=headers(req),
                follow_redirects=False,timeout=10,max_response_bytes=1048576)
            text=response.text
            response_headers={k.lower():v for k,v in response.headers.items()}
            if not accepted(check,response.status_code,text):
                return {'stable':False,'reason':'control_status_or_auth','statuses':[o['status'] for o in observations]+[response.status_code]}
            if 'set-cookie' in response_headers or 'location' in response_headers:
                return {'stable':False,'reason':'control_session_or_redirect'}
            if re.search(r'type\s*=\s*["\x27]?password|(?:csrf|xsrf)',text,re.I):
                return {'stable':False,'reason':'control_login_or_csrf'}
            # A truncated response cannot establish equality of full responses.
            if len(response.content)>=1048576:
                return {'stable':False,'reason':'control_body_limit'}
            observations.append({'status':response.status_code,'sha256':hashlib.sha256(response.content).hexdigest(),
                'content_type':response_headers.get('content-type',''),
                'elapsed':round(time.monotonic()-started,3)})
        finally: session.s.close()
    stable=(observations[0]['sha256']==observations[1]['sha256'] and
            observations[0]['status']==observations[1]['status'] and
            observations[0]['content_type']==observations[1]['content_type'] and
            max(o['elapsed'] for o in observations)<=5)
    return {'stable':stable,'reason':'stable_controls' if stable else 'control_changed_or_slow',
            'observations':observations}


class AutoConcurrency:
    def __init__(self,config,directory,entries,policy):
        self.config=config;self.path=Path(directory)/'auto-concurrency.json';self.policy=policy
        self.data=json.loads(self.path.read_text()) if self.path.exists() else {'version':1,'origins':{},'decisions':{}}
        for entry in entries:
            entry['_auto_reasons']=candidate_reasons(entry,config)
        self.save()
    def save(self): atomic(self.path,self.data)
    def summary(self):
        return {'path':str(self.path), 'assessed_groups':len(self.data['decisions']),
                'stable_controls':sum(bool(d.get('stable')) for d in self.data['decisions'].values()),
                'origins':self.data['origins']}
    def limit(self,target_origin):
        state=self.data['origins'].get(target_origin,{})
        return 2 if state.get('promoted') and not state.get('backoff') else 1
    def backoff(self,entry,reason):
        state=self.data['origins'].setdefault(origin(entry['_entry']['request']['url']),{})
        state.update(backoff=True,reason=reason);self.save()
        print('[zap:auto] origin reduced to one worker: '+reason,flush=True)
    def prepare(self,entry):
        # Called only after scope/approval, and only for a task not restored/skipped.
        from zap_workers import scheduling_reasons
        if self.policy.match(entry) or scheduling_reasons(entry,'auto',self.policy): return
        state=self.data['origins'].get(origin(entry['_entry']['request']['url']),{})
        if state.get('backoff'):
            entry['_auto_reasons']=['auto_origin_backoff'];return
        try: decision=controls(self.config,entry,self.path.parent)
        except Exception:
            decision={'stable':False,'reason':'control_request_error'}
        self.data['decisions'][entry['request_id']]=decision
        if not decision['stable']:
            entry['_auto_reasons']=[decision['reason']]
            self.backoff(entry,decision['reason'])
        self.save()
    def observe(self,entry,result):
        if self.policy.match(entry): return
        state=self.data['origins'].setdefault(origin(entry['_entry']['request']['url']),{})
        coverage=(result.get('data') or {}).get('coverage') or {}
        decision=self.data['decisions'].get(entry['request_id'],{})
        if result.get('outcome') in ('error','timeout','partial'):
            self.backoff(entry,'scanner_incomplete');return
        if entry.get('auth_context','anonymous')!='anonymous' and coverage.get('auth_state')!='verified':
            self.backoff(entry,'scanner_auth_unverified');return
        # Inspect status-only observer records; no bodies/cookies enter diagnostics.
        path=coverage.get('active_requests_path')
        seen = 0
        if path and Path(path).is_file():
            try:
                with Path(path).open() as stream:
                    for line in stream:
                        row=json.loads(line)
                        status=row.get('status')
                        if isinstance(status,int) and status>0: seen += 1
                        baseline=max((o.get('elapsed',0) for o in decision.get('observations',[])),default=0)
                        if row.get('set_cookie') or row.get('redirect'):
                            self.backoff(entry,'active_session_or_redirect');return
                        if float(row.get('elapsed_ms') or 0)>max(5000,baseline*4000):
                            self.backoff(entry,'active_response_slow');return
                        if status in (401,403,429) or isinstance(status,int) and status>=500:
                            self.backoff(entry,'active_http_error_or_rate_limit');return
            except (ValueError,OSError,TypeError):
                self.backoff(entry,'observer_unreadable');return
        if decision.get('stable') and result.get('outcome')=='ok' and seen>0:
            state['promoted']=True;self.save()
