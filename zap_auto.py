"""Bounded automatic concurrency trials; observations never prove independence."""
import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit, unquote, parse_qsl, urljoin
from adapters.zap import origin
from scan_state import atomic
from captured_auth import headers, oracle, accepted

# Deliberately conservative for workflows even when their seed method is GET.
WORKFLOW = re.compile(r'(?:^|[/_.\-])(login|logout|signin|signout|auth|account|profile|admin|cart|basket|checkout|payment|order|delete|remove|update|save|upload|subscribe|reset|confirm|activate)(?:$|[/_.\-])', re.I)
LOGIN = re.compile(r'(?:^|[/_.\-])(login|signin|sign-in|auth|sso)(?:$|[/_.\-])', re.I)
LOGOUT = re.compile(r'(?:^|[/_.\-])(logout|signout|sign-out)(?:$|[/_.\-])', re.I)
LANGUAGE = re.compile(r'^/(?:[a-z]{2}(?:-[A-Z]{2})?)(?:/|$)')
SESSION_COOKIE = re.compile(r'(?:^|[._-])(session|sess|sid|auth|jwt|token)(?:$|[._-])|phpsessid|jsessionid|asp\.net_sessionid', re.I)
CSRF_COOKIE = re.compile(r'csrf|xsrf', re.I)
AFFINITY_COOKIE = re.compile(r'arrAffinity|awsalb|awsalbcors|bigip|jroute|routeid|sticky', re.I)
ANALYTICS_COOKIE = re.compile(r'^_(?:ga|gid|gat)|analytics|amplitude|^mp_', re.I)
PREFERENCE_COOKIE = re.compile(r'lang|locale|theme|consent|preference|^pref', re.I)
REDIRECT_STATUS = {301, 302, 303, 307, 308}


def _cookie_class(name):
    if CSRF_COOKIE.search(name): return 'csrf'
    if AFFINITY_COOKIE.search(name): return 'affinity'
    if ANALYTICS_COOKIE.search(name): return 'analytics'
    if PREFERENCE_COOKIE.search(name): return 'preference'
    if SESSION_COOKIE.search(name): return 'session'
    return 'unknown'


def classify_cookies(row):
    """Classify names only. Cookie values must never enter scheduler state/logs."""
    response = {str(v) for v in row.get('set_cookie_names', []) if v}
    request = {str(v) for v in row.get('request_cookie_names', []) if v}
    if not response and row.get('set_cookie'):
        return 'unknown', -1
    classified = {name:_cookie_class(name) for name in response}
    classes = set(classified.values())
    if 'session' in classes:
        session_names = {name for name,kind in classified.items() if kind == 'session'}
        return ('session_refresh', -1) if session_names & request else ('session_mutation', -3)
    if 'csrf' in classes: return 'csrf_rotation', -1
    if 'unknown' in classes: return 'unknown', -1
    if 'affinity' in classes: return 'affinity', 0
    if 'analytics' in classes: return 'analytics', 0
    if 'preference' in classes: return 'preference', 0
    return 'none', 0


def classify_redirect(row):
    status = row.get('status')
    if status not in REDIRECT_STATUS:
        return 'none', 0
    source = str(row.get('url') or '')
    raw_target = str(row.get('location') or '')
    if not raw_target:
        return ('unknown', -1) if row.get('redirect') else ('none', 0)
    target = urljoin(source, raw_target)
    before, after = urlsplit(source), urlsplit(target)
    target_path = unquote(after.path or '/')
    if LOGOUT.search(target_path): return 'logout', -4
    if LOGIN.search(target_path): return 'login', -4
    if before.hostname == after.hostname and before.scheme == 'http' and after.scheme == 'https' \
            and before.path == after.path and before.query == after.query:
        return 'http_to_https', 0
    same_origin = (before.scheme, before.hostname, before.port or (443 if before.scheme == 'https' else 80)) == \
                  (after.scheme, after.hostname, after.port or (443 if after.scheme == 'https' else 80))
    if same_origin and before.query == after.query and before.path.rstrip('/') == after.path.rstrip('/'):
        return 'canonical', 0
    if same_origin and LANGUAGE.match(target_path) and not LANGUAGE.match(before.path or '/'):
        return 'language', 0
    # A redirect within the same origin is routing/normalization, not evidence
    # of shared-session corruption. Login/logout destinations were handled above.
    if same_origin: return 'same_origin', 0
    before_host=(before.hostname or '').lower().removeprefix('www.')
    after_host=(after.hostname or '').lower().removeprefix('www.')
    if before_host == after_host and before.scheme == after.scheme:
        return 'canonical_host', 0
    return 'cross_origin', -3


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
    captured_status=int(captured.get('status') or 0)
    captured_headers={str(h.get('name','')).lower():str(h.get('value',''))
                      for h in captured.get('headers',[]) if h.get('name')}
    captured_location=captured_headers.get('location') or str(captured.get('redirectURL') or '')
    captured_redirect,_=classify_redirect({'status':captured_status,'url':req['url'],
        'redirect':bool(captured_location),'location':captured_location})
    benign_capture=captured_redirect in {'canonical','canonical_host','http_to_https','language','same_origin'}
    if not 200 <= captured_status < 300 and not benign_capture:
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
            redirect_class,redirect_delta=classify_redirect({'status':response.status_code,
                'url':req['url'],'redirect':'location' in response_headers,
                'location':response_headers.get('location','')})
            benign_redirect=redirect_class in {'canonical','canonical_host','http_to_https','language','same_origin'}
            if not accepted(check,response.status_code,text) and not benign_redirect:
                return {'stable':False,'reason':'control_status_or_auth','statuses':[o['status'] for o in observations]+[response.status_code]}
            if redirect_delta < 0:
                return {'stable':False,'reason':'control_session_redirect','redirect_class':redirect_class}
            if 'set-cookie' in response_headers:
                # The controls cannot retain values. Extract only the first name;
                # combined headers remain conservatively classified as unknown.
                set_name=response_headers['set-cookie'].split(';',1)[0].split('=',1)[0].strip()
                request_names={part.split('=',1)[0].strip() for part in headers(req).get('Cookie','').split(';') if part.strip()}
                cookie_class,cookie_delta=classify_cookies({'set_cookie':True,
                    'set_cookie_names':[set_name] if set_name else [],
                    'request_cookie_names':sorted(request_names)})
                if cookie_delta <= -3:
                    return {'stable':False,'reason':'control_session_mutation','cookie_class':cookie_class}
            if re.search(r'type\s*=\s*["\x27]?password|(?:csrf|xsrf)',text,re.I):
                return {'stable':False,'reason':'control_login_or_csrf'}
            # A truncated response cannot establish equality of full responses.
            if len(response.content)>=1048576:
                return {'stable':False,'reason':'control_body_limit'}
            observations.append({'status':response.status_code,'sha256':hashlib.sha256(response.content).hexdigest(),
                'content_type':response_headers.get('content-type',''),
                'redirect_class':redirect_class,
                'location_sha256':hashlib.sha256(response_headers.get('location','').encode()).hexdigest() if benign_redirect else '',
                'elapsed':round(time.monotonic()-started,3)})
        finally: session.s.close()
    stable=(observations[0]['sha256']==observations[1]['sha256'] and
            observations[0]['status']==observations[1]['status'] and
            observations[0]['content_type']==observations[1]['content_type'] and
            observations[0]['location_sha256']==observations[1]['location_sha256'] and
            max(o['elapsed'] for o in observations)<=5)
    return {'stable':stable,'reason':'stable_controls' if stable else 'control_changed_or_slow',
            'observations':observations}


class AutoConcurrency:
    def __init__(self,config,directory,entries,policy):
        self.config=config;self.path=Path(directory)/'auto-concurrency.json';self.policy=policy
        self.max_workers=max(1,min(8,int(config.get('zap_workers',2))))
        self.recovery_groups=max(2,int(config.get('zap_auto_recovery_groups',2)))
        self.escalation_groups=max(2,int(config.get('zap_auto_escalation_groups',2)))
        self.minimum_dwell=max(1,int(config.get('zap_auto_minimum_dwell_groups',3)))
        self.promotion_cooldown=max(self.minimum_dwell,int(config.get('zap_auto_promotion_cooldown_groups',4)))
        self.demotion_cooldown=max(self.minimum_dwell,int(config.get('zap_auto_demotion_cooldown_groups',3)))
        self.data=json.loads(self.path.read_text()) if self.path.exists() else {'version':2,'origins':{},'groups':{},'decisions':{}}
        self.data['version']=2;self.data.setdefault('groups',{})
        for state in self.data.setdefault('origins',{}).values():
            if 'level' not in state:
                state['level']=1 if state.pop('backoff',False) else (2 if state.pop('promoted',False) else 1)
            state.setdefault('score',-3 if state.get('reason') else 0)
            state.setdefault('stable_groups',0);state.setdefault('unstable_groups',{})
            state.setdefault('groups_since_change',0)
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
        return min(self.max_workers,max(1,int(state.get('level',1))))
    def _state(self,entry):
        return self.data['origins'].setdefault(origin(entry['_entry']['request']['url']),
            {'level':1,'score':0,'stable_groups':0,'unstable_groups':{},'groups_since_change':0})
    def _next_level(self,level,up):
        if up: return min(self.max_workers,2 if level<2 else level*2)
        return max(1,level//2)
    def _log_change(self,entry,previous,current,reason,evidence,cookie_class='none',redirect_class='none'):
        state=self._state(entry)
        print('[zap:auto] concurrency changed\n'
              f'  Origin: {origin(entry["_entry"]["request"]["url"])}\n'
              f'  Current workers: {current}\n  Previous workers: {previous}\n'
              f'  Reason: {reason}\n  Evidence: {evidence}\n'
              f'  Cookie class: {cookie_class}\n  Redirect class: {redirect_class}\n'
              f'  Stability score: {state["score"]}\n'
              f'  Next promotion threshold: {self.recovery_groups} stable groups; cooldown={self.promotion_cooldown}\n'
              f'  Next demotion threshold: {self.escalation_groups} distinct unstable groups; cooldown={self.demotion_cooldown}\n'
              f'  Minimum dwell: {self.minimum_dwell} groups',flush=True)
    def _quarantine(self,entry,reason,delta,evidence,cookie_class='none',redirect_class='none'):
        fid=entry['request_id'];state=self._state(entry)
        group=self.data['groups'].setdefault(fid,{'quarantined':False,'events':0})
        group.update(quarantined=True,reason=reason,evidence=evidence,
                     cookie_class=cookie_class,redirect_class=redirect_class)
        group['events']+=1;state['stable_groups']=0
        state['groups_since_change']=int(state.get('groups_since_change',0))+1
        state['score']=max(-20,int(state.get('score',0))+delta)
        state['unstable_groups'][fid]={'reason':reason,'delta':delta}
        if (len(state['unstable_groups']) < self.escalation_groups or
                state['groups_since_change'] < self.demotion_cooldown):
            self.save();return
        previous=self.limit(origin(entry['_entry']['request']['url']))
        current=self._next_level(previous,False)
        state.update(level=current,reason=reason,groups_since_change=0)
        self.save()
        if current != previous:
            self._log_change(entry,previous,current,reason,evidence,cookie_class,redirect_class)
    def _stable(self,entry):
        state=self._state(entry);state['score']=min(20,int(state.get('score',0))+3)
        state['stable_groups']=int(state.get('stable_groups',0))+1
        state['groups_since_change']=int(state.get('groups_since_change',0))+1
        # Alternating clean/unstable workloads must not accumulate stale evidence
        # into an origin-wide demotion.
        state['unstable_groups']={}
        if (state['stable_groups'] < self.recovery_groups or
                state['score'] < self.recovery_groups*3 or
                state['groups_since_change'] < self.promotion_cooldown):
            self.save();return
        previous=self.limit(origin(entry['_entry']['request']['url']))
        current=self._next_level(previous,True)
        state.update(level=current,stable_groups=0,reason='stable_groups',groups_since_change=0)
        state['unstable_groups']={}
        self.data['groups'].pop(entry['request_id'],None)
        self.save()
        if current != previous:
            self._log_change(entry,previous,current,'stable_groups','consecutive clean successful groups')
    def backoff(self,entry,reason):
        """Compatibility entry point: backoff is now group-local and recoverable."""
        self._quarantine(entry,reason,-3,'legacy backoff signal')
    def prepare(self,entry):
        # Called only after scope/approval, and only for a task not restored/skipped.
        from zap_workers import scheduling_reasons
        if self.policy.match(entry) or scheduling_reasons(entry,'auto',self.policy): return
        group=self.data['groups'].get(entry['request_id'],{})
        if group.get('quarantined'):
            entry['_auto_reasons']=['auto_group_quarantine'];return
        try: decision=controls(self.config,entry,self.path.parent)
        except Exception:
            decision={'stable':False,'reason':'control_request_error'}
        self.data['decisions'][entry['request_id']]=decision
        if not decision['stable']:
            entry['_auto_reasons']=[decision['reason']]
            self._quarantine(entry,decision['reason'],-2,'unstable control pair')
        self.save()
    def observe(self,entry,result):
        if self.policy.match(entry): return
        coverage=(result.get('data') or {}).get('coverage') or {}
        decision=self.data['decisions'].get(entry['request_id'],{})
        if result.get('outcome') in ('error','timeout','partial'):
            self._quarantine(entry,'scanner_incomplete',-3,result.get('outcome'));return
        if entry.get('auth_context','anonymous')!='anonymous' and coverage.get('auth_state')!='verified':
            self._quarantine(entry,'scanner_auth_unverified',-5,'authenticated scan was not verified');return
        # Inspect status-only observer records; no bodies/cookies enter diagnostics.
        path=coverage.get('active_requests_path')
        seen = 0
        worst=None
        if path and Path(path).is_file():
            try:
                with Path(path).open() as stream:
                    for line in stream:
                        row=json.loads(line)
                        status=row.get('status')
                        if isinstance(status,int) and status>0: seen += 1
                        baseline=max((o.get('elapsed',0) for o in decision.get('observations',[])),default=0)
                        cookie_class,cookie_delta=classify_cookies(row)
                        redirect_class,redirect_delta=classify_redirect(row)
                        delta=min(cookie_delta,redirect_delta)
                        if delta < 0 and (worst is None or delta < worst[0]):
                            worst=(delta,'active_session_or_redirect',
                                f'status={status}; cookie={cookie_class}; redirect={redirect_class}',
                                cookie_class,redirect_class)
                        if float(row.get('elapsed_ms') or 0)>max(5000,baseline*4000):
                            value=(-2,'active_response_slow',f'elapsed_ms={row.get("elapsed_ms")}',cookie_class,redirect_class)
                            worst=value if worst is None or value[0]<worst[0] else worst
                        if status in (401,403,429) or isinstance(status,int) and status>=500:
                            value=(-5,'active_http_error_or_rate_limit',f'status={status}',cookie_class,redirect_class)
                            worst=value if worst is None or value[0]<worst[0] else worst
            except (ValueError,OSError,TypeError):
                self._quarantine(entry,'observer_unreadable',-3,'invalid active observer record');return
        if worst:
            self._quarantine(entry,worst[1],worst[0],worst[2],worst[3],worst[4]);return
        if result.get('outcome')=='ok' and seen>0:
            self._stable(entry)
