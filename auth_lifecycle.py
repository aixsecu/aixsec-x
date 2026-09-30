"""Thread-safe authentication lifecycle with generation-fenced retry ledger."""
import json, os, threading, time
from pathlib import Path


class AuthLifecycle:
    def __init__(self, context='anonymous'):
        self.context=context; self.state='anonymous_stateless' if context=='anonymous' else 'auth_configured'
        self.generation=0; self.reason=''; self.refreshes=0; self._lock=threading.RLock()
        self.events=[]; self.path=None

    def bind(self,path):
        self.path=Path(path)
        if self.path.exists():
            try:
                value=json.loads(self.path.read_text(encoding='utf-8'))
                self.generation=int(value.get('generation',self.generation)); self.refreshes=int(value.get('refreshes',0))
                self.events=list(value.get('events') or [])[-1000:]
            except (OSError,ValueError,TypeError): pass
        self._save(); return self

    def _save(self):
        if not self.path: return
        temporary=self.path.with_suffix(self.path.suffix+'.tmp')
        temporary.write_text(json.dumps(self.public(),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        os.chmod(temporary,0o600); temporary.replace(self.path); os.chmod(self.path,0o600)

    def _event(self,job,state,generation,reason=''):
        self.events.append({'time':time.time(),'job':str(job or ''),'state':state,
                            'generation':generation,'reason':reason})
        self.events=self.events[-1000:]; self._save()

    @staticmethod
    def _tag(result,generation,disposition):
        if not isinstance(result,dict): return result
        data=result.setdefault('data',{}); coverage=data.setdefault('coverage',{}) if isinstance(data,dict) else {}
        if isinstance(coverage,dict):
            coverage['auth_generation']=generation; coverage['auth_disposition']=disposition
            if disposition in ('auth_uncertain','deferred_auth_expired') and coverage.get('status')=='complete':
                coverage['status']='partial'
        for row in data.get('alerts',[]) if isinstance(data,dict) else []:
            if isinstance(row,dict): row.update(auth_generation=generation,auth_disposition=disposition)
        return result

    def verified(self):
        with self._lock:
            self.state='auth_verified'; self.generation=max(1,self.generation); self.reason='authentication verified'

    def expired(self, reason='authentication expired or unverified'):
        with self._lock: self.state='auth_expired'; self.reason=reason

    def run(self, operation, expired, *, safe_retry=True, job_id=''):
        """Run once; serialize one refresh/retry generation on auth failure."""
        before=self.generation; result=operation()
        if not expired(result):
            with self._lock:
                if self.generation != before and before > 0:
                    self._event(job_id,'auth_uncertain',before,'generation changed while job was running')
                    if not safe_retry: return self._tag(result,before,'auth_uncertain')
                    retry=operation()
                    disposition='retry_after_refresh' if not expired(retry) else 'deferred_auth_expired'
                    self._event(job_id,disposition,self.generation)
                    return self._tag(retry,self.generation,disposition)
            self.verified(); self._event(job_id,'complete',self.generation)
            return self._tag(result,self.generation,'complete')
        self.expired()
        self._event(job_id,'auth_uncertain',before,'scanner returned unverified/login response')
        if not safe_retry:
            self._event(job_id,'deferred_auth_expired',before,'unsafe request was not replayed')
            return self._tag(result,before,'deferred_auth_expired')
        with self._lock:
            self.state='auth_refreshing'; self.reason='refreshing credentials and session'
            retry=operation(); self.refreshes += 1
            if expired(retry):
                self.state='auth_blocked'; self.reason='authentication refresh did not verify'
                self._event(job_id,'deferred_auth_expired',before,self.reason)
                return self._tag(retry,before,'deferred_auth_expired')
            self.generation=max(before+1,1); self.state='auth_verified'; self.reason='refresh verified'
            self._event(job_id,'retry_after_refresh',self.generation)
            return self._tag(retry,self.generation,'retry_after_refresh')

    def public(self):
        with self._lock:
            return {'context':self.context,'state':self.state,'generation':self.generation,
                    'refreshes':self.refreshes,'reason':self.reason,'events':list(self.events)}
