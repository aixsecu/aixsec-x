"""Persistent, isolated ZAP daemon workers used as execution containers."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib
import os
from pathlib import Path
import queue
import signal
import subprocess
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class WorkerState(str, Enum):
    HEALTHY='healthy'; BUSY='busy'; RECOVERING='recovering'; DEAD='dead'


class WorkerError(RuntimeError): pass


def _milliseconds(): return time.perf_counter_ns()/1_000_000


@dataclass
class ZapWorker:
    worker_id: int
    binary: str
    port: int
    workspace: Path
    max_jobs: int = 100
    memory_limit_mb: int = 0
    process: object = None
    state: WorkerState = WorkerState.RECOVERING
    jobs: int = 0
    started_ms: float = 0
    startup_ms: float = 0
    shutdown_ms: float = 0
    last_error: str = ''
    policy_signature: str = ''
    context_signature: str = ''
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def base_url(self): return f'http://127.0.0.1:{self.port}'

    def _api(self, component, operation, name, params=None, timeout=10):
        path=f'/JSON/{component}/{operation}/{name}/'
        query=urlencode(params or {}, doseq=True)
        request=Request(self.base_url+path+('?' + query if query else ''), method='GET')
        with urlopen(request, timeout=timeout) as response:
            value=json.loads(response.read().decode('utf-8'))
        if not isinstance(value,dict): raise WorkerError('Malformed ZAP API response')
        return value

    def start(self, command, timeout=45):
        self.workspace.mkdir(parents=True,exist_ok=True,mode=0o700)
        log_path=self.workspace/'worker.log'
        self._log=log_path.open('a')
        began=_milliseconds();self.started_ms=began
        self.process=subprocess.Popen(command+['-daemon','-host','127.0.0.1','-port',str(self.port),
            '-dir',str(self.workspace/'home'),'-config','api.disablekey=true',
            '-config','api.addrs.addr.name=127.0.0.1','-config','api.addrs.addr.regex=false'],
            stdout=self._log,stderr=subprocess.STDOUT,start_new_session=True,
            env={k:v for k,v in os.environ.items() if not k.startswith('ZAP_AUTH_HEADER')})
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if self.process.poll() is not None: break
            try:
                self._api('core','view','version',timeout=1)
                self.startup_ms=_milliseconds()-began;self.state=WorkerState.HEALTHY;return
            except (HTTPError,URLError,TimeoutError,OSError,ValueError,WorkerError): time.sleep(.1)
        self.state=WorkerState.DEAD
        raise WorkerError(f'ZAP worker {self.worker_id} did not become ready')

    def healthy(self):
        if self.state==WorkerState.DEAD or self.process is None or self.process.poll() is not None: return False
        try: self._api('core','view','version',timeout=2);return True
        except Exception: return False

    def memory_mb(self):
        if not self.process: return 0
        try:
            value=subprocess.run(['ps','-o','rss=','-p',str(self.process.pid)],capture_output=True,
                                 text=True,timeout=2,check=False).stdout.strip()
            return int(value or 0)/1024
        except (OSError,ValueError,subprocess.TimeoutExpired): return 0

    def cpu_percent(self):
        if not self.process:return 0
        try:
            value=subprocess.run(['ps','-o','%cpu=','-p',str(self.process.pid)],capture_output=True,
                                 text=True,timeout=2,check=False).stdout.strip()
            return float(value or 0)
        except (OSError,ValueError,subprocess.TimeoutExpired): return 0

    def needs_recycle(self):
        return self.jobs>=self.max_jobs or bool(self.memory_limit_mb and self.memory_mb()>self.memory_limit_mb)

    def reset(self):
        try:
            self._api('core','action','deleteAllAlerts',timeout=10)
            sites=self._api('core','view','sites',timeout=10).get('sites') or []
            for site in sites:
                # deleteSiteNode removes the site's history/tree without replacing
                # the daemon, proxy, workspace, or add-on state.
                try: self._api('httpSessions','action','clearActiveSession',{'site':site},timeout=5)
                except HTTPError: pass  # Older HTTP Sessions add-ons omit this action.
                self._api('core','action','deleteSiteNode',{'url':site},timeout=10)
        except (HTTPError,URLError,TimeoutError,OSError,ValueError,WorkerError) as exc:
            raise WorkerError(f'worker reset failed: {exc}') from exc

    def run_plan(self, plan_path, timeout, cancelled=None):
        with self._lock:
            if not self.healthy(): raise WorkerError('worker is unhealthy before job')
            self.state=WorkerState.BUSY;began=_milliseconds()
            try:
                self.reset()
                plan=json.loads(Path(plan_path).read_text())
                contexts=((plan.get('env') or {}).get('contexts') or [])
                context_signature=hashlib.sha256(json.dumps(contexts,sort_keys=True).encode()).hexdigest()
                context_reused=bool(contexts and context_signature==self.context_signature)
                policies=[job for job in plan.get('jobs',[]) if job.get('type')=='activeScan-policy']
                signature=hashlib.sha256(json.dumps(policies,sort_keys=True).encode()).hexdigest() if policies else ''
                policy_reused=bool(signature and signature==self.policy_signature)
                if policy_reused:
                    plan['jobs']=[job for job in plan['jobs'] if job.get('type')!='activeScan-policy']
                    Path(plan_path).write_text(json.dumps(plan));Path(plan_path).chmod(0o600)
                response=self._api('automation','action','runPlan',{'filePath':str(plan_path)},timeout=10)
                plan_id=response.get('planId') or response.get('planid')
                if plan_id is None: raise WorkerError(f'runPlan did not return planId: {response}')
                deadline=time.monotonic()+timeout
                while time.monotonic()<deadline:
                    if cancelled is not None and cancelled.is_set(): raise TimeoutError('ZAP job cancelled')
                    progress=self._api('automation','view','planProgress',{'planId':plan_id},timeout=5)
                    value=progress.get('planProgress') or progress
                    if isinstance(value,dict) and value.get('finished'):
                        errors=value.get('error') or value.get('errors') or []
                        if errors: raise WorkerError('Automation plan failed: '+str(errors)[:500])
                        if signature:self.policy_signature=signature
                        if contexts:self.context_signature=context_signature
                        self.jobs+=1;return {'returncode':0,'job_ms':_milliseconds()-began,
                            'plan_id':str(plan_id),'progress':value,'policy_reused':policy_reused,
                            'context_reused':context_reused}
                    time.sleep(.1)
                raise TimeoutError('ZAP automation plan timed out')
            except BaseException as exc:
                self.last_error=str(exc);self.state=WorkerState.DEAD
                raise
            finally:
                if self.state!=WorkerState.DEAD: self.state=WorkerState.HEALTHY

    def close(self, timeout=10):
        if not self.process: self.state=WorkerState.DEAD;return
        began=_milliseconds();self.state=WorkerState.RECOVERING
        try: self._api('core','action','shutdown',timeout=3)
        except Exception: pass
        try: self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try: os.killpg(self.process.pid,signal.SIGTERM);self.process.wait(timeout=5)
            except (ProcessLookupError,subprocess.TimeoutExpired):
                try: os.killpg(self.process.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                self.process.wait()
        self.shutdown_ms=_milliseconds()-began;self.state=WorkerState.DEAD
        if getattr(self,'_log',None): self._log.close()


class WorkerLease:
    def __init__(self,pool,worker): self.pool=pool;self.worker=worker
    def __enter__(self): return self.worker
    def __exit__(self,kind,value,tb): self.pool.release(self.worker,unhealthy=kind is not None)


class WorkerPool:
    def __init__(self,config,binary,command,port_factory,port_releaser=lambda port:None):
        self.config=config;self.binary=binary;self.command=command;self.port_factory=port_factory
        self.port_releaser=port_releaser
        self.size=max(1,int(config.get('zap_workers',2)));self.root=Path(config.get('evidence_dir') or '.aixsec-evidence').resolve()/'zap-workers'
        self.max_jobs=max(1,int(config.get('zap_worker_max_jobs',100)))
        self.memory_limit_mb=max(0,int(config.get('zap_worker_memory_mb',0)))
        self._available=queue.Queue(self.size);self._workers=[];self._lock=threading.Lock();self._closed=False
        self.metrics={'jvm_created':0,'jobs':0,'reused_jobs':0,'recycled':0,'crashes':0,
                      'acquire_wait_ms':0.0,'worker_busy_ms':0.0}

    def _new_worker(self,index):
        worker=ZapWorker(index,self.binary,self.port_factory(),self.root/f'worker-{index}',
                         self.max_jobs,self.memory_limit_mb)
        worker.start(self.command);self.metrics['jvm_created']+=1;return worker

    def start(self):
        with self._lock:
            if self._workers: return self
            self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
            try:
                for index in range(self.size):
                    worker=self._new_worker(index);self._workers.append(worker);self._available.put(worker)
            except BaseException:
                self.close();raise
        return self

    def acquire(self,timeout=None):
        if self._closed: raise WorkerError('worker pool is closed')
        self.start();began=_milliseconds()
        try: worker=self._available.get(timeout=timeout)
        except queue.Empty as exc: raise TimeoutError('ZAP worker pool exhausted') from exc
        self.metrics['acquire_wait_ms']+=_milliseconds()-began
        return WorkerLease(self,worker)

    def release(self,worker,unhealthy=False):
        self.metrics['jobs']+=1;self.metrics['reused_jobs']+=int(worker.jobs>1)
        recycle=unhealthy or not worker.healthy() or worker.needs_recycle()
        if recycle:
            if unhealthy:self.metrics['crashes']+=1
            worker.close();self.port_releaser(worker.port);self.metrics['recycled']+=1
            try:
                replacement=self._new_worker(worker.worker_id)
                with self._lock:
                    self._workers[self._workers.index(worker)]=replacement
                worker=replacement
            except BaseException:
                return
        if not self._closed:self._available.put(worker)

    def request_recycle(self,worker_id):
        with self._lock:
            worker=next((w for w in self._workers if w.worker_id==worker_id),None)
            if worker: worker.max_jobs=worker.jobs

    def snapshot(self):
        lifetimes=[max(0,_milliseconds()-w.started_ms) for w in self._workers if w.started_ms]
        wall=max(lifetimes,default=0)
        return {**self.metrics,'pool_size':self.size,
            'reuse_ratio':round(self.metrics['reused_jobs']/max(1,self.metrics['jobs']),4),
            'average_worker_lifetime_ms':sum(lifetimes)/len(lifetimes) if lifetimes else 0,
            'average_job_ms':self.metrics['worker_busy_ms']/max(1,self.metrics['jobs']),
            'average_worker_startup_ms':sum(w.startup_ms for w in self._workers)/len(self._workers) if self._workers else 0,
            'average_worker_shutdown_ms':sum(w.shutdown_ms for w in self._workers)/len(self._workers) if self._workers else 0,
            'throughput_jobs_per_second':self.metrics['jobs']/(wall/1000) if wall else 0,
            'memory_mb':sum(w.memory_mb() for w in self._workers),
            'cpu_percent':sum(w.cpu_percent() for w in self._workers),
            'healthy':sum(w.healthy() for w in self._workers)}

    def close(self):
        self._closed=True
        for worker in list(self._workers):
            worker.close();self.port_releaser(worker.port)
