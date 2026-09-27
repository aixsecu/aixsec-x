#!/usr/bin/env python3
"""Local-only Active Scan timing benchmark using the production adapter/scheduler."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import resource
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from adapters.zap import executable, run_scan, worker_pool  # noqa: E402
from pipeline import _active_performance  # noqa: E402
from zap_workers import drive  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body=b'<html><body><form><input name="id"></form></body></html>'
        self.send_response(200);self.send_header('Content-Type','text/html')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args): pass


def _pool_totals(before_close, after_close):
    created=int(before_close.get('jvm_created',0) or 0)
    return {
        **before_close,
        'startup_total_ms':round(float(before_close.get('average_worker_startup_ms',0))*created,3),
        'shutdown_total_ms':round(float(after_close.get('average_worker_shutdown_ms',0))*created,3),
        'peak_memory_mb':float(before_close.get('memory_mb',0) or 0),
        'cpu_percent_snapshot':float(before_close.get('cpu_percent',0) or 0),
    }


def _aggregate_pools(samples):
    created=sum(int(item.get('jvm_created',0) or 0) for item in samples)
    jobs=sum(int(item.get('jobs',0) or 0) for item in samples)
    startup=sum(float(item.get('startup_total_ms',0) or 0) for item in samples)
    shutdown=sum(float(item.get('shutdown_total_ms',0) or 0) for item in samples)
    return {
        'workers':max((int(item.get('pool_size',0) or 0) for item in samples),default=0),
        'jobs':jobs,'jvm_created':created,
        'jvm_reused':max(0,jobs-created),
        'reuse_ratio':round(max(0,jobs-created)/jobs,4) if jobs else 0.0,
        'average_worker_startup_ms':round(startup/created,3) if created else 0.0,
        'average_worker_shutdown_ms':round(shutdown/created,3) if created else 0.0,
        'startup_total_ms':round(startup,3),'shutdown_total_ms':round(shutdown,3),
        'peak_memory_mb':max((float(item.get('peak_memory_mb',0) or 0) for item in samples),default=0.0),
        'cpu_percent_snapshot':max((float(item.get('cpu_percent_snapshot',0) or 0) for item in samples),default=0.0),
    }


def _finding_signature(findings):
    encoded=json.dumps(sorted(findings),separators=(',',':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def run(job_count=2, workers=2, evidence_dir='', persistent=True):
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        temporary=tempfile.TemporaryDirectory() if not evidence_dir else None
        root=evidence_dir or temporary.name
        try:
            base=f'http://127.0.0.1:{server.server_port}/'
            binary=executable({})
            if not binary: raise RuntimeError('ZAP executable unavailable')
            jobs=[]
            for index in range(job_count):
                url=f'{base}item/{index}?id={index}'
                request={'url':url,'method':'GET','headers':[],'cookies':[],'queryString':[{'name':'id','value':str(index)}],
                         'httpVersion':'HTTP/1.1','headersSize':-1,'bodySize':0}
                response={'status':200,'statusText':'OK','httpVersion':'HTTP/1.1','headers':[],
                          'cookies':[],'content':{'size':2,'mimeType':'text/html','text':'ok'},
                          'redirectURL':'','headersSize':-1,'bodySize':2}
                jobs.append({'request_id':str(index),'auth_context':'anonymous',
                             '_entry':{'startedDateTime':'2026-01-01T00:00:00Z','time':1,
                                       'request':request,'response':response,'cache':{},'timings':{'send':0,'wait':1,'receive':0}}})
            rows=[];findings=[];pool_samples=[];scheduler={};pool=None
            shared={'evidence_dir':root,'zap_executable':binary,'zap_workers':workers,
                    'zap_worker_max_jobs':100,'zap_worker_memory_mb':0}
            if persistent:
                pool=worker_pool(shared);shared['_zap_worker_pool']=pool
            def start(entry,cancelled):
                cfg={**shared,'zap_allowed_rules':[40018],
                     'zap_strength':'Low','zap_phase_minutes':1,'zap_timeout':120,'zap_delay_ms':0,
                     '_zap_seed_entries':[entry['_entry']], '_zap_cancelled':cancelled}
                job_pool=None
                if not persistent:
                    job_pool=worker_pool({**cfg,'zap_workers':1})
                    cfg['_zap_worker_pool']=job_pool
                try:
                    result=yield lambda: run_scan(cfg,entry['_entry']['request']['url'],active=True,
                                                   rule_ids=[40018],timeout=120)
                finally:
                    if job_pool:
                        before=job_pool.snapshot();job_pool.close()
                        pool_samples.append(_pool_totals(before,job_pool.snapshot()))
                _,data=result;perf=data['coverage']['performance'];perf.update(entry.get('_scheduler_performance',{}))
                perf['total_job_ms']+=sum(float(perf.get(key,0)) for key in
                    ('scheduler_wait_ms','scheduler_dispatch_ms','prepare_ms'))
                rows.append(perf)
                for alert in data.get('alerts',[]):
                    parsed=urlsplit(str(alert.get('url','')))
                    findings.append((str(alert.get('rule_id','')),str(alert.get('category','')),
                                     parsed.path+'?'+parsed.query,str(alert.get('method','')),
                                     str(alert.get('parameter','')),str(alert.get('severity',''))))
            began=time.perf_counter()
            cpu_before=resource.getrusage(resource.RUSAGE_CHILDREN)
            try: drive(jobs,start,workers=workers,cookie_mode='guest',metrics=scheduler)
            finally:
                if pool:
                    before=pool.snapshot();pool.close()
                    pool_samples.append(_pool_totals(before,pool.snapshot()))
            elapsed=time.perf_counter()-began
            cpu_after=resource.getrusage(resource.RUSAGE_CHILDREN)
            pool_metrics=_aggregate_pools(pool_samples)
            report=_active_performance(rows,scheduler,len(jobs),len(jobs),workers)
            report['benchmark']={'mode':'persistent' if persistent else 'per_job',
                'total_scan_ms':round(elapsed*1000,3),
                'throughput_jobs_per_second':round(job_count/elapsed,4),
                'child_cpu_seconds':round((cpu_after.ru_utime+cpu_after.ru_stime)-
                                           (cpu_before.ru_utime+cpu_before.ru_stime),4),
                'lifecycle_percent':round(100*(pool_metrics['startup_total_ms']+
                                               pool_metrics['shutdown_total_ms'])/(elapsed*1000),2),
                'finding_count':len(findings),'finding_signature':_finding_signature(findings),
                **pool_metrics}
            report['evidence_dir']=str(root)
            return report
        finally:
            if temporary: temporary.cleanup()
    finally:
        server.shutdown();server.server_close();thread.join()


def compare(job_count=2,workers=2,evidence_dir=''):
    base=Path(evidence_dir) if evidence_dir else None
    previous=run(job_count,workers,str(base/'per-job') if base else '',False)
    current=run(job_count,workers,str(base/'persistent') if base else '',True)
    old=previous['benchmark'];new=current['benchmark']
    return {'previous':previous,'persistent':current,'comparison':{
        'finding_behavior_equal':old['finding_signature']==new['finding_signature'],
        'throughput_gain_percent':round(100*(new['throughput_jobs_per_second']/old['throughput_jobs_per_second']-1),2),
        'wall_time_reduction_percent':round(100*(1-new['total_scan_ms']/old['total_scan_ms']),2),
        'peak_memory_delta_mb':round(new['peak_memory_mb']-old['peak_memory_mb'],3),
        'child_cpu_delta_seconds':round(new['child_cpu_seconds']-old['child_cpu_seconds'],4)}}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--jobs',type=int,default=2)
    parser.add_argument('--workers',type=int,default=2);parser.add_argument('--output')
    parser.add_argument('--evidence-dir',default='');parser.add_argument('--legacy',action='store_true')
    parser.add_argument('--compare',action='store_true')
    args=parser.parse_args()
    report=(compare(max(1,args.jobs),max(1,args.workers),args.evidence_dir) if args.compare else
            run(max(1,args.jobs),max(1,args.workers),args.evidence_dir,not args.legacy))
    text=json.dumps(report,indent=2)
    if args.output: Path(args.output).write_text(text+'\n')
    print(text)
