#!/usr/bin/env python3
"""Local-only Active Scan timing benchmark using the production adapter/scheduler."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import time

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
            rows=[];scheduler={};pool=None
            shared={'evidence_dir':root,'zap_executable':binary,'zap_workers':workers,
                    'zap_worker_max_jobs':100,'zap_worker_memory_mb':0}
            if persistent:
                pool=worker_pool(shared);shared['_zap_worker_pool']=pool
            def start(entry,cancelled):
                cfg={**shared,'zap_allowed_rules':[40018],
                     'zap_strength':'Low','zap_phase_minutes':1,'zap_timeout':120,'zap_delay_ms':0,
                     '_zap_seed_entries':[entry['_entry']], '_zap_cancelled':cancelled}
                result=yield lambda: run_scan(cfg,entry['_entry']['request']['url'],active=True,
                                               rule_ids=[40018],timeout=120)
                _,data=result;perf=data['coverage']['performance'];perf.update(entry.get('_scheduler_performance',{}))
                perf['total_job_ms']+=sum(float(perf.get(key,0)) for key in
                    ('scheduler_wait_ms','scheduler_dispatch_ms','prepare_ms'))
                rows.append(perf)
            began=time.perf_counter()
            try: drive(jobs,start,workers=workers,cookie_mode='guest',metrics=scheduler)
            finally:
                pool_metrics=pool.snapshot() if pool else {'jvm_created':job_count,'reuse_ratio':0}
                if pool:
                    pool.close()
                    pool_metrics['average_worker_shutdown_ms']=pool.snapshot()['average_worker_shutdown_ms']
            report=_active_performance(rows,scheduler,len(jobs),len(jobs),workers)
            report['benchmark']={'mode':'persistent' if persistent else 'per_job',
                'total_scan_ms':round((time.perf_counter()-began)*1000,3),**pool_metrics}
            report['evidence_dir']=str(root)
            return report
        finally:
            if temporary: temporary.cleanup()
    finally:
        server.shutdown();server.server_close();thread.join()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--jobs',type=int,default=2)
    parser.add_argument('--workers',type=int,default=2);parser.add_argument('--output')
    parser.add_argument('--evidence-dir',default='');parser.add_argument('--legacy',action='store_true')
    args=parser.parse_args();report=run(max(1,args.jobs),max(1,args.workers),args.evidence_dir,not args.legacy)
    text=json.dumps(report,indent=2)
    if args.output: Path(args.output).write_text(text+'\n')
    print(text)
