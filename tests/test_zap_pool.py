import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from zap_pool import WorkerError, WorkerPool, WorkerState, ZapWorker


class FakeWorker:
    def __init__(self,index):
        self.worker_id=index;self.jobs=0;self.state=WorkerState.HEALTHY
        self.started_ms=time.perf_counter_ns()/1_000_000;self.startup_ms=5;self.port=10000+index
        self.shutdown_ms=0;self.closed=False;self.fail=False;self.max_jobs=100
    def healthy(self): return not self.closed and not self.fail
    def needs_recycle(self): return self.jobs>=self.max_jobs
    def memory_mb(self): return 10
    def cpu_percent(self): return 1
    def close(self): self.closed=True;self.state=WorkerState.DEAD
    def run_plan(self,*args,**kwargs):
        if self.fail: raise WorkerError('crash')
        self.jobs+=1;return {'returncode':0,'job_ms':1}


class WorkerPoolTests(unittest.TestCase):
    def pool(self,size=2,**updates):
        root=tempfile.TemporaryDirectory();self.addCleanup(root.cleanup)
        config={'evidence_dir':root.name,'zap_workers':size,'zap_worker_max_jobs':100,
                'zap_worker_memory_mb':0,**updates}
        pool=WorkerPool(config,'zap',['zap'],lambda:12345)
        created=[]
        def create(index):
            worker=FakeWorker(index);worker.max_jobs=pool.max_jobs;created.append(worker);return worker
        pool._new_worker=create
        self.addCleanup(pool.close)
        return pool,created

    def test_lifecycle_acquire_release_and_reuse(self):
        pool,created=self.pool(1);pool.start()
        with pool.acquire() as first: first.jobs+=1
        with pool.acquire() as second: second.jobs+=1
        self.assertIs(first,second);self.assertEqual(len(created),1)
        self.assertEqual(pool.snapshot()['reuse_ratio'],.5)

    def test_recycles_only_worker_at_job_limit(self):
        pool,created=self.pool(2,zap_worker_max_jobs=1);pool.start()
        with pool.acquire() as worker: worker.jobs+=1
        self.assertTrue(worker.closed);self.assertEqual(len(created),3)
        self.assertEqual(pool.metrics['recycled'],1)
        self.assertFalse(created[1].closed)

    def test_crash_recovery_replaces_worker(self):
        pool,created=self.pool(1);pool.start()
        lease=pool.acquire();worker=lease.__enter__();worker.fail=True
        lease.__exit__(WorkerError,WorkerError('boom'),None)
        self.assertTrue(worker.closed);self.assertEqual(pool.metrics['crashes'],1)
        with pool.acquire() as replacement: self.assertIsNot(worker,replacement)

    def test_pool_exhaustion_and_release(self):
        pool,_=self.pool(1);pool.start();lease=pool.acquire()
        with self.assertRaises(TimeoutError): pool.acquire(timeout=.01)
        lease.__exit__(None,None,None)
        with pool.acquire(timeout=.01): pass

    def test_parallel_workers_are_isolated(self):
        pool,_=self.pool(2);pool.start();barrier=threading.Barrier(2);seen=[]
        def task():
            with pool.acquire() as worker:
                seen.append((worker.worker_id,worker.port,id(worker)))
                barrier.wait(timeout=1)
        threads=[threading.Thread(target=task) for _ in range(2)]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertEqual(len({row[0] for row in seen}),2)
        self.assertEqual(len({row[2] for row in seen}),2)

    def test_shutdown_closes_every_worker(self):
        pool,created=self.pool(2);pool.start();pool.close()
        self.assertTrue(all(worker.closed for worker in created));self.assertTrue(pool._closed)


class ZapWorkerTests(unittest.TestCase):
    def test_reset_clears_only_job_state(self):
        worker=ZapWorker(1,'zap',1234,MagicMock())
        worker.process=MagicMock();worker.process.poll.return_value=None;worker.state=WorkerState.HEALTHY
        with patch.object(worker,'_api',side_effect=[{}, {'sites':['https://one.test']},{},{}]) as api: worker.reset()
        self.assertEqual([call.args[2] for call in api.call_args_list],
                         ['deleteAllAlerts','sites','clearActiveSession','deleteSiteNode'])

    def test_worker_identity_has_private_resources(self):
        one=ZapWorker(1,'zap',1234,MagicMock());two=ZapWorker(2,'zap',1235,MagicMock())
        self.assertNotEqual(one.port,two.port);self.assertIsNot(one._lock,two._lock)


if __name__=='__main__': unittest.main()
