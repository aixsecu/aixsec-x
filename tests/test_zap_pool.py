import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
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

    def test_pool_starts_one_worker_and_expands_lazily(self):
        pool,created=self.pool(4);pool.start()
        self.assertEqual(len(created),1)
        first=pool.acquire();second=pool.acquire()
        self.assertEqual(len(created),2)
        first.__exit__(None,None,None);second.__exit__(None,None,None)

    def test_recycles_only_worker_at_job_limit(self):
        pool,created=self.pool(2,zap_worker_max_jobs=1);pool.start()
        with pool.acquire() as worker: worker.jobs+=1
        self.assertTrue(worker.closed);self.assertEqual(len(created),2)
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

    def test_session_binding_returns_workflow_to_same_worker(self):
        pool,_=self.pool(2);pool.start()
        first=pool.acquire(binding='context-a');worker_a=first.__enter__()
        second=pool.acquire(binding='context-b');worker_b=second.__enter__()
        self.assertNotEqual(worker_a.worker_id,worker_b.worker_id)
        first.__exit__(None,None,None);second.__exit__(None,None,None)
        with pool.acquire(binding='context-a') as resumed:
            self.assertEqual(resumed.worker_id,worker_a.worker_id)

    def test_guest_session_slots_bind_to_distinct_workers(self):
        pool,_=self.pool(4);pool.start();barrier=threading.Barrier(4);seen=[]
        def task(slot):
            with pool.acquire(binding=f'guest-origin-slot-{slot}') as worker:
                seen.append((slot,worker.worker_id));barrier.wait(2)
        threads=[threading.Thread(target=task,args=(slot,)) for slot in range(4)]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertEqual(len({worker for _,worker in seen}),4)

    def test_shutdown_closes_every_worker(self):
        pool,created=self.pool(2);pool.start();pool.close()
        self.assertTrue(all(worker.closed for worker in created));self.assertTrue(pool._closed)

    def test_startup_timeout_is_forwarded_and_failed_port_released(self):
        root=tempfile.TemporaryDirectory();self.addCleanup(root.cleanup)
        released=[]
        pool=WorkerPool({'evidence_dir':root.name,'zap_workers':1,
                         'zap_startup_timeout':77},'zap',['zap'],lambda:12345,released.append)
        with patch.object(ZapWorker,'start',side_effect=WorkerError('boom')) as start:
            with self.assertRaises(WorkerError): pool._new_worker(0)
        start.assert_called_once_with(['zap'],77)
        self.assertEqual(released,[12345])


class ZapWorkerTests(unittest.TestCase):
    def test_start_timeout_closes_process_and_disables_updates(self):
        worker=ZapWorker(1,'zap',1234,MagicMock())
        process=MagicMock();process.poll.return_value=None
        with patch('zap_pool.subprocess.Popen',return_value=process) as popen, \
                patch.object(worker,'_api',side_effect=OSError('not ready')), \
                patch('zap_pool.time.monotonic',side_effect=[0,16]), \
                patch.object(worker,'close') as close:
            with self.assertRaisesRegex(WorkerError,'within 15s'):
                worker.start(['zap'],timeout=15)
        close.assert_called_once()
        command=popen.call_args.args[0]
        self.assertIn('autoupdate.checkOnStart=false',command)
        self.assertIn('autoupdate.downloadNewRelease=false',command)
    def test_reset_clears_only_job_state(self):
        worker=ZapWorker(1,'zap',1234,MagicMock())
        worker.process=MagicMock();worker.process.poll.return_value=None;worker.state=WorkerState.HEALTHY
        with patch.object(worker,'_api',side_effect=[{}, {'sites':['https://one.test']},{},{}]) as api: worker.reset()
        self.assertEqual([call.args[2] for call in api.call_args_list],
                         ['deleteAllAlerts','sites','clearActiveSession','deleteSiteNode'])

    def test_reset_fails_closed_when_authentication_state_cannot_be_cleared(self):
        worker=ZapWorker(1,'zap',1234,MagicMock())
        worker.process=MagicMock();worker.process.poll.return_value=None;worker.state=WorkerState.HEALTHY
        unsupported=HTTPError('http://127.0.0.1',404,'unsupported',{},None)
        with patch.object(worker,'_api',side_effect=[{}, {'sites':['https://one.test']},unsupported]):
            with self.assertRaisesRegex(WorkerError,'worker reset failed'):
                worker.reset()

    def test_worker_identity_has_private_resources(self):
        one=ZapWorker(1,'zap',1234,MagicMock());two=ZapWorker(2,'zap',1235,MagicMock())
        self.assertNotEqual(one.port,two.port);self.assertIsNot(one._lock,two._lock)


if __name__=='__main__': unittest.main()
