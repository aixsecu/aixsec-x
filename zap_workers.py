"""Bounded ZAP workers; all journal/evidence mutations stay on the caller thread."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import threading


def parallel_safe(entry):
    request = entry['_entry']['request']
    # Shared login state and state-changing workflows must not race.
    return (entry.get('auth_context', 'anonymous') == 'anonymous'
            and request.get('method', 'GET').upper() in ('GET', 'HEAD')
            and not any(h.get('name', '').lower() in ('cookie', 'authorization', 'x-api-key', 'x-csrf-token', 'x-xsrf-token')
                        for h in request.get('headers', [])))


def drive(jobs, start, workers=2):
    """start returns a generator: yield a callable, receive its result on caller thread."""
    cancelled = threading.Event()
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='zap')
    pending = {}
    completed = 0
    stop = False
    stop_reason = ''

    def collect(block=True):
        nonlocal completed, stop, stop_reason
        if not pending:
            return
        done, _ = wait(pending, timeout=30 if block else 0, return_when=FIRST_COMPLETED)
        if not done and block:
            print(f'[zap] {completed}/{len(jobs)} groups finished; {len(pending)} running', flush=True)
        for future in done:
            generator = pending.pop(future)
            result = future.result()
            try:
                generator.send(result)
                raise RuntimeError('ZAP task yielded more than once')
            except StopIteration as finished:
                completed += 1
                if isinstance(finished.value, dict) and finished.value.get('outcome') in ('blocked', 'denied'):
                    stop = True
                    stop_reason = str(finished.value.get('output') or finished.value['outcome'])
            print(f'[zap] {completed}/{len(jobs)} groups finished', flush=True)

    try:
        for entry in jobs:
            safe = parallel_safe(entry)
            while pending and (len(pending) >= workers or not safe):
                collect()
            if stop:
                break
            generator = start(entry, cancelled)
            try:
                call = next(generator)
            except StopIteration as finished:
                completed += 1
                if isinstance(finished.value, dict) and finished.value.get('outcome') in ('blocked', 'denied'):
                    stop_reason = str(finished.value.get('output') or finished.value['outcome'])
                    break
                continue
            pending[pool.submit(call)] = generator
            if not safe:
                while pending:
                    collect()
        while pending:
            collect()
        return stop_reason
    finally:
        cancelled.set()
        for future in pending:
            future.cancel()
        pool.shutdown(wait=True, cancel_futures=True)
