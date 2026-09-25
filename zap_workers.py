"""Bounded ZAP workers; all journal/evidence mutations stay on the caller thread."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import threading


def scheduling_reasons(entry, cookie_mode='strict'):
    """Return all serial constraints; anonymous is a label, not proof of logout."""
    from urllib.parse import urlsplit, parse_qsl
    import re
    if cookie_mode not in ('strict', 'guest'):
        raise ValueError('WEBX_ZAP_COOKIE_PARALLEL must be strict or guest')
    request = entry['_entry']['request']
    reasons = []
    if entry.get('auth_context', 'anonymous') != 'anonymous':
        reasons.append('authenticated_context')
    if request.get('method', 'GET').upper() not in ('GET', 'HEAD'):
        reasons.append('non_read_method')
    names = {h.get('name', '').lower() for h in request.get('headers', [])}
    if names & {'authorization', 'proxy-authorization', 'x-api-key'}:
        reasons.append('credential_header')
    if any(re.search(r'csrf|xsrf', name, re.I) for name in names):
        reasons.append('csrf_header')
    query_names = [k for k, _ in parse_qsl(urlsplit(request.get('url', '')).query, keep_blank_values=True)]
    if any(re.search(r'csrf|xsrf|token|session|password|secret|api.?key', name, re.I) for name in query_names):
        reasons.append('sensitive_query')
    # Structured HAR cookies can carry credentials even when headers are omitted.
    has_cookie = 'cookie' in names or bool(request.get('cookies'))
    if has_cookie and cookie_mode == 'strict':
        reasons.append('cookie_requires_opt_in')
    if request.get('postData'):
        reasons.append('request_body')
    return reasons


def parallel_safe(entry, cookie_mode='strict'):
    return not scheduling_reasons(entry, cookie_mode)


def scheduling_summary(jobs, workers=2, cookie_mode='strict'):
    from collections import Counter
    counts = Counter()
    rows = []
    for entry in jobs:
        reasons = scheduling_reasons(entry, cookie_mode)
        counts.update(reasons)
        rows.append({'request_id':entry.get('request_id'),
                     'mode':'serial' if reasons else 'parallel_eligible', 'reasons':reasons})
    eligible = sum(row['mode'] == 'parallel_eligible' for row in rows)
    return {'workers':workers, 'cookie_mode':cookie_mode, 'total_groups':len(jobs),
            'parallel_eligible':eligible, 'serial_groups':len(jobs)-eligible,
            'serial_reasons':dict(counts), 'groups':rows}


def drive(jobs, start, workers=2, cookie_mode='strict'):
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
            reasons = scheduling_reasons(entry, cookie_mode)
            safe = not reasons
            if reasons:
                print('[zap] serial group: ' + ', '.join(reasons), flush=True)
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
