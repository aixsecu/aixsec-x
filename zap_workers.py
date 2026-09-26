"""Bounded ZAP workers; all journal/evidence mutations stay on the caller thread."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import threading
import time


def batch_jobs(jobs, max_size=1, cookie_mode='strict', policy=None):
    """Coalesce only groups that share an explicit isolation boundary.

    Auto-mode groups without an operator parallel_read rule remain individual so
    their control/observation feedback continues to drive AutoConcurrency.
    """
    from adapters.zap import origin
    max_size = max(1, int(max_size))
    batches = []
    for entry in jobs:
        reasons = scheduling_reasons(entry, cookie_mode, policy)
        rule = policy.match(entry) if policy else None
        safe = not reasons and (cookie_mode != 'auto' or (rule and rule['mode'] == 'parallel_read'))
        key = (origin(entry['_entry']['request']['url']), entry.get('auth_context', 'anonymous'),
               rule['id'] if rule else '', tuple(reasons))
        target = next((batch for batch in reversed(batches)
                       if batch['_batch_key'] == key and batch['_batch_safe'] and safe
                       and len(batch['_batch_members']) < max_size), None)
        if target is None:
            target = dict(entry)
            target['_batch_members'] = [entry]
            target['_batch_key'] = key
            target['_batch_safe'] = safe
            batches.append(target)
        else:
            target['_batch_members'].append(entry)
    return batches


def has_request_body(request):
    """HAR exporters can emit postData metadata for an empty GET body."""
    post = request.get('postData')
    if post is not None and not isinstance(post, dict):
        return True  # malformed/unknown capture: do not assume safe to parallelize
    if isinstance(post, dict):
        # Whitespace, JSON {} and empty-valued form fields are real payloads.
        if post.get('text') not in (None, '') or post.get('params'):
            return True
    size = request.get('bodySize', -1)
    try:
        if float(size) > 0:
            return True
    except (ValueError, TypeError):
        return True
    for header in request.get('headers', []):
        name = header.get('name', '').lower()
        if name == 'content-length':
            try:
                if int(header.get('value', '')) > 0:
                    return True
            except (ValueError, TypeError):
                return True
        if name == 'transfer-encoding' and header.get('value'):
            return True  # streamed/omitted body cannot be established as empty
    return False


def scheduling_reasons(entry, cookie_mode='strict', policy=None):
    """Return all serial constraints; anonymous is a label, not proof of logout."""
    from urllib.parse import urlsplit, parse_qsl
    import re
    if cookie_mode not in ('auto', 'strict', 'guest'):
        raise ValueError('WEBX_ZAP_COOKIE_PARALLEL must be auto, strict or guest')
    request = entry['_entry']['request']
    rule = policy.match(entry) if policy else None
    independent = rule is not None and rule['mode'] == 'parallel_read'
    reasons = ['operator_serial'] if rule is not None and rule['mode'] == 'serial' else []
    if entry.get('auth_context', 'anonymous') != 'anonymous' and not independent and cookie_mode != 'auto':
        reasons.append('authenticated_context')
    if request.get('method', 'GET').upper() not in ('GET', 'HEAD'):
        reasons.append('non_read_method')
    names = {h.get('name', '').lower() for h in request.get('headers', [])}
    if names & {'authorization', 'proxy-authorization', 'x-api-key'} and not independent and cookie_mode != 'auto':
        reasons.append('credential_header')
    if any(re.search(r'csrf|xsrf', name, re.I) for name in names):
        reasons.append('csrf_header')
    query_names = [k for k, _ in parse_qsl(urlsplit(request.get('url', '')).query, keep_blank_values=True)]
    if any(re.search(r'csrf|xsrf|token|session|password|secret|api.?key', name, re.I) for name in query_names):
        reasons.append('sensitive_query')
    # Structured HAR cookies can carry credentials even when headers are omitted.
    has_cookie = 'cookie' in names or bool(request.get('cookies'))
    if has_cookie and cookie_mode == 'strict' and not independent:
        reasons.append('cookie_requires_opt_in')
    if has_request_body(request):
        reasons.append('request_body')
    if cookie_mode == 'auto' and not rule:
        reasons.extend(entry.get('_auto_reasons', ['auto_not_assessed']))
    return reasons


def parallel_safe(entry, cookie_mode='strict', policy=None):
    return not scheduling_reasons(entry, cookie_mode, policy)


def scheduling_summary(jobs, workers=2, cookie_mode='strict', policy=None):
    from collections import Counter
    counts = Counter()
    policy_counts = Counter()
    rows = []
    for entry in jobs:
        reasons = scheduling_reasons(entry, cookie_mode, policy)
        rule = policy.match(entry) if policy else None
        counts.update(reasons)
        if rule:
            policy_counts[rule['id']] += 1
        rows.append({'request_id':entry.get('request_id'),
                     'mode':'serial' if reasons else 'parallel_eligible', 'reasons':reasons,
                     'policy_rule':rule['id'] if rule else None})
    eligible = sum(row['mode'] == 'parallel_eligible' for row in rows)
    return {'workers':workers, 'cookie_mode':cookie_mode, 'total_groups':len(jobs),
            'parallel_eligible':eligible, 'serial_groups':len(jobs)-eligible,
            'serial_reasons':dict(counts), 'policy_matches':dict(policy_counts), 'groups':rows}


def drive(jobs, start, workers=2, cookie_mode='strict', policy=None, auto=None, metrics=None):
    """start returns a generator: yield a callable, receive its result on caller thread."""
    from adapters.zap import origin
    # Classify before dispatch so malformed/ambiguous policy cannot partly run.
    queue = [(entry, origin(entry['_entry']['request']['url']),
              scheduling_reasons(entry, cookie_mode, policy)) for entry in jobs]
    cancelled = threading.Event()
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='zap')
    pending = {}
    enqueued = {id(entry): time.perf_counter_ns() for entry, _, _ in queue}
    waiting = {}
    submitted = {}
    completed_at = {}
    metrics_started = time.perf_counter_ns()
    scheduler_idle_ns = 0
    completed = 0
    stop = False
    stop_reason = ''

    def mark_wait(entry, kind):
        now = time.perf_counter_ns();state = waiting.get(id(entry))
        if state and state[0] == kind:
            return
        if state:
            entry.setdefault('_scheduler_performance', {})[state[0]] = \
                entry.setdefault('_scheduler_performance', {}).get(state[0], 0) + (now-state[1])/1_000_000
        waiting[id(entry)] = (kind, now)

    def finish_wait(entry):
        state = waiting.pop(id(entry), None)
        if state:
            now=time.perf_counter_ns();perf=entry.setdefault('_scheduler_performance', {})
            perf[state[0]]=perf.get(state[0],0)+(now-state[1])/1_000_000

    def collect(block=True):
        nonlocal completed, stop, stop_reason, scheduler_idle_ns
        if not pending:
            return
        wait_started=time.perf_counter_ns()
        done, _ = wait(pending, timeout=30 if block else 0, return_when=FIRST_COMPLETED)
        if block:
            scheduler_idle_ns += time.perf_counter_ns()-wait_started
        if not done and block:
            print(f'[zap] {completed}/{len(jobs)} groups finished; {len(pending)} running', flush=True)
        for future in done:
            generator, _, _ = pending.pop(future)
            completed_at[future] = getattr(future, '_aixsec_finished_ns', time.perf_counter_ns())
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
        while queue and not stop:
            # Collect already finished tasks before reserving additional work.
            collect(block=False)
            if stop:
                break
            if len(pending) >= workers:
                collect()
                continue
            index = None
            waiting_origins = {}
            for i, (entry, target_origin, reasons) in enumerate(queue):
                # Preserve dispatch order within an origin, including barriers.
                if target_origin in waiting_origins:
                    mark_wait(entry, waiting_origins[target_origin])
                    continue
                reasons = scheduling_reasons(entry, cookie_mode, policy)
                width = auto.limit(target_origin, entry) if auto and not (policy and policy.match(entry)) else workers
                serial = bool(reasons) or bool(auto and not (policy and policy.match(entry))
                                               and auto.bootstrap_serial(entry))
                saturated = sum(active_origin == target_origin for _, active_origin, _ in pending.values()) >= width
                conflicts = saturated or any(active_origin == target_origin and (serial or active_serial)
                                for _, active_origin, active_serial in pending.values())
                if conflicts:
                    if any(active_origin == target_origin and active_serial
                           for _, active_origin, active_serial in pending.values()) or serial:
                        kind='serial_barrier_wait_ms'
                    elif auto and auto.data.get('origins',{}).get(target_origin,{}).get('mode')=='bootstrap':
                        kind='bootstrap_wait_ms'
                    elif auto:
                        kind='auto_concurrency_wait_ms'
                    else:
                        kind='origin_saturation_ms'
                    waiting_origins[target_origin]=kind;mark_wait(entry,kind)
                    continue
                index = i
                break
            if index is None:
                collect()
                continue
            entry, target_origin, _ = queue.pop(index)
            finish_wait(entry)
            perf=entry.setdefault('_scheduler_performance', {})
            perf['scheduler_wait_ms']=(time.perf_counter_ns()-enqueued[id(entry)])/1_000_000
            reasons = scheduling_reasons(entry, cookie_mode, policy)
            serial = bool(reasons) or bool(auto and not (policy and policy.match(entry))
                                           and auto.bootstrap_serial(entry))
            if serial:
                print('[zap] serial group (origin): ' + ', '.join(reasons or ['bootstrap_neutral']), flush=True)
            dispatch_started=time.perf_counter_ns();generator = start(entry, cancelled)
            try:
                call = next(generator)
            except StopIteration as finished:
                completed += 1
                if isinstance(finished.value, dict) and finished.value.get('outcome') in ('blocked', 'denied'):
                    stop_reason = str(finished.value.get('output') or finished.value['outcome'])
                    break
                continue
            # Preparation may downgrade a group after fresh controls. Drain that
            # origin before starting its now-serial scan; other origins continue.
            reasons = scheduling_reasons(entry, cookie_mode, policy)
            serial = bool(reasons) or bool(auto and not (policy and policy.match(entry))
                                           and auto.bootstrap_serial(entry))
            if serial:
                while any(active_origin == target_origin for _, active_origin, _ in pending.values()):
                    collect()
            perf['scheduler_dispatch_ms']=(time.perf_counter_ns()-dispatch_started)/1_000_000-float(perf.get('prepare_ms',0))
            future=pool.submit(call);submitted[future]=time.perf_counter_ns()
            future.add_done_callback(lambda value:setattr(value,'_aixsec_finished_ns',time.perf_counter_ns()))
            pending[future] = (generator, target_origin, serial)
        while pending:
            collect()
        if metrics is not None:
            elapsed=max(1,time.perf_counter_ns()-metrics_started)
            busy=sum(max(0,completed_at.get(future,time.perf_counter_ns())-started)
                     for future,started in submitted.items())
            rows=[entry.get('_scheduler_performance',{}) for entry in jobs]
            metrics.update(workers=workers,elapsed_ms=elapsed/1_000_000,
                worker_utilization=min(1.0,busy/(elapsed*max(1,workers))),
                scheduler_idle_ms=scheduler_idle_ns/1_000_000,
                scheduler_wait_ms=sum(float(row.get('scheduler_wait_ms',0)) for row in rows),
                scheduler_dispatch_ms=sum(float(row.get('scheduler_dispatch_ms',0)) for row in rows),
                serial_barrier_wait_ms=sum(float(row.get('serial_barrier_wait_ms',0)) for row in rows),
                bootstrap_wait_ms=sum(float(row.get('bootstrap_wait_ms',0)) for row in rows),
                auto_concurrency_wait_ms=sum(float(row.get('auto_concurrency_wait_ms',0)) for row in rows),
                origin_saturation_ms=sum(float(row.get('origin_saturation_ms',0)) for row in rows))
        return stop_reason
    finally:
        cancelled.set()
        for future in pending:
            future.cancel()
        pool.shutdown(wait=True, cancel_futures=True)
