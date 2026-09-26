"""Bounded ZAP workers; all journal/evidence mutations stay on the caller thread."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import threading


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


def drive(jobs, start, workers=2, cookie_mode='strict', policy=None, auto=None):
    """start returns a generator: yield a callable, receive its result on caller thread."""
    from adapters.zap import origin
    # Classify before dispatch so malformed/ambiguous policy cannot partly run.
    queue = [(entry, origin(entry['_entry']['request']['url']),
              scheduling_reasons(entry, cookie_mode, policy)) for entry in jobs]
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
            generator, _, _ = pending.pop(future)
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
            waiting_origins = set()
            for i, (entry, target_origin, reasons) in enumerate(queue):
                # Preserve dispatch order within an origin, including barriers.
                if target_origin in waiting_origins:
                    continue
                reasons = scheduling_reasons(entry, cookie_mode, policy)
                width = auto.limit(target_origin) if auto and not (policy and policy.match(entry)) else workers
                saturated = sum(active_origin == target_origin for _, active_origin, _ in pending.values()) >= width
                conflicts = saturated or any(active_origin == target_origin and (reasons or active_serial)
                                for _, active_origin, active_serial in pending.values())
                if conflicts:
                    waiting_origins.add(target_origin)
                    continue
                index = i
                break
            if index is None:
                collect()
                continue
            entry, target_origin, _ = queue.pop(index)
            reasons = scheduling_reasons(entry, cookie_mode, policy)
            if reasons:
                print('[zap] serial group (origin): ' + ', '.join(reasons), flush=True)
            generator = start(entry, cancelled)
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
            if reasons:
                while any(active_origin == target_origin for _, active_origin, _ in pending.values()):
                    collect()
            pending[pool.submit(call)] = (generator, target_origin, bool(reasons))
        while pending:
            collect()
        return stop_reason
    finally:
        cancelled.set()
        for future in pending:
            future.cancel()
        pool.shutdown(wait=True, cancel_futures=True)
