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
               rule['id'] if rule else '', tuple(reasons),
               tuple(entry.get('_applicable_rules') or ()))
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
    from session_classifier import classify_entry
    lane=classify_entry(entry)
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
    if lane == 'csrf':
        reasons.append('csrf_session_binding')
    elif lane == 'unknown' and not independent and cookie_mode != 'guest':
        reasons.append('unknown_cookie_state')
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
        session_lane=entry.get('_session_lane','unclassified')
        if session_lane == 'csrf' or 'csrf_session_binding' in reasons:
            scheduler_lane='csrf_session_bound'
        elif any(reason in reasons for reason in ('non_read_method','request_body','auto_workflow_route',
                                                   'auto_workflow_action','operator_serial')):
            scheduler_lane='serial_stateful'
        elif any(reason in reasons for reason in ('unknown_cookie_state','auto_group_quarantine',
                                                   'control_changed_or_slow','control_session_mutation')):
            scheduler_lane='quarantined'
        elif not reasons:
            try:
                from zap_auto import bootstrap_eligible
                scheduler_lane='bootstrap_safe' if bootstrap_eligible(entry) else 'parallel_read'
            except (KeyError,TypeError,ValueError):
                scheduler_lane='parallel_read'
        else:
            scheduler_lane='serial_guarded'
        counts.update(reasons)
        if rule:
            policy_counts[rule['id']] += 1
        rows.append({'request_id':entry.get('request_id'),
                     'mode':'serial' if reasons else 'parallel_eligible', 'reasons':reasons,
                     'session_lane':session_lane,'scheduler_lane':scheduler_lane,
                     'policy_rule':rule['id'] if rule else None})
    eligible = sum(row['mode'] == 'parallel_eligible' for row in rows)
    lane_counts=Counter(row['session_lane'] for row in rows)
    scheduler_lane_counts=Counter(row['scheduler_lane'] for row in rows)
    return {'workers':workers, 'cookie_mode':cookie_mode, 'total_groups':len(jobs),
            'parallel_eligible':eligible, 'serial_groups':len(jobs)-eligible,
            'serial_reasons':dict(counts), 'session_lanes':dict(lane_counts),
            'scheduler_lanes':dict(scheduler_lane_counts),
            'policy_matches':dict(policy_counts), 'groups':rows}


def drive(jobs, start, workers=2, cookie_mode='strict', policy=None, auto=None, metrics=None,
          deadline=None, reserve_seconds=0, expected_job_seconds=90):
    """start returns a generator: yield a callable, receive its result on caller thread."""
    from adapters.zap import origin
    # Classify before dispatch so malformed/ambiguous policy cannot partly run.
    risk_ordered = sorted(jobs, key=lambda entry: (-int(entry.get('risk_score', 0)),
                                                   entry.get('url', entry.get('request_id', ''))))
    bootstrap_prioritized = []
    if auto:
        # Establish a bounded concurrency capability before expensive serial
        # attack points monopolize an origin. This is scheduling only: the
        # probes are already-approved active jobs and remain fully accounted.
        from collections import Counter
        from adapters.zap import origin as request_origin
        selected=Counter()
        for entry in risk_ordered:
            key=auto.lane_key(request_origin(entry['_entry']['request']['url']),entry)
            if (auto._bootstrap_active(entry) and
                    selected[key] < max(1,int(auto.bootstrap_ceiling))):
                bootstrap_prioritized.append(entry);selected[key]+=1
    prioritized_ids={id(entry) for entry in bootstrap_prioritized}
    ordered=bootstrap_prioritized+[entry for entry in risk_ordered if id(entry) not in prioritized_ids]
    deferred = []
    # A fixed scheduler has a known capacity and can reserve low-risk tail work
    # immediately. Adaptive capacity is deliberately not guessed here: it may
    # promote after bootstrap, so early deferral would discard feasible work.
    if deadline is not None and auto is None:
        available = max(0.0, deadline - time.monotonic() - max(0, reserve_seconds))
        budget_units=available/max(1.0,float(expected_job_seconds));used_units=0.0;capacity=0
        for entry in ordered:
            serial=bool(scheduling_reasons(entry,cookie_mode,policy))
            cost=1.0 if serial else 1.0/max(1,workers)
            if used_units+cost > budget_units:break
            used_units+=cost;capacity+=1
        if capacity < len(ordered):
            deferred.extend(ordered[capacity:]);ordered=ordered[:capacity]
    def execution_lane(entry):
        target=origin(entry['_entry']['request']['url'])
        context=entry.get('auth_context','anonymous')
        return target if context=='anonymous' else target+'|auth='+context
    queue = [(entry, execution_lane(entry),
              scheduling_reasons(entry, cookie_mode, policy)) for entry in ordered]
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
    scheduled_total = len(ordered)
    requests_executed = 0
    job_durations = []
    lane_durations = {'serial':[],'parallel':[]}
    budget_recalculations = 0
    budget_capacity_last = None
    preparing = 0
    # Until the scheduler inspects the first group, only one slot is proven
    # usable. This also avoids claiming configured capacity as effective
    # capacity during the initial progress event.
    effective_limit = 1
    single_worker_since = metrics_started
    peak_effective_limit = 0
    peak_active_workers = 0
    peak_session_slots = 0
    stop = False
    stop_reason = ('Active jobs deferred because the estimated workload exceeds the remaining session budget'
                   if deferred else '')
    limit_note = 'awaiting scheduler decision'

    def eta_text(seconds):
        seconds=max(0,int(seconds))
        if seconds >= 3600:
            hours,remainder=divmod(seconds,3600);minutes,_=divmod(remainder,60)
            return f'~{hours}h{minutes:02d}m'
        minutes,seconds=divmod(seconds,60)
        return f'~{minutes}m{seconds:02d}s'

    def emit_progress():
        nonlocal peak_active_workers, peak_effective_limit, peak_session_slots
        from terminal_output import event
        peak_active_workers=max(peak_active_workers,len(pending))
        peak_effective_limit=max(peak_effective_limit,effective_limit)
        peak_session_slots=max(peak_session_slots,len({(value[1],value[3]) for value in pending.values()}))
        fallback=sum(job_durations)/len(job_durations) if job_durations else float(expected_job_seconds)
        serial_average=(sum(lane_durations['serial'])/len(lane_durations['serial'])
                        if lane_durations['serial'] else fallback)
        parallel_average=(sum(lane_durations['parallel'])/len(lane_durations['parallel'])
                          if lane_durations['parallel'] else fallback)
        queued_serial=sum(bool(scheduling_reasons(entry,cookie_mode,policy)) or
            bool(auto and not (policy and policy.match(entry)) and auto.bootstrap_serial(entry))
            for entry,_,_ in queue)
        queued_parallel=len(queue)-queued_serial
        eta=queued_serial*serial_average+(queued_parallel*parallel_average/max(1,effective_limit))
        eta+=len(pending)*fallback/max(1,effective_limit)
        confidence = 'low' if len(job_durations) < 10 else 'medium' if len(job_durations) < 30 else 'high'
        wait_counts={kind:sum(state[0] == kind for state in waiting.values()) for kind in (
            'serial_barrier_wait_ms','bootstrap_wait_ms','auto_concurrency_wait_ms','origin_saturation_ms')}
        waits=[]
        if queued_serial: waits.append(f'serial-jobs {queued_serial}')
        if wait_counts['serial_barrier_wait_ms']: waits.append(f'behind-serial {wait_counts["serial_barrier_wait_ms"]}')
        if wait_counts['bootstrap_wait_ms']: waits.append(f'bootstrap {wait_counts["bootstrap_wait_ms"]}')
        if wait_counts['auto_concurrency_wait_ms']: waits.append(f'concurrency {wait_counts["auto_concurrency_wait_ms"]}')
        if wait_counts['origin_saturation_ms']: waits.append(f'origin {wait_counts["origin_saturation_ms"]}')
        wait_text=f' | wait {",".join(waits)}' if waits else ''
        constrained_seconds=(time.perf_counter_ns()-single_worker_since)/1_000_000_000 \
            if single_worker_since is not None and workers > 1 and effective_limit == 1 else 0
        constrained_text=(f' | constrained {int(constrained_seconds // 60)}m'
                          if constrained_seconds >= 120 else '')
        event('stage','zap_active',f'{completed}/{scheduled_total} jobs finished',
              f'W {len(pending)}/{effective_limit} effective (configured {workers})' +
              (f' + prep {preparing}' if preparing else '') + wait_text + constrained_text +
              f' | ETA {eta_text(eta)} {confidence} | '
              f'req {requests_executed} | def {len(deferred)}/{len(jobs)} | limit {limit_note}')

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
        nonlocal completed, requests_executed, stop, stop_reason, scheduler_idle_ns
        if not pending:
            return
        wait_started=time.perf_counter_ns()
        done, _ = wait(pending, timeout=30 if block else 0, return_when=FIRST_COMPLETED)
        if block:
            scheduler_idle_ns += time.perf_counter_ns()-wait_started
        if not done and block:
            emit_progress()
            print(f'[zap] {completed}/{scheduled_total} scheduled groups finished; '
                  f'{len(pending)} running; {len(deferred)} deferred', flush=True)
        for future in done:
            generator, _, was_serial, _ = pending.pop(future)
            completed_at[future] = getattr(future, '_aixsec_finished_ns', time.perf_counter_ns())
            duration=max(0.001,(completed_at[future]-submitted[future])/1_000_000_000)
            job_durations.append(duration);lane_durations['serial' if was_serial else 'parallel'].append(duration)
            result = future.result()
            coverage=(result.get('data') or {}).get('coverage') if isinstance(result,dict) else {}
            if isinstance(coverage,dict):
                requests_executed += int(coverage.get('active_test_requests',0) or 0)
            try:
                generator.send(result)
                raise RuntimeError('ZAP task yielded more than once')
            except StopIteration as finished:
                completed += 1
                if isinstance(finished.value, dict) and finished.value.get('outcome') in ('blocked', 'denied'):
                    stop = True
                    stop_reason = str(finished.value.get('output') or finished.value['outcome'])
            emit_progress()
            print(f'[zap] {completed}/{scheduled_total} scheduled groups finished', flush=True)

    try:
        emit_progress()
        while queue and not stop:
            budget_recalculations += int(deadline is not None)
            # Collect already finished tasks before reserving additional work.
            collect(block=False)
            if stop:
                break
            if deadline is not None:
                remaining_time = deadline-time.monotonic()-max(0, reserve_seconds)
                fallback = (sum(job_durations)/len(job_durations) if job_durations
                            else float(expected_job_seconds))
                next_wave=max(1.0,min(
                    sum(lane_durations['serial'])/len(lane_durations['serial']) if lane_durations['serial'] else fallback,
                    sum(lane_durations['parallel'])/len(lane_durations['parallel']) if lane_durations['parallel'] else fallback))
                budget_capacity_last=max(0,int(max(0,remaining_time)/next_wave)*max(1,effective_limit))
                if remaining_time < next_wave:
                    newly_deferred=len(queue)
                    deferred.extend(row[0] for row in queue); queue.clear()
                    scheduled_total=max(completed+len(pending),scheduled_total-newly_deferred)
                    stop_reason = 'Active jobs deferred because the remaining session budget is insufficient'
                    emit_progress()
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
                raw_origin=origin(entry['_entry']['request']['url'])
                width = auto.limit(raw_origin, entry) if auto and not (policy and policy.match(entry)) else workers
                serial = bool(reasons) or bool(auto and not (policy and policy.match(entry))
                                               and auto.bootstrap_serial(entry))
                saturated = sum(active_origin == target_origin for _, active_origin, _, _ in pending.values()) >= width
                raw_lane=target_origin.split('|auth=',1)[0]
                conflicts = saturated or any(
                    (active_origin == target_origin or
                     ((serial or active_serial) and active_origin.split('|auth=',1)[0] == raw_lane))
                    and (serial or active_serial)
                    for _, active_origin, active_serial, _ in pending.values())
                if conflicts:
                    if any(active_origin.split('|auth=',1)[0] == raw_lane and active_serial
                           for _, active_origin, active_serial, _ in pending.values()) or serial:
                        kind='serial_barrier_wait_ms'
                    elif auto and auto.data.get('origins',{}).get(auto.lane_key(raw_origin,entry),{}).get('mode')=='bootstrap':
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
            if deadline is not None:
                candidate=queue[index][0]
                candidate_serial=bool(scheduling_reasons(candidate,cookie_mode,policy)) or bool(
                    auto and not (policy and policy.match(candidate)) and auto.bootstrap_serial(candidate))
                samples=lane_durations['serial' if candidate_serial else 'parallel']
                predicted=(sum(samples)/len(samples) if samples else
                           (sum(job_durations)/len(job_durations) if job_durations else float(expected_job_seconds)))
                remaining_time=deadline-time.monotonic()-max(0,reserve_seconds)
                if remaining_time < max(1.0,predicted):
                    newly_deferred=len(queue)
                    deferred.extend(row[0] for row in queue);queue.clear()
                    scheduled_total=max(completed+len(pending),scheduled_total-newly_deferred)
                    stop_reason='Active jobs deferred because the next scheduler lane exceeds the remaining session budget'
                    emit_progress();break
            entry, target_origin, _ = queue.pop(index)
            raw_origin=origin(entry['_entry']['request']['url'])
            selected_limit = (auto.limit(raw_origin, entry)
                              if auto and not (policy and policy.match(entry)) else workers)
            if auto and not (policy and policy.match(entry)):
                limit_note = auto.limit_status(raw_origin, entry)['reason']
            else:
                limit_note = 'operator policy' if policy and policy.match(entry) else 'configured maximum'
            reasons = scheduling_reasons(entry, cookie_mode, policy)
            serial = bool(reasons) or bool(auto and not (policy and policy.match(entry))
                                           and auto.bootstrap_serial(entry))
            new_effective_limit=1 if serial else max(1,min(workers,selected_limit))
            if new_effective_limit != effective_limit:
                single_worker_since=time.perf_counter_ns() if new_effective_limit == 1 else None
            effective_limit=new_effective_limit
            used_slots={slot for _,active_origin,_,slot in pending.values()
                        if active_origin == target_origin}
            worker_slot=0 if serial else next(
                (slot for slot in range(effective_limit) if slot not in used_slots),0)
            entry['_scheduler_worker_slot']=worker_slot
            preparing=1;emit_progress()
            finish_wait(entry)
            perf=entry.setdefault('_scheduler_performance', {})
            perf['scheduler_wait_ms']=(time.perf_counter_ns()-enqueued[id(entry)])/1_000_000
            if serial:
                print('[zap] serial group (origin): ' + ', '.join(reasons or ['bootstrap_neutral']), flush=True)
            dispatch_started=time.perf_counter_ns();generator = start(entry, cancelled)
            try:
                call = next(generator)
            except StopIteration as finished:
                preparing=0
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
            new_effective_limit=1 if serial else max(1,min(workers,
                auto.limit(raw_origin,entry) if auto and not (policy and policy.match(entry)) else workers))
            if new_effective_limit != effective_limit:
                single_worker_since=time.perf_counter_ns() if new_effective_limit == 1 else None
            effective_limit=new_effective_limit
            if auto and not (policy and policy.match(entry)):
                limit_note=auto.limit_status(raw_origin,entry)['reason']
            if serial:
                while any(active_origin == target_origin for _, active_origin, _, _ in pending.values()):
                    collect()
            perf['scheduler_dispatch_ms']=(time.perf_counter_ns()-dispatch_started)/1_000_000-float(perf.get('prepare_ms',0))
            future=pool.submit(call);submitted[future]=time.perf_counter_ns()
            future.add_done_callback(lambda value:setattr(value,'_aixsec_finished_ns',time.perf_counter_ns()))
            pending[future] = (generator, target_origin, serial, worker_slot)
            preparing=0
            emit_progress()
        while pending:
            collect()
        if metrics is not None:
            elapsed=max(1,time.perf_counter_ns()-metrics_started)
            busy=sum(max(0,completed_at.get(future,time.perf_counter_ns())-started)
                     for future,started in submitted.items())
            rows=[entry.get('_scheduler_performance',{}) for entry in jobs]
            metrics.update(workers=workers,configured_workers=workers,
                effective_limit_last=effective_limit,
                peak_effective_limit=peak_effective_limit,
                peak_active_workers=peak_active_workers,
                peak_session_slots=peak_session_slots,
                bootstrap_prioritized_jobs=len(bootstrap_prioritized),
                limit_reason_last=limit_note,
                constrained_single_worker_seconds=(max(0,(time.perf_counter_ns()-single_worker_since)/1_000_000_000)
                    if single_worker_since is not None and workers > 1 else 0),
                elapsed_ms=elapsed/1_000_000,
                worker_utilization=min(1.0,busy/(elapsed*max(1,workers))),
                average_active_workers=busy/elapsed,
                scheduler_idle_ms=scheduler_idle_ns/1_000_000,
                scheduler_wait_ms=sum(float(row.get('scheduler_wait_ms',0)) for row in rows),
                scheduler_dispatch_ms=sum(float(row.get('scheduler_dispatch_ms',0)) for row in rows),
                serial_barrier_wait_ms=sum(float(row.get('serial_barrier_wait_ms',0)) for row in rows),
                bootstrap_wait_ms=sum(float(row.get('bootstrap_wait_ms',0)) for row in rows),
                auto_concurrency_wait_ms=sum(float(row.get('auto_concurrency_wait_ms',0)) for row in rows),
                origin_saturation_ms=sum(float(row.get('origin_saturation_ms',0)) for row in rows),
                completed_jobs=completed, deferred_jobs=len(deferred),
                scheduled_jobs=scheduled_total, planned_jobs=len(jobs),
                requests_executed=requests_executed,
                budget_recalculations=budget_recalculations,
                budget_capacity_last=budget_capacity_last,
                deferred_reason_counts=({'insufficient_remaining_time':len(deferred)} if deferred else {}),
                lane_average_seconds={key:(sum(values)/len(values) if values else 0)
                                      for key,values in lane_durations.items()},
                deferred_request_ids=sorted({member.get('request_id') for entry in deferred
                    for member in (entry.get('_batch_members') or [entry]) if member.get('request_id')}),
                average_job_seconds=(sum(job_durations)/len(job_durations) if job_durations else 0),
                estimated_remaining_seconds=int(len(deferred) * (sum(job_durations)/len(job_durations)
                    if job_durations else float(expected_job_seconds)) / max(1, effective_limit)))
        return stop_reason
    finally:
        cancelled.set()
        for future in pending:
            future.cancel()
        pool.shutdown(wait=True, cancel_futures=True)
