"""Single-flight authentication refresh with generation-fenced retry state."""
import json
import os
import threading
import time
from pathlib import Path

UNCERTAIN = {'auth_uncertain', 'deferred_auth_expired'}


class AuthLifecycle:
    def __init__(self, context='anonymous'):
        self.context = context
        self.state = 'anonymous_stateless' if context == 'anonymous' else 'auth_configured'
        self.generation = 0
        self.reason = ''
        self.refreshes = 0
        self.refresh_ledger = {}
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._refreshing_generation = None
        self.events = []
        self.path = None

    def bind(self, path):
        self.path = Path(path)
        if self.path.exists():
            try:
                value = json.loads(self.path.read_text(encoding='utf-8'))
                self.generation = int(value.get('generation', self.generation))
                self.refreshes = int(value.get('refreshes', 0))
                self.events = list(value.get('events') or [])[-1000:]
                self.refresh_ledger = {str(k): dict(v) for k, v in
                                       (value.get('refresh_ledger') or {}).items()
                                       if isinstance(v, dict)}
                for row in self.refresh_ledger.values():
                    if row.get('state') == 'running':
                        row.update(state='interrupted', finished_at=time.time(),
                                   reason='refresh was interrupted before verification')
            except (OSError, ValueError, TypeError):
                pass
        self._save()
        return self

    def _save(self):
        if not self.path:
            return
        temporary = self.path.with_suffix(self.path.suffix + '.tmp')
        temporary.write_text(json.dumps(self.public(), ensure_ascii=False, indent=2) + '\n',
                             encoding='utf-8')
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)
        os.chmod(self.path, 0o600)

    def _event(self, job, state, generation, reason=''):
        self.events.append({'time': time.time(), 'job': str(job or ''), 'state': state,
                            'generation': generation, 'reason': reason})
        self.events = self.events[-1000:]
        self._save()

    @staticmethod
    def _pairs(pairs):
        output = []
        for pair in pairs or []:
            if not isinstance(pair, dict) or not pair.get('request_id'):
                continue
            for rule in pair.get('rule_ids') or [pair.get('rule_id')]:
                if rule is not None:
                    output.append({'request_id': str(pair['request_id']), 'rule_id': int(rule)})
        return output

    @classmethod
    def _tag(cls, result, generation, disposition, pairs=None):
        if not isinstance(result, dict):
            return result
        data = result.setdefault('data', {})
        coverage = data.setdefault('coverage', {}) if isinstance(data, dict) else {}
        if isinstance(coverage, dict):
            coverage['auth_generation'] = generation
            coverage['auth_disposition'] = disposition
            existing = coverage.get('auth_pair_dispositions')
            complete = bool(coverage.get('auth_pair_attribution_complete'))
            if disposition in UNCERTAIN and not (complete and isinstance(existing, list)):
                coverage['auth_pair_dispositions'] = [
                    {**pair, 'auth_generation': generation,
                     'auth_disposition': disposition} for pair in cls._pairs(pairs)]
                coverage['auth_pair_attribution_complete'] = bool(coverage['auth_pair_dispositions'])
            elif disposition not in UNCERTAIN:
                coverage['auth_pair_dispositions'] = [
                    {**pair, 'auth_generation': generation,
                     'auth_disposition': disposition} for pair in cls._pairs(pairs)]
                coverage['auth_pair_attribution_complete'] = bool(coverage['auth_pair_dispositions'])
            if disposition in UNCERTAIN and coverage.get('status') == 'complete':
                coverage['status'] = 'partial'
        for row in data.get('alerts', []) if isinstance(data, dict) else []:
            if isinstance(row, dict):
                row.update(auth_generation=generation, auth_disposition=disposition)
        return result

    def verified(self):
        with self._condition:
            self.state = 'auth_verified'
            self.generation = max(1, self.generation)
            self.reason = 'authentication verified'

    def expired(self, reason='authentication expired or unverified'):
        with self._condition:
            self.state = 'auth_expired'
            self.reason = reason

    def _retry_after_other_refresh(self, operation, expired, safe_retry, job_id, before, pairs):
        if not safe_retry:
            self._event(job_id, 'deferred_auth_expired', before,
                        'generation changed; unsafe request was not replayed')
            return None
        retry = operation()
        with self._condition:
            generation = self.generation
        disposition = 'retry_after_refresh' if not expired(retry) else 'deferred_auth_expired'
        self._event(job_id, disposition, generation,
                    'reused refresh completed by another worker')
        return self._tag(retry, generation, disposition, pairs)

    def run(self, operation, expired, *, safe_retry=True, job_id='', pairs=None):
        """Execute once and coordinate at most one refresh for each generation."""
        with self._condition:
            # Jobs dispatched after refresh begins do not enter the old
            # generation. They wait for the owner to publish success/failure.
            while self._refreshing_generation is not None:
                self._condition.wait()
            before = self.generation
            prior = self.refresh_ledger.get(str(before))
            if prior and prior.get('state') in ('failed', 'interrupted', 'running'):
                self.state = 'auth_blocked'
                self.reason = prior.get('reason') or 'refresh already attempted for this generation'
                deferred = {'name': 'auth_generation_gate', 'outcome': 'partial',
                            'output': self.reason,
                            'data': {'coverage': {'status': 'partial',
                                'auth_context': self.context, 'auth_state': 'unverified'}}}
                self._event(job_id, 'deferred_auth_expired', before, self.reason)
                return self._tag(deferred, before, 'deferred_auth_expired', pairs)
        result = operation()
        failed = bool(expired(result))
        with self._condition:
            changed = self.generation != before
        if changed:
            if not failed:
                self._event(job_id, 'auth_uncertain', before,
                            'generation changed while job was running')
            replay = self._retry_after_other_refresh(
                operation, expired, safe_retry, job_id, before, pairs)
            return replay if replay is not None else self._tag(
                result, before, 'auth_uncertain' if not failed else 'deferred_auth_expired', pairs)
        if not failed:
            self.verified()
            self._event(job_id, 'complete', self.generation)
            return self._tag(result, self.generation, 'complete', pairs)
        self.expired()
        self._event(job_id, 'auth_uncertain', before,
                    'scanner returned unverified/login response')
        if not safe_retry:
            self._event(job_id, 'deferred_auth_expired', before,
                        'unsafe request was not replayed')
            return self._tag(result, before, 'deferred_auth_expired', pairs)
        key = str(before)
        with self._condition:
            while self._refreshing_generation == before:
                self._condition.wait()
            if self.generation != before:
                owner = False
                prior = None
            elif key in self.refresh_ledger:
                owner = False
                prior = dict(self.refresh_ledger[key])
            else:
                owner = True
                prior = None
                self._refreshing_generation = before
                self.state = 'auth_refreshing'
                self.reason = 'refreshing credentials and session'
                self.refresh_ledger[key] = {'state': 'running', 'started_at': time.time(),
                                            'job': str(job_id or '')}
                self._save()
        if not owner:
            with self._condition:
                advanced = self.generation != before
            if advanced:
                replay = self._retry_after_other_refresh(
                    operation, expired, safe_retry, job_id, before, pairs)
                return replay if replay is not None else self._tag(
                    result, before, 'deferred_auth_expired', pairs)
            reason = (prior or {}).get('reason') or 'refresh already attempted for this generation'
            self._event(job_id, 'deferred_auth_expired', before, reason)
            return self._tag(result, before, 'deferred_auth_expired', pairs)
        try:
            retry = operation()
            retry_failed = bool(expired(retry))
            refresh_error = ''
        except BaseException as exc:
            retry_failed = True
            retry = result
            refresh_error = type(exc).__name__
        with self._condition:
            self.refreshes += 1
            if retry_failed:
                self.state = 'auth_blocked'
                self.reason = ('authentication refresh failed: ' + refresh_error
                               if refresh_error else 'authentication refresh did not verify')
                self.refresh_ledger[key].update(state='failed', finished_at=time.time(),
                                                reason=self.reason)
                disposition = 'deferred_auth_expired'
                generation = before
            else:
                self.generation = max(before + 1, 1)
                generation = self.generation
                self.state = 'auth_verified'
                self.reason = 'refresh verified'
                self.refresh_ledger[key].update(state='complete', finished_at=time.time(),
                                                next_generation=generation)
                disposition = 'retry_after_refresh'
            self._refreshing_generation = None
            self._event(job_id, disposition, generation, self.reason)
            self._condition.notify_all()
        return self._tag(retry, generation, disposition, pairs)

    def public(self):
        with self._lock:
            return {'context': self.context, 'state': self.state,
                    'generation': self.generation, 'refreshes': self.refreshes,
                    'reason': self.reason, 'events': list(self.events),
                    'refresh_ledger': dict(self.refresh_ledger)}
