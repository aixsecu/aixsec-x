"""Deterministic, request-backed active scheduling with a durable per-rule ledger."""
import hashlib
import fnmatch
from contextlib import contextmanager
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit, urlunsplit, parse_qsl, unquote

from zap_discovery import same_origin
from http_engine import EvidenceRedactor

ROUTING_KEYS = {'action', 'act', 'type', 'view', 'route', 'controller', 'task', 'operation', 'op'}
STATIC = re.compile(r'\.(?:css|js|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|mp4|mp3|pdf)$', re.I)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def body_shape(post):
    mime = post.get('mimeType', '').split(';')[0].lower()
    pairs = [(p['name'], p.get('value', '')) for p in post.get('params', []) if p.get('name')]
    text = post.get('text', '')
    if mime == 'application/x-www-form-urlencoded' and not pairs:
        pairs = parse_qsl(text, keep_blank_values=True)
    if 'json' in mime:
        try:
            obj = json.loads(text)
        except (TypeError, ValueError):
            return mime, [('opaque-sha256', digest(text))]
        def walk(value, prefix=''):
            if isinstance(value, dict):
                return [p for k, v in sorted(value.items()) for p in walk(v, prefix + '/' + k)]
            if isinstance(value, list):
                return sorted(set(p for v in value for p in walk(v, prefix + '/*')))
            return [(prefix, str(value) if prefix.rsplit('/', 1)[-1] in ROUTING_KEYS else type(value).__name__)]
        return mime, walk(obj)
    if pairs:
        return mime, sorted((k, str(v) if k.lower() in ROUTING_KEYS else '') for k, v in pairs)
    return mime, [('opaque-sha256', digest(text))] if text else []


def family(request, auth='anonymous'):
    p = urlsplit(request['url'])
    def segment(value):
        decoded = unquote(value)
        if re.fullmatch(r'\d+', decoded):
            return '{integer}'
        if re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', decoded):
            return '{uuid}'
        return value  # Slugs and unknown route names must not be merged blindly.
    path = '/'.join(segment(v) for v in (p.path or '/').split('/'))
    port = p.port or (443 if p.scheme == 'https' else 80)
    query = sorted((k, v if k.lower() in ROUTING_KEYS else '') for k, v in parse_qsl(p.query, keep_blank_values=True))
    mime, body = body_shape(request.get('postData') or {})
    return {'origin': [p.scheme.lower(), p.hostname, port], 'path': path,
            'method': request.get('method', 'GET').upper(), 'query': query,
            'body_type': mime, 'body': body, 'auth_context': auth}


class ScanSchedule:
    def __init__(self, directory, namespace='default', route_groups_file=''):
        root = Path(directory).resolve(); root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = root / 'scan-history.sqlite3'
        self.namespace = namespace
        self.route_groups = []
        if route_groups_file:
            groups = json.loads(Path(route_groups_file).read_text())
            if not isinstance(groups, list):
                raise ValueError('ZAP route groups must be a JSON array')
            for group in groups:
                if (not isinstance(group, dict) or set(group) != {'origin', 'group', 'paths'}
                        or not isinstance(group['group'], str) or not group['group']
                        or not isinstance(group['origin'], str)
                        or urlsplit(group['origin']).scheme not in ('http', 'https')
                        or not urlsplit(group['origin']).hostname
                        or urlsplit(group['origin']).path not in ('', '/')
                        or urlsplit(group['origin']).query or urlsplit(group['origin']).fragment
                        or not isinstance(group['paths'], list) or not group['paths']
                        or any(not isinstance(v, str) or not v.startswith('/') for v in group['paths'])):
                    raise ValueError('Invalid ZAP route group: require origin, group and absolute path globs')
            self.route_groups = groups
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS attempts (namespace TEXT, family TEXT, rule INTEGER, state TEXT, artifact_ref TEXT DEFAULT "", PRIMARY KEY(namespace,family,rule))')
            db.execute('CREATE TABLE IF NOT EXISTS auth_retry_ledger (namespace TEXT, family TEXT, rule INTEGER, generation INTEGER, state TEXT, artifact_ref TEXT DEFAULT "", created_at REAL, PRIMARY KEY(namespace,family,rule,generation,state))')
            db.execute('CREATE TABLE IF NOT EXISTS auth_retry_pairs (namespace TEXT, request_id TEXT, rule INTEGER, auth_context TEXT, generation INTEGER, attempt_id TEXT, state TEXT, artifact_ref TEXT DEFAULT "", created_at REAL, PRIMARY KEY(namespace,request_id,rule,generation,attempt_id,state))')
            if 'artifact_ref' not in {r[1] for r in db.execute('PRAGMA table_info(attempts)')}:
                db.execute('ALTER TABLE attempts ADD COLUMN artifact_ref TEXT DEFAULT ""')
            if 'auth_generation' not in {r[1] for r in db.execute('PRAGMA table_info(attempts)')}:
                db.execute('ALTER TABLE attempts ADD COLUMN auth_generation INTEGER DEFAULT 0')
        self.path.chmod(0o600)
        self.entries = {}
        self.rules = []
        self.skipped_static = 0
        self.report = []
        self.import_errors = []
        self.stop_reason = ''
        self.limit_report = {'configured': 0, 'before': 0, 'after': 0, 'dropped': 0}
        self.deferred = {}

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def collect(self, coverage):
        har = coverage.get('har_path')
        if not har or not Path(har).is_file():
            return 0
        try:
            data = json.loads(Path(har).read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                raise ValueError('HAR root must be an object')
            log = data.get('log')
            entries = log.get('entries') if isinstance(log, dict) else None
            if not isinstance(entries, list):
                raise ValueError('HAR log.entries must be an array')
        except (json.JSONDecodeError, UnicodeDecodeError, OSError, TypeError, ValueError) as exc:
            # ZAP exports are external artifacts and can be truncated or
            # malformed. Preserve the artifact, downgrade coverage, and let
            # discovery/form seeds continue instead of crashing the session.
            reason = f'HAR import failed ({Path(har).name}): {exc}'
            self.import_errors.append(reason)
            self.stop_reason = reason
            coverage['har_import'] = {'status': 'error', 'reason': reason,
                                      'path': str(Path(har))}
            gaps = coverage.setdefault('gaps', [])
            if reason not in gaps:
                gaps.append(reason)
            if coverage.get('status') == 'complete':
                coverage['status'] = 'partial'
            return 0
        auth = coverage.get('auth_context', 'anonymous')
        # Authenticated scans without verified login must not seed active requests.
        if auth != 'anonymous' and coverage.get('auth_state') != 'verified':
            return 0
        collected = 0
        malformed_entries = 0
        for entry in entries:
            if not isinstance(entry, dict):
                malformed_entries += 1
                continue
            req = entry.get('request') or {}
            if not isinstance(req, dict):
                malformed_entries += 1
                continue
            url = req.get('url', '')
            response = entry.get('response') or {}
            if (not isinstance(url, str) or not isinstance(response, dict)
                    or not isinstance(req.get('postData') or {}, dict)):
                malformed_entries += 1
                continue
            if not same_origin(url, coverage.get('target', '')) or not response.get('status'):
                continue
            if STATIC.search(urlsplit(url).path):
                self.skipped_static += 1
                continue
            try:
                shape = family(req, auth)
            except (TypeError, ValueError, AttributeError):
                malformed_entries += 1
                continue
            matches = [g for g in self.route_groups if same_origin(url, g['origin'])
                       and any(fnmatch.fnmatchcase(urlsplit(url).path, pattern) for pattern in g['paths'])]
            if len(matches) > 1:
                raise ValueError('Captured URL matches multiple ZAP route groups')
            if matches:
                shape['path'] = '{operator-route:' + matches[0]['group'] + '}'
                shape['route_policy'] = digest(matches[0])
            fid = digest(shape)
            if fid not in self.entries:
                self.entries[fid] = {'request_id': fid, 'structure': shape,
                    'url': EvidenceRedactor().redact_url(url), 'method': shape['method'],
                    'auth_context': auth, 'equivalent_requests': 0, '_entry': entry}
                collected += 1
            self.entries[fid]['equivalent_requests'] += 1
        coverage['har_import'] = {'status': 'complete', 'entries': len(entries),
                                  'request_families': collected,
                                  'malformed_entries_skipped': malformed_entries}
        if malformed_entries:
            reason = f'HAR import skipped {malformed_entries} malformed entries'
            coverage['har_import']['status'] = 'partial'
            gaps = coverage.setdefault('gaps', [])
            if reason not in gaps:
                gaps.append(reason)
            if coverage.get('status') == 'complete':
                coverage['status'] = 'partial'
        return collected

    def collect_seed(self, template, entry):
        """Admit a generated safe seed before family reduction.

        A seed is import-only and is not evidence of a successful request.
        """
        req = entry['request']
        shape = family(req, template.auth_context)
        fid = digest(shape)
        if fid in self.entries:
            template.state = 'requested'
            template.reason = 'matching captured request exists'
            return self.entries[fid]
        self.entries[fid] = {'request_id': fid, 'structure': shape,
            'url': EvidenceRedactor().redact_url(req['url']), 'method': shape['method'],
            'auth_context': template.auth_context, 'equivalent_requests': 1,
            'seed_source': template.source, 'template_id': template.id,
            'coverage_state': 'seeded', '_entry': entry}
        return self.entries[fid]

    @staticmethod
    def _active_priority(entry):
        """Prefer request shapes with injectable input and dynamic methods."""
        structure = entry.get('structure') or {}
        has_input = bool(structure.get('query') or structure.get('body'))
        method = str(structure.get('method') or 'GET').upper()
        return (not has_input, method in ('GET', 'HEAD'), entry.get('url', ''))

    def limit(self, maximum):
        """Hard-cap structures offered to route grouping and active scanning."""
        maximum = max(1, int(maximum))
        before = len(self.entries)
        selected = sorted(self.entries.items(), key=lambda item: self._active_priority(item[1]))[:maximum]
        self.entries = dict(selected)
        self.limit_report = {'configured': maximum, 'before': before,
                             'after': len(self.entries), 'dropped': max(0, before-len(self.entries))}
        return self.limit_report

    def select(self, args):
        if args.get('request_id'):
            return self.entries.get(args['request_id'])
        # The planner can only select a captured shape. Never synthesize POST data.
        candidates = [e for e in self.entries.values()
                      if e['auth_context'] == args.get('auth_context', 'anonymous')
                      and e['_entry']['request']['url'] == args.get('url')
                      and (not args.get('method') or e['method'] == args['method'].upper())]
        return candidates[0] if len(candidates) == 1 else None

    def remaining(self, fid, rules):
        with self.connection() as db:
            done = {r[0] for r in db.execute('SELECT rule FROM attempts WHERE namespace=? AND family=?', (self.namespace, fid))}
        return sorted(set(rules) - done)

    def claim(self, fid, rules):
        claimed = []
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            for rule in rules:
                cur = db.execute('INSERT OR IGNORE INTO attempts (namespace,family,rule,state) VALUES (?,?,?,?)', (self.namespace, fid, rule, 'reserved'))
                if cur.rowcount:
                    claimed.append(rule)
        return claimed

    def finish(self, fid, rules, result):
        outcome = result.get('outcome')
        coverage=((result.get('data') or {}).get('coverage') or {})
        disposition=coverage.get('auth_disposition','')
        generation=int(coverage.get('auth_generation') or 0)
        auth_context=str(coverage.get('auth_context') or '')
        attempt_id=str(coverage.get('scan_id') or result.get('attempt_id') or '')
        pair_rows=coverage.get('auth_pair_dispositions') if isinstance(
            coverage.get('auth_pair_dispositions'),list) else []
        pair_complete=bool(coverage.get('auth_pair_attribution_complete'))
        pair_map={(str(row.get('request_id')),int(row.get('rule_id'))):row
                  for row in pair_rows if isinstance(row,dict) and row.get('request_id')
                  and str(row.get('rule_id','')).isdigit()}
        observed = {int(rule) for row in ((result.get('data') or {}).get('discovery') or {}).get('endpoints', [])
                    for rule in row.get('tested_rule_ids', []) if str(rule).isdigit()}
        captured = set(((result.get('data') or {}).get('coverage') or {}).get('active_evidence', {}).get('rules_with_evidence', []))
        with self.connection() as db:
            for rule in rules:
                pair=pair_map.get((str(fid),int(rule)))
                pair_disposition=(str(pair.get('auth_disposition') or disposition) if pair else
                                  '' if pair_complete else disposition)
                pair_generation=int((pair or {}).get('auth_generation') or generation)
                if pair_disposition in ('auth_uncertain','deferred_auth_expired'):
                    import time
                    db.execute('INSERT OR REPLACE INTO auth_retry_ledger VALUES (?,?,?,?,?,?,?)',
                        (self.namespace,fid,rule,pair_generation,pair_disposition,coverage.get('report_path',''),time.time()))
                    db.execute('INSERT OR REPLACE INTO auth_retry_pairs VALUES (?,?,?,?,?,?,?,?,?)',
                        (self.namespace,fid,rule,auth_context,pair_generation,attempt_id,
                         pair_disposition,coverage.get('report_path',''),time.time()))
                    db.execute('DELETE FROM attempts WHERE namespace=? AND family=? AND rule=?', (self.namespace,fid,rule))
                    self.defer(fid,[rule],pair_disposition)
                elif outcome in ('denied', 'blocked', 'scope_rejected'):
                    db.execute('DELETE FROM attempts WHERE namespace=? AND family=? AND rule=?', (self.namespace, fid, rule))
                else:
                    self.deferred.get(fid,{}).pop(int(rule),None)
                    state = (outcome if outcome in ('error', 'timeout', 'partial') else
                             'responses_recorded' if rule in observed and rule in captured else
                             'requests_observed' if rule in observed else 'attempted_unverified')
                    artifact = ((result.get('data') or {}).get('coverage') or {}).get('report_path', '')
                    db.execute('UPDATE attempts SET state=?,artifact_ref=?,auth_generation=? WHERE namespace=? AND family=? AND rule=?', (state, artifact, generation, self.namespace, fid, rule))

    def defer(self, fid, rules, reason='session budget'):
        """Record unclaimed work as deferred without poisoning persistent history."""
        bucket = self.deferred.setdefault(fid, {})
        for rule in rules:
            bucket[int(rule)] = reason

    def summary(self, rules):
        rows = []
        with self.connection() as db:
            for fid, entry in self.entries.items():
                states = {r[0]: (r[1], r[2], r[3]) for r in db.execute('SELECT rule,state,artifact_ref,auth_generation FROM attempts WHERE namespace=? AND family=?', (self.namespace, fid))}
                rows.append({k:v for k,v in entry.items() if not k.startswith('_')} | {
                    'rules': [{'id':r,
                               'state':('deferred_auth_expired' if str(self.deferred.get(fid,{}).get(r,'')).startswith(('auth_','deferred_auth')) else 'deferred_by_budget')
                                   if r in self.deferred.get(fid,{}) else states.get(r,('not_run',''))[0],
                               'reason':self.deferred.get(fid,{}).get(r,''),
                               'artifact_ref':states.get(r,('not_run','',0))[1],
                               'auth_generation':states.get(r,('not_run','',0))[2]} for r in rules]})
            retry_rows=[dict(zip(('request_id','rule','auth_context','auth_generation','attempt_id','state','artifact_ref','created_at'),r))
                for r in db.execute('SELECT request_id,rule,auth_context,generation,attempt_id,state,artifact_ref,created_at FROM auth_retry_pairs WHERE namespace=? ORDER BY created_at',(self.namespace,))]
            if not retry_rows:
                retry_rows=[dict(zip(('request_id','rule','auth_generation','state','artifact_ref','created_at'),r))
                    for r in db.execute('SELECT family,rule,generation,state,artifact_ref,created_at FROM auth_retry_ledger WHERE namespace=? ORDER BY created_at',(self.namespace,))]
        return {'namespace': self.namespace, 'history_path': str(self.path), 'families': rows,
                'auth_retry_ledger':retry_rows,
                'rules': self.rules, 'skipped_static_requests': self.skipped_static,
                'import_errors': list(self.import_errors),
                'active_input_limit': self.limit_report,
                'stop_reason': self.stop_reason,
                'interpretation': 'A reserved/attempted rule is never automatically repeated; requests_observed/responses_recorded do not mean the rule completed or the endpoint is safe. Use a new operator-selected namespace for intentional retesting.'}
