"""Deterministic, request-backed active scheduling with a durable per-rule ledger."""
import hashlib
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
    def __init__(self, directory, namespace='default'):
        root = Path(directory).resolve(); root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = root / 'scan-history.sqlite3'
        self.namespace = namespace
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS attempts (namespace TEXT, family TEXT, rule INTEGER, state TEXT, artifact_ref TEXT DEFAULT "", PRIMARY KEY(namespace,family,rule))')
            if 'artifact_ref' not in {r[1] for r in db.execute('PRAGMA table_info(attempts)')}:
                db.execute('ALTER TABLE attempts ADD COLUMN artifact_ref TEXT DEFAULT ""')
        self.path.chmod(0o600)
        self.entries = {}
        self.rules = []
        self.skipped_static = 0
        self.report = []
        self.stop_reason = ''

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
            return
        data = json.loads(Path(har).read_text())
        auth = coverage.get('auth_context', 'anonymous')
        # Authenticated scans without verified login must not seed active requests.
        if auth != 'anonymous' and coverage.get('auth_state') != 'verified':
            return
        for entry in data.get('log', {}).get('entries', []):
            req = entry.get('request') or {}
            url = req.get('url', '')
            if not same_origin(url, coverage.get('target', '')) or not (entry.get('response') or {}).get('status'):
                continue
            if STATIC.search(urlsplit(url).path):
                self.skipped_static += 1
                continue
            shape = family(req, auth)
            fid = digest(shape)
            if fid not in self.entries:
                self.entries[fid] = {'request_id': fid, 'structure': shape,
                    'url': EvidenceRedactor().redact_url(url), 'method': shape['method'],
                    'auth_context': auth, 'equivalent_requests': 0, '_entry': entry}
            self.entries[fid]['equivalent_requests'] += 1

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
        observed = {int(rule) for row in ((result.get('data') or {}).get('discovery') or {}).get('endpoints', [])
                    for rule in row.get('tested_rule_ids', []) if str(rule).isdigit()}
        captured = set(((result.get('data') or {}).get('coverage') or {}).get('active_evidence', {}).get('rules_with_evidence', []))
        with self.connection() as db:
            for rule in rules:
                if outcome in ('denied', 'blocked', 'scope_rejected'):
                    db.execute('DELETE FROM attempts WHERE namespace=? AND family=? AND rule=?', (self.namespace, fid, rule))
                else:
                    state = ('responses_recorded' if rule in observed and rule in captured else
                             'requests_observed' if rule in observed else 'attempted_unverified')
                    artifact = ((result.get('data') or {}).get('coverage') or {}).get('report_path', '')
                    db.execute('UPDATE attempts SET state=?,artifact_ref=? WHERE namespace=? AND family=? AND rule=?', (state, artifact, self.namespace, fid, rule))

    def summary(self, rules):
        rows = []
        with self.connection() as db:
            for fid, entry in self.entries.items():
                states = {r[0]: (r[1], r[2]) for r in db.execute('SELECT rule,state,artifact_ref FROM attempts WHERE namespace=? AND family=?', (self.namespace, fid))}
                rows.append({k:v for k,v in entry.items() if not k.startswith('_')} | {
                    'rules': [{'id':r, 'state':states.get(r,('not_run',''))[0],
                               'artifact_ref':states.get(r,('not_run',''))[1]} for r in rules]})
        return {'namespace': self.namespace, 'history_path': str(self.path), 'families': rows,
                'rules': self.rules, 'skipped_static_requests': self.skipped_static,
                'stop_reason': self.stop_reason,
                'interpretation': 'A reserved/attempted rule is never automatically repeated; requests_observed/responses_recorded do not mean the rule completed or the endpoint is safe. Use a new operator-selected namespace for intentional retesting.'}
