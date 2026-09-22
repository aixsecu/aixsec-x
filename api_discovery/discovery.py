"""GET-only discovery using the existing stateful HTTP engine."""
from __future__ import annotations

import hashlib
import json
import re
import time
from collections import deque
from urllib.parse import urljoin

import requests
import http_engine as he
from .parser import MAX_BYTES, canonical, origin, import_document, infer_schema

PATHS = ('/swagger.json', '/openapi.json', '/api-docs', '/v2/api-docs',
         '/v3/api-docs', '/swagger/v1/swagger.json', '/swagger/index.html',
         '/swagger-ui', '/swagger-ui.html', '/redoc', '/docs',
         '/openapi.yaml', '/openapi.yml', '/graphql', '/graphql/')


def discover(url, *, max_requests=24, time_budget=90, timeout=15, session=None):
    if not 1 <= max_requests <= 100 or not 0 < time_budget <= 300 or not 0 < timeout <= 60:
        raise ValueError('Invalid discovery request/time limits')
    scope = origin(url)
    session = session or he.session_for(url)
    queue = deque([url] + [urljoin(url, p) for p in PATHS])
    seen = set()
    end = time.monotonic() + time_budget
    out = {'url': canonical(url), 'operations': [], 'documents': [], 'warnings': [], 'requests': []}
    while queue and len(seen) < max_requests and time.monotonic() < end:
        target = queue.popleft()
        try:
            if origin(target) != scope or target in seen:
                continue
        except ValueError:
            continue
        seen.add(target)
        try:
            resp, _ = session.request('GET', target, follow_redirects=False,
                                      timeout=max(.01, min(timeout, end - time.monotonic())), record=False,
                                      max_response_bytes=MAX_BYTES)
        except (requests.RequestException, ValueError):
            out['warnings'].append('Request failed: ' + canonical(target))
            continue
        headers = {k.lower(): v for k, v in resp.headers.items()}
        evidence = {'source_url': canonical(target), 'status': resp.status_code,
                    'sha256': hashlib.sha256(resp.content).hexdigest()}
        out['requests'].append(evidence)
        if resp.status_code in (301, 302, 303, 307, 308):
            dest = urljoin(target, headers.get('location', ''))
            try:
                if origin(dest) == scope:
                    queue.appendleft(dest)
                else:
                    out['warnings'].append('Blocked out-of-origin redirect')
            except ValueError:
                out['warnings'].append('Blocked invalid redirect')
            continue
        if len(resp.content) > MAX_BYTES:
            out['warnings'].append('Skipped response over parser size limit')
            continue
        body = resp.text
        if 200 <= resp.status_code < 300:
            try:
                parsed = import_document(body, target, url)
            except (ValueError, TypeError, AttributeError, RecursionError):
                parsed = None
            if parsed is not None:
                out['operations'].extend(parsed['operations'])
                out['documents'].extend(parsed['documents'])
                out['warnings'].extend(parsed['warnings'])
                continue
            if 'html' in headers.get('content-type', '').lower():
                from crawler import parse_html
                html = parse_html(body, target)
                for hint in html.hints:
                    if hint.in_scope:
                        out['operations'].append({'url': canonical(hint.url),
                            'method': hint.method or 'UNKNOWN', 'source': 'crawler:js',
                            'confidence': .8, 'state': 'candidate', 'evidence': evidence,
                            'metadata': {'kind': hint.kind}})
            # Swagger UI/ReDoc literal config references; never execute JavaScript.
            for ref in re.findall(r'''(?:\burl\s*:|spec-url\s*=)\s*["']([^"']+)["']''', body):
                queue.appendleft(urljoin(target, ref))
            if 'json' in headers.get('content-type', '').lower():
                try:
                    data = json.loads(body)
                    out['operations'].append({'url': canonical(target), 'method': 'GET',
                        'source': 'observed-json', 'confidence': 1.0, 'state': 'observed',
                        'evidence': evidence, 'metadata': {'responseSchema': infer_schema(data)}})
                except (ValueError, RecursionError):
                    pass
        markers = [m for m in ('graphiql', 'apollo', 'graphql yoga', 'hasura') if m in body.lower()]
        graphql_error = ('graphql' in body.lower() and resp.status_code in (200, 400, 405)
                         and any(m in body.lower() for m in ('query', 'operation', 'syntax')))
        if markers or graphql_error:
            out['operations'].append({'url': canonical(target), 'method': 'UNKNOWN',
                'source': 'graphql-hint', 'confidence': .6, 'state': 'candidate',
                'evidence': evidence, 'metadata': {'kind': 'graphql', 'markers': markers}})
    out['truncated'] = bool(queue)
    return out
