"""Merge operation observations without overwriting conflicting declarations."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit
from .parser import canonical, METHODS


def merge_operation(endpoint, operation):
    method = str(operation.get('method', 'UNKNOWN')).upper()
    if method not in METHODS and method != 'UNKNOWN':
        return
    source = str(operation.get('source', 'unknown'))
    metadata = operation.get('metadata', {})
    if not isinstance(metadata, dict):
        return
    confidence = max(0., min(1., float(operation.get('confidence', 0))))
    current = endpoint.api_operations.setdefault(method, {'sources': [], 'confidence': 0., 'observations': []})
    current['sources'] = sorted(set(current['sources']) | {source})
    current['confidence'] = max(current['confidence'], confidence)
    observation = {'source': source, 'state': operation.get('state', 'candidate'),
                   'confidence': confidence, 'evidence': operation.get('evidence', {}), 'metadata': metadata}
    if observation not in current['observations']:
        current['observations'].append(observation)
    endpoint.sources.add(source)
    if method != 'UNKNOWN':
        endpoint.methods.add(method)
    for p in metadata.get('parameters', []):
        if isinstance(p, dict) and isinstance(p.get('name'), str):
            endpoint.params.add(p['name'])
    for requirement in metadata.get('security', []):
        if isinstance(requirement, dict):
            endpoint.auth_hints.update(requirement)


def ingest(inv, name, args, data):
    count = 0
    for op in data.get('operations', []):
        if not isinstance(op, dict):
            continue
        try:
            url = canonical(op.get('url', ''))
        except (ValueError, TypeError):
            continue
        host = inv.ensure_web(url, name)
        from inventory import Endpoint
        service = host.service_for_url(url)
        ep = service.endpoints.setdefault(url, Endpoint(url=url))
        ep.sources.add(name)
        merge_operation(ep, op)
        count += 1
    return count


def ingest_existing(inv, name, data):
    """Add structured provenance from existing adapters, no extra traffic."""
    operations = []
    def add(url, method, source, confidence, state):
        if not url:
            return
        operations.append({'url': url, 'method': method or 'UNKNOWN', 'source': source,
                           'confidence': confidence, 'state': state,
                           'metadata': {'parameters': [{'name': k, 'in': 'query'}
                                       for k, _ in parse_qsl(urlsplit(url).query)]}})
    if name == 'crawler':
        for p in data.get('pages', []):
            if isinstance(p, dict):
                add(p.get('url'), 'GET', 'crawler', 1., 'observed')
        for u in data.get('links', []):
            add(u, 'GET', 'crawler:link', .6, 'candidate')
        for h in data.get('js_hints', []):
            if isinstance(h, dict) and h.get('in_scope'):
                add(h.get('url'), h.get('method'), 'crawler:js', .8, 'candidate')
    elif name in ('http_request', 'http_probe') and data.get('status'):
        add(data.get('final_url') or data.get('url'), data.get('method', 'GET'), 'observed', 1., 'observed')
        if operations:
            operations[-1]['evidence'] = data.get('evidence', {})
            if 'response_schema' in data:
                operations[-1]['metadata']['responseSchema'] = data['response_schema']
    ingest(inv, name, {}, {'operations': operations})
