"""Inventory from captured HTTP traffic; static references never imply execution.

Only names, methods and redacted URLs leave this module. No field values,
credentials or response bodies are copied into the public inventory.
"""
from __future__ import annotations

import base64
import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from http_engine import EvidenceRedactor


def same_origin(url, target):
    def key(value):
        p = urlsplit(value)
        if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
            raise ValueError('invalid origin')
        return p.scheme, p.hostname, p.port or (443 if p.scheme == 'https' else 80)
    try:
        return key(url) == key(target)
    except (ValueError, TypeError):
        return False


def query_names(url):
    return sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


class PageParser(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url = url
        self.base = url
        self.forms = []
        self.inputs = []
        self.scripts = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'base' and a.get('href'):
            self.base = urljoin(self.url, a['href'])
        if tag == 'script' and a.get('src'):
            self.scripts.append(urljoin(self.base, a['src']))
        if tag == 'form':
            self.current = {'action': urljoin(self.base, a.get('action') or self.url),
                            'method': a.get('method', 'GET').upper(),
                            'id': a.get('id', ''), 'parameters': []}
            self.forms.append(self.current)
        if tag in ('input', 'select', 'textarea', 'button'):
            name = a.get('name') or a.get('id')
            if name:
                item = {'name': name, 'type': a.get('type', tag),
                        'form_id': a.get('form', ''), 'in_form': self.current is not None}
                self.inputs.append(item)
                if self.current is not None and a.get('name'):
                    self.current['parameters'].append(a['name'])

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None

    def close(self):
        super().close()
        for item in self.inputs:
            if item['form_id']:
                for form in self.forms:
                    if form['id'] == item['form_id']:
                        form['parameters'].append(item['name'])
                        item['in_form'] = True


def js_references(text):
    """Conservative literal extraction, not a JavaScript evaluator.

    Dynamic expressions stay hints. fetch/options and $.ajax default methods
    are not guessed when options cannot be resolved.
    """
    for m in re.finditer(r'''(?:\$|jQuery)\.(get|post)\(\s*['"]([^'"\n]+)['"]''', text):
        yield m[2], m[1].upper(), []
    for m in re.finditer(r'''\.load\(\s*['"]([^'"\n]+)['"]''', text):
        tail = re.split(r'[\r\n;]', text[m.end():m.end()+500], maxsplit=1)[0]
        params = re.findall(r'''['"]&([\w.-]+)=''', tail)
        yield m[1], 'UNKNOWN', params  # a data argument can turn .load into POST
    for m in re.finditer(r'''fetch\(\s*['"]([^'"\n]+)['"]''', text):
        yield m[1], 'UNKNOWN', []
    for m in re.finditer(r'''\.open\(\s*['"](GET|POST|PUT|PATCH|DELETE)['"]\s*,\s*['"]([^'"\n]+)['"]''', text, re.I):
        yield m[2], m[1].upper(), []
    for m in re.finditer(r'''(?:\$|jQuery)\.ajax\(\s*\{(.{0,4000}?)\}\s*\)''', text, re.S):
        block = m[1]
        url = re.search(r'''\burl\s*:\s*['"]([^'"\n]+)['"]''', block)
        method = re.search(r'''\b(?:type|method)\s*:\s*['"]([A-Za-z]+)['"]''', block)
        data = re.search(r'\bdata\s*:\s*\{([^{}]*)\}', block)
        params = re.findall(r'''(?:^|,)\s*['"]?([\w.-]+)['"]?\s*:''', data[1]) if data else []
        if url:
            yield url[1], method[1].upper() if method else 'UNKNOWN', params


class Discovery:
    def __init__(self, target, auth_context='anonymous', allowed_rules=()):
        self.target, self.auth = target, auth_context
        self.rules = {str(x) for x in allowed_rules}
        self.endpoints, self.forms, self.inputs = {}, [], []
        self._pages = set()
        self.script_pages = {}
        self.request_count = 0
        self.test_request_count = 0

    def add(self, url, method, params, source, *, sent=False, rule=None):
        if not same_origin(url, self.target):
            return
        p = urlsplit(url)
        url = p._replace(fragment='').geturl()
        # Values are intentionally excluded from identity/public inventory.
        names = sorted(set(params) | set(query_names(url)))
        public_url = EvidenceRedactor().redact_url(url)
        endpoint = urlsplit(public_url)._replace(query='').geturl()
        key = (endpoint, method, tuple(names), self.auth)
        row = self.endpoints.setdefault(key, {'url': endpoint, 'method': method,
            'parameters': names, 'auth_context': self.auth, 'sources': [],
            'discovered': True, 'requested': False, 'tested': False,
            'request_count': 0, 'tested_rule_ids': [], 'state': 'discovered'})
        if source not in row['sources']:
            row['sources'].append(source)
        if sent:
            row['requested'] = True
            row['request_count'] += 1
            row['state'] = 'requested'
        if rule and str(rule) in self.rules:
            row['tested'] = True
            if str(rule) not in row['tested_rule_ids']:
                row['tested_rule_ids'].append(str(rule))
        if row['tested']:
            row['state'] = 'tested'

    def page(self, url, text, mime, document_url=None):
        signature = (url, document_url, hashlib.sha256(text.encode()).hexdigest())
        if signature in self._pages:
            return
        self._pages.add(signature)
        redacted = EvidenceRedactor().redact_url(url)
        base = document_url or url
        if 'html' in mime:
            page = PageParser(url)
            page.feed(text)
            page.close()
            base = page.base
            for script in page.scripts:
                self.script_pages.setdefault(script, set()).add(base)
            for form in page.forms:
                if not same_origin(form['action'], self.target):
                    continue
                self.add(form['action'], form['method'], form['parameters'], 'html_form')
                self.forms.append({'page': redacted, 'action': EvidenceRedactor().redact_url(form['action']),
                    'method': form['method'], 'parameters': sorted(set(form['parameters']))})
            self.inputs.extend({'page': redacted, **i} for i in page.inputs)
        if 'html' in mime or 'javascript' in mime:
            for ref, method, params in js_references(text):
                if 'javascript' in mime and not document_url and not ref.startswith(('/', 'http://', 'https://')):
                    continue  # Relative script URLs resolve against a document, not /js/.
                self.add(urljoin(base, ref), method, params, 'javascript_literal')

    def har(self, path):
        raw = json.loads(Path(path).read_text())
        entries = raw.get('log', {}).get('entries')
        if not isinstance(entries, list):
            raise ValueError('HAR missing log.entries')
        pages = []
        for entry in entries:
            request = entry.get('request') or {}
            url = request.get('url', '')
            if not same_origin(url, self.target):
                continue
            response = entry.get('response') or {}
            # A history entry without a response is an attempt, not proof of delivery.
            sent = int(response.get('status') or 0) > 0
            post = request.get('postData') or {}
            params = [p['name'] for p in post.get('params', []) if p.get('name')]
            body = post.get('text', '')
            if 'application/x-www-form-urlencoded' in post.get('mimeType', ''):
                params += [k for k, _ in parse_qsl(body, keep_blank_values=True)]
            if 'json' in post.get('mimeType', ''):
                try:
                    obj = json.loads(body)
                    if isinstance(obj, dict):
                        params += list(obj)
                except (ValueError, TypeError):
                    pass
            headers = {h.get('name', '').lower(): h.get('value', '') for h in request.get('headers', [])}
            rule = headers.get('x-zap-scan-id') if sent else None
            self.add(url, request.get('method', 'UNKNOWN').upper(), params, 'har', sent=sent, rule=rule)
            self.request_count += int(sent)
            self.test_request_count += int(sent and str(rule) in self.rules)
            content = response.get('content') or {}
            text = content.get('text') or ''
            if content.get('encoding') == 'base64':
                try:
                    text = base64.b64decode(text).decode('utf-8', errors='replace')
                except (ValueError, TypeError):
                    text = ''
            pages.append((url, text, content.get('mimeType', '')))
        self.pages(pages)

    def pages(self, pages):
        for url, text, mime in pages:
            if 'html' in mime:
                self.page(url, text, mime)
        for url, text, mime in pages:
            if 'javascript' in mime:
                for document in self.script_pages.get(url) or [None]:
                    self.page(url, text, mime, document)

    def report(self, path):
        """Backwards-compatible offline extraction; alert reports are incomplete."""
        report = json.loads(Path(path).read_text())
        pages = []
        for site in report.get('site', []):
            for alert in site.get('alerts', []):
                for item in alert.get('instances', []):
                    url = item.get('uri', '')
                    if not same_origin(url, self.target):
                        continue
                    self.add(url, item.get('method', 'UNKNOWN'), [], 'alert_report')
                    header = item.get('response-header', '').lower()
                    mime = 'text/html' if 'text/html' in header else 'application/javascript' if 'javascript' in header else ''
                    pages.append((url, item.get('response-body', ''), mime))
        self.pages(pages)

    def active_records(self, path):
        # Observer is executor-owned and restricted to ACTIVE_SCANNER_INITIATOR.
        # Reset the count to this authoritative stream, avoiding HAR duplicates.
        self.test_request_count = 0
        for line in Path(path).read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if not same_origin(row.get('url', ''), self.target):
                continue
            if str(row.get('rule_id')) not in self.rules or int(row.get('status') or 0) <= 0:
                continue
            self.add(row['url'], row['method'], row.get('parameters', []),
                     'active_observer', sent=True, rule=row['rule_id'])
            self.test_request_count += 1

    def result(self):
        rows = list(self.endpoints.values())
        redundant = []
        # Link a static hint to captured traffic only if method and parameter names agree.
        for row in rows:
            if row['requested']:
                continue
            matches = [r for r in rows if r['requested'] and r['url'] == row['url']
                       and (row['method'] == 'UNKNOWN' or r['method'] == row['method'])
                       and set(row['parameters']) <= set(r['parameters'])]
            if matches:
                row['requested'] = True
                row['tested'] = any(r['tested'] for r in matches)
                row['state'] = 'tested' if row['tested'] else 'requested'
                row['tested_rule_ids'] = sorted({i for r in matches for i in r['tested_rule_ids']})
                if not {'har', 'active_observer'} & set(row['sources']):
                    for match in matches:
                        match['sources'] = sorted(set(match['sources']) | set(row['sources']))
                    redundant.append(row)
        rows = [r for r in rows if r not in redundant]
        forms = list({json.dumps(f, sort_keys=True): f for f in self.forms}.values())
        inputs = list({json.dumps(i, sort_keys=True): i for i in self.inputs}.values())
        for form in forms:
            path = urlsplit(form['action'])._replace(query='', fragment='').geturl()
            matches = [r for r in rows if r['url'] == path and r['method'] == form['method']
                       and set(form['parameters']) <= set(r['parameters'])]
            form['requested'] = any(r['requested'] for r in matches)
            form['tested'] = any(r['tested'] for r in matches)
            form['state'] = 'tested' if form['tested'] else 'requested' if form['requested'] else 'discovered'
        return {'endpoints': rows, 'forms': forms, 'inputs': inputs,
                'request_count': self.request_count, 'test_request_count': self.test_request_count,
                'summary': {'endpoints': len(rows), 'forms': len(forms), 'inputs': len(inputs),
                    'discovered_only': sum(not r['requested'] for r in rows),
                    'requested': sum(r['requested'] for r in rows), 'tested': sum(r['tested'] for r in rows)}}
