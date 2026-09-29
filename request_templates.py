"""Unified discovered-input inventory and safe request seed generation.

The inventory is intentionally value-free. Only read-like GET templates are
seeded automatically; write requests require captured traffic or a later
operator-owned side-effect policy.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import base64
from html.parser import HTMLParser
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from zap_discovery import same_origin

SENSITIVE = re.compile(r'csrf|xsrf|token|session|password|passwd|secret|api.?key|otp|captcha', re.I)
CSRF = re.compile(r'csrf|xsrf|nonce|request.?verification.?token', re.I)
CREDENTIAL = re.compile(r'password|passwd|secret|api.?key|otp|captcha|session', re.I)
SEARCH_INPUT = re.compile(r'(^|[_-])(q|query|search|keyword|key|term|filter|sort|page|category|product_code)($|[_-])|timkiem|txt.?key', re.I)
DESTRUCTIVE = re.compile(r'(^|[_-])(delete|remove|destroy|payment|checkout|purchase|order|transfer|withdraw|reset|change_password)($|[_-])', re.I)


def _id(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@dataclass
class RequestTemplate:
    id: str
    source: str
    page_url: str
    request_url: str
    method: str
    parameters: list[str]
    parameter_location: str
    body_type: str = ''
    auth_context: str = 'anonymous'
    request_template: str = ''
    template_parameter: str = ''
    side_effect_class: str = 'unknown'
    state: str = 'discovered'
    reason: str = ''
    sensitive_parameters: list[str] = field(default_factory=list)
    field_defaults: dict[str, str] = field(default_factory=dict, repr=False)
    private_headers: list[dict] = field(default_factory=list, repr=False)

    def to_dict(self):
        value=asdict(self)
        value.pop('field_defaults',None);value.pop('private_headers',None)
        return value

    def seed_entry(self, allow_safe_post=False):
        """Return a harmless HAR-shaped read/safe-search seed when allowed."""
        if self.method not in ('GET', 'POST'):
            self.state, self.reason = 'skipped_by_policy', 'uncaptured write request'
            return None
        safe = [name for name in self.parameters if not SENSITIVE.search(name)]
        self.sensitive_parameters = sorted(set(self.parameters) - set(safe))
        unavailable=[name for name in self.sensitive_parameters
                     if CREDENTIAL.search(name) or not self.field_defaults.get(name)]
        if self.method == 'POST' and unavailable:
            self.state, self.reason = 'blocked_by_csrf', 'dynamic or sensitive field requires a fresh captured request'
            return None
        if not safe:
            self.state, self.reason = 'skipped_by_policy', 'only sensitive parameters'
            return None
        if self.method == 'POST' and (not allow_safe_post or self.side_effect_class != 'likely_safe_write'):
            self.state, self.reason = 'skipped_by_policy', 'uncaptured write request'
            return None
        parsed = urlsplit(self.request_url)
        existing = parse_qsl(parsed.query, keep_blank_values=True)
        query = list(existing)
        body = [(name, self.field_defaults.get(name, 'aixsec-test')) for name in safe]
        if self.method == 'POST':
            body.extend((name,self.field_defaults[name]) for name in self.sensitive_parameters
                        if CSRF.search(name) and self.field_defaults.get(name))
        if self.method == 'GET':
            supplied = set(safe)
            query = [(key, value) for key, value in existing if key not in supplied]
            query.extend(body)
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ''))
        self.state, self.reason = 'seeded', ''
        headers = list(self.private_headers)
        if self.method == 'POST' and not any(h.get('name','').lower()=='content-type' for h in headers):
            headers.append({'name': 'Content-Type', 'value': 'application/x-www-form-urlencoded'})
        post = ({} if self.method == 'GET' else
                {'mimeType': 'application/x-www-form-urlencoded', 'text': urlencode(body),
                 'params': [{'name': key, 'value': value} for key, value in body]})
        return {'request': {'url': url, 'method': self.method, 'headers': headers,
                            'queryString': [{'name': k, 'value': v} for k, v in query],
                            'postData': post},
                # Import-only synthetic response. It is never counted as proof
                # that the target responded; the active observer owns that fact.
                'response': {'status': 200, 'statusText': 'Synthetic seed',
                             'headers': [], 'content': {'mimeType': 'text/plain', 'text': ''}},
                '_aixsec_seed': True, '_aixsec_template_id': self.id}


def build_templates(target, discovery, auth_context='anonymous'):
    """Build deterministic input-level templates from ZAP discovery output."""
    rows = []
    seen = set()

    def add(source, page, url, method, parameters, **extra):
        method = str(method or 'UNKNOWN').upper()
        parameters = sorted({str(v) for v in parameters or [] if str(v)})
        if not parameters or not same_origin(url, target):
            return
        location = 'query' if method == 'GET' else 'body'
        identity = {'url': urlsplit(url)._replace(query='', fragment='').geturl(),
                    'method': method, 'parameters': parameters,
                    'location': location, 'auth_context': auth_context}
        tid = _id(identity)
        if tid in seen:
            return
        seen.add(tid)
        if method in ('GET', 'HEAD'):
            side_effect = 'read_only'
        elif any(DESTRUCTIVE.search(name) for name in parameters):
            side_effect = 'destructive'
        elif method == 'POST' and any(SEARCH_INPUT.search(name) for name in parameters):
            side_effect = 'likely_safe_write'
        else:
            side_effect = 'state_creating' if method in ('POST', 'PUT', 'PATCH') else 'unknown'
        rows.append(RequestTemplate(tid, source, page or '', identity['url'], method,
                    parameters, location, auth_context=auth_context,
                    request_template=str(extra.get('request_template') or ''),
                    template_parameter=str(extra.get('template_parameter') or ''),
                    side_effect_class=side_effect,
                    state=str(extra.get('state') or 'discovered')))

    for endpoint in discovery.get('endpoints') or []:
        sources = endpoint.get('sources') or ['endpoint']
        add(','.join(sorted(sources)), '', str(endpoint.get('url') or ''),
            endpoint.get('method'), endpoint.get('parameters'),
            request_template=endpoint.get('request_template'),
            template_parameter=endpoint.get('template_parameter'), state=endpoint.get('state'))
    for form in discovery.get('forms') or []:
        add('html_form', str(form.get('page') or ''), str(form.get('action') or ''),
            form.get('method'), form.get('parameters'), state=form.get('state'))
    return rows


class _PrivateFormParser(HTMLParser):
    def __init__(self,page):
        super().__init__(convert_charrefs=True);self.page=page;self.forms=[];self.current=None
    def handle_starttag(self,tag,attrs):
        from urllib.parse import urljoin
        data=dict(attrs)
        if tag=='form':
            self.current={'action':urljoin(self.page,data.get('action') or self.page),
                          'method':data.get('method','GET').upper(),'values':{}}
            self.forms.append(self.current)
        elif tag in ('input','button','textarea','select') and self.current is not None and data.get('name'):
            self.current['values'][data['name']]=data.get('value','')
    def handle_endtag(self,tag):
        if tag=='form':self.current=None


def hydrate_from_har(templates, har_path):
    """Hydrate private token defaults/cookies without placing values in reports."""
    from pathlib import Path
    path=Path(str(har_path or ''))
    if not path.is_file(): return templates
    try: entries=json.loads(path.read_text()).get('log',{}).get('entries',[])
    except (ValueError,OSError,TypeError): return templates
    forms=[]
    for entry in entries:
        request=entry.get('request') or {};response=entry.get('response') or {}
        content=response.get('content') or {};mime=str(content.get('mimeType') or '')
        if 'html' not in mime: continue
        text=content.get('text') or ''
        if content.get('encoding')=='base64':
            try:text=base64.b64decode(text).decode('utf-8',errors='replace')
            except (ValueError,TypeError):continue
        parser=_PrivateFormParser(str(request.get('url') or ''));parser.feed(text);parser.close()
        headers=[{'name':h.get('name',''),'value':h.get('value','')} for h in request.get('headers',[])
                 if str(h.get('name','')).lower() in ('cookie','authorization')]
        forms.extend((form,headers) for form in parser.forms)
    for template in templates:
        for form,headers in forms:
            if template.method==form['method'] and template.request_url==urlsplit(form['action'])._replace(query='',fragment='').geturl():
                template.field_defaults={name:value for name,value in form['values'].items()
                                         if name in template.parameters and value}
                template.private_headers=headers
                break
    return templates


def coverage_report(templates):
    counts = {}
    inputs = []
    for template in templates:
        for parameter in template.parameters:
            sensitive = bool(SENSITIVE.search(parameter))
            state = 'skipped_by_policy' if sensitive else template.state
            reason = 'sensitive parameter' if sensitive else template.reason
            counts[state] = counts.get(state, 0) + 1
            inputs.append({'template_id': template.id, 'source': template.source,
                           'url': template.request_url, 'method': template.method,
                           'parameter': parameter, 'location': template.parameter_location,
                           'auth_context': template.auth_context, 'state': state,
                           'reason': reason})
    total = len(inputs)
    accounted = sum(value for key, value in counts.items()
                    if key in ('seeded', 'requested', 'tested', 'active_tested',
                               'active_attempted', 'skipped_by_policy', 'blocked_by_csrf',
                               'unsupported'))
    return {'templates': [template.to_dict() for template in templates], 'inputs': inputs,
            'summary': {'discovered_inputs': total, **counts,
                        'accounted_inputs': accounted,
                        'unaccounted_inputs': max(0, total-accounted),
                        'ready': accounted == total}}
