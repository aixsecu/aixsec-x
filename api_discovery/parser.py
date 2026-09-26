"""OpenAPI/Swagger and Postman import. All input is untrusted data."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl

MAX_BYTES = 2_000_000
MAX_NODES = 50000
METHODS = frozenset('GET POST PUT PATCH DELETE HEAD OPTIONS TRACE'.split())


def origin(url):
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('Expected HTTP(S) URL without credentials')
    return p.scheme.lower(), p.hostname.lower(), p.port or (443 if p.scheme == 'https' else 80)


def canonical(url):
    """Operation identity excludes query values; parameter names live in metadata."""
    scheme, host, port = origin(url)
    host = '[' + host + ']' if ':' in host else host
    authority = host if port == (443 if scheme == 'https' else 80) else f'{host}:{port}'
    return urlunsplit((scheme, authority, urlsplit(url).path or '/', '', ''))


def bounded(value):
    """Reject cycles, YAML alias expansion and excessively deep/large trees."""
    count = 0
    def visit(v, depth, ancestors):
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > 40:
            raise ValueError('Document exceeds structure limits')
        if isinstance(v, (dict, list)):
            if id(v) in ancestors:
                raise ValueError('Cyclic document')
            ancestors = ancestors | {id(v)}
            for child in (v.values() if isinstance(v, dict) else v):
                visit(child, depth + 1, ancestors)
    visit(value, 0, set())
    return value


def load_document(text):
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError('Document exceeds 2 MB')
    try:
        result = json.loads(text)
    except ValueError:
        import yaml
        try:
            result = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError('Invalid JSON/YAML document') from exc
    bounded(result)
    if not isinstance(result, dict):
        raise ValueError('Document must be an object')
    return result


def metadata(value, depth=0):
    """Discard example/default/credential values; preserve schema field names."""
    if depth > 30:
        return {'truncated': True}
    if isinstance(value, dict):
        return {str(k): (metadata(v, depth + 1) if k != 'properties' else
                        {str(n): metadata(s, depth + 1) for n, s in v.items()})
                for k, v in value.items()
                if k not in ('example', 'examples', 'default', 'value')
                and not str(k).startswith('x-') and (k != 'properties' or isinstance(v, dict))}
    if isinstance(value, list):
        return [metadata(v, depth + 1) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def infer_schema(value, depth=0):
    """Observed shape only: never copy response values or infer required fields."""
    if depth >= 12:
        return {}
    if value is None:
        return {'type': 'null'}
    if isinstance(value, bool):
        return {'type': 'boolean'}
    if isinstance(value, dict):
        return {'type': 'object', 'properties': {
            str(k): infer_schema(v, depth + 1) for k, v in list(value.items())[:200]}}
    if isinstance(value, list):
        shapes = []
        for v in value[:20]:
            s = infer_schema(v, depth + 1)
            if s not in shapes:
                shapes.append(s)
        return {'type': 'array', 'items': (shapes[0] if len(shapes) == 1 else {'anyOf': shapes})}
    return {'type': 'integer' if isinstance(value, int) else 'number' if isinstance(value, float) else 'string'}


class Resolver:
    def __init__(self, doc, warnings):
        self.doc, self.warnings = doc, warnings
        self.remaining = MAX_NODES

    def resolve(self, value, refs=(), depth=0):
        self.remaining -= 1
        if self.remaining < 0:
            raise ValueError('Reference expansion exceeds limits')
        if depth > 25:
            return {'truncated': True}
        if isinstance(value, list):
            return [self.resolve(v, refs, depth + 1) for v in value]
        if not isinstance(value, dict):
            return value
        ref = value.get('$ref')
        if isinstance(ref, str):
            if not ref.startswith('#/') or ref in refs:
                self.warnings.add('Unresolved external or recursive $ref: ' + ref[:200])
                return {'$ref': ref}
            target = self.doc
            try:
                for key in ref[2:].split('/'):
                    target = target[key.replace('~1', '/').replace('~0', '~')]
            except (KeyError, TypeError):
                self.warnings.add('Missing $ref: ' + ref[:200])
                return {'$ref': ref}
            return self.resolve(target, refs + (ref,), depth + 1)
        return {str(k): self.resolve(v, refs, depth + 1) for k, v in value.items()}


def import_document(document, source_url, base_url=None):
    """Import text/dict without network. Endpoints restricted to base_url origin.

    base_url sets the scope and fallback server; declared foreign servers are skipped.
    """
    scope = base_url or source_url
    origin(scope)
    doc = load_document(document) if isinstance(document, str) else bounded(document)
    if not isinstance(doc, dict):
        raise ValueError('Document must be an object')
    warnings = set()
    result = {'url': canonical(scope), 'operations': [], 'warnings': [], 'documents': []}
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, default=str).encode()).hexdigest()
    evidence = {'source_url': canonical(source_url), 'sha256': digest}
    if isinstance(doc.get('info'), dict) and 'schema.getpostman.com' in str(doc['info'].get('schema', '')):
        result['operations'] = _postman(doc, scope, evidence, warnings)
    else:
        v2 = doc.get('swagger') == '2.0'
        if not v2 and not re.match(r'^3\.[01]\.\d+', str(doc.get('openapi', ''))):
            raise ValueError('Supported: Swagger 2.0, OpenAPI 3.0/3.1, Postman 2.x')
        if not isinstance(doc.get('paths'), dict):
            raise ValueError('Spec paths must be an object')
        resolver = Resolver(doc, warnings)
        schemes = doc.get('securityDefinitions', {}) if v2 else doc.get('components', {}).get('securitySchemes', {})
        schemes = metadata(resolver.resolve(schemes))
        for path, raw in doc['paths'].items():
            if not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or not isinstance(raw, dict):
                continue
            item = resolver.resolve(raw)
            for method, op in item.items():
                if method.upper() not in METHODS or not isinstance(op, dict):
                    continue
                if v2:
                    p = urlsplit(scope)
                    servers = [{'url': (doc.get('schemes') or [p.scheme])[0] + '://' +
                                str(doc.get('host') or p.netloc) + str(doc.get('basePath') or '')}]
                else:
                    servers = op.get('servers', item.get('servers', doc.get('servers', [{'url': '/'}])))
                if not isinstance(servers, list):
                    raise ValueError('servers must be a list')
                for server in servers:
                    if not isinstance(server, dict):
                        continue
                    server_url = str(server.get('url', '/'))
                    for key, var in server.get('variables', {}).items():
                        server_url = server_url.replace('{' + key + '}', str(var.get('default', '')))
                    full = urljoin(source_url, server_url).rstrip('/') + path
                    try:
                        if origin(full) != origin(scope) or '{' in urlsplit(full).netloc:
                            warnings.add('Skipped out-of-origin server')
                            continue
                        full = canonical(full)
                    except ValueError:
                        warnings.add('Skipped invalid server')
                        continue
                    params = {}
                    for param in item.get('parameters', []) + op.get('parameters', []):
                        if isinstance(param, dict) and 'name' in param and 'in' in param:
                            params[(param['in'], param['name'])] = metadata(param)
                    security = op.get('security', doc.get('security', []))
                    result['operations'].append({
                        'url': full, 'method': method.upper(), 'source': 'openapi',
                        'confidence': 1.0, 'state': 'declared', 'evidence': evidence,
                        'metadata': {**{k: metadata(op[k]) for k in ('summary', 'description', 'tags', 'operationId', 'deprecated') if k in op},
                                     'parameters': list(params.values()),
                                     'requestBody': metadata(op.get('requestBody', {})),
                                     'responses': metadata(op.get('responses', {})),
                                     'consumes': op.get('consumes', doc.get('consumes', list(op.get('requestBody', {}).get('content', {})))),
                                     'produces': op.get('produces', doc.get('produces', [])),
                                     'security': security, 'securitySchemes': schemes}})
                    if len(result['operations']) > 5000:
                        raise ValueError('Too many API operations')
    result['warnings'] = sorted(warnings)
    result['documents'] = [evidence]
    return result


def _postman(doc, scope, evidence, warnings):
    variables = {str(v.get('key')): str(v.get('value', '')) for v in doc.get('variable', []) if isinstance(v, dict)}
    def expand(s):
        return re.sub(r'\{\{([^{}]+)\}\}', lambda m: variables.get(m[1], m[0]), s)
    out = []
    def visit(items, auth=None):
        for item in items:
            if not isinstance(item, dict):
                continue
            if 'item' in item:
                visit(item['item'], item.get('auth', auth))
                continue
            req = item.get('request', {})
            if not isinstance(req, dict):
                continue
            raw = req.get('url', '')
            raw = raw.get('raw', '') if isinstance(raw, dict) else raw
            if not raw:
                warnings.add('Skipped Postman URL without raw representation')
                continue
            url = expand(str(raw))
            url = re.sub(r'/:([A-Za-z_][\w]*)', r'/{\1}', url)
            if '{{' in url:
                warnings.add('Skipped unresolved Postman URL variable')
                continue
            url = urljoin(scope, url)
            try:
                if origin(url) != origin(scope):
                    warnings.add('Skipped out-of-origin Postman request')
                    continue
            except ValueError:
                warnings.add('Skipped invalid Postman URL')
                continue
            method = str(req.get('method', 'GET')).upper()
            if method not in METHODS:
                continue
            params = [{'name': k, 'in': 'query'} for k, _ in parse_qsl(urlsplit(url).query)]
            params += [{'name': k, 'in': 'path', 'required': True} for k in re.findall(r'\{([^{}]+)\}', urlsplit(url).path)]
            params += [{'name': h['key'], 'in': 'header'} for h in req.get('header', []) if isinstance(h, dict) and 'key' in h and not h.get('disabled')]
            body = req.get('body', {})
            schema = {}
            if body.get('mode') == 'raw':
                try:
                    schema = infer_schema(json.loads(body.get('raw', '')))
                except ValueError:
                    pass
            for field in body.get('urlencoded', []) + body.get('formdata', []):
                if isinstance(field, dict) and 'key' in field and not field.get('disabled'):
                    params.append({'name': field['key'], 'in': 'formData'})
            a = req.get('auth', auth) or {}
            out.append({'url': canonical(url), 'method': method, 'source': 'postman',
                        'confidence': 1.0, 'state': 'declared', 'evidence': evidence,
                        'metadata': {'parameters': params, 'bodySchema': schema,
                                     'authType': a.get('type', 'unknown')}})
    visit(doc.get('item', []), doc.get('auth'))
    return out
