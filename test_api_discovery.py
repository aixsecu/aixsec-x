"""Hermetic parser/merge tests and local HTTP integration for Phase 2.1."""
import copy
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from api_discovery import import_document, discover, infer_schema
from api_discovery.parser import canonical
from inventory import Inventory

URL = 'https://example.test/openapi.json'


def spec():
    return {'openapi': '3.0.3', 'info': {'title': 'test', 'version': '1'},
            'servers': [{'url': '/api'}],
            'security': [{'bearer': []}],
            'components': {'securitySchemes': {'bearer': {'type': 'http', 'scheme': 'bearer'}},
                           'schemas': {'User': {'type': 'object', 'required': ['email'], 'properties': {
                               'email': {'type': 'string', 'format': 'email', 'nullable': True},
                               'password': {'type': 'string', 'example': 'TOPSECRET'}}}}},
            'paths': {'/users/{id}': {'parameters': [{'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}],
                'get': {'operationId': 'readUser', 'tags': ['users'], 'responses': {'200': {'content': {'application/json': {'schema': {'$ref': '#/components/schemas/User'}}}}}},
                'post': {'security': [], 'requestBody': {'content': {'application/json': {'schema': {'$ref': '#/components/schemas/User'}}}}, 'responses': {}}}}}


class ParserTests(unittest.TestCase):
    def test_metadata_and_method_isolation(self):
        ops = import_document(spec(), URL)['operations']
        self.assertEqual([o['method'] for o in ops], ['GET', 'POST'])
        get, post = [o['metadata'] for o in ops]
        self.assertEqual(get['security'], [{'bearer': []}])
        self.assertEqual(post['security'], [])
        schema = post['requestBody']['content']['application/json']['schema']
        self.assertEqual(schema['required'], ['email'])
        self.assertTrue(schema['properties']['email']['nullable'])
        self.assertIn('password', schema['properties'])
        self.assertNotIn('TOPSECRET', json.dumps(ops))
        self.assertEqual(ops[0]['url'], 'https://example.test/api/users/{id}')

    def test_parameter_override(self):
        d = spec()
        d['paths']['/users/{id}']['get']['parameters'] = [{'name': 'id', 'in': 'path', 'schema': {'type': 'integer'}}]
        p = import_document(d, URL)['operations'][0]['metadata']['parameters']
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]['schema']['type'], 'integer')

    def test_all_parameter_locations(self):
        d = spec()
        d['paths']['/users/{id}']['get']['parameters'] = [{'name': location, 'in': location} for location in ('query', 'header', 'cookie', 'body')]
        p = import_document(d, URL)['operations'][0]['metadata']['parameters']
        self.assertEqual({v['in'] for v in p}, {'path', 'query', 'header', 'cookie', 'body'})

    def test_swagger_basepath_security_and_body(self):
        d = {'swagger': '2.0', 'host': 'example.test', 'basePath': '/v2', 'schemes': ['https'],
             'consumes': ['application/json'], 'securityDefinitions': {'key': {'type': 'apiKey', 'in': 'header', 'name': 'X-Key'}},
             'paths': {'/users': {'post': {'parameters': [{'name': 'body', 'in': 'body', 'schema': {'type': 'object'}}]}}}}
        op = import_document(d, URL)['operations'][0]
        self.assertEqual(op['url'], 'https://example.test/v2/users')
        self.assertEqual(op['metadata']['consumes'], ['application/json'])
        self.assertEqual(op['metadata']['securitySchemes']['key']['name'], 'X-Key')

    def test_yaml(self):
        result = import_document('openapi: 3.0.3\npaths:\n  /ping:\n    get:\n      responses: {}\n', URL)
        self.assertEqual(result['operations'][0]['url'], 'https://example.test/ping')

    def test_31_union(self):
        d = spec(); d['openapi'] = '3.1.0'
        d['components']['schemas']['User']['properties']['email']['type'] = ['string', 'null']
        self.assertIn('null', json.dumps(import_document(d, URL)))

    def test_invalid_documents(self):
        for d in ('[]', 'not a spec', '{broken', '!!python/object:os.system {}', {'openapi': '4.0.0'}, {'openapi': '3.0.3', 'paths': []}):
            with self.subTest(d=d), self.assertRaises(ValueError):
                import_document(d, URL)

    def test_cycles_and_size(self):
        d = {}; d['self'] = d
        for doc in (d, 'x' * 2_000_001, 'a: &a [*a]'):
            with self.assertRaises(ValueError):
                import_document(doc, URL)

    def test_recursive_and_external_refs(self):
        d = spec(); d['components']['schemas']['User']['properties']['self'] = {'$ref': '#/components/schemas/User'}
        d['paths']['/external'] = {'$ref': 'https://evil.test/spec'}
        r = import_document(d, URL)
        self.assertTrue(any('recursive' in w for w in r['warnings']))
        self.assertTrue(any('external' in w for w in r['warnings']))

    def test_missing_ref(self):
        d = spec(); d['paths']['/missing'] = {'$ref': '#/absent'}
        self.assertTrue(any('Missing' in w for w in import_document(d, URL)['warnings']))

    def test_foreign_server_never_rebased(self):
        d = spec(); d['servers'] = [{'url': 'https://evil.test/api'}]
        r = import_document(d, URL)
        self.assertEqual(r['operations'], [])
        self.assertTrue(r['warnings'])

    def test_server_precedence_variables(self):
        d = spec(); d['paths']['/users/{id}']['get']['servers'] = [{'url': '/{version}', 'variables': {'version': {'default': 'v9'}}}]
        self.assertIn('/v9/users/', import_document(d, URL)['operations'][0]['url'])

    def test_relative_server(self):
        d = spec(); d['servers'] = [{'url': './api'}]
        self.assertEqual(import_document(d, 'https://example.test/docs/spec.json')['operations'][0]['url'], 'https://example.test/docs/api/users/{id}')

    def test_no_input_mutation(self):
        d = spec(); before = copy.deepcopy(d); import_document(d, URL)
        self.assertEqual(d, before)

    def test_fingerprints(self):
        a = import_document(spec(), URL); b = import_document(spec(), URL)
        self.assertEqual(a['documents'], b['documents'])
        self.assertEqual(len(a['documents'][0]['sha256']), 64)

    def test_observed_schema_no_values(self):
        shape = infer_schema({'token': 'SECRET', 'active': True, 'n': 2, 'list': [None, 'foo'], 'empty': []})
        self.assertNotIn('SECRET', json.dumps(shape))
        self.assertEqual(shape['properties']['active']['type'], 'boolean')
        self.assertNotIn('required', shape)

    def test_canonical(self):
        self.assertEqual(canonical('https://EXAMPLE.test:443/a?token=secret#x'), 'https://example.test/a')
        self.assertNotEqual(canonical('https://example.test/a'), canonical('https://example.test/a/'))
        for u in ('file:///tmp/a', 'https://user:pass@example.test/', '//example.test/a'):
            with self.assertRaises(ValueError): canonical(u)

    def test_postman(self):
        d = {'info': {'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'},
             'variable': [{'key': 'base', 'value': 'https://example.test'}], 'auth': {'type': 'bearer', 'bearer': [{'key': 'token', 'value': 'SECRET'}]},
             'item': [{'name': 'folder', 'item': [{'request': {'method': 'POST', 'url': '{{base}}/users/:id?q=secret',
                       'header': [{'key': 'Authorization', 'value': 'SECRET'}],
                       'body': {'mode': 'raw', 'raw': '{"password":"SECRET"}'}}}]}]}
        op = import_document(d, URL)['operations'][0]
        self.assertEqual(op['url'], 'https://example.test/users/{id}')
        self.assertEqual(op['metadata']['authType'], 'bearer')
        self.assertNotIn('SECRET', json.dumps(op))
        d['variable'] = []
        self.assertEqual(import_document(d, URL)['operations'], [])


class InventoryTests(unittest.TestCase):
    def test_merge_persistence_conflicts(self):
        inv = Inventory()
        data = import_document(spec(), URL)
        call = {'name': 'api_import', 'outcome': 'ok', 'data': data}
        inv.ingest([call, call])
        ep = inv.host(URL).endpoints['https://example.test/api/users/{id}']
        self.assertEqual(len(ep.api_operations['GET']['observations']), 1)
        change = copy.deepcopy(data); change['operations'][0]['metadata']['security'] = []
        inv.ingest([{'name': 'api_import', 'outcome': 'ok', 'data': change}])
        self.assertEqual(len(ep.api_operations['GET']['observations']), 2)
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'inventory.json'); inv.save(path)
            self.assertEqual(inv.to_dict(), Inventory.load(path).to_dict())

    def test_crawler_and_spec_merge(self):
        inv = Inventory()
        inv.ingest([{'name': 'api_import', 'outcome': 'ok', 'data': import_document(spec(), URL)},
                    {'name': 'crawler', 'outcome': 'ok', 'data': {'url': URL, 'js_hints': [
                        {'url': 'https://example.test/api/users/{id}', 'method': 'GET', 'in_scope': True},
                        {'url': 'https://evil.test/users', 'method': 'POST', 'in_scope': False}]}}])
        ep = inv.host(URL).endpoints['https://example.test/api/users/{id}']
        self.assertEqual(set(ep.api_operations['GET']['sources']), {'openapi', 'crawler:js'})
        self.assertEqual(ep.api_operations['GET']['confidence'], 1.)
        self.assertIsNone(inv.host('https://evil.test'))

    def test_trailing_slash_and_query_identity_roundtrip(self):
        inv = Inventory()
        ops = [{'url': u, 'method': 'GET', 'source': 'observed'} for u in
               ('https://example.test/a?x=1', 'https://example.test/a?x=2', 'https://example.test/a/')]
        inv.ingest([{'name': 'api_discovery', 'outcome': 'ok', 'data': {'operations': ops}}])
        self.assertEqual([o['url'] for o in inv.api_inventory()], ['https://example.test/a', 'https://example.test/a/'])
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'inv.json'); inv.save(path)
            self.assertEqual(inv.api_inventory(), Inventory.load(path).api_inventory())

    def test_unknown_not_get_and_failed_not_ingested(self):
        inv = Inventory()
        op = {'url': URL, 'method': 'UNKNOWN', 'source': 'graphql-hint'}
        inv.ingest([{'name': 'api_discovery', 'outcome': 'error', 'data': {'operations': [op]}}])
        self.assertFalse(inv.hosts)
        inv.ingest([{'name': 'api_discovery', 'outcome': 'ok', 'data': {'operations': [op]}}])
        self.assertEqual(inv.host(URL).endpoints[URL].methods, set())


class DiscoveryTests(unittest.TestCase):
    def session(self, pages):
        calls = []
        def request(method, url, **kw):
            calls.append((method, url, kw))
            status, body, headers = pages.get(url, (404, '', {}))
            return SimpleNamespace(status_code=status, text=body, content=body.encode(), headers=headers), None
        return SimpleNamespace(request=request), calls

    def test_ui_spec_and_scope(self):
        session, calls = self.session({URL: (200, '<redoc spec-url="/real.json"></redoc>', {'Content-Type': 'text/html'}),
                                     'https://example.test/real.json': (200, json.dumps(spec()), {})})
        result = discover(URL, session=session, max_requests=2)
        self.assertEqual(len(result['operations']), 2)
        self.assertEqual(len(calls), 2)
        self.assertTrue(result['truncated'])
        self.assertTrue(all(c[0] == 'GET' and not c[2]['follow_redirects'] for c in calls))

    def test_external_redirect(self):
        session, calls = self.session({URL: (302, '', {'Location': 'https://evil.test/'})})
        r = discover(URL, session=session, max_requests=3)
        self.assertTrue(any('Blocked' in w for w in r['warnings']))
        self.assertFalse(any('evil.test' in c[1] for c in calls))

    def test_json_and_graphql_hint(self):
        session, _ = self.session({URL: (200, '{"token":"SECRET"}', {'Content-Type': 'application/json'}),
            'https://example.test/graphql': (400, '{"errors":[{"message":"GraphQL query missing"}]}', {})})
        result = discover(URL, session=session)
        self.assertEqual({o['source'] for o in result['operations']}, {'observed-json', 'graphql-hint'})
        self.assertNotIn('SECRET', json.dumps(result))

    def test_no_false_graphql_from_path_alone(self):
        session, _ = self.session({'https://example.test/graphql': (404, 'not found', {})})
        self.assertEqual(discover(URL, session=session)['operations'], [])

    def test_loop_bounded(self):
        session, calls = self.session({URL: (302, '', {'Location': URL})})
        discover(URL, session=session, max_requests=2)
        self.assertEqual(len(calls), 2)

    def test_html_js_hint(self):
        session, _ = self.session({URL: (200, "<script>axios.post('/api/users')</script>", {'Content-Type': 'text/html'})})
        op = discover(URL, session=session, max_requests=1)['operations'][0]
        self.assertEqual(op['method'], 'POST')
        self.assertEqual(op['state'], 'candidate')

    def test_limits(self):
        for kw in ({'max_requests': 0}, {'time_budget': -1}, {'timeout': 0}):
            with self.assertRaises(ValueError): discover(URL, **kw)

    def test_oversized(self):
        session, _ = self.session({URL: (200, 'a' * 2_000_001, {})})
        r = discover(URL, session=session, max_requests=1)
        self.assertFalse(r['operations']); self.assertTrue(r['warnings'])


class LocalIntegrationTests(unittest.TestCase):
    def test_session_cookie_redirect_and_import(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/large':
                    self.send_response(200); self.end_headers(); self.wfile.write(b'x' * 500)
                elif self.path == '/start':
                    self.send_response(302); self.send_header('Set-Cookie', 'sid=demo'); self.send_header('Location', '/spec'); self.end_headers()
                elif self.path == '/spec' and 'sid=demo' in self.headers.get('Cookie', ''):
                    self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                    self.wfile.write(json.dumps({'openapi': '3.0.3', 'paths': {'/ping': {'get': {}}}}).encode())
                else:
                    self.send_response(404); self.end_headers()
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            url = f'http://127.0.0.1:{server.server_port}/start'
            import tools
            text, data = tools._api_discovery(url=url, max_requests=2)
            self.assertFalse(text.startswith('[!]'))
            inv = Inventory(); inv.ingest([{'name': 'api_discovery', 'outcome': 'ok', 'data': data}])
            self.assertEqual(data['operations'][0]['method'], 'GET')
            self.assertIn('/ping', inv.render())
            import http_engine
            with self.assertRaises(ValueError):
                http_engine.session_for(url).request('GET', url.replace('/start', '/large'), max_response_bytes=100)
            r, _ = http_engine.session_for(url).request('GET', url.replace('/start', '/large'), max_response_bytes=600)
            self.assertEqual(len(r.content), 500)
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    unittest.main()
