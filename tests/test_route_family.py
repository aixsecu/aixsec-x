import json
from pathlib import Path
import tempfile
import unittest

from route_family import RouteFamilyBuilder, fingerprint


def entry(url='https://example.test/orders/123',method='GET',query_headers=None,
          post=None,status=200,body='<html><body><input id="generated-1" name="q"></body></html>'):
    return {'request':{'url':url,'method':method,'headers':query_headers or [],
                       **({'postData':post} if post else {})},
            'response':{'status':status,'headers':[{'name':'ETag','value':'abc-123'}],
                        'content':{'mimeType':'text/html','text':body}}}


def groups(*items):
    return {str(index):{'request_id':str(index),'url':item['request']['url'],
        'method':item['request']['method'],'auth_context':'anonymous','_entry':item}
        for index,item in enumerate(items)}


class RouteFamilyTests(unittest.TestCase):
    def test_semantic_routes_never_merge(self):
        rows=groups(*(entry('https://example.test/'+name) for name in ('login','logout','register','search')))
        result=RouteFamilyBuilder().build(rows)
        self.assertEqual(result['family_count'],4)

    def test_unstable_path_and_dom_values_merge(self):
        one=entry('https://example.test/orders/550e8400-e29b-41d4-a716-446655440000',
                  body='<html><form id="react-123"><input name="csrf" value="aaa"></form></html>')
        two=entry('https://example.test/orders/6ba7b810-9dad-11d1-80b4-00c04fd430c8',
                  body='<html><form id="react-987"><input name="csrf" value="bbb"></form></html>')
        result=RouteFamilyBuilder().build(groups(one,two))
        self.assertEqual(result['family_count'],1)
        self.assertEqual(len(result['families'][0]['members']),2)

    def test_parameter_name_location_and_method_are_structural(self):
        get=entry('https://example.test/search?q=x')
        get_other=entry('https://example.test/search?page=1')
        post=entry('https://example.test/search','POST',post={'mimeType':'application/x-www-form-urlencoded',
                   'params':[{'name':'q','value':'x'}]})
        self.assertEqual(RouteFamilyBuilder().build(groups(get,get_other,post))['family_count'],3)

    def test_routing_values_preserve_application_semantics(self):
        login=entry('https://example.test/api?action=login')
        logout=entry('https://example.test/api?action=logout')
        self.assertEqual(RouteFamilyBuilder().build(groups(login,logout))['family_count'],2)

    def test_status_and_response_template_are_structural(self):
        ok=entry(status=200,body='<html><h1>Order accepted</h1></html>')
        denied=entry(status=403,body='<html><h1>Access denied</h1></html>')
        self.assertEqual(RouteFamilyBuilder().build(groups(ok,denied))['family_count'],2)

    def test_output_contract_and_permissions(self):
        rows=groups(entry())
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'family.json';result=RouteFamilyBuilder().write(rows,path)
            saved=json.loads(path.read_text());family=saved['families'][0]
            self.assertEqual(set(('family_id','fingerprint','members','representative_candidates'))-set(family),set())
            self.assertEqual(family['representative_candidates'],[])
            self.assertEqual(rows['0']['route_family_id'],family['family_id'])
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_fingerprint_is_deterministic(self):
        value=entry()
        self.assertEqual(fingerprint(value),fingerprint(json.loads(json.dumps(value))))


if __name__=='__main__':unittest.main()
