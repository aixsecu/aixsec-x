import json
from pathlib import Path
import tempfile
import unittest

from route_family import RepresentativeSelector,RouteFamilyBuilder, fingerprint


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

    def test_representative_limits_follow_family_size_tiers(self):
        selector=RepresentativeSelector(extra_large=5)
        for size,expected in ((1,1),(5,1),(6,2),(30,2),(31,3),(100,3),(101,5)):
            rows=groups(*(entry() for _ in range(size)))
            report=RouteFamilyBuilder().build(rows)
            selected=selector.select(rows,report)
            self.assertEqual(selected['scan_groups_after'],expected)

    def test_representative_selection_scores_every_member_and_prefers_richness(self):
        plain=entry(body='<html><body>small</body></html>')
        rich=entry('https://example.test/orders/123?a=1&b=2',body=(
            '<html><body><form><input name="a"><input name="b"></form><section>large</section></body></html>'))
        rows=groups(plain,rich)
        # Exercise selection independently with both candidates assigned to one family.
        report=RouteFamilyBuilder().build(rows)
        report['families'][0]['members'].append(report['families'][1]['members'][0])
        report['families']=report['families'][:1]
        selected=RepresentativeSelector().select(rows,report)
        scored=selected['families'][0]['scored_members']
        self.assertEqual(len(scored),2)
        self.assertEqual(selected['representative_request_ids'],['1'])
        self.assertGreater(scored[1]['score'],scored[0]['score'])
        self.assertEqual(set(scored[0]['metrics']),{'response_size','form_count','input_count',
            'parameter_count','response_complexity','unique_parameter_names','dom_complexity','url_depth'})

    def test_representatives_are_deterministic_and_persisted(self):
        rows=groups(*(entry(body='<html><body><input name="csrf" value="'+('x'*(size+1))+'"></body></html>')
                      for size in range(6)))
        family=RouteFamilyBuilder().build(rows)
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'representatives.json';family_path=Path(root)/'family.json'
            first=RepresentativeSelector().write(rows,family,path,family_path)
            second=RepresentativeSelector().select(rows,RouteFamilyBuilder().build(rows))
            self.assertEqual(first['representative_request_ids'],second['representative_request_ids'])
            self.assertEqual(first['scan_groups_before'],6)
            self.assertEqual(first['scan_groups_after'],2)
            self.assertIn('coverage_estimate',first)
            self.assertEqual(json.loads(path.read_text())['algorithm'],first['algorithm'])
            saved_family=json.loads(family_path.read_text())
            self.assertEqual(saved_family['families'][0]['representative_candidates'],
                             first['representative_request_ids'])
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            for request_id in first['representative_request_ids']:
                self.assertEqual(rows[request_id]['representative_id'],request_id)
            for row in rows.values():
                self.assertEqual(row['route_family_member_count'],6)
                self.assertEqual(row['route_family_member_urls'],['https://example.test/orders/123'])


if __name__=='__main__':unittest.main()
