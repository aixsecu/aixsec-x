import json
from pathlib import Path
import tempfile
import unittest

from evidence import EvidenceStore
from evidence_normalizer import SCHEMA_FIELDS, normalize, validate_schema
from ledger import Ledger


URL='https://example.test/items?id=1'


class EvidenceNormalizerTests(unittest.TestCase):
    def alert(self,category='Missing Header'):
        return {'category':category,'rule_id':'10038','severity':'medium','url':URL,
            'method':'GET','parameter':'id','description':'candidate',
            'request_sha256':'request-hash','response_sha256':'response-hash',
            '_request_header':'GET /items?id=1 HTTP/1.1\r\nAccept: text/html\r\n',
            '_response_header':'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n',
            '_url':URL,'_body_sha256':'body-hash'}

    def test_supported_tools_share_one_schema(self):
        results=[
            {'name':'zap_active_scan','outcome':'ok','args':{'url':URL},
             'data':{'alerts':[self.alert()],'coverage':{'status':'complete'}}},
            {'name':'nuclei_scan','outcome':'ok','args':{'url':URL},
             'data':{'alerts':[self.alert('Template Match')]}},
            {'name':'sqlmap_runner','outcome':'ok','args':{'url':URL},
             'output':'Parameter: id (GET)\n    Type: boolean-based blind','data':{}},
            {'name':'ffuf_dir','outcome':'ok','args':{'url':'https://example.test'},'data':{}},
            {'name':'http_request','outcome':'ok','args':{'url':URL,'method':'get'},'data':{}},
        ]
        for result in results:
            rows=normalize(result,'/private/raw.json')
            self.assertTrue(rows,result['name'])
            self.assertTrue(validate_schema(rows[0]))
            self.assertEqual(set(SCHEMA_FIELDS)-set(rows[0]),set())
            self.assertEqual(rows[0]['tool'],result['name'])
            self.assertTrue(rows[0]['capability'])

    def test_raw_result_and_raw_report_references_are_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            report=Path(root)/'zap-report.json';report.write_text('{"raw":"retained"}')
            row=self.alert();row['artifact_ref']=str(report)
            store=EvidenceStore(Ledger(),root)
            store.ingest({'name':'zap_baseline','outcome':'ok','args':{'url':URL},
                'data':{'alerts':[row]}})
            record=next(iter(store.records.values()))
            self.assertEqual(record['artifact_ref'],str(report))
            self.assertTrue(Path(record['raw_result_reference']).is_file())
            self.assertEqual(json.loads(Path(record['raw_result_reference']).read_text())['name'],'zap_baseline')
            self.assertIn(str(report),record['request_reference'])

    def test_verification_consumes_normalized_record(self):
        store=EvidenceStore(Ledger())
        store.ingest({'name':'zap_baseline','outcome':'ok','args':{'url':URL},
            'data':{'alerts':[self.alert()]}})
        record=next(iter(store.records.values()))
        self.assertEqual(record['_normalized_schema'],1)
        result=store.validate(record['evidence_id'])
        self.assertEqual(result['status'],'confirmed')
        self.assertEqual(record['verification_state'],'confirmed')

    def test_planner_view_is_provider_neutral(self):
        store=EvidenceStore(Ledger())
        store.ingest({'name':'nuclei_scan','outcome':'ok','args':{'url':URL},
            'data':{'alerts':[self.alert('Template Match')]}})
        row=store.planner_records()[0]
        self.assertNotIn('tool',row)
        self.assertNotIn('tool_version',row)
        self.assertNotIn('source_tool',row)
        self.assertEqual(row['capability'],'template_scan')


if __name__=='__main__':
    unittest.main()
