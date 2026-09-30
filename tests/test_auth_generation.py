import json
import os
from types import SimpleNamespace

from captured_auth import artifact_expired, artifact_expired_pairs
from evidence import EvidenceStore
from family_evidence import FamilyEvidenceStore
from inventory import Inventory, TestHistory as HistoryStore
from ledger import Ledger
from pipeline import record_result


def auth_file(tmp_path):
    path=tmp_path/'auth.json'
    path.write_text(json.dumps({'user_A':{'origin':'https://example.test',
        'authentication':{'method':'form','verification':{
            'loggedInRegex':'Logout','loggedOutRegex':'Please login'}}}}))
    return path


def test_login_page_in_active_artifact_is_expired(tmp_path):
    evidence=tmp_path/'active.jsonl'
    evidence.write_text(json.dumps({'response_body':'Please login to continue'})+'\n')
    assert artifact_expired({'zap_auth_file':str(auth_file(tmp_path))},'user_A',evidence)


def test_login_marker_is_attributed_to_exact_request_rule_pair(tmp_path):
    evidence=tmp_path/'active.jsonl'
    evidence.write_text('\n'.join((
        json.dumps({'request_url':'https://example.test/a?id=payload','method':'GET',
                    'rule_id':'40018','response_body':'Please login to continue'}),
        json.dumps({'request_url':'https://example.test/b','method':'GET',
                    'rule_id':'40018','response_body':'Logout'}))))
    pairs,complete=artifact_expired_pairs({'zap_auth_file':str(auth_file(tmp_path))},
        'user_A',evidence,[
            {'request_id':'request-a','url':'https://example.test/a?id=1',
             'method':'GET','rule_ids':[40018]},
            {'request_id':'request-b','url':'https://example.test/b',
             'method':'GET','rule_ids':[40018]}])
    assert complete is True
    assert pairs==[{'request_id':'request-a','rule_id':40018,
                    'auth_disposition':'deferred_auth_expired'}]


def test_uncertain_authenticated_result_cannot_create_findings(tmp_path):
    store=EvidenceStore(Ledger(),tmp_path)
    store.ingest({'name':'zap_active_scan','outcome':'ok','args':{'url':'https://example.test','auth_context':'user_A'},
        'data':{'coverage':{'status':'partial','auth_context':'user_A','auth_generation':3,
                            'auth_disposition':'auth_uncertain'},
                'alerts':[{'category':'SQL Injection','severity':'high','url':'https://example.test/search',
                           'method':'GET','auth_context':'user_A'}]}})
    assert store.records == {}
    assert store.coverage == []
    assert store.discovery == []
    assert store.planner_records() == []
    assert store.summary()['auth_quarantine_count'] == 1
    assert store.quarantined[0]['auth_generation'] == 3
    quarantine=store.directory/'auth-quarantine.json'
    assert json.loads(quarantine.read_text())['count'] == 1
    assert os.stat(quarantine).st_mode & 0o777 == 0o600


def test_auth_quarantine_blocks_inventory_transcript_history_and_planner(tmp_path):
    store=EvidenceStore(Ledger(),tmp_path)
    inventory=Inventory()
    history=HistoryStore()
    recorded=[]
    agent=SimpleNamespace(evidence_store=store,inventory=inventory,test_history=history,
        transcript=[],_record_test=lambda *args:recorded.append(args))
    returned=record_result(agent,'zap_baseline',
        {'url':'https://example.test','auth_context':'user_A'},
        {'outcome':'ok','data':{
            'coverage':{'status':'partial','auth_context':'user_A','auth_generation':7,
                        'auth_disposition':'auth_uncertain'},
            'discovery':{'endpoints':[{'url':'https://example.test/private','method':'GET'}]},
            'alerts':[{'category':'SQL Injection','severity':'high',
                       'url':'https://example.test/private','method':'GET'}],
            'secret_response':'DO_NOT_EXPOSE'}})
    assert returned['auth_quarantined'] is True
    assert inventory.hosts == {}
    assert history.records == []
    assert recorded == []
    assert inventory.analysis['scanner_evidence'] == []
    assert inventory.analysis['web_discovery'] == []
    assert 'auth_quarantine' not in inventory.analysis
    assert 'auth_quarantine_count' not in inventory.analysis
    transcript=json.dumps(agent.transcript)
    assert 'DO_NOT_EXPOSE' not in transcript
    assert '/private' not in transcript


def test_family_evidence_rejects_uncertain_rows_even_if_called_directly():
    report=FamilyEvidenceStore().build([{'tool':'zap_active_scan','family_id':'rf-one',
        'representative_id':'request-one','evidence_id':'ev-one','_candidate':True,
        'auth_disposition':'auth_uncertain'}])
    assert report['finding_count'] == 0
