import auth_context
from auth_zap_bridge import prepare, public
from adapters.zap import build_plan, _scrub_bridge_artifacts
import json


class Response:
    status_code=200
    text='account ready'


def test_runtime_bearer_is_resolved_for_zap_and_public_view_hides_value(monkeypatch):
    monkeypatch.setenv('BRIDGE_TOKEN','very-secret')
    manager=auth_context.AuthContextManager()
    manager.configure('api','https://example.test',
        transport={'auth':'bearer:${ENV:BRIDGE_TOKEN}'},replace=True)
    context=manager.get('api')
    context.request=lambda *args,**kwargs:(Response(),object())
    manifest={'contexts':{'api':{'origin':'https://example.test',
        'zap':{'authentication':{'method':'manual'}},
        'runtime':{'verification':{'url':'https://example.test/me',
                                   'loggedInRegex':'account ready'}}}}}
    material=prepare(manifest,'api',manager)
    assert material['headers']['Authorization']=='Bearer very-secret'
    assert 'very-secret' not in str(public(material))
    assert public(material)['header_names']==['Authorization']


def test_browser_context_requires_imported_session_material():
    manager=auth_context.AuthContextManager();manager.configure(
        'admin','https://example.test',replace=True)
    manifest={'contexts':{'admin':{'origin':'https://example.test',
        'zap':{'authentication':{'method':'browser'}},'runtime':{}}}}
    import pytest
    with pytest.raises(ValueError,match='requires imported'):prepare(manifest,'admin',manager)


def test_bridge_material_is_injected_into_ephemeral_zap_plan_and_seed(tmp_path):
    auth_file=tmp_path/'auth.json';auth_file.write_text(json.dumps({'api':{
        'origin':'https://example.test','authentication':{'method':'manual'},
        'runtime':{'transport':{'auth':'bearer:${ENV:TOKEN}'}}}}))
    seed={'request':{'url':'https://example.test/api','method':'GET','headers':[]},
          'response':{'status':200,'headers':[],'content':{'text':'','mimeType':'text/html'}}}
    plan=build_plan({'zap_auth_file':str(auth_file),'_zap_seed_entry':seed,
        '_zap_auth_material':{'context':'api','verified':True,
            'headers':{'Authorization':'Bearer secret'},'cookies':{'sid':'cookie-secret'}},
        'zap_allowed_rules':[40018]},'https://example.test/api',tmp_path,
        active=True,rule_ids=[40018],auth_context='api')
    replacer=next(job for job in plan['jobs'] if job['type']=='replacer')
    assert len(replacer['rules'])==2
    imported=json.loads((tmp_path/'seed.har').read_text())['log']['entries'][0]['request']['headers']
    assert {'name':'Authorization','value':'Bearer secret'} in imported
    assert any(row['name']=='Cookie' and 'cookie-secret' in row['value'] for row in imported)
    assert _scrub_bridge_artifacts(tmp_path,{'headers':{'Authorization':'Bearer secret'},
                                                 'cookies':{'sid':'cookie-secret'}})>=1
    assert 'Bearer secret' not in (tmp_path/'seed.har').read_text()
    assert 'cookie-secret' not in (tmp_path/'seed.har').read_text()
