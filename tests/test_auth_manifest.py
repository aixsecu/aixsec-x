import json

import auth_context
from auth_manifest import bind_runtime, load, public, require_ready


def test_zap_form_profile_binds_shared_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv('AUTH_U','alice'); monkeypatch.setenv('AUTH_P','secret')
    path=tmp_path/'auth.json'
    path.write_text(json.dumps({'staff':{'origin':'https://example.test',
        'authentication':{'method':'form','parameters':{
            'loginRequestUrl':'https://example.test/login',
            'loginRequestBody':'user={%username%}&pass={%password%}'},
            'verification':{'loggedInRegex':'Logout','loggedOutRegex':'Login'}},
        'credential_env':{'username':'AUTH_U','password':'AUTH_P'}}}))
    manifest=load({'zap_auth_file':str(path)}); manager=auth_context.AuthContextManager()
    assert bind_runtime(manifest,manager)==['staff']
    context=manager.get('staff')
    assert context.login_steps[0]['form']['user']=='env:AUTH_U'
    assert public(manifest)['contexts'][0]['zap_supported'] is True


def test_runtime_bearer_profile_is_not_claimed_as_zap_supported(tmp_path):
    path=tmp_path/'auth.json'; path.write_text(json.dumps({'api':{
        'origin':'https://example.test','authentication':{'method':'manual'},
        'runtime':{'transport':{'auth':'bearer:${ENV:TOKEN}'}},
        'credential_env':{'token':'TOKEN'}}}))
    assert public(load({'zap_auth_file':str(path)}))['contexts'][0]['zap_supported'] is False


def test_mfa_pause_requires_explicit_process_resume(tmp_path, monkeypatch):
    path=tmp_path/'auth.json'; path.write_text(json.dumps({'admin':{
        'origin':'https://example.test','authentication':{'method':'browser'},
        'operator_pause':{'kind':'mfa','ready_env':'TEST_MFA_READY'}}}))
    manifest=load({'zap_auth_file':str(path)})
    monkeypatch.delenv('TEST_MFA_READY',raising=False)
    import pytest
    with pytest.raises(ValueError,match='paused'): require_ready(manifest,'admin')
    monkeypatch.setenv('TEST_MFA_READY','1'); require_ready(manifest,'admin')
