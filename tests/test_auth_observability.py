import json

from auth_observability import configured, observe


def test_configured_auth_is_pending_verification():
    assert configured({'zap_auth_context':'staff'})['state'] == 'auth_configured'


def test_verified_auth_has_generation():
    value=observe({'zap_auth_context':'staff'},[{'auth_state':'verified'}])
    assert (value['state'],value['generation']) == ('auth_verified',1)


def test_anonymous_cookie_capture_is_guest_session(tmp_path):
    har=tmp_path/'capture.har'
    har.write_text(json.dumps({'log':{'entries':[{'request':{'cookies':[{'name':'sid','value':'secret'}]},'response':{'headers':[]}}]}}))
    value=observe({'zap_auth_context':'anonymous'},[{'har_path':str(har)}])
    assert value['state'] == 'guest_session'
    assert 'secret' not in json.dumps(value)

