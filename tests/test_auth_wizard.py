import json, os

from auth_wizard import load_profiles, save_profiles, validate_profile, import_cookies, build_profile


def profile():
    return {'origin':'https://example.test','authentication':{'method':'form','parameters':{},
        'verification':{'loggedInRegex':'Logout','loggedOutRegex':'Login'}},
        'sessionManagement':{'method':'cookie'},
        'credential_env':{'username':'TEST_AUTH_USER','password':'TEST_AUTH_PASS'}}


def test_auth_file_is_private_and_contains_references_only(tmp_path):
    path=save_profiles({'staff':profile()},tmp_path/'auth.json')
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_profiles(path)['staff']['authentication']['method'] == 'form'
    assert 'password-value' not in path.read_text()


def test_validation_requires_available_secret_environment(monkeypatch):
    monkeypatch.setenv('TEST_AUTH_USER','u'); monkeypatch.setenv('TEST_AUTH_PASS','p')
    assert validate_profile('staff',profile())['valid'] is True
    monkeypatch.delenv('TEST_AUTH_PASS')
    assert validate_profile('staff',profile())['valid'] is False


def test_cookie_import_is_origin_scoped_and_session_only(tmp_path, monkeypatch):
    source=tmp_path/'cookies.json'
    source.write_text(json.dumps([
        {'domain':'.example.test','name':'sid','value':'secret'},
        {'domain':'.outside.test','name':'foreign','value':'leak'}]))
    refs=import_cookies('guest','https://app.example.test',source)
    assert set(refs)=={'sid'}
    env=refs['sid'][6:-1]
    assert os.environ[env]=='secret'
    assert 'secret' not in json.dumps(refs)


def test_oauth_refresh_profile_uses_extracted_token_without_storing_secrets(monkeypatch):
    answers=iter(['https://api.example.test','https://api.example.test/oauth/token','1'])
    monkeypatch.setattr('builtins.input',lambda prompt='':next(answers))
    raw=['raw-client-123','raw-secret-456','raw-refresh-789']; secrets=iter(raw)
    monkeypatch.setattr('auth_wizard.getpass',lambda prompt='':next(secrets))
    value=build_profile('api','oauth_refresh')
    text=json.dumps(value)
    assert value['runtime']['login_steps'][0]['extract']['access_token']['path']=='access_token'
    assert value['runtime']['transport']['headers']['Authorization']=='Bearer {{access_token}}'
    assert not any(secret in text for secret in raw)
