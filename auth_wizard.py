"""Interactive, non-secret ZAP authentication profile management."""
from getpass import getpass
import json, os, re
from pathlib import Path

DEFAULT_AUTH_FILE = Path('.aixsec-auth.json')
SUPPORTED_METHODS = ('form', 'json', 'http', 'browser')
RUNTIME_METHODS = ('bearer', 'api_key', 'cookie', 'oauth_refresh')

def load_profiles(path):
    path = Path(path)
    if not path.exists(): return {}
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, dict) for k,v in data.items()):
        raise ValueError('Auth profile file must be an object of named profiles')
    return data

def save_profiles(profiles, path):
    path=Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temporary=path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(profiles,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    os.chmod(temporary,0o600); temporary.replace(path); os.chmod(path,0o600)
    return path.resolve()

def _value(prompt, default=''):
    return input(prompt+(f' [{default}]' if default else '')+': ').strip() or default

def _credentials(name, existing=None, fields=('username','password')):
    existing=existing or {}; mode=_value('Credential: 1 session-only, 2 environment references','1'); result={}
    for field in fields:
        if mode == '2':
            env_name=_value(f'Environment variable for {field}',existing.get(field,''))
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',env_name or ''): raise ValueError('Invalid environment variable name')
        else:
            env_name='AIXSEC_SESSION_'+re.sub(r'\W+','_',name).upper()+'_'+field.upper()
            secret=getpass(f'{field} (session only): ')
            if not secret: raise ValueError(f'{field} cannot be empty')
            os.environ[env_name]=secret
        result[field]=env_name
    return result

def build_profile(name, method, old=None):
    old=old or {}; method=method.lower()
    aliases={'basic':'http','json_api':'json','sso':'browser'}; method=aliases.get(method,method)
    if method=='oauth_refresh':
        origin=_value('Application origin',old.get('origin','')); token_url=_value('OAuth/OIDC token endpoint')
        credentials=_credentials(name,old.get('credential_env'),('client_id','client_secret','refresh_token'))
        form={'grant_type':'refresh_token','client_id':f'${{ENV:{credentials["client_id"]}}}',
              'client_secret':f'${{ENV:{credentials["client_secret"]}}}',
              'refresh_token':f'${{ENV:{credentials["refresh_token"]}}}'}
        return {'origin':origin,'authentication':{'method':'manual','parameters':{},'verification':{}},
            'runtime':{'transport':{'headers':{'Authorization':'Bearer {{access_token}}'}},
                'login_steps':[{'method':'POST','url':token_url,'form':form,'expected_status':[200],
                    'extract':{'access_token':{'from':'json','path':'access_token'}}}]},
            'credential_env':credentials}
    if method in RUNTIME_METHODS:
        origin=_value('Application origin',old.get('origin',''))
        field='token' if method=='bearer' else 'value'; credentials=_credentials(name,old.get('credential_env'),(field,))
        if method=='bearer': transport={'auth':f'bearer:${{ENV:{credentials[field]}}}'}
        elif method=='api_key':
            header=_value('API key header name','X-API-Key'); transport={'auth':f'api_key:{header}:${{ENV:{credentials[field]}}}'}
        else:
            cookie=_value('Cookie name','session'); transport={'cookies':{cookie:f'${{ENV:{credentials[field]}}}'}}
        return {'origin':origin,'authentication':{'method':'manual','parameters':{},'verification':{}},
                'runtime':{'transport':transport},'credential_env':credentials}
    if method not in SUPPORTED_METHODS: raise ValueError('Supported: form, json, basic/http, browser, bearer, api_key, cookie')
    previous_auth=old.get('authentication') or {}
    profile={'origin':_value('Application origin',old.get('origin',''))}; params=dict(previous_auth.get('parameters') or {})
    if method in ('form','json'):
        params['loginPageUrl']=_value('Login page URL',params.get('loginPageUrl',''))
        params['loginRequestUrl']=_value('Login request URL',params.get('loginRequestUrl',''))
        user=_value('Username field','username'); password=_value('Password field','password')
        params['loginRequestBody']=(f'{user}={{%username%}}&{password}={{%password%}}' if method=='form'
                                    else json.dumps({user:'{%username%}',password:'{%password%}'}))
    elif method == 'http':
        params['hostname']=_value('HTTP auth hostname',params.get('hostname',''))
        params['realm']=_value('HTTP auth realm (optional)',params.get('realm',''))
    else:
        params['loginPageUrl']=_value('Browser/SSO login URL',params.get('loginPageUrl',''))
    profile['authentication']={'method':method,'parameters':params,'verification':{
        'loggedInRegex':_value('Logged-in indicator regex',(previous_auth.get('verification') or {}).get('loggedInRegex','')),
        'loggedOutRegex':_value('Logged-out indicator regex',(previous_auth.get('verification') or {}).get('loggedOutRegex',''))}}
    profile['sessionManagement']=old.get('sessionManagement') or {'method':'cookie'}
    profile['credential_env']=_credentials(name,old.get('credential_env'))
    if method=='browser' and _value('MFA requires operator pause? y/n','n').lower() in ('y','yes','1'):
        profile['operator_pause']={'kind':'mfa','ready_env':'AIXSEC_MFA_'+re.sub(r'\W+','_',name).upper()+'_READY'}
    return profile

def import_cookies(name, origin, cookie_path):
    from urllib.parse import urlsplit
    path=Path(cookie_path); host=(urlsplit(origin).hostname or '').lower(); values={}
    text=path.read_text(encoding='utf-8')
    try:
        data=json.loads(text)
        rows=data if isinstance(data,list) else [{'name':k,'value':v,'domain':host} for k,v in data.items()]
        for row in rows:
            domain=str(row.get('domain') or host).lstrip('.').lower()
            if host==domain or host.endswith('.'+domain): values[str(row['name'])]=str(row['value'])
    except (ValueError,TypeError,KeyError,AttributeError):
        for line in text.splitlines():
            if not line or line.startswith('#'): continue
            parts=line.split('\t')
            if len(parts)>=7:
                domain=parts[0].lstrip('.').lower()
                if host==domain or host.endswith('.'+domain): values[parts[5]]=parts[6]
    if not values or len(values)>50: raise ValueError('Cookie import found no scoped cookies or exceeded 50 cookies')
    refs={}
    for cookie,value in values.items():
        env='AIXSEC_SESSION_'+re.sub(r'\W+','_',name).upper()+'_COOKIE_'+re.sub(r'\W+','_',cookie).upper()
        os.environ[env]=value; refs[cookie]=f'${{ENV:{env}}}'
    return refs

def validate_profile(name, profile):
    errors=[]; authentication=profile.get('authentication') or {}; verification=authentication.get('verification') or {}
    runtime_only=authentication.get('method')=='manual' and bool(profile.get('runtime'))
    if authentication.get('method') not in SUPPORTED_METHODS and not runtime_only: errors.append('unsupported method')
    if not profile.get('origin'): errors.append('missing origin')
    if not runtime_only and (not verification.get('loggedInRegex') or not verification.get('loggedOutRegex')): errors.append('both login indicators are required')
    missing=[v for v in (profile.get('credential_env') or {}).values() if not os.environ.get(v)]
    if missing: errors.append('missing credential environment: '+', '.join(missing))
    return {'name':name,'valid':not errors,'errors':errors}

def interactive(config):
    path=Path(config.get('zap_auth_file') or DEFAULT_AUTH_FILE); profiles=load_profiles(path)
    while True:
        selected=str(config.get('zap_auth_context') or 'anonymous')
        print(f'\nAUTH — selected: {selected}; file: {path}')
        print('1 List  2 Add/edit  3 Test  4 Select  5 Remove  6 Guest  7 Resume MFA  8 Import cookies  0 Done')
        action=input('Choose: ').strip() or '0'
        if action=='0': break
        if action=='1':
            print('  anonymous (guest)')
            for name,p in sorted(profiles.items()): print(('*' if name==selected else ' '),f'{name}: {(p.get("authentication") or {}).get("method","?")} @ {p.get("origin","?")}')
        elif action=='2':
            name=_value('Profile name')
            if not re.fullmatch(r'[A-Za-z0-9_.-]+',name): print('[!] Invalid profile name.'); continue
            method=_value('Method form/json/basic/browser/sso/bearer/api_key/cookie/oauth_refresh',(profiles.get(name,{}).get('authentication') or {}).get('method','form'))
            profiles[name]=build_profile(name,method,profiles.get(name)); save_profiles(profiles,path)
            print('[✓] Profile saved without secret values.')
        elif action=='3':
            name=_value('Profile name',selected if selected!='anonymous' else '')
            check=validate_profile(name,profiles.get(name,{})); print('[✓] Ready for discovery verification.' if check['valid'] else '[!] '+'; '.join(check['errors']))
        elif action=='4':
            name=_value('Profile name')
            if name not in profiles: print('[!] Unknown profile.'); continue
            if (profiles[name].get('authentication') or {}).get('method') not in SUPPORTED_METHODS:
                print('[!] Runtime-only profile: usable by HTTP verification, not selectable for ZAP scan.'); continue
            pause=profiles[name].get('operator_pause') or {}
            if pause and not os.environ.get(pause.get('ready_env','')):
                print('[!] MFA đang pause. Hoàn tất bước MFA rồi chọn action 7.'); continue
            config.update(zap_auth_context=name,zap_auth_file=str(path.resolve()))
        elif action=='5':
            name=_value('Profile name'); profiles.pop(name,None); save_profiles(profiles,path)
            if selected==name: config['zap_auth_context']='anonymous'
        elif action=='6': config['zap_auth_context']='anonymous'
        elif action=='7':
            name=_value('Profile name',selected if selected!='anonymous' else '')
            pause=(profiles.get(name) or {}).get('operator_pause') or {}; env=pause.get('ready_env')
            if not env: print('[!] Profile không cấu hình MFA pause.'); continue
            os.environ[env]='1'; print('[✓] MFA resume chỉ có hiệu lực trong process hiện tại.')
        elif action=='8':
            name=_value('Profile name'); origin=_value('Application origin'); cookie_path=_value('Cookie JSON/Netscape file')
            cookies=import_cookies(name,origin,cookie_path)
            profiles[name]={'origin':origin,'authentication':{'method':'manual','parameters':{},'verification':{}},
                'runtime':{'transport':{'cookies':cookies}},'credential_env':{}}
            save_profiles(profiles,path); print(f'[✓] Imported {len(cookies)} scoped cookie names; values remain session-only.')
    if profiles: config['zap_auth_file']=str(path.resolve())
    return config
