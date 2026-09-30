"""Load one operator auth manifest into ZAP and HTTP runtime contexts."""
import json, os
from pathlib import Path
from urllib.parse import parse_qsl

class AuthPauseRequired(ValueError): pass


def load(config):
    path=config.get('zap_auth_file')
    if not path: return {'version':1,'contexts':{}}
    raw=json.loads(Path(path).read_text(encoding='utf-8'))
    contexts={}
    for name, profile in raw.items():
        if not isinstance(profile,dict): continue
        authentication=profile.get('authentication') or {}
        contexts[name]={'name':name,'origin':profile.get('origin',''),
            'zap':{'supported':authentication.get('method') in ('form','json','http','browser'),
                   'authentication':authentication,
                   'sessionManagement':profile.get('sessionManagement') or {'method':'cookie'}},
            'runtime':profile.get('runtime') or {},
            'operator_pause':profile.get('operator_pause') or {},
            'credential_env':profile.get('credential_env') or {}}
    return {'version':1,'source':str(Path(path).resolve()),'contexts':contexts}


def _marker(value, credentials):
    text=str(value)
    for key, env_name in credentials.items():
        text=text.replace('{%'+key+'%}','env:'+env_name)
    return text


def bind_runtime(manifest, manager):
    """Create isolated HTTP contexts from the same profiles used by ZAP."""
    bound=[]
    for name,row in manifest.get('contexts',{}).items():
        origin=row.get('origin'); runtime=row.get('runtime') or {}; credentials=row.get('credential_env') or {}
        auth=(row.get('zap') or {}).get('authentication') or {}; method=auth.get('method')
        transport=dict(runtime.get('transport') or {}); steps=list(runtime.get('login_steps') or [])
        if not runtime and method in ('form','json'):
            parameters=auth.get('parameters') or {}; body=parameters.get('loginRequestBody','')
            step={'method':'POST','url':parameters.get('loginRequestUrl') or parameters.get('loginPageUrl'),
                  'expected_status':list(range(200,400)),
                  'logged_in_regex':(auth.get('verification') or {}).get('loggedInRegex',''),
                  'logged_out_regex':(auth.get('verification') or {}).get('loggedOutRegex','')}
            if method=='form': step['form']={k:_marker(v,credentials) for k,v in parse_qsl(body,keep_blank_values=True)}
            else:
                try: step['json']={k:_marker(v,credentials) for k,v in json.loads(body).items()}
                except (ValueError,AttributeError): continue
            steps=[step]
        elif not runtime and method=='http':
            user=credentials.get('username'); password=credentials.get('password')
            if user and password: transport['auth']=f'basic:${{ENV:{user}}}:${{ENV:{password}}}'
        if not origin: continue
        verification=runtime.get('verification') or (auth.get('verification') or {})
        manager.configure(name,origin,transport=transport,login_steps=steps,
                          logout_step=runtime.get('logout_step'),verification=verification,replace=True)
        bound.append(name)
    return bound


def public(manifest):
    return {'version':manifest.get('version',1),'source':manifest.get('source',''),
            'contexts':[{ 'name':r['name'],'origin':r['origin'],
                'zap_supported':r['zap']['supported'],
                'runtime_configured':bool(r.get('runtime') or r['zap'].get('authentication')),
                'operator_pause':(r.get('operator_pause') or {}).get('kind',''),
                'credential_names':sorted((r.get('credential_env') or {}).keys())}
                for r in manifest.get('contexts',{}).values()]}

def require_ready(manifest, context):
    if context=='anonymous': return
    row=(manifest.get('contexts') or {}).get(context) or {}
    pause=row.get('operator_pause') or {}; env=pause.get('ready_env')
    if env and not os.environ.get(env):
        raise AuthPauseRequired(f'Authentication context {context} is paused for {pause.get("kind","operator action")}; use /auth Resume MFA first')
