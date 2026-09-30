"""One conservative cookie/session classifier shared by the scan pipeline."""
from __future__ import annotations

import re

TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
SESSION = re.compile(r'(?:^|[._-])(session|sess|sid|auth|jwt|token)(?:$|[._-])|phpsessid|jsessionid|asp\.net_sessionid', re.I)
CSRF = re.compile(r'csrf|xsrf', re.I)
AFFINITY = re.compile(r'arrAffinity|awsalb|awsalbcors|bigip|jroute|routeid|sticky', re.I)
ANALYTICS = re.compile(r'^_(?:ga|gid|gat)|analytics|amplitude|^mp_', re.I)
PREFERENCE = re.compile(r'lang|locale|theme|consent|preference|^pref', re.I)


def split_set_cookie(value):
    """Split a possibly combined Set-Cookie field without splitting Expires/quotes."""
    value = str(value or '')
    if not value:
        return []
    parts=[]; start=0; quoted=False; escaped=False
    for index,char in enumerate(value):
        if escaped:
            escaped=False; continue
        if char == '\\' and quoted:
            escaped=True; continue
        if char == '"':
            quoted=not quoted; continue
        if char != ',' or quoted:
            continue
        remainder=value[index+1:]
        match=re.match(r'\s*([^=;,\s]+)\s*=',remainder)
        if match and TOKEN.fullmatch(match.group(1)):
            parts.append(value[start:index].strip());start=index+1
    parts.append(value[start:].strip())
    return [part for part in parts if part]


def parse_set_cookie(headers):
    """Return name-only records; malformed input is explicitly unknown."""
    values=[]
    if isinstance(headers,dict):
        for key,value in headers.items():
            if str(key).lower() == 'set-cookie':
                values.extend(value if isinstance(value,list) else [value])
    else:
        for header in headers or []:
            if isinstance(header,dict) and str(header.get('name','')).lower() == 'set-cookie':
                values.append(header.get('value',''))
    records=[]
    for value in values:
        for cookie in split_set_cookie(value):
            first=cookie.split(';',1)[0].strip()
            if '=' not in first:
                records.append({'name':'','valid':False});continue
            name=first.split('=',1)[0].strip()
            records.append({'name':name if TOKEN.fullmatch(name) else '',
                            'valid':bool(TOKEN.fullmatch(name))})
    return records


def classify_name(name):
    if CSRF.search(name): return 'csrf'
    if AFFINITY.search(name): return 'affinity'
    if ANALYTICS.search(name): return 'analytics'
    if PREFERENCE.search(name): return 'preference'
    if SESSION.search(name): return 'session'
    return 'unknown'


def request_cookie_names(request):
    names={str(row.get('name','')) for row in request.get('cookies',[]) if row.get('name')}
    for header in request.get('headers',[]):
        if str(header.get('name','')).lower() == 'cookie':
            for part in str(header.get('value','')).split(';'):
                if '=' in part:
                    name=part.split('=',1)[0].strip()
                    if TOKEN.fullmatch(name): names.add(name)
    return names


def _cookie_header_parts(value):
    value=str(value or '');parts=[];start=0;quoted=False;escaped=False
    for index,char in enumerate(value):
        if escaped:escaped=False;continue
        if char == '\\' and quoted:escaped=True;continue
        if char == '"':quoted=not quoted;continue
        if char == ';' and not quoted:
            parts.append(value[start:index].strip());start=index+1
    parts.append(value[start:].strip())
    return [part for part in parts if part]


def isolate_guest_entries(entries):
    """Strip captured session/CSRF state from private guest-worker seeds."""
    removed=set()
    for entry in entries:
        request=entry.get('request') or {};response=entry.get('response') or {}
        kept=[]
        for row in request.get('cookies',[]):
            name=str(row.get('name') or '')
            if classify_name(name) in {'session','csrf'}:removed.add(name)
            else:kept.append(row)
        request['cookies']=kept
        request_headers=[]
        for header in request.get('headers',[]):
            if str(header.get('name','')).lower() != 'cookie':
                request_headers.append(header);continue
            parts=[]
            for part in _cookie_header_parts(header.get('value','')):
                name=part.split('=',1)[0].strip() if '=' in part else ''
                if classify_name(name) in {'session','csrf'}:removed.add(name)
                else:parts.append(part)
            if parts:request_headers.append({**header,'value':'; '.join(parts)})
        request['headers']=request_headers
        kept=[]
        for row in response.get('cookies',[]):
            name=str(row.get('name') or '')
            if classify_name(name) in {'session','csrf'}:removed.add(name)
            else:kept.append(row)
        response['cookies']=kept
        response_headers=[]
        for header in response.get('headers',[]):
            if str(header.get('name','')).lower() != 'set-cookie':
                response_headers.append(header);continue
            parts=[]
            for part in split_set_cookie(header.get('value','')):
                first=part.split(';',1)[0]
                name=first.split('=',1)[0].strip() if '=' in first else ''
                if classify_name(name) in {'session','csrf'}:removed.add(name)
                else:parts.append(part)
            if parts:response_headers.append({**header,'value':', '.join(parts)})
        response['headers']=response_headers
    return {'isolated':True,'removed_cookie_names':sorted(name for name in removed if name)}


def classify_entry(entry):
    request=(entry.get('_entry') or entry).get('request') or {}
    response=(entry.get('_entry') or entry).get('response') or {}
    names=request_cookie_names(request)
    parsed=parse_set_cookie(response.get('headers',[]))
    if any(not row['valid'] for row in parsed): return 'unknown'
    names.update(row['name'] for row in parsed if row['name'])
    classes={classify_name(name) for name in names}
    if entry.get('auth_context','anonymous') != 'anonymous': return 'authenticated_session'
    if not classes: return 'stateless'
    if classes <= {'analytics'}: return 'analytics'
    if classes <= {'preference'}: return 'preference'
    if classes <= {'affinity'}: return 'affinity'
    if classes <= {'analytics','preference','affinity'}: return 'benign_cookie'
    if 'csrf' in classes: return 'csrf'
    if 'session' in classes: return 'guest_session'
    return 'unknown'


def classify_mutation(row):
    response={str(v) for v in row.get('set_cookie_names',[]) if v}
    request={str(v) for v in row.get('request_cookie_names',[]) if v}
    if not response and row.get('response_headers'):
        parsed=parse_set_cookie(row['response_headers'])
        if any(not item['valid'] for item in parsed): return 'unknown',-1
        response={item['name'] for item in parsed if item['name']}
    if not response and row.get('set_cookie'): return 'unknown',-1
    classes={name:classify_name(name) for name in response}
    kinds=set(classes.values())
    if 'session' in kinds:
        sessions={name for name,kind in classes.items() if kind=='session'}
        return ('session_refresh',-1) if sessions & request else ('session_mutation',-3)
    if 'csrf' in kinds: return 'csrf_rotation',-1
    if 'unknown' in kinds: return 'unknown',-1
    if 'affinity' in kinds: return 'affinity',0
    if 'analytics' in kinds: return 'analytics',0
    if 'preference' in kinds: return 'preference',0
    return 'none',0
