"""Deterministic structural Route Families built from captured request groups."""
from __future__ import annotations

from html.parser import HTMLParser
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qsl, unquote, urlsplit


_UUID=re.compile(r'^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$',re.I)
_HEX_ID=re.compile(r'^[0-9a-f]{16,}$',re.I)
_TOKEN_ID=re.compile(r'^[A-Za-z0-9_-]{24,}$')
_UNIX_TIME=re.compile(r'^(?:1[5-9]\d{8}|2\d{9}|1[5-9]\d{11}|2\d{12})$')
_ISO_TIME=re.compile(r'^\d{4}-\d{2}-\d{2}(?:T|%20| )\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?$')
_NUMERIC_ID=re.compile(r'^\d+$')
_GENERATED_ELEMENT_ID=re.compile(r'^(?:ember|react|vue|ng|ext|yui|generated)[_:-]?\d+$',re.I)
_UNSTABLE_NAMES=re.compile(r'(?:^|[_-])(csrf|xsrf|nonce|timestamp|time|uuid|random|request[_-]?id|etag)(?:$|[_-])',re.I)
_ROUTING_NAMES={'action','act','type','view','route','controller','task','operation','op'}


def _hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


def _unstable(value,name=''):
    text=unquote(str(value or ''))
    if name.lower()=='id' and _GENERATED_ELEMENT_ID.fullmatch(text): return '{generated-id}'
    if _UNSTABLE_NAMES.search(name): return '{unstable}'
    if _UUID.fullmatch(text): return '{uuid}'
    if _UNIX_TIME.fullmatch(text) or _ISO_TIME.fullmatch(text): return '{timestamp}'
    if _HEX_ID.fullmatch(text) or (_TOKEN_ID.fullmatch(text) and any(c.isdigit() for c in text)):
        return '{random-id}'
    return None


def _path_tokens(path):
    values=[]
    for token in (unquote(v) for v in (path or '/').split('/') if v):
        normalized=_unstable(token)
        # A path consisting entirely of digits is a structural resource id, but
        # words/slugs remain literal application semantics.
        if normalized is None and _NUMERIC_ID.fullmatch(token): normalized='{numeric-id}'
        values.append(normalized or token)
    return values


def _request_parameters(request):
    query=[]
    for name,value in parse_qsl(urlsplit(request.get('url','')).query,keep_blank_values=True):
        query.append([name, value if name.lower() in _ROUTING_NAMES else (_unstable(value,name) or '{value}')])
    post=request.get('postData') or {};mime=str(post.get('mimeType') or '').split(';')[0].lower()
    body=[]
    pairs=[(str(row.get('name') or ''),str(row.get('value') or '')) for row in post.get('params',[]) if row.get('name')]
    if mime=='application/x-www-form-urlencoded' and not pairs:
        pairs=parse_qsl(str(post.get('text') or ''),keep_blank_values=True)
    if 'json' in mime:
        try: value=json.loads(post.get('text') or '')
        except (TypeError,ValueError): value=None
        def walk(item,prefix=''):
            if isinstance(item,dict):
                for key,child in sorted(item.items()): walk(child,prefix+'/'+str(key))
            elif isinstance(item,list):
                for child in item: walk(child,prefix+'/*')
            else:
                name=prefix.rsplit('/',1)[-1]
                body.append([prefix,item if name.lower() in _ROUTING_NAMES else (_unstable(item,name) or type(item).__name__)])
        walk(value)
    else:
        for name,value in pairs:
            body.append([name,value if name.lower() in _ROUTING_NAMES else (_unstable(value,name) or '{value}')])
    return sorted(query),mime,sorted(body)


class _DOM(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True);self.nodes=[];self.forms=[];self.inputs=[];self._form=None
    def handle_starttag(self,tag,attrs):
        values=dict(attrs);identity=values.get('id','')
        identity=_unstable(identity,'id') or identity
        self.nodes.append([tag,sorted(values),identity])
        if tag=='form':
            action=urlsplit(values.get('action',''))
            action_query=[[name,value if name.lower() in _ROUTING_NAMES else (_unstable(value,name) or '{value}')]
                          for name,value in parse_qsl(action.query,keep_blank_values=True)]
            self._form={'method':values.get('method','GET').upper(),
                'action':{'path_tokens':_path_tokens(action.path),'query':sorted(action_query)},'inputs':[]}
            self.forms.append(self._form)
        if tag in ('input','select','textarea','button'):
            item=[tag,values.get('type',tag),values.get('name',''),_unstable(values.get('id',''),'id') or values.get('id','')]
            self.inputs.append(item)
            if self._form is not None:self._form['inputs'].append(item)
    def handle_endtag(self,tag):
        if tag=='form':self._form=None


def _response_shape(response):
    headers={str(h.get('name') or '').lower():str(h.get('value') or '') for h in response.get('headers',[])}
    content=response.get('content') or {};mime=str(content.get('mimeType') or headers.get('content-type','')).split(';')[0].lower()
    text=str(content.get('text') or '')
    dom_hash='';forms=[];inputs=[]
    if 'html' in mime and text:
        parser=_DOM()
        try:parser.feed(text);parser.close()
        except (ValueError,TypeError):pass
        dom_hash=_hash(parser.nodes);forms=parser.forms;inputs=parser.inputs
    # Template normalization is deliberately narrow: only known unstable token
    # forms are removed. Literal words, paths, labels, and business actions stay.
    template=text
    def stable_tag(match):
        tag=match.group(0)
        named=re.search(r'(?i)\bname\s*=\s*(["\'])([^"\']+)\1',tag)
        if named and _UNSTABLE_NAMES.search(named.group(2)):
            tag=re.sub(r'(?i)\bvalue\s*=\s*(["\'])([^"\']*)\1',lambda value:
                'value='+value.group(1)+'{unstable}'+value.group(1),tag)
        return tag
    template=re.sub(r'<[^>]+>',stable_tag,template)
    template=re.sub(r'(?i)(csrf|xsrf|nonce|etag)(["\'\s:=_-]+)[A-Za-z0-9._~+/-]+',r'\1\2{unstable}',template)
    template=re.sub(r'\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b','{uuid}',template,flags=re.I)
    template=re.sub(r'\b(?:1[5-9]\d{8}|2\d{9}|1[5-9]\d{11}|2\d{12})\b','{timestamp}',template)
    template=re.sub(r'\b[A-Za-z0-9_-]{24,}\b',lambda match:_unstable(match.group(0)) or match.group(0),template)
    def stable_id(match):
        quote,value=match.group(1),match.group(2)
        return 'id='+quote+(_unstable(value,'id') or value)+quote
    template=re.sub(r'(?i)\bid\s*=\s*(["\'])([^"\']+)\1',stable_id,template)
    return {'status':int(response.get('status') or 0),'content_type':mime,
        'etag':'{etag}' if headers.get('etag') else '',
        'dom_fingerprint':dom_hash,'form_signatures':forms,'input_signatures':inputs,
        'response_template_fingerprint':_hash(template) if template else ''}


def fingerprint(entry,auth_context='anonymous'):
    request=entry.get('request') or {};response=entry.get('response') or {};parsed=urlsplit(request.get('url',''))
    query,mime,body=_request_parameters(request)
    if not mime:
        headers={str(h.get('name') or '').lower():str(h.get('value') or '') for h in request.get('headers',[])}
        mime=headers.get('content-type','').split(';')[0].lower()
    shape={'method':str(request.get('method') or 'UNKNOWN').upper(),
        'request_content_type':mime,'path_depth':len([v for v in parsed.path.split('/') if v]),
        'path_tokens':_path_tokens(parsed.path),'query_parameters':query,'body_parameters':body,
        'parameter_locations':{'query':sorted({v[0] for v in query}),'body':sorted({v[0] for v in body})},
        'auth_context':auth_context,'response':_response_shape(response)}
    return shape,_hash(shape)


class RouteFamilyBuilder:
    def build(self,entries):
        groups={}
        for request_id,row in sorted(entries.items()):
            shape,value=fingerprint(row.get('_entry') or {},row.get('auth_context','anonymous'))
            family_id='rf-'+value[:20]
            member={'request_id':request_id,'url':row.get('url',''),'method':row.get('method',''),
                    'auth_context':row.get('auth_context','anonymous')}
            family=groups.setdefault(value,{'family_id':family_id,'fingerprint':value,
                'structure':shape,'members':[],'representative_candidates':[]})
            family['members'].append(member);row['route_family_id']=family_id
        return {'version':1,'algorithm':'deterministic-structural-v1','families':list(groups.values()),
                'request_groups':len(entries),'family_count':len(groups)}

    def write(self,entries,path):
        result=self.build(entries);path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        temporary=path.with_suffix(path.suffix+'.tmp')
        temporary.write_text(json.dumps(result,ensure_ascii=False,indent=2));temporary.chmod(0o600);temporary.replace(path)
        return result
