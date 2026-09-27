"""Deterministic structural Route Families built from captured request groups."""
from __future__ import annotations

from html.parser import HTMLParser
import hashlib
import json
import math
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
    _VOID={'area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'}
    def __init__(self):
        super().__init__(convert_charrefs=True);self.nodes=[];self.forms=[];self.inputs=[];self._form=None
        self.depth=0;self.max_depth=0;self.attribute_count=0
    def handle_starttag(self,tag,attrs):
        self.depth+=1;self.max_depth=max(self.max_depth,self.depth);self.attribute_count+=len(attrs)
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
        if tag in self._VOID:self.depth=max(0,self.depth-1)
    def handle_endtag(self,tag):
        if tag=='form':self._form=None
        self.depth=max(0,self.depth-1)

    def handle_startendtag(self,tag,attrs):
        self.handle_starttag(tag,attrs)
        if tag not in self._VOID:self.depth=max(0,self.depth-1)


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


def _member_metrics(entry):
    request=entry.get('request') or {};response=entry.get('response') or {}
    query,mime,body=_request_parameters(request)
    content=response.get('content') or {};text=str(content.get('text') or '')
    response_mime=str(content.get('mimeType') or '').lower();parser=_DOM()
    if 'html' in response_mime and text:
        try:parser.feed(text);parser.close()
        except (ValueError,TypeError):pass
    parameter_names={location+':'+str(item[0]) for location,items in (('query',query),('body',body)) for item in items}
    url_depth=len([part for part in urlsplit(request.get('url','')).path.split('/') if part])
    response_complexity=(len(parser.nodes)+parser.attribute_count+parser.max_depth+
                         len(response.get('headers') or [])+max(1,text.count('\n')+1 if text else 0))
    measured_size=len(text.encode('utf-8'))
    try:reported_size=max(0,int(content.get('size',response.get('bodySize',0)) or 0))
    except (TypeError,ValueError):reported_size=0
    metrics={'response_size':max(measured_size,reported_size),'form_count':len(parser.forms),
             'input_count':len(parser.inputs),'parameter_count':len(query)+len(body),
             'response_complexity':response_complexity,'unique_parameter_names':len(parameter_names),
             'dom_complexity':len(parser.nodes)+parser.attribute_count+parser.max_depth,
             'url_depth':url_depth}
    coverage={'status:'+str(response.get('status') or 0),'response-type:'+response_mime,
              'request-type:'+mime,'url-depth:'+str(url_depth)}
    coverage.update('parameter:'+name for name in parameter_names)
    coverage.update('dom-tag:'+node[0] for node in parser.nodes)
    coverage.update('input:'+':'.join(map(str,item[:3])) for item in parser.inputs)
    coverage.update('form:'+str(form.get('method'))+':'+_hash(form) for form in parser.forms)
    return metrics,coverage


def _score(metrics):
    # Log scaling keeps response bytes from overwhelming richer structural signals.
    weights={'response_size':1.0,'form_count':5.0,'input_count':4.0,'parameter_count':4.0,
             'response_complexity':2.0,'unique_parameter_names':5.0,
             'dom_complexity':2.0,'url_depth':1.5}
    components={name:round(weights[name]*math.log2(1+value),6) for name,value in metrics.items()}
    return round(sum(components.values()),6),components


class RepresentativeSelector:
    """Choose deterministic request-group representatives without changing them."""
    def __init__(self,small=1,medium=2,large=3,extra_large=4):
        self.limits=(max(1,int(small)),max(1,int(medium)),max(1,int(large)),max(1,int(extra_large)))

    def _limit(self,size):
        if size<=5:return self.limits[0]
        if size<=30:return self.limits[1]
        if size<=100:return self.limits[2]
        return self.limits[3]

    def select(self,entries,family_report):
        selected=[];families=[];covered_total=set();available_total=set()
        for family in family_report.get('families',[]):
            scored=[]
            for member in family['members']:
                request_id=member['request_id'];raw=(entries[request_id].get('_entry') or {})
                metrics,coverage=_member_metrics(raw);score,components=_score(metrics)
                scored.append({'request_id':request_id,'score':score,'score_breakdown':components,
                               'metrics':metrics,'_coverage':coverage})
                available_total.update(coverage)
            chosen=[];covered=set();remaining=list(scored)
            while remaining and len(chosen)<min(self._limit(len(scored)),len(scored)):
                # Maximize new structural features first, richness score second, request id last.
                candidate=min(remaining,key=lambda item:(-len(item['_coverage']-covered),-item['score'],item['request_id']))
                remaining.remove(candidate);chosen.append(candidate);covered.update(candidate['_coverage'])
            chosen_ids=[item['request_id'] for item in chosen];selected.extend(chosen_ids);covered_total.update(covered)
            family['representative_candidates']=chosen_ids
            member_urls=sorted({str(member.get('url') or '') for member in family['members'] if member.get('url')})
            for member in family['members']:
                entries[member['request_id']]['route_family_member_count']=len(scored)
                entries[member['request_id']]['route_family_member_urls']=member_urls
            for request_id in chosen_ids:
                entries[request_id]['representative_id']=request_id
            families.append({'family_id':family['family_id'],'member_count':len(scored),
                'limit':self._limit(len(scored)),'representatives':chosen_ids,
                'scored_members':[{k:v for k,v in item.items() if k!='_coverage'}
                                  for item in sorted(scored,key=lambda item:item['request_id'])],
                'coverage_estimate':round(100*len(covered)/len(set().union(*(v['_coverage'] for v in scored))),2)
                                    if scored and set().union(*(v['_coverage'] for v in scored)) else 100.0})
        before=len(entries);after=len(selected)
        return {'version':1,'algorithm':'deterministic-greedy-structural-coverage-v1',
                'limits':{'1-5':self.limits[0],'6-30':self.limits[1],
                          '31-100':self.limits[2],'100+':self.limits[3]},
                'scan_groups_before':before,'scan_groups_after':after,
                'reduction':before-after,
                'coverage_estimate':round(100*len(covered_total)/len(available_total),2) if available_total else 100.0,
                'representative_request_ids':selected,'families':families}

    def write(self,entries,family_report,path,family_path=None):
        result=self.select(entries,family_report)
        self.persist(result,path)
        if family_path is not None:
            family_path=Path(family_path);temporary=family_path.with_suffix(family_path.suffix+'.tmp')
            temporary.write_text(json.dumps(family_report,ensure_ascii=False,indent=2));temporary.chmod(0o600)
            temporary.replace(family_path)
        return result

    @staticmethod
    def persist(result,path):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        temporary=path.with_suffix(path.suffix+'.tmp')
        temporary.write_text(json.dumps(result,ensure_ascii=False,indent=2));temporary.chmod(0o600);temporary.replace(path)
