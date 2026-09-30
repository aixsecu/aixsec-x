"""Private, worker-slot-local CSRF extraction and request rewriting."""
from __future__ import annotations

from html.parser import HTMLParser
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TOKEN_NAME = re.compile(r'csrf|xsrf|requestverificationtoken', re.I)


class _HiddenTokens(HTMLParser):
    def __init__(self):
        super().__init__();self.tokens={}
    def handle_starttag(self, tag, attrs):
        if tag.lower() != 'input': return
        values={str(k).lower():str(v or '') for k,v in attrs}
        name=values.get('name','')
        if TOKEN_NAME.search(name) and values.get('value'):
            self.tokens[name]=values['value']


def _json_tokens(value, output):
    if isinstance(value,dict):
        for key,child in value.items():
            if TOKEN_NAME.search(str(key)) and isinstance(child,(str,int,float)):
                output[str(key)]=str(child)
            else:_json_tokens(child,output)
    elif isinstance(value,list):
        for child in value:_json_tokens(child,output)


def extract(entry):
    response=entry.get('response') or {};content=response.get('content') or {}
    text=str(content.get('text') or '');mime=str(content.get('mimeType') or '').lower()
    tokens={}
    if 'html' in mime or '<input' in text.lower():
        parser=_HiddenTokens()
        try:parser.feed(text);tokens.update(parser.tokens)
        except (ValueError,TypeError):pass
    if 'json' in mime or text.lstrip().startswith(('{','[')):
        try:_json_tokens(json.loads(text),tokens)
        except (ValueError,TypeError):pass
    for header in response.get('headers',[]):
        name=str(header.get('name') or '')
        if TOKEN_NAME.search(name) and header.get('value'):
            tokens[name]=str(header['value'])
    return tokens


def rewrite(request, tokens):
    """Rewrite only names already present in a request; never add new inputs."""
    changed=0
    parsed=urlsplit(str(request.get('url') or ''))
    pairs=parse_qsl(parsed.query,keep_blank_values=True)
    updated=[]
    for name,value in pairs:
        replacement=next((token for key,token in tokens.items() if key.lower()==name.lower()),None)
        updated.append((name,replacement if replacement is not None else value));changed+=replacement is not None
    if changed:request['url']=urlunsplit(parsed._replace(query=urlencode(updated,doseq=True)))
    for header in request.get('headers',[]):
        name=str(header.get('name') or '')
        if TOKEN_NAME.search(name):
            replacement=next((token for key,token in tokens.items() if key.lower()==name.lower()),None)
            if replacement is not None:header['value']=replacement;changed+=1
    post=request.get('postData') or {};mime=str(post.get('mimeType') or '').lower()
    if 'application/x-www-form-urlencoded' in mime:
        pairs=parse_qsl(str(post.get('text') or ''),keep_blank_values=True);updated=[]
        for name,value in pairs:
            replacement=next((token for key,token in tokens.items() if key.lower()==name.lower()),None)
            updated.append((name,replacement if replacement is not None else value));changed+=replacement is not None
        if pairs:post['text']=urlencode(updated,doseq=True)
    elif 'json' in mime:
        try:value=json.loads(str(post.get('text') or ''))
        except (ValueError,TypeError):value=None
        def visit(node):
            nonlocal changed
            if isinstance(node,dict):
                for key,child in list(node.items()):
                    replacement=next((token for name,token in tokens.items() if name.lower()==str(key).lower()),None)
                    if replacement is not None:node[key]=replacement;changed+=1
                    else:visit(child)
            elif isinstance(node,list):
                for child in node:visit(child)
        if value is not None:visit(value);post['text']=json.dumps(value,separators=(',',':'))
    return changed


def bind(entries):
    """Apply response→request token flow inside one ordered worker session."""
    tokens={};rewritten=0;requests_with_unbound=0
    for entry in entries:
        request=entry.get('request') or {}
        has_csrf=(TOKEN_NAME.search(urlsplit(str(request.get('url') or '')).query or '') or
                  any(TOKEN_NAME.search(str(h.get('name') or '')) for h in request.get('headers',[])) or
                  TOKEN_NAME.search(str((request.get('postData') or {}).get('text') or '')))
        changed=rewrite(request,tokens) if tokens else 0
        rewritten+=changed
        if has_csrf and not changed: requests_with_unbound+=1
        tokens.update(extract(entry))
    return {'tokens_observed':len(tokens),'request_fields_rewritten':rewritten,
            'requests_with_unbound_csrf':requests_with_unbound,
            'values_retained_in_memory_only':True}
