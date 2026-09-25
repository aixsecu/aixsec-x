"""Select and mutate one captured input without guessing duplicate locations."""
import json
from urllib.parse import parse_qsl, urlsplit, urlunsplit


def load_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON object keys require a raw-body verifier')
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def inputs(entry, parameter):
    req = entry['request']; post = req.get('postData') or {}
    result = []
    def pairs(text, location):
        for index, segment in enumerate(text.split('&')):
            values = parse_qsl(segment, keep_blank_values=True)
            if values and values[0][0] == parameter:
                result.append({'location':location,'index':index,'name':parameter})
    pairs(urlsplit(req['url']).query,'query')
    mime = post.get('mimeType','').split(';')[0].lower()
    text = post.get('text','')
    if mime == 'application/x-www-form-urlencoded':
        pairs(text,'form')
    elif 'json' in mime and text:
        obj = load_json(text)
        def walk(value, path, name):
            if isinstance(value,dict):
                for key, item in value.items(): walk(item, path+[key],key)
            elif isinstance(value,list):
                for index,item in enumerate(value): walk(item,path+[index],str(index))
            elif isinstance(value,(str,int,float)) and not isinstance(value,bool):
                pointer = '/' + '/'.join(str(p).replace('~','~0').replace('/','~1') for p in path)
                dotted='.'.join(str(p) for p in path)
                bracket=''.join(('['+str(p)+']') if isinstance(p,int) else ('.' if index else '')+p for index,p in enumerate(path))
                if parameter in (name,pointer,dotted,bracket,'$.'+bracket):
                    result.append({'location':'json','path':path,'pointer':pointer,'name':name})
        walk(obj,[],'')
    if not result:
        raise ValueError('No supported captured input matches the parameter')
    return result


def mutate(entry, selector):
    req = entry['request']; post = req.get('postData') or {}
    url, body = req['url'], post.get('text','')
    def change(text):
        parts = text.split('&'); index = selector['index']
        # Preserve all original bytes except the selected value; keep duplicate order.
        parts[index] += '%27' if '=' in parts[index] else '=%27'
        return '&'.join(parts)
    if selector['location']=='query':
        p=urlsplit(url);url=urlunsplit((p.scheme,p.netloc,p.path,change(p.query),p.fragment))
    elif selector['location']=='form': body=change(body)
    else:
        obj=load_json(body); target=obj
        for component in selector['path'][:-1]: target=target[component]
        component=selector['path'][-1]
        target[component]=str(target[component])+"'"
        body=json.dumps(obj,ensure_ascii=False,separators=(',',':'))
    return url,body
