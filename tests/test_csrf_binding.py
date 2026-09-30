import json
from urllib.parse import parse_qs

from csrf_binding import bind


def test_response_token_is_rewritten_into_next_request_without_reporting_value():
    entries=[
        {'request':{'url':'https://example.test/form','method':'GET','headers':[]},
         'response':{'content':{'mimeType':'text/html','text':
             '<input type="hidden" name="csrf_token" value="fresh-secret">'},'headers':[]}},
        {'request':{'url':'https://example.test/save','method':'POST','headers':[],
                    'postData':{'mimeType':'application/x-www-form-urlencoded',
                                'text':'name=a&csrf_token=stale'}},
         'response':{'content':{'mimeType':'text/html','text':''},'headers':[]}},
    ]
    report=bind(entries)
    values=parse_qs(entries[1]['request']['postData']['text'])
    assert values['csrf_token']==['fresh-secret']
    assert report['request_fields_rewritten']==1
    assert 'fresh-secret' not in json.dumps(report)


def test_json_and_header_tokens_are_worker_sequence_bound():
    entries=[
        {'request':{'url':'https://example.test/bootstrap','method':'GET','headers':[]},
         'response':{'content':{'mimeType':'application/json','text':'{"csrf":"new"}'},'headers':[]}},
        {'request':{'url':'https://example.test/api','method':'POST',
                    'headers':[{'name':'csrf','value':'old'}],
                    'postData':{'mimeType':'application/json','text':'{"csrf":"old","x":1}'}},
         'response':{'content':{},'headers':[]}},
    ]
    report=bind(entries)
    assert entries[1]['request']['headers'][0]['value']=='new'
    assert json.loads(entries[1]['request']['postData']['text'])['csrf']=='new'
    assert report['request_fields_rewritten']==2
