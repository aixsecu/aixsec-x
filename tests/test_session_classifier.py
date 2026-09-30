from session_classifier import (classify_entry, classify_mutation,
                                parse_set_cookie, split_set_cookie)


def entry(headers,auth='anonymous'):
    return {'auth_context':auth,'_entry':{'request':{'headers':[],'cookies':[]},
        'response':{'headers':headers}}}


def test_combined_set_cookie_preserves_expires_comma_and_quoted_comma():
    value='sid="a,b"; Path=/, token=x; Expires=Wed, 21 Oct 2030 07:28:00 GMT, _ga=one; Path=/'
    assert len(split_set_cookie(value))==3
    parsed=parse_set_cookie([{'name':'Set-Cookie','value':value}])
    assert [row['name'] for row in parsed]==['sid','token','_ga']


def test_repeated_headers_and_malformed_cookie_fail_closed():
    headers=[{'name':'Set-Cookie','value':'_ga=one'},{'name':'set-cookie','value':'AWSALB=two'}]
    assert classify_entry(entry(headers))=='benign_cookie'
    assert classify_entry(entry([{'name':'Set-Cookie','value':'bad cookie'}]))=='unknown'


def test_all_consumers_get_same_session_classification():
    item=entry([{'name':'Set-Cookie','value':'PHPSESSID=x'}])
    assert classify_entry(item)=='guest_session'
    assert classify_entry({**item,'auth_context':'member'})=='authenticated_session'
    assert classify_mutation({'set_cookie_names':['PHPSESSID'],
                              'request_cookie_names':['PHPSESSID']})==('session_refresh',-1)
