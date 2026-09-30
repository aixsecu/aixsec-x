from multi_role_campaign import run


class Manager:
    def __init__(self):self.configured=[]
    def get(self,name):
        if name=='anonymous' and 'anonymous' not in self.configured:raise ValueError('missing')
        return object()
    def configure(self,name,origin,replace=False):self.configured.append(name)
    def compare(self,names,request):
        observations=[{'context':name,'response':{'status':200,'body_sha256':'same'}} for name in names]
        comparisons=[{'left':names[i],'right':names[j],'same_status':True,
            'same_redirect_target':True,'same_content_type':True,'same_json_shape':True,
            'same_body_hash':True,'length_delta':0,'body_similarity':1.0}
            for i in range(len(names)) for j in range(i+1,len(names))]
        return {'url':request['url'],'method':'GET','contexts':names,
                'observations':observations,'comparisons':comparisons,'interpretation':'facts_only'}


def entry(url):return {'_entry':{'request':{'url':url,'method':'GET'}}}


def test_declared_protected_and_owned_paths_create_candidates():
    manifest={'contexts':{
        'user_a':{'origin':'https://example.test','authorization':{
            'role':'user','subject':'A','protected_paths':['/objects/*'],'owned_paths':['/objects/1']}},
        'user_b':{'origin':'https://example.test','authorization':{
            'role':'user','subject':'B','protected_paths':['/objects/*'],'owned_paths':['/objects/2']}}}}
    result=run(manifest,Manager(),[entry('https://example.test/objects/1')],
               'https://example.test')
    assert result['requests']==1
    assert {row['kind'] for row in result['candidates']}=={
        'unauthenticated_protected_access','cross_subject_object_access'}
    assert all(row['verdict'] is False for row in result['candidates'])


def test_no_declared_policy_keeps_facts_without_candidates():
    manifest={'contexts':{'user':{'origin':'https://example.test','authorization':{}}}}
    result=run(manifest,Manager(),[entry('https://example.test/public')],
               'https://example.test')
    assert result['comparisons']
    assert result['candidates']==[]
