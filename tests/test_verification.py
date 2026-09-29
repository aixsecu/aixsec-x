import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from verification import variants, paired, discovered_get_probe, discovered_search_form_probe

URL='https://example.test/search?q=abc'
ENTRY={'request':{'url':URL,'method':'GET','headers':[]}}

class VerificationTests(unittest.TestCase):
    def test_discovered_get_quote_parity_creates_candidate_without_extraction(self):
        from types import SimpleNamespace
        def response(text):
            return SimpleNamespace(text=text,content=text.encode(),status_code=200), {}
        endpoint={'url':'https://example.test/ajax/load_search.php','method':'UNKNOWN',
                  'parameters':['txt_key'],'sources':['javascript_literal']}
        with tempfile.TemporaryDirectory() as root, patch('http_engine.HttpSession') as session:
            session.return_value.request.side_effect=[response(v) for v in
                ('ok','SQL syntax error','ok','SQL syntax error','ok')]
            data=discovered_get_probe({'evidence_dir':root},endpoint)
        self.assertEqual(len(data['alerts']),1)
        self.assertEqual(data['alerts'][0]['parameter'],'txt_key')
        self.assertEqual(data['coverage']['requests'],5)
        self.assertEqual(session.return_value.request.call_count,5)
        for call in session.return_value.request.call_args_list:
            self.assertFalse(call.kwargs['follow_redirects'])

    def test_discovered_post_search_form_quote_parity_creates_candidate(self):
        from types import SimpleNamespace
        def response(text,status=200):
            return SimpleNamespace(text=text,content=text.encode(),status_code=status), {}
        form={'action':'https://example.test/WebTinTuc/TimKiem','method':'POST',
              'parameters':['keyword']}
        replies=[response('ok'),response('SQL error',500),response('ok'),
                 response('SQL error',500),response('ok')]
        with tempfile.TemporaryDirectory() as root, patch('http_engine.HttpSession') as session:
            session.return_value.request.side_effect=replies
            data=discovered_search_form_probe({'evidence_dir':root},form)
        self.assertEqual(len(data['alerts']),1)
        self.assertEqual(data['alerts'][0]['method'],'POST')
        self.assertEqual(data['alerts'][0]['parameter'],'keyword')
        self.assertEqual(data['coverage']['requests'],5)
        for call in session.return_value.request.call_args_list:
            self.assertEqual(call.args[:2],('POST',form['action']))
            self.assertFalse(call.kwargs['follow_redirects'])
            self.assertIn('keyword',call.kwargs['form'])

    def test_discovered_post_probe_rejects_non_search_and_blocked_forms(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                discovered_search_form_probe({'evidence_dir':root},{'action':'https://example.test/contact',
                    'method':'POST','parameters':['email','message']})
        from types import SimpleNamespace
        blocked=lambda: (SimpleNamespace(text='blocked',content=b'blocked',status_code=403),{})
        with tempfile.TemporaryDirectory() as root, patch('http_engine.HttpSession') as session:
            session.return_value.request.side_effect=[blocked() for _ in range(5)]
            data=discovered_search_form_probe({'evidence_dir':root},{'action':'https://example.test/search',
                'method':'POST','parameters':['query']})
        self.assertEqual(data['alerts'],[])

    def test_discovered_get_search_form_checks_each_named_input_in_query(self):
        from types import SimpleNamespace
        response=lambda text: (SimpleNamespace(text=text,content=text.encode(),status_code=200),{})
        form={'action':'https://example.test/search?category=news','method':'GET',
              'parameters':['q','page']}
        replies=[response('ok'),response('different'),response('ok'),
                 response('different'),response('ok')]*2
        with tempfile.TemporaryDirectory() as root, patch('http_engine.HttpSession') as session:
            session.return_value.request.side_effect=replies
            data=discovered_search_form_probe({'evidence_dir':root},form)
        self.assertEqual(data['alerts'][0]['method'],'GET')
        self.assertEqual(data['alerts'][0]['parameter'],'q')
        for call in session.return_value.request.call_args_list:
            self.assertEqual(call.args[0],'GET')
            self.assertIn('category=news',call.args[1])
            self.assertIn('q=',call.args[1])
            self.assertIn('page=',call.args[1])
            self.assertNotIn('form',call.kwargs)

    def test_discovered_get_form_does_not_require_search_parameter_name(self):
        from types import SimpleNamespace
        response=lambda text: (SimpleNamespace(text=text,content=text.encode(),status_code=200),{})
        form={'action':'https://example.test/x7','method':'GET','parameters':['product_code']}
        replies=[response('ok'),response('different'),response('ok'),
                 response('different'),response('ok')]
        with tempfile.TemporaryDirectory() as root, patch('http_engine.HttpSession') as session:
            session.return_value.request.side_effect=replies
            data=discovered_search_form_probe({'evidence_dir':root},form)
        self.assertEqual(data['alerts'][0]['parameter'],'product_code')
        self.assertTrue(all('product_code=' in call.args[1]
                            for call in session.return_value.request.call_args_list))

    def test_variants_preserve_post_context_and_avoid_ambiguous_parameters(self):
        entry={'request':{'url':URL,'method':'POST','postData':{'mimeType':'application/x-www-form-urlencoded','text':'name=bob'}}}
        steps=variants(entry,'name')
        self.assertEqual(steps[0],(URL,'name=bob'))
        self.assertEqual(steps[1],(URL,'name=bob%27'))
        with self.assertRaises(ValueError): variants({'request':{'url':URL+'&q=other','method':'GET'}},'q')

    def test_paired_candidate_requires_two_positive_pairs(self):
        from types import SimpleNamespace
        def response(text,status=200):
            return SimpleNamespace(text=text,content=text.encode(),status_code=status), {}
        for texts, expected in [(['ok','syntax error: select id']*2,True),
                                (['syntax error: select id']*4,False),
                                (['ok','syntax error: select id','ok','ok'],False)]:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as root, \
                 patch('http_engine.HttpSession') as session, patch('time.sleep'):
                session.return_value.request.side_effect=[response(t) for t in texts]
                _,data=paired({'evidence_dir':root},ENTRY,'q',{'url':URL},timeout=30)
                self.assertEqual(data['verification']['reproduced_error'],expected)
                self.assertFalse(data['verification']['confirmed_sqli'])
                self.assertEqual(session.return_value.request.call_count,4)
                for call in session.return_value.request.call_args_list:
                    self.assertFalse(call.kwargs['follow_redirects'])
                self.assertEqual(len(json.loads(Path(data['verification']['artifact_ref']).read_text())),4)

    def test_sqlmap_uses_private_captured_request_without_enumeration(self):
        from verification import sqlmap_probe
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as root:
            entry={'request':{'url':URL,'method':'GET', 'headers':[{'name':'Cookie','value':'sid=PRIVATE'}]}}
            commands=[]
            def launch(command,**kwargs):
                commands.append(command)
                request_path=Path(command[command.index('-r')+1])
                self.assertIn('sid=PRIVATE',request_path.read_text())
                self.assertEqual(request_path.stat().st_mode & 0o777,0o600)
                kwargs['stdout'].write('Parameter: q (GET)\n    Type: boolean-based blind\nPRIVATE output\n')
                process=MagicMock();process.wait.return_value=0
                return process
            with patch('shutil.which',return_value='/fake/sqlmap'),patch('verification.subprocess.Popen',side_effect=launch),patch('captured_auth.preflight',return_value='verified'):
                output,data=sqlmap_probe({'evidence_dir':root},entry,'q',timeout=10)
            self.assertIn('--technique=BE',commands[0])
            self.assertFalse(set(commands[0]) & {'--dbs','--tables','--dump','--current-user','--banner'})
            self.assertNotIn('PRIVATE',output)
            self.assertEqual(data['coverage']['status'],'complete')
