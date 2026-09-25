import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from verification import variants, paired

URL='https://example.test/search?q=abc'
ENTRY={'request':{'url':URL,'method':'GET','headers':[]}}

class VerificationTests(unittest.TestCase):
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
            with patch('shutil.which',return_value='/fake/sqlmap'),patch('verification.subprocess.Popen',side_effect=launch):
                output,data=sqlmap_probe({'evidence_dir':root},entry,'q',timeout=10)
            self.assertIn('--technique=BE',commands[0])
            self.assertFalse(set(commands[0]) & {'--dbs','--tables','--dump','--current-user','--banner'})
            self.assertNotIn('PRIVATE',output)
            self.assertEqual(data['coverage']['status'],'complete')
