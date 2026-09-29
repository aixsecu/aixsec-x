import unittest

from advanced_coverage import evaluate
from request_templates import build_templates

BASE='https://example.test/'


class AdvancedCoverageTests(unittest.TestCase):
    def test_advanced_surfaces_report_prerequisites_without_verdicts(self):
        discovery={'endpoints':[{'url':BASE+'graphql','method':'POST','parameters':['query'],
                    'sources':['graphql-hint']}],
                   'inputs':[{'page':BASE,'name':'q','in_form':False}]}
        templates=build_templates(BASE,discovery)
        report=evaluate(templates,[discovery],[{'phases':{'spiderAjax':'failed'}}],
                        [],{}, {'allow_oast':False,'oast_callback_url':''})
        rows={row['surface']:row for row in report['surfaces']}
        self.assertEqual(rows['graphql']['state'],'discovered')
        self.assertEqual(rows['dom_browser']['state'],'blocked')
        self.assertEqual(rows['multi_role_authorization']['state'],'blocked')
        self.assertEqual(rows['oast']['state'],'blocked')
        self.assertNotIn('vulnerability',str(report).lower())

    def test_ready_states_require_real_operator_inputs(self):
        contexts=[{'name':'user_A','state':'authenticated'},
                  {'name':'user_B','state':'authenticated'}]
        analysis={'business_rules':{'checkout':[{'type':'sequence'}]},
                  'workflow_runs':[{'workflow':'checkout','steps':[]}]}
        report=evaluate([],[],[{'phases':{'spiderAjax':'completed'}}],contexts,analysis,
            {'allow_oast':True,'oast_callback_url':'https://oast.example.test/callback'})
        rows={row['surface']:row for row in report['surfaces']}
        self.assertEqual(rows['multi_role_authorization']['state'],'ready')
        self.assertEqual(rows['dom_browser']['state'],'tested')
        self.assertEqual(rows['oast']['state'],'ready')
        self.assertEqual(rows['business_workflows']['state'],'tested')

    def test_invalid_oast_callback_never_becomes_ready(self):
        report=evaluate([],[],[],[],{}, {'allow_oast':True,'oast_callback_url':'javascript:alert(1)'})
        row=next(row for row in report['surfaces'] if row['surface']=='oast')
        self.assertEqual(row['state'],'blocked')


if __name__=='__main__':unittest.main()
