import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ledger import Finding, Ledger
from terminal_output import TerminalOutput, event, prompt


class TerminalTests(unittest.TestCase):
    def session(self, root, screen, verbose=False):
        terminal = TerminalOutput(verbose, screen, root)
        agent = SimpleNamespace(config={'targets': ['https://example.test']}, ledger=Ledger())
        return terminal, agent

    def test_diagnostics_findings_and_last_summary(self):
        for verbose in (False, True):
            with self.subTest(verbose=verbose), tempfile.TemporaryDirectory() as root:
                screen = io.StringIO()
                terminal, agent = self.session(root, screen, verbose)
                with terminal:
                    event('bind', agent)
                    f = agent.ledger.add(Finding('SQL Injection', severity='critical'))
                    self.assertNotIn('[CRITICAL]', screen.getvalue())
                    agent.ledger.transition(f, 'needs_validation')
                    agent.ledger.transition(f, 'confirmed')
                    self.assertIn('[CRITICAL] SQL Injection', screen.getvalue())
                    agent.ledger.add(f)
                    for i in range(100):
                        print(f'[scheduler] queue decision {i}')
                    event('completed', {'progress': {'status': 'complete', 'tasks': [
                        {'stage': 'zap_active', 'status': 'complete'},
                        {'stage': 'zap_active', 'status': 'timeout'}]},
                        'route_families': {'family_count': 3},
                        'representatives': {'scan_groups_after': 2}})
                    event('output_file', 'Report', 'report.json')
                    print('JVM shutdown complete')
                output = screen.getvalue()
                self.assertEqual(output.count('[CRITICAL] SQL Injection'), 1)
                self.assertEqual('[scheduler]' in output, verbose)
                self.assertTrue(output.endswith('=' * 50 + '\n'))
                self.assertIn('  Critical: 1', output)
                self.assertIn('  Success: 1', output)
                self.assertIn('  Failed: 1', output)
                self.assertIn('  Representatives: 2', output)
                log = Path(terminal.log_path).read_text()
                self.assertIn('queue decision 99', log)
                self.assertIn('JVM shutdown complete', log)
                self.assertEqual(Path(terminal.log_path).stat().st_mode & 0o777, 0o600)

    def test_batch_summary_follows_exports(self):
        import agent as cli
        ledger = Ledger()
        fake = SimpleNamespace(
            config={'targets': ['https://example.test']}, ledger=ledger,
            policy=SimpleNamespace(describe=lambda: 'scope'), missing_tools=[],
            run=lambda _: {'findings': [], 'final_text': 'diagnostic result'},
            export_report=lambda: print('report written') or 'report.json',
            save_inventory=lambda: print('inventory written') or 'inventory.json')
        with tempfile.TemporaryDirectory() as root:
            screen = io.StringIO()
            with patch.object(cli, 'load_config', return_value=fake.config), \
                 patch.object(cli, 'WebXAgent', return_value=fake), \
                 patch('sys.argv', ['agent.py', '-n']):
                with TerminalOutput(screen=screen, log_dir=root) as terminal:
                    cli._main()
            output = screen.getvalue()
            self.assertIn('Report: report.json', output)
            self.assertIn('Attack surface: inventory.json', output)
            self.assertNotIn('diagnostic result', output)
            log = Path(terminal.log_path).read_text()
            self.assertLess(log.index('inventory written'), log.index('AIXSEC-X Scan Summary'))

    def test_exception_finishes_with_summary_and_restores_stream(self):
        import sys
        original = sys.stdout
        with tempfile.TemporaryDirectory() as root:
            screen = io.StringIO()
            terminal, agent = self.session(root, screen)
            with self.assertRaises(KeyboardInterrupt):
                with terminal:
                    event('bind', agent)
                    raise KeyboardInterrupt()
            self.assertIn('Status: Interrupted', screen.getvalue())
            self.assertIs(sys.stdout, original)

    def test_tty_updates_clear_only_current_line(self):
        class TTY(io.StringIO):
            def isatty(self):
                return True
        with tempfile.TemporaryDirectory() as root:
            screen = TTY()
            terminal, agent = self.session(root, screen)
            with terminal:
                event('bind', agent)
                agent.ledger.add(Finding('Missing CSP', status='confirmed'))
                event('stage', 'verification')
                with patch('builtins.input', return_value='y'):
                    self.assertEqual(prompt('[APPROVAL] run? '), 'y')
            self.assertIn('[APPROVAL] run?', screen.getvalue())
            self.assertIn('\r\033[2K', screen.getvalue())
            self.assertNotIn('\033[2J', screen.getvalue())


if __name__ == '__main__':
    unittest.main()
