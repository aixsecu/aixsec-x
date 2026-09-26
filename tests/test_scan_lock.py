"""Lock contention must not crash the CLI or bypass persistent scan history."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scan_state import RunLock, ScanBusyError
from tests.test_sequential_pipeline import config
from agent import WebXAgent

class LockTests(unittest.TestCase):
    def test_owner_and_release_with_existing_file(self):
        with tempfile.TemporaryDirectory() as root:
            with RunLock(root,'same') as lock:
                path=Path(lock.stream.name)
                with self.assertRaises(ScanBusyError) as error:
                    with RunLock(root,'same'): pass
                self.assertEqual(error.exception.owner['pid'],os.getpid())
                self.assertEqual(error.exception.path,str(path))
            self.assertTrue(path.exists())
            with RunLock(root,'same'): pass

    def test_legacy_empty_metadata_is_still_locked(self):
        with tempfile.TemporaryDirectory() as root:
            with RunLock(root,'same') as lock:
                lock.stream.seek(0);lock.stream.truncate();lock.stream.flush()
                with self.assertRaises(ScanBusyError) as error:
                    with RunLock(root,'same'): pass
                self.assertEqual(error.exception.owner,{})

    def test_busy_run_never_starts_pipeline_or_changes_existing_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            agent=WebXAgent(config(root))
            original=agent.ledger
            with RunLock(root,'default'),patch('pipeline._run',side_effect=AssertionError('scan started')):
                result=agent.run('scan')
            self.assertTrue(result['busy'])
            self.assertEqual(result['calls'],0)
            self.assertEqual(result['findings'],[])
            self.assertIs(agent.ledger,original)
            self.assertIn('PID',result['final_text'])
