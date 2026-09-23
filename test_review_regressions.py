"""Regression checks for scan observations and streaming timeout diagnostics."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests
from urllib3.exceptions import ReadTimeoutError
from agent import WebXAgent, _LiveDisplay
from config import load_config
from llm import ollama_chat
from tools import _wapiti_parse_report
from test_agent import cfg, FakeChat


class ScanContractTests(unittest.TestCase):
    def agent(self, findings):
        agent = WebXAgent(config=cfg(), chat=FakeChat())
        agent.transcript = [{"type": "tools", "calls": [{
            "name": "wapiti_scan", "outcome": "ok",
            "args": {"url": "https://example.com"},
            "output": "engine ước lượng từ headers = mysql",
            "data": {"target": "https://example.com", "findings": findings}}]}]
        return agent

    def apply(self, agent, finding):
        result = {"final_text": json.dumps({"findings": [finding],
                  "risk_level": "MEDIUM", "overall_summary": "MySQL confirmed"})}
        agent._apply_final_contract(result)
        return result

    def test_reported_scan_summary_is_not_medium_vulnerability(self):
        agent = self.agent([])
        result = self.apply(agent, {"name": "Wapiti Domain Scan", "severity": "medium",
            "source": "wapiti_scan", "url": "https://example.com/",
            "parameter": "scope=domain", "service": "HTTP/MySQL"})
        self.assertEqual(result["risk_level"], "UNKNOWN")
        self.assertEqual(result["findings"], [])
        self.assertEqual(agent.ledger.all(), [])
        self.assertNotIn("MySQL confirmed", result["final_text"])

    def test_renaming_or_omitting_source_does_not_bypass_empty_scanner(self):
        agent = self.agent([])
        result = self.apply(agent, {"name": "SQL Injection", "severity": "high",
                                    "url": "https://example.com/"})
        self.assertEqual(result["findings"], [])

    def test_real_finding_survives_with_scanner_severity(self):
        agent = self.agent([{"category": "SQL Injection", "path": "/item?id=1",
                             "parameter": "id", "level": "3"}])
        result = self.apply(agent, {"name": "SQL Injection", "severity": "critical",
            "source": "wapiti_scan", "url": "https://example.com/item?id=1", "parameter": "id"})
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["findings"][0]["severity"], "high")
        self.assertEqual(len(agent.ledger.all()), 1)

    def test_wrong_endpoint_does_not_borrow_scanner_evidence(self):
        agent = self.agent([{"category": "SQL Injection", "path": "/item",
                             "parameter": "id", "level": "3"}])
        result = self.apply(agent, {"name": "SQL Injection", "source": "wapiti_scan",
            "url": "https://other.example/item", "parameter": "id"})
        self.assertEqual(result["findings"], [])

    def test_other_tool_finding_survives_empty_wapiti_report(self):
        agent = self.agent([])
        agent.transcript[0]["calls"].append({
            "name": "http_request", "outcome": "ok",
            "args": {"url": "https://example.com/"},
            "output": "Missing Content-Security-Policy"})
        result = self.apply(agent, {"name": "Missing CSP", "severity": "low",
            "source": "http_request", "url": "https://example.com/"})
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(len(result["findings"]), 1)

    def test_final_request_has_no_tool_schemas(self):
        agent = self.agent([])
        agent._chat_contextual([{"role": "user", "content": "summarize"}],
                               "summarize", json_mode=True)
        self.assertEqual(agent.chat.calls[-1]["tools"], [])

    def test_incomplete_report_is_not_successful_empty_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.json'
            path.write_text('{}')
            with self.assertRaises(ValueError):
                _wapiti_parse_report(str(path))
            path.write_text('{"infos": {}, "vulnerabilities": {}}')
            self.assertEqual(_wapiti_parse_report(str(path))["findings"], [])


class StreamDiagnosticsTests(unittest.TestCase):
    def test_wrapped_read_timeout_keeps_phase_and_closes_response(self):
        for started in (False, True):
            with self.subTest(started=started):
                response = MagicMock()
                def lines(**kwargs):
                    if started:
                        yield json.dumps({"message": {"content": "hello"}})
                    raise requests.exceptions.ConnectionError(ReadTimeoutError(None, '/api/chat', 'timeout'))
                response.iter_lines.side_effect = lines
                config = load_config()
                config['stream'] = True
                with patch('llm.requests.post', return_value=response):
                    result = ollama_chat([], config=config)
                self.assertEqual(result['metrics']['timeout_phase'],
                                 'completion' if started else 'first_token')
                response.close.assert_called_once()

    def test_failed_display_does_not_claim_model_finished(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            display = _LiveDisplay(1, 8)
            display.done({'content': '[!] Ollama first-token timeout.'})
        self.assertIn('model failed', output.getvalue())
        self.assertIn('first-token timeout', output.getvalue())
        self.assertNotIn('model finished', output.getvalue())
