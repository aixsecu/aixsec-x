"""Evidence-bound candidates and deterministic validators shared by scanners.

A model may select evidence IDs, but cannot supply validation facts or verdicts.
Raw scanner reports live in private artifacts; public metadata is redacted.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.parse import urljoin

from http_engine import EvidenceRedactor
from ledger import Finding

RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def stable_id(prefix, value):
    return prefix + '-' + hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:24]


def public(value):
    if isinstance(value, dict):
        return {k: public(v) for k, v in value.items() if not str(k).startswith('_')}
    if isinstance(value, list):
        return [public(v) for v in value]
    return value


class EvidenceStore:
    def __init__(self, ledger, directory=None):
        self.ledger = ledger
        self.records = {}
        self.candidates = {}
        self.coverage = []
        self.observations = []
        self.discovery = []
        self.active_rules = []
        self.directory = None
        if directory:
            root = Path(directory).resolve()
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.directory = Path(tempfile.mkdtemp(prefix='session-', dir=root))

    def ingest(self, result):
        name = result.get('name', '')
        args = result.get('args') or {}
        data = result.get('data') or {}
        if not isinstance(data, dict):
            data = {}
        raw_artifact = ''
        if self.directory:
            artifact = self.directory / f'tool-{len(self.observations) + 1}.json'
            with artifact.open('w') as out:
                os.chmod(artifact, 0o600)
                json.dump(result, out, ensure_ascii=False, default=str)
            raw_artifact = str(artifact)
        coverage = data.get('coverage')
        if isinstance(coverage, dict):
            self.coverage.append(public(coverage))
        if isinstance(data.get('discovery'), dict):
            self.discovery.append({'scan_id': data.get('scan_id', ''), **public(data['discovery'])})
        if isinstance(data.get('active_rules'), list) and data['active_rules']:
            self.active_rules = public(data['active_rules'])
        self.observations.append({'tool': name, 'outcome': result.get('outcome'),
            'url': EvidenceRedactor().redact_url(str(args.get('url') or '')),
            'data_sha256': stable_id('data', public(data)), 'artifact_ref': raw_artifact, 'time': time.time()})
        if result.get('outcome') not in ('ok', 'partial', 'timeout'):
            self.persist()
            return
        rows = []
        if name in ('zap_baseline', 'zap_active_scan', 'nuclei_scan', 'sql_error_verify'):
            rows = data.get('alerts') or []
        elif name == 'wapiti_scan':
            for f in data.get('findings') or []:
                rows.append({'category': f.get('category'), 'rule_id': f.get('category'),
                    'url': urljoin(str(data.get('target') or args.get('url') or ''), str(f.get('path') or '')),
                    'method': f.get('method', 'GET'), 'parameter': f.get('parameter', ''),
                    'severity': {'0': 'info', '1': 'low', '2': 'medium', '3': 'high', '4': 'critical'}.get(str(f.get('level')), 'info'),
                    'artifact_ref': data.get('report_path', ''), 'description': 'Wapiti scanner candidate.'})
        elif name == 'sqli_manual_test' and data.get('confirmed'):
            # Preserve the scanner's verdict as a candidate until independently validated.
            rows = [{'category': 'SQL Injection', 'rule_id': 'sqli',
                     'url': args.get('url'), 'parameter': args.get('param', ''),
                     'method': args.get('method', 'GET'), 'severity': 'high',
                     'description': 'Manual SQLi oracle reported a positive result.'}]
        elif name in ('sqlmap_runner', 'sqlmap_check'):
            output = str(result.get('output') or '')
            for param, method in re.findall(r'^Parameter:\s*(\S+)\s*\((GET|POST|URI|Cookie|HEADER)\)', output, re.M):
                if re.search(r'^\s+Type:\s*\S', output, re.M):
                    rows.append({'category': 'SQL Injection', 'rule_id': 'sqli',
                        'url': args.get('url'), 'parameter': param, 'method': method,
                        'severity': 'high', 'description': 'sqlmap reported an injection point; validation required.'})
        for row in rows:
            if not isinstance(row, dict) or not row.get('category') or not row.get('url'):
                continue
            row = dict(row)
            row['source_tool'] = name
            if not row.get('artifact_ref'):
                row['artifact_ref'] = raw_artifact
            row.setdefault('auth_context', args.get('auth_context', 'anonymous'))
            row['url'] = EvidenceRedactor().redact_url(str(row['url']))
            row['method'] = str(row.get('method') or 'GET').upper()
            eid = stable_id('ev', [name, row.get('scan_id'), row.get('rule_id'), row['url'],
                row['method'], row.get('parameter'), row['auth_context'], row.get('request_sha256'), row.get('response_sha256')])
            row['evidence_id'] = eid
            self.records[eid] = row
            # Same tool/rule repeated is provenance, not independent confirmation.
            category = str(row['category']).lower()
            if category in ('sql injection', 'sqli'):
                category = 'sqli'
            key = stable_id('finding', [category, row['url'], row['method'],
                            row.get('parameter', ''), row['auth_context']])
            if key not in self.candidates:
                finding = Finding(name=row['category'], url=row['url'],
                    severity=row.get('severity') if row.get('severity') in RANK else 'info',
                    description=row.get('description', ''), fix=row.get('fix', ''),
                    source_tool=name, sources=[name], parameter=str(row.get('parameter') or ''),
                    evidence=[eid], status='candidate', evidence_gaps=['Needs rule-specific validation'],
                    method=row['method'], auth_context=row['auth_context'], finding_id=key)
                self.candidates[key] = self.ledger.add(finding)
            else:
                finding = self.candidates[key]
                if eid not in finding.evidence:
                    finding.evidence.append(eid)
                if name not in finding.sources:
                    finding.sources.append(name)
            # Even ZAP confidence=confirmed is not authority to change our state.
        self.persist()

    def validate(self, evidence_id):
        row = self.records.get(evidence_id)
        if row is None:
            raise ValueError('Unknown evidence_id in this session')
        finding = next(f for f in self.candidates.values() if evidence_id in f.evidence)
        verdict, reason = 'needs_validation', 'No deterministic validator for this rule; replay/control evidence required'
        if row.get('auth_state') == 'unverified':
            reason = 'Requested authentication identity was not verified; configure auth verification before replay'
        headers_raw = row.get('_response_header') or ''
        request_raw = row.get('_request_header') or ''
        # Validate only clearly defined missing-header facts on successful HTML
        # responses. Do not infer XSS/CORS/SQLi from a reflected string or HTTP 200.
        match = re.match(r'HTTP/\S+\s+(\d{3})', headers_raw)
        headers = {}
        for line in headers_raw.splitlines()[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers.setdefault(key.lower().strip(), []).append(value.strip())
        missing_header_rules = {'10038': 'content-security-policy', '10035': 'strict-transport-security'}
        rule = str(row.get('rule_id') or '').split('-')[0]
        header = missing_header_rules.get(rule)
        if (row.get('source_tool', '').startswith('zap_') and header and match
                and 200 <= int(match.group(1)) < 300 and request_raw
                and row.get('auth_context') == 'anonymous'):
            applicable = (header == 'strict-transport-security' and row['url'].startswith('https://')) or (
                header == 'content-security-policy' and any('text/html' in v.lower()
                    for v in headers.get('content-type', [])))
            if applicable and header not in headers:
                verdict, reason = 'confirmed', f'Captured response is missing {header}; header configuration finding only'
            elif header in headers:
                # Do not rule out other instances or a malformed-header alert.
                reason = f'{header} is present; this missing-header validator does not confirm the alert'
        if finding.status != 'confirmed':
            self.ledger.transition(finding, 'needs_validation')
            if verdict == 'confirmed':
                self.ledger.transition(finding, 'confirmed')
                finding.evidence_gaps = []
                finding.confidence = 1.0
            else:
                finding.evidence_gaps = [reason]
        row['validation'] = {'status': verdict, 'reason': reason, 'validator': 'headers-v1'}
        self.persist()
        return {'evidence_id': evidence_id, 'finding_id': finding.finding_id,
                'status': finding.status, 'reason': reason}

    def replay(self, evidence_id, policy, timeout=15):
        import auth_context
        import http_engine as he
        row = self.records.get(evidence_id)
        if not row or not row.get('_request_header'):
            raise ValueError('Evidence has no captured request to replay')
        url = str(row.get('_url') or row['url'])
        if not policy.in_scope_url(url):
            raise ValueError('Replay URL outside current scope')
        if EvidenceRedactor().redact_url(url) != url:
            raise ValueError('Replay URL contains credentials; use a configured auth context and fresh request')
        context_name = row.get('auth_context', 'anonymous')
        headers = {}
        # Do not copy stale credentials, cookies, Host, or hop-by-hop headers.
        for line in row['_request_header'].splitlines()[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                if key.lower().strip() in ('content-type', 'accept'):
                    headers[key.strip()] = value.strip()
        spec = {'url': url, 'method': row['method'], 'headers': headers,
                'body': row.get('_request_body') or None,
                'follow_redirects': False, 'timeout': min(30, max(1, timeout))}
        if context_name != 'anonymous':
            context = auth_context.manager().get(context_name)
            if context.state not in ('ready', 'authenticated'):
                raise ValueError('Replay requires an authenticated AIXSEC context with the same name; ZAP cookies are not copied')
            response, record = context._request(spec, record=True)
        else:
            session = he.HttpSession('evidence-replay', proxies=he.get_proxies())
            try:
                response, record = session.request(spec['method'], url, headers=headers,
                    body=spec['body'], follow_redirects=False, timeout=spec['timeout'],
                    max_response_bytes=2 * 1024 * 1024)
            finally:
                session.s.close()
        digest = hashlib.sha256(response.content).hexdigest()
        value = {'evidence_id': evidence_id, 'auth_context': context_name,
                 'status': response.status_code, 'url': row['url'],
                 'body_sha256': digest, 'body_matches_capture': digest == row.get('_body_sha256'),
                 'interpretation': 'facts_only', 'verdict': False}
        row.setdefault('replays', []).append(value)
        self.persist()
        return value

    def summary(self):
        return {'coverage': self.coverage,
                'discovery': self.discovery,
                'evidence': [public(v) for v in self.records.values()],
                'findings': [asdict(f) for f in self.candidates.values()],
                'observations': self.observations}

    def persist(self):
        if self.directory:
            path = self.directory / 'evidence.json'
            temporary = self.directory / 'evidence.tmp'
            with temporary.open('w') as out:
                os.chmod(temporary, 0o600)
                json.dump(self.summary(), out, ensure_ascii=False, indent=2)
            temporary.replace(path)

    def finish(self, llm_down=False):
        findings = [asdict(f) for f in self.candidates.values()]
        confirmed = [f for f in findings if f['status'] == 'confirmed']
        risk = max((f['severity'] for f in confirmed if f['severity'] != 'info'), key=RANK.get, default='UNKNOWN').upper()
        candidate_risk = max((f['severity'] for f in findings if f['severity'] != 'info'), key=RANK.get, default='UNKNOWN').upper()
        summary = (f'{len(confirmed)} finding đã xác minh; {len(findings) - len(confirmed)} candidate cần xác minh. '
                   'Coverage chỉ phản ánh các bước đã chạy, không chứng minh ứng dụng an toàn.')
        if llm_down:
            summary += ' Model không phản hồi; kết quả được dựng trực tiếp từ evidence.'
        result = {'risk_level': risk, 'candidate_risk_level': candidate_risk,
                  'overall_summary': summary, 'findings': findings, 'coverage': self.coverage,
                  'discovery': self.discovery,
                  'llm_down': llm_down}
        if self.directory:
            result['evidence_path'] = str(self.directory / 'evidence.json')
        self.persist()
        return result
