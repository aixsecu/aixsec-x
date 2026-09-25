"""Offline, bounded comparison of executor-owned active evidence. No network I/O."""
import base64
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl
from http_engine import EvidenceRedactor

SENSITIVE = re.compile(r'password|passwd|secret|token|session|cookie|authorization|api.?key|csrf', re.I)

SQL_ERROR = re.compile(r'(?:syntax\s+error\s*:\s*(?:select|insert|update|delete)\b|you have an error in your sql syntax|SQLSTATE\[42\w{3}\])', re.I)


def analyze(directory, target, rules, auth_context, scan_id):
    directory = Path(directory)
    path = directory / 'active-evidence.jsonl'
    summary = {'artifact_ref': str(path), 'records': 0, 'rules_with_evidence': [],
               'meaning': 'Recorded responses are not proof of complete coverage or absence of vulnerabilities',
               'gaps': []}
    if not path.exists():
        summary['gaps'].append('Active payload/response evidence unavailable')
        return summary, []
    path.chmod(0o600)
    if (directory / 'active-evidence-truncated').exists():
        summary['gaps'].append('Evidence byte limit reached; some responses were not retained')
    seed = directory / 'seed.har'
    controls = []
    if seed.exists():
        try:
            controls = json.loads(seed.read_text())['log']['entries']
        except (ValueError, KeyError, TypeError):
            summary['gaps'].append('Invalid control HAR')
    allowed = {str(r) for r in rules}
    candidates, seen, observed = [], set(), set()
    def identity(url):
        p = urlsplit(url)
        return p.scheme, p.hostname, p.port or (443 if p.scheme == 'https' else 80), p.path or '/'
    with path.open() as stream:
        for number, line in enumerate(stream, 1):
            try:
                row = json.loads(line)
                rule = str(row['rule_id'])
                url = row['request_url']
                if rule not in allowed or identity(url) != identity(target) or int(row['status']) <= 0:
                    continue
                summary['records'] += 1
                observed.add(int(rule))
                if row.get('response_truncated') or row.get('request_truncated'):
                    if 'Some request/response bodies truncated' not in summary['gaps']:
                        summary['gaps'].append('Some request/response bodies truncated')
                if row.get('request_truncated') or rule != '40018' or not SQL_ERROR.search(row.get('response_body', '')):
                    continue
                for control in controls:
                    req, res = control['request'], control['response']
                    if identity(req['url']) != identity(url) or req['method'] != row['method'] or not 200 <= int(res['status']) < 300:
                        continue
                    content = res.get('content', {})
                    if 'text' not in content:
                        continue
                    text = content['text']
                    if content.get('encoding') == 'base64':
                        text = base64.b64decode(text).decode('utf-8', errors='replace')
                    if SQL_ERROR.search(text):
                        continue
                    before = parse_qsl(urlsplit(req['url']).query, keep_blank_values=True)
                    after = parse_qsl(urlsplit(url).query, keep_blank_values=True)
                    post = req.get('postData') or {}
                    if post.get('mimeType', '').split(';')[0] == 'application/x-www-form-urlencoded':
                        before += parse_qsl(post.get('text', ''), keep_blank_values=True)
                        after += parse_qsl(row.get('request_body', ''), keep_blank_values=True)
                    elif 'json' in post.get('mimeType','').lower():
                        from request_inputs import load_json
                        def flatten(value,path=''):
                            if isinstance(value,dict):
                                return [pair for k,v in sorted(value.items()) for pair in flatten(v,path+'/'+k.replace('~','~0').replace('/','~1'))]
                            if isinstance(value,list):
                                return [pair for i,v in enumerate(value) for pair in flatten(v,path+'/'+str(i))]
                            return [(path,value)]
                        before += flatten(load_json(post.get('text','')))
                        after += flatten(load_json(row.get('request_body','')))
                    elif post.get('text') or row.get('request_body'):
                        continue  # Opaque bodies require a location-aware executor.
                    if [k for k,v in before] != [k for k,v in after]:
                        continue
                    changed = [k for (k,v),(_,w) in zip(before, after) if v != w and not SENSITIVE.search(k)]
                    if len(changed) != 1:
                        continue
                    key = (identity(url), row['method'], changed[0])
                    if key in seen:
                        break
                    seen.add(key)
                    candidates.append({'rule_id': 'aixsec-sql-error-differential', 'category': 'SQL Injection',
                        'severity': 'high', 'cwe': '89', 'url': EvidenceRedactor().redact_url(req['url']),
                        'method': row['method'], 'parameter': changed[0], 'auth_context': auth_context,
                        'scan_id': scan_id, 'artifact_ref': str(path) + '#line=' + str(number),
                        'request_sha256': row.get('request_sha256', ''), 'response_sha256': row.get('response_sha256', ''),
                        'description': 'SQL error appeared in an active-rule response after one parameter changed; absent from captured control. Candidate only: control may be stale; repeat paired validation required.',
                        'fix': 'Use parameterized queries and suppress database error details.'})
                    break
            except (ValueError, KeyError, TypeError, AttributeError):
                if 'Malformed evidence records skipped' not in summary['gaps']:
                    summary['gaps'].append('Malformed evidence records skipped')
    summary['rules_with_evidence'] = sorted(observed)
    summary['retention'] = '16 MiB maximum; headers omitted; response bodies may contain sensitive application data'
    return summary, candidates
