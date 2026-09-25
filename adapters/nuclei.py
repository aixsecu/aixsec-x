"""Operator-selected local HTTP templates, isolated CLI execution and JSONL evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import yaml

from adapters.zap import canonical_url, within
from http_engine import EvidenceRedactor


def executable(config):
    return shutil.which(config.get('nuclei_executable', 'nuclei'))


def filters(config):
    args = ['-duc', '-ni', '-dr', '-pt', 'http', '-etags', 'dos,fuzz,bruteforce', '-nc', '-no-stdin']
    for key, flag in (('nuclei_templates','-t'), ('nuclei_tags','-tags'), ('nuclei_severity','-s')):
        value = str(config.get(key) or '').strip()
        if value:
            if key == 'nuclei_templates' and '://' in value:
                raise ValueError('Nuclei templates must be local operator-owned paths')
            args += [flag, value]
    return args


def template_info(path):
    """Limit automatic selection to HTTP requests rooted at the authorized input.

    Complex flow/code/raw socket templates need a separate scope-aware executor.
    Unsupported templates are reported as exclusions, not scanned silently.
    """
    path = Path(path).expanduser().resolve()
    raw = path.read_bytes()
    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict) or not isinstance(doc.get('id'), str):
        raise ValueError('Invalid template')
    if any(k in doc for k in ('flow', 'code', 'javascript', 'headless', 'dns', 'tcp', 'network', 'file', 'workflows')):
        raise ValueError('Unsupported protocol/flow')
    for values in (doc.get('variables') or {}, doc.get('constants') or {}):
        if set(values) & {'BaseURL','RootURL','Hostname','Host','Port','Scheme'}:
            raise ValueError('Template overrides target variables')
    requests = doc.get('http') or doc.get('requests')
    if not isinstance(requests, list) or not requests:
        raise ValueError('No HTTP requests')
    root_only = True
    for request in requests:
        paths = request.get('path') or []
        if request.get('raw') or not paths or request.get('unsafe') or request.get('race') or request.get('fuzzing'):
            raise ValueError('Raw/unsafe/fuzzing request needs a separate executor')
        if request.get('redirects') or request.get('host-redirects'):
            raise ValueError('Template redirects not supported')
        for value in paths:
            if not isinstance(value, str) or not re.match(r'^\{\{(?:BaseURL|RootURL)\}\}(?:/|$)', value):
                raise ValueError('HTTP path not rooted at input URL')
            # Prevent encoded network-path / authority tricks in templated paths.
            if '\\' in value or '\r' in value or '\n' in value:
                raise ValueError('Invalid path')
            root_only &= value.startswith('{{RootURL}}')
    return {'id':doc['id'], 'path':str(path), 'sha256':hashlib.sha256(raw).hexdigest(),
            'scope':'origin' if root_only else 'request_family'}


def catalog(config):
    binary = executable(config)
    if not binary:
        return [], {'status':'skipped', 'reason':'Nuclei executable unavailable'}
    with tempfile.TemporaryDirectory(prefix='aixsec-nuclei-catalog-') as tmp:
        cfg = Path(tmp)/'config.yaml'; cfg.write_text('{}')
        try:
            result = subprocess.run([binary, '-config', str(cfg), '-tl'] + filters(config),
                capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [], {'status':'error', 'reason':type(exc).__name__}
    rows, excluded, seen = [], 0, set()
    for line in result.stdout.splitlines():
        path = Path(line.strip()).expanduser()
        if path.suffix not in ('.yaml', '.yml') or not path.is_file():
            continue
        try:
            info = template_info(path)
        except (ValueError, OSError, yaml.YAMLError, TypeError, AttributeError):
            excluded += 1
            continue
        key = (info['id'], info['sha256'])
        if key not in seen:
            rows.append(info); seen.add(key)
    return rows, {'status':'complete' if rows and result.returncode == 0 else 'error',
                  'reason':'' if rows else 'No eligible local HTTP templates; install templates or select WEBX_NUCLEI_TEMPLATES',
                  'eligible':len(rows), 'excluded':excluded, 'returncode':result.returncode}


def parse_report(path, target, templates, scan_id):
    allowed = {r['id'] for r in templates}
    rows, errors, rejected = [], 0, 0
    if not Path(path).exists():
        return rows, 0, 0
    with Path(path).open() as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                url = item.get('matched-at') or item.get('url') or item.get('host')
                rule = item['template-id']
                if rule not in allowed or not within(url, target) or item.get('matcher-status') is False:
                    rejected += 1; continue
                info = item['info']
                request, response = str(item.get('request') or ''), str(item.get('response') or '')
                rows.append({'rule_id':'nuclei:' + rule, 'category':str(info.get('name') or rule),
                    'url':EvidenceRedactor().redact_url(canonical_url(url)),
                    'method':request.split(' ', 1)[0] if request else 'GET', 'parameter':'',
                    'auth_context':'anonymous', 'severity':info.get('severity', 'info'),
                    'scan_id':scan_id, 'artifact_ref':str(path),
                    'request_sha256':hashlib.sha256(request.encode()).hexdigest(),
                    'response_sha256':hashlib.sha256(response.encode()).hexdigest(),
                    'description':f'Nuclei template {rule} matched; independent validation required.',
                    'fix':str(info.get('remediation') or '')[:1500]})
            except (ValueError, KeyError, TypeError, AttributeError):
                errors += 1
    return rows, errors, rejected


def run_scan(config, url, templates, timeout=None):
    url = canonical_url(url)
    binary = executable(config)
    if not binary:
        raise ValueError('Nuclei executable unavailable')
    if not templates:
        raise ValueError('Select installed templates through the pipeline catalog')
    for item in templates:
        fresh = template_info(item['path'])
        if (fresh['id'], fresh['sha256']) != (item['id'], item['sha256']):
            raise ValueError('Template changed after catalog; start a new scan')
    root = Path(config.get('evidence_dir', '.aixsec-evidence')).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = Path(tempfile.mkdtemp(prefix='nuclei-', dir=root))
    cfg = directory/'config.yaml'; cfg.write_text('{}'); cfg.chmod(0o600)
    report, log = directory/'report.jsonl', directory/'nuclei.log'
    report.touch(mode=0o600)
    # Catalog already applied selection filters; pass only immutable chosen templates.
    command = [binary, '-config', str(cfg), '-u', url, '-t', ','.join(t['path'] for t in templates),
        '-duc', '-ni', '-dr', '-pt', 'http', '-nc', '-no-stdin', '-jsonl', '-o', str(report),
        '-rl', str(max(1, int(config.get('nuclei_rate',5)))), '-c', '2', '-bs', '1',
        '-timeout', '10', '-retries', '1']
    state, code = 'complete', None
    with log.open('w') as stream:
        log.chmod(0o600)
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=max(1, int(timeout or config.get('nuclei_timeout',600))))
        except subprocess.TimeoutExpired:
            state = 'timeout'
            try: os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait()
        except BaseException:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
            raise
    rows, malformed, rejected = parse_report(report, url, templates, directory.name)
    logs = log.read_text(errors='replace')
    loaded = re.search(r'Templates loaded for current scan:\s*(\d+)', logs)
    if state == 'complete' and (code != 0 or not loaded or int(loaded.group(1)) != len(templates) or malformed):
        state = 'partial' if code == 0 else 'error'
    coverage = {'tool':'nuclei_scan', 'target':EvidenceRedactor().redact_url(url), 'status':state,
        'auth_context':'anonymous', 'template_ids':[t['id'] for t in templates],
        'report_path':str(report), 'log_path':str(log), 'returncode':code,
        'malformed_records':malformed, 'rejected_records':rejected,
        'status_meaning':'execution_only_not_proof_of_safety',
        'gaps':[] if state == 'complete' else ['Template execution not fully established; inspect private log']}
    return f'Nuclei {state}: {len(rows)} candidates, {len(templates)} selected templates', {
        'target':url, 'scan_id':directory.name, 'alerts':rows, 'coverage':coverage}
