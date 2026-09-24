"""Isolated, bounded ZAP Automation Framework executor (no LLM-generated plans)."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, parse_qsl

from http_engine import EvidenceRedactor


def executable(config):
    value = str(config.get('zap_executable') or 'zap.sh')
    # Kali packages expose `zaproxy`; upstream archives expose `zap.sh`.
    # Only the default setting enables discovery. Custom paths remain binding.
    if sys.platform.startswith('linux') and value == 'zap.sh':
        for name in ('zaproxy', 'zap.sh'):
            found = shutil.which(name)
            if found:
                return found
        for path in ('/usr/bin/zaproxy', '/usr/share/zaproxy/zap.sh'):
            if Path(path).is_file() and os.access(path, os.X_OK):
                return path
    found = shutil.which(value)
    if found:
        return found
    if Path(value).is_file() and os.access(value, os.X_OK):
        return value
    # The macOS application bundle is normally not installed on PATH. Respect
    # an explicit override; only resolve the default launcher automatically.
    if sys.platform == 'darwin' and value == 'zap.sh':
        for root in (Path('/Applications'), Path.home() / 'Applications'):
            launcher = root / 'ZAP.app' / 'Contents' / 'MacOS' / 'ZAP.sh'
            if launcher.is_file() and os.access(launcher, os.X_OK):
                return str(launcher)
    return None



def launch_command(binary):
    """Use the app's Java/JAR CLI on macOS; other launchers retain their argv.

    Each scan still supplies its own -dir, so an open ZAP GUI is unaffected.
    No quarantine flags, signatures, or OS security settings are modified.
    """
    launcher = Path(binary)
    if sys.platform == 'darwin' and launcher.parent.name == 'MacOS' and launcher.parent.parent.name == 'Contents':
        contents = launcher.parent.parent
        jars = sorted((contents / 'Java').glob('zap-*.jar'))
        runtimes = sorted((contents / 'PlugIns').glob('*/Contents/Home/bin/java'))
        if len(jars) == 1 and runtimes and os.access(runtimes[0], os.X_OK):
            return [str(runtimes[0]), '-Xmx512m', '-Djava.awt.headless=true', '-jar', str(jars[0])]
    return [binary]


def origin(url):
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('ZAP target must be an HTTP(S) URL without credentials')
    port = p.port
    host = f'[{p.hostname}]' if ':' in p.hostname else p.hostname
    if port and port != (443 if p.scheme == 'https' else 80):
        host += f':{port}'
    return f'{p.scheme}://{host}'


def canonical_url(url):
    p = urlsplit(url)
    return origin(url) + (p.path or '/') + (('?' + p.query) if p.query else '')


def within(url, target):
    try:
        return origin(url) == origin(target)
    except (ValueError, TypeError):
        return False


def _operator_context(config, target, context_name):
    context = {'name': 'aixsec', 'urls': [canonical_url(target)],
               'includePaths': [re.escape(origin(target)) + r'(?:/.*)?'],
               'excludePaths': list(config.get('zap_exclude_paths') or [])}
    if context_name == 'anonymous':
        return context, None
    path = config.get('zap_auth_file')
    if not path:
        raise ValueError('Authenticated ZAP scan requires WEBX_ZAP_AUTH_FILE')
    profiles = json.loads(Path(path).read_text())
    profile = profiles.get(context_name)
    if not isinstance(profile, dict) or origin(profile.get('origin', '')) != origin(target):
        raise ValueError('ZAP auth profile missing or bound to another origin')
    auth = copy.deepcopy(profile.get('authentication') or {})
    # Executable scripts and arbitrary imported plans are not accepted from tool arguments.
    if auth.get('method') not in ('form', 'json', 'http', 'browser'):
        raise ValueError('ZAP auth method must be form/json/http/browser')
    verification = auth.get('verification') or {}
    if not verification.get('loggedInRegex') or not verification.get('loggedOutRegex'):
        raise ValueError('ZAP auth profile requires loggedInRegex and loggedOutRegex')
    for k, value in (auth.get('parameters') or {}).items():
        if k.endswith('Url') and not within(value, target):
            raise ValueError('ZAP authentication URL outside target origin')
    if auth.get('method') == 'http':
        if (auth.get('parameters') or {}).get('hostname') != urlsplit(target).hostname:
            raise ValueError('HTTP authentication hostname must match target')
    context['authentication'] = auth
    context['sessionManagement'] = copy.deepcopy(profile.get('sessionManagement') or {'method': 'cookie'})
    credentials = {}
    for name, env_name in (profile.get('credential_env') or {}).items():
        if not isinstance(env_name, str) or env_name not in os.environ:
            raise ValueError('Missing authentication credential environment variable')
        credentials[name] = os.environ[env_name]
    if not credentials:
        raise ValueError('ZAP auth profile needs credential_env mapping')
    context['users'] = [{'name': context_name, 'credentials': credentials}]
    return context, context_name


def _openapi_file(config, target, workdir):
    """Only an operator-selected local JSON specification; no external refs/servers."""
    path = config.get('zap_openapi_file')
    if not path:
        return None
    spec = json.loads(Path(path).read_text())
    if not isinstance(spec, dict) or not (spec.get('openapi') or spec.get('swagger')):
        raise ValueError('Expected an OpenAPI/Swagger JSON specification')
    def visit(value):
        if isinstance(value, dict):
            if '$ref' in value and not str(value['$ref']).startswith('#/'):
                raise ValueError('External OpenAPI references are not allowed; bundle the spec first')
            for server in value.get('servers', []):
                server_url = str(server.get('url', ''))
                if server_url.startswith('//') or ('://' in server_url and not within(server_url, target)):
                    raise ValueError('OpenAPI server outside target origin')
            if 'host' in value and value['host'] != urlsplit(target).netloc:
                raise ValueError('Swagger host outside target origin')
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(spec)
    dest = Path(workdir) / 'openapi.json'
    dest.write_text(json.dumps(spec))
    dest.chmod(0o600)
    return str(dest)


def build_plan(config, target, workdir, *, active=False, rule_ids=(), auth_context='anonymous', ajax=False):
    target = canonical_url(target)
    context, user = _operator_context(config, target, auth_context)
    if active:
        # URL-only active jobs can select just the GET node and miss POST nodes.
        # Scan the context instead, constrained to exactly this endpoint path.
        context['includePaths'] = [re.escape(origin(target) + (urlsplit(target).path or '/')) + r'(?:\?.*)?$']
    minutes = max(1, int(config.get('zap_phase_minutes', 2)))
    common = {'context': 'aixsec', **({'user': user} if user else {})}
    depth = max(1, int(config.get('zap_spider_depth', 10)))
    jobs = [{'type': 'passiveScan-config', 'parameters': {'scanOnlyInScope': True}}]
    if not active:
        catalog = Path(workdir) / 'rule-catalog.js'
        catalog.write_text((Path(__file__).parent / 'examples/zap/rule-catalog.js').read_text().replace(
            '__AIXSEC_OUTPUT__', json.dumps(str(Path(workdir) / 'active-rules.json'))))
        catalog.chmod(0o600)
        jobs.extend([{'type': 'script', 'parameters': {'action': 'add', 'type': 'standalone',
            'engine': 'ECMAScript : Graal.js', 'name': 'aixsec-rule-catalog', 'source': str(catalog)}},
            {'type': 'script', 'parameters': {'action': 'run', 'type': 'standalone', 'name': 'aixsec-rule-catalog'}}])
    # Executor-owned capture only; the model cannot supply a filesystem path.
    # Import requests/responses without replay, retaining POST bodies for the
    # selected endpoint so active scans are not limited to a fresh GET crawl.
    seed_entry = config.get('_zap_seed_entry') if active else None
    seed = config.get('_zap_seed_har') if active else None
    if seed_entry:
        seed_path = Path(workdir) / 'seed.har'
        entry = copy.deepcopy(seed_entry)
        entry['request']['headers'] = [h for h in entry['request'].get('headers', []) if h.get('name', '').lower() != 'x-zap-scan-id']
        seed_path.write_text(json.dumps({'log': {'version': '1.2', 'creator': {'name': 'AIXSEC-X', 'version': '1'}, 'entries': [entry]}}))
        seed_path.chmod(0o600)
        jobs.append({'type': 'import', 'parameters': {'type': 'har', 'fileName': str(seed_path)}})
        seed = None
    if seed:
        capture = json.loads(Path(seed).read_text())
        target_path = urlsplit(target).path or '/'
        target_params = {k for k, _ in parse_qsl(urlsplit(target).query, keep_blank_values=True)}
        entries = []
        for entry in capture.get('log', {}).get('entries', []):
            request = entry.get('request') or {}
            u = request.get('url', '')
            if not within(u, target) or (urlsplit(u).path or '/') != target_path:
                continue
            if not target_params <= {k for k, _ in parse_qsl(urlsplit(u).query, keep_blank_values=True)}:
                continue
            entry = copy.deepcopy(entry)
            entry['request']['headers'] = [h for h in request.get('headers', [])
                if h.get('name', '').lower() != 'x-zap-scan-id']
            entries.append(entry)
        if entries:
            seed_path = Path(workdir) / 'seed.har'
            seed_path.write_text(json.dumps({'log': {'version': '1.2',
                'creator': {'name': 'AIXSEC-X', 'version': '1'}, 'entries': entries}}))
            seed_path.chmod(0o600)
            jobs.append({'type': 'import', 'parameters': {'type': 'har',
                         'fileName': str(seed_path)}})  # default: import only; older add-ons lack sendRequests
    spec = _openapi_file(config, target, workdir) if not seed_entry else None
    if spec:
        # Older bundled OpenAPI add-ons reject maxMessages. Keep the plan
        # compatible; zap_max_urls is only a planning estimate, not an import cap.
        jobs.append({'type': 'openapi', 'parameters': {**common, 'apiFile': spec,
                     'targetUrl': origin(target)}})
    if not seed_entry:
        jobs.append({'type': 'spider', 'parameters': {**common, 'url': target,
            'maxDuration': minutes, 'maxDepth': depth,
            'maxChildren': max(1, int(config.get('zap_spider_children', 50))), 'logoutAvoidance': True}})
    if ajax and not seed_entry:
        jobs.append({'type': 'spiderAjax', 'parameters': {**common, 'url': target,
            'maxDuration': minutes, 'maxCrawlDepth': depth, 'numberOfBrowsers': 1,
            'inScopeOnly': True, 'scopeCheck': 'Strict',
            'browserId': config.get('zap_browser', 'firefox-headless'),
            'clickDefaultElems': False,
            'elements': [v.strip() for v in config.get('zap_ajax_elements', ['a', 'button', 'input']) if v.strip()],
            'randomInputs': True, 'clickElemsOnce': True, 'logoutAvoidance': True,
            'eventWait': 1500, 'reloadWait': 1500,
            'maxCrawlStates': max(1, int(config.get('zap_ajax_states', 100)))}})
    jobs.append({'type': 'passiveScan-wait', 'parameters': {'maxDuration': minutes}})
    if active:
        allowed = {int(x) for x in config.get('zap_allowed_rules', [])}
        selected = {int(x) for x in rule_ids}
        if not selected or not selected <= allowed:
            raise ValueError('Active scan requires explicit rule_ids within WEBX_ZAP_ALLOWED_RULES')
        observer = Path(workdir) / 'active-observer.js'
        observer.write_text((Path(__file__).parent / 'examples/zap/active-observer.js').read_text().replace(
            '__AIXSEC_OUTPUT__', json.dumps(str(Path(workdir) / 'active-requests.jsonl'))))
        observer.chmod(0o600)
        jobs.append({'type': 'script', 'parameters': {'action': 'add', 'type': 'httpsender',
            'engine': 'ECMAScript : Graal.js', 'name': 'aixsec-active-observer', 'source': str(observer)}})
        jobs.append({'type': 'activeScan-policy', 'parameters': {'name': 'aixsec-targeted'},
            'policyDefinition': {'defaultStrength': 'Low', 'defaultThreshold': 'Off',
                'rules': [{'id': i, 'strength': 'Low', 'threshold': 'Medium'} for i in sorted(selected)]}})
        jobs.append({'type': 'activeScan', 'parameters': {**common,
            'policy': 'aixsec-targeted', 'maxScanDurationInMins': minutes,
            'maxRuleDurationInMins': minutes, 'threadPerHost': 1,
            'injectPluginIdInHeader': True,
            'delayInMs': int(config.get('zap_delay_ms', 200))}})
        jobs.append({'type': 'passiveScan-wait', 'parameters': {'maxDuration': minutes}})
    jobs.extend([
        {'type': 'export', 'alwaysRun': True, 'parameters': {'context': 'aixsec',
            'type': 'har', 'source': 'all', 'fileName': str(Path(workdir) / 'traffic.har')}},
        {'type': 'export', 'alwaysRun': True, 'parameters': {'context': 'aixsec',
            'type': 'url', 'source': 'all', 'fileName': str(Path(workdir) / 'urls.txt')}},
        {'type': 'report', 'alwaysRun': True, 'parameters': {
            'template': 'traditional-json-plus', 'reportDir': str(workdir),
            'reportFile': 'report.json', 'displayReport': False}},
    ])
    return {'env': {'contexts': [context], 'parameters': {
        'failOnError': True, 'failOnWarning': False, 'continueOnFailure': False}}, 'jobs': jobs}


def parse_report(path, target, scan_id, auth_context='anonymous'):
    report = json.loads(Path(path).read_text())
    if not isinstance(report, dict) or not isinstance(report.get('site'), list):
        raise ValueError('ZAP report missing site array')
    rows, rejected, stats, matched_sites = [], 0, {}, 0
    redactor = EvidenceRedactor()
    for site in report['site']:
        if not isinstance(site, dict) or not within(site.get('@name', ''), target):
            rejected += 1
            continue
        matched_sites += 1
        stats.update(site.get('statistics') or {})
        alerts = site.get('alerts')
        if not isinstance(alerts, list):
            raise ValueError('ZAP report missing alerts array')
        for alert in alerts:
            if not isinstance(alert, dict) or not isinstance(alert.get('instances'), list):
                raise ValueError('Malformed ZAP alert instances')
            if str(alert.get('confidence')) == '0':
                continue  # Explicitly classified false positive by the scanner.
            for instance in alert['instances']:
                url = str(instance.get('uri') or '')
                if not within(url, target):
                    rejected += 1
                    continue
                rule = str(alert.get('alertRef') or alert.get('pluginid') or '')
                if not rule or not alert.get('name', alert.get('alert')):
                    raise ValueError('ZAP alert missing rule/name')
                response_header = str(instance.get('response-header') or '')
                # Raw evidence is retained in the private report. Only bounded,
                # redacted metadata leaves the adapter for graph/model context.
                rows.append({'rule_id': rule, 'category': str(alert.get('name') or alert.get('alert')),
                    'url': redactor.redact_url(canonical_url(url)), 'method': str(instance.get('method') or 'GET'),
                    'parameter': str(instance.get('param') or ''), 'auth_context': auth_context,
                    'severity': {'0': 'info', '1': 'low', '2': 'medium', '3': 'high'}.get(str(alert.get('riskcode')), 'info'),
                    'scanner_confidence': str(alert.get('confidence') or ''),
                    'cwe': str(alert.get('cweid') or ''), 'scan_id': scan_id,
                    'request_sha256': hashlib.sha256(str(instance.get('request-header', '')).encode()
                                                     + str(instance.get('request-body', '')).encode()).hexdigest(),
                    'response_sha256': hashlib.sha256(response_header.encode()
                                                      + str(instance.get('response-body', '')).encode()).hexdigest(),
                    'artifact_ref': str(path),
                    # Private in-memory validation facts; excluded from graph/report summaries.
                    '_response_header': response_header, '_request_header': str(instance.get('request-header') or ''),
                    '_url': canonical_url(url), '_request_body': str(instance.get('request-body') or ''),
                    '_body_sha256': hashlib.sha256(str(instance.get('response-body') or '').encode()).hexdigest(),
                    '_evidence': str(instance.get('evidence') or ''),
                    'description': f'ZAP rule {rule}; validation required.',
                    'fix': re.sub('<[^>]+>', '', str(alert.get('solution') or ''))[:1500]})
    return rows, {'version': str(report.get('@version') or ''),
                  'warnings': len(report.get('afPlanWarns') or []),
                  'errors': len(report.get('afPlanErrors') or []),
                  'rejected_out_of_origin': rejected, 'matched_sites': matched_sites, 'statistics': stats}


def run_scan(config, url, *, active=False, rule_ids=(), auth_context='anonymous', ajax=False, timeout=None):
    binary = executable(config)
    if not binary:
        raise ValueError('ZAP executable unavailable; on Kali install zaproxy, or set '
                         'WEBX_ZAP_EXECUTABLE to an executable path (zaproxy or zap.sh)')
    root = Path(config.get('evidence_dir') or '.aixsec-evidence').resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = Path(tempfile.mkdtemp(prefix='zap-', dir=root))
    scan_id = directory.name
    plan = build_plan(config, url, directory, active=active, rule_ids=rule_ids,
                      auth_context=auth_context, ajax=ajax)
    plan_path = directory / 'plan.yaml'  # JSON is a YAML subset accepted by SnakeYAML.
    plan_path.write_text(json.dumps(plan))
    plan_path.chmod(0o600)
    home = directory / 'home'
    home.mkdir(mode=0o700)
    log_path = directory / 'zap.log'
    deadline = max(1, int(timeout or config.get('zap_timeout', 300)))
    timed_out = False
    started = time.monotonic()
    # Do not inherit global header injection from an unrelated scan.
    env = {k: v for k, v in os.environ.items() if not k.startswith('ZAP_AUTH_HEADER')}
    try:
        with log_path.open('w') as log:
            process = subprocess.Popen(launch_command(binary) + ['-cmd', '-host', '127.0.0.1', '-port', '0',
                '-dir', str(home), '-autorun', str(plan_path)],
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True, env=env)
            try:
                code = process.wait(timeout=deadline)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                code = process.returncode
    finally:
        # Plan contains credentials resolved from operator environment.
        plan_path.unlink(missing_ok=True)
    report_path = directory / 'report.json'
    rows, metadata = [], {'version': '', 'errors': 0, 'warnings': 0, 'statistics': {}}
    parse_error = ''
    if report_path.exists():
        report_path.chmod(0o600)
        try:
            rows, metadata = parse_report(report_path, url, scan_id, auth_context)
        except (ValueError, TypeError, KeyError) as exc:
            parse_error = str(exc)
    urls_path = directory / 'urls.txt'
    urls = []
    if urls_path.exists():
        urls = sorted({canonical_url(v.strip()) for v in urls_path.read_text().splitlines()
                       if within(v.strip(), url)})
    state = 'complete' if code == 0 and report_path.exists() and urls and not parse_error \
        and metadata.get('matched_sites', 0) and not metadata.get('rejected_out_of_origin') \
        and not metadata['errors'] and not metadata['warnings'] else 'partial'
    if timed_out:
        state = 'timeout'
    elif not report_path.exists() or parse_error:
        state = 'error'
    # Auth is explicitly unverified unless the configured verification yielded
    # logged-in statistics and no logged-out responses. Never label anonymous
    # fallback traffic as authenticated coverage.
    stats = metadata.pop('statistics', {})
    auth_state = 'anonymous'
    if auth_context != 'anonymous':
        logged_in = sum(float(v) for k, v in stats.items() if k.endswith('auth.state.loggedin'))
        logged_out = sum(float(v) for k, v in stats.items() if k.endswith('auth.state.loggedout'))
        auth_state = 'verified' if logged_in > 0 and logged_out == 0 else 'unverified'
        if auth_state != 'verified' and state == 'complete':
            state = 'partial'
    for row in rows:
        row['auth_state'] = auth_state
    from zap_discovery import Discovery
    discovery = Discovery(url, auth_context, rule_ids if active else ())
    har_path = directory / 'traffic.har'
    inventory_error = ''
    if har_path.exists():
        har_path.chmod(0o600)
        try:
            discovery.har(har_path)
        except (ValueError, TypeError, KeyError, OSError) as exc:
            inventory_error = 'Cannot parse HAR: ' + str(exc)
    else:
        inventory_error = 'HAR unavailable; inventory based on alert samples and exported URLs only'
    if report_path.exists() and not parse_error:
        discovery.report(report_path)
    active_path = directory / 'active-requests.jsonl'
    if active and active_path.exists():
        active_path.chmod(0o600)
        try:
            discovery.active_records(active_path)
        except (ValueError, TypeError, KeyError, OSError) as exc:
            inventory_error = 'Cannot parse active request evidence: ' + str(exc)
    for endpoint in urls:
        discovery.add(endpoint, 'UNKNOWN', [], 'url_export')
    inventory = discovery.result()
    inventory_path = directory / 'inventory.json'
    inventory_path.write_text(json.dumps(inventory, ensure_ascii=False, indent=2))
    inventory_path.chmod(0o600)
    log_text = log_path.read_text(errors='replace')
    phases = {job: ('completed' if f'Job {job} finished' in log_text else
                    'started' if f'Job {job} started' in log_text else 'not_run')
              for job in ('spider', 'spiderAjax', 'activeScan', 'passiveScan-wait')}
    engine_log = home / 'zap.log'
    engine_text = engine_log.read_text(errors='replace') if engine_log.exists() else ''
    browser_failed = ajax and any(marker in engine_text for marker in (
        'Failed to start browser', 'Unable to start browser', 'SessionNotCreatedException'))
    if browser_failed:
        phases['spiderAjax'] = 'failed'
        if state == 'complete':
            state = 'partial'
    gaps = []
    if not ajax:
        gaps.append('AJAX Spider disabled; browser interactions not covered')
    elif phases['spiderAjax'] != 'completed':
        gaps.append('AJAX Spider did not complete; check browser/add-on and time budget')
    if inventory_error:
        gaps.append(inventory_error)
        if state == 'complete':
            state = 'partial'
    if inventory['summary']['discovered_only']:
        gaps.append('Some discovered endpoints have no captured request')
    if not active:
        gaps.append('Active testing not run')
    elif not inventory['test_request_count']:
        gaps.append('No captured request attributed to the selected active rules')
        if state == 'complete':
            state = 'partial'
    coverage = {'scan_id': scan_id, 'tool': 'zap_active_scan' if active else 'zap_baseline',
        'target': EvidenceRedactor().redact_url(canonical_url(url)), 'status': state,
        'auth_context': auth_context, 'auth_state': auth_state,
        'discovered_urls': len(urls), 'alerts': len(rows), 'active_requested': active,
        'requested_rule_ids': sorted(set(rule_ids)), 'ajax_requested': ajax,
        'openapi_requested': bool(config.get('zap_openapi_file')), 'returncode': code,
        'duration': round(time.monotonic() - started, 2), 'report_path': str(report_path),
        'log_path': str(log_path), 'error': parse_error, **metadata}
    coverage.update(status_meaning='execution_only_not_full_coverage', phases=phases, gaps=gaps,
                    inventory_path=str(inventory_path), har_path=str(har_path),
                    active_requests_path=str(active_path),
                    inventory_summary=inventory['summary'],
                    captured_requests=inventory['request_count'], active_test_requests=inventory['test_request_count'])
    active_rules = []
    catalog_path = directory / 'active-rules.json'
    if catalog_path.exists():
        try:
            active_rules = json.loads(catalog_path.read_text())
            if not isinstance(active_rules, list) or any(type(r.get('id')) is not int for r in active_rules):
                active_rules = []
        except (ValueError, TypeError, AttributeError):
            active_rules = []
    summary = inventory['summary']
    return (f"ZAP {state}: {len(urls)} URLs, {len(rows)} alert instances; "
            f"{summary['forms']} forms, {summary['inputs']} inputs; "
            f"endpoints discovered-only/requested/tested="
            f"{summary['discovered_only']}/{summary['requested']}/{summary['tested']}; "
            f"active requests={inventory['test_request_count']}; AJAX={phases['spiderAjax']}; "
            f"auth={auth_state}; inventory={inventory_path}; report={report_path}",
            {'target': canonical_url(url), 'scan_id': scan_id, 'coverage': coverage,
             'endpoints': [EvidenceRedactor().redact_url(u) for u in urls], 'alerts': rows,
             'discovery': inventory, 'active_rules': active_rules})
