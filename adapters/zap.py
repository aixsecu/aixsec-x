"""Isolated, bounded ZAP Automation Framework executor (no LLM-generated plans)."""
from __future__ import annotations

import copy
import atexit
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import threading
import sys
import tempfile
import time
from datetime import datetime
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
    seed_entries = list(config.get('_zap_seed_entries') or [])
    if active:
        # URL-only active jobs can select just the GET node and miss POST nodes.
        # Scan the context instead, constrained to exactly this endpoint path.
        targets = [str((entry.get('request') or {}).get('url') or '') for entry in seed_entries] or [target]
        if any(not within(value, target) for value in targets):
            raise ValueError('Batched ZAP seeds must remain within one origin')
        context['includePaths'] = sorted({re.escape(origin(value) + (urlsplit(value).path or '/')) + r'(?:\?.*)?$'
                                          for value in targets})
    minutes = max(1, int(config.get('zap_phase_minutes', 2)))
    common = {'context': 'aixsec', **({'user': user} if user else {})}
    depth = max(1, int(config.get('zap_spider_depth', 10)))
    jobs = [{'type': 'passiveScan-config', 'parameters': {'scanOnlyInScope': True}}]
    if not active:
        catalog = Path(workdir) / 'rule-catalog.js'
        catalog.write_text((Path(__file__).resolve().parent.parent / 'examples/zap/rule-catalog.js').read_text().replace(
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
    if seed_entries or seed_entry:
        seed_path = Path(workdir) / 'seed.har'
        entries = copy.deepcopy(seed_entries or [seed_entry])
        for entry in entries:
            entry['request']['headers'] = [h for h in entry['request'].get('headers', [])
                                           if h.get('name', '').lower() != 'x-zap-scan-id']
        seed_path.write_text(json.dumps({'log': {'version': '1.2', 'creator': {'name': 'AIXSEC-X', 'version': '1'}, 'entries': entries}}))
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
    spec = _openapi_file(config, target, workdir) if not (seed_entry or seed_entries) else None
    if spec:
        # Older bundled OpenAPI add-ons reject maxMessages. Keep the plan
        # compatible; zap_max_urls is only a planning estimate, not an import cap.
        jobs.append({'type': 'openapi', 'parameters': {**common, 'apiFile': spec,
                     'targetUrl': origin(target)}})
    if not (seed_entry or seed_entries):
        jobs.append({'type': 'spider', 'parameters': {**common, 'url': target,
            'maxDuration': minutes, 'maxDepth': depth,
            'maxChildren': max(1, int(config.get('zap_spider_children', 50))), 'logoutAvoidance': True}})
    if ajax and not (seed_entry or seed_entries):
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
        strength = str(config.get('zap_strength', 'Medium')).capitalize()
        if strength not in ('Low', 'Medium', 'High', 'Insane'):
            raise ValueError('WEBX_ZAP_STRENGTH must be Low, Medium, High or Insane')
        observer = Path(workdir) / 'active-observer.js'
        observer.write_text((Path(__file__).resolve().parent.parent / 'examples/zap/active-observer.js').read_text().replace(
            '__AIXSEC_OUTPUT__', json.dumps(str(Path(workdir) / 'active-requests.jsonl'))))
        if config.get('_zap_rate_root'):
            # A Java FileLock serializes request start times across ZAP JVMs.
            rate_path = Path(config['_zap_rate_root']) / ('zap-rate-' + hashlib.sha256(origin(target).encode()).hexdigest() + '.lock')
            rate_path.touch(mode=0o600, exist_ok=True)
            rate_script = (Path(__file__).resolve().parent.parent / 'examples/zap/shared-rate.js').read_text()
            observer.write_text(observer.read_text().replace(
                'function sendingRequest(msg, initiator, helper) {}',
                rate_script.replace('__AIXSEC_RATE_PATH__', json.dumps(str(rate_path)))
                           .replace('__AIXSEC_RATE_MS__', str(max(0, int(config.get('zap_delay_ms', 200)))))))
        observer.chmod(0o600)
        jobs.append({'type': 'script', 'parameters': {'action': 'add', 'type': 'httpsender',
            'engine': 'ECMAScript : Graal.js', 'name': 'aixsec-active-observer', 'source': str(observer)}})
        jobs.append({'type': 'activeScan-policy', 'parameters': {'name': 'aixsec-targeted'},
            'policyDefinition': {'defaultStrength': strength, 'defaultThreshold': 'Off',
                'rules': [{'id': i, 'strength': strength, 'threshold': 'Medium'} for i in sorted(selected)]}})
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


_port_lock = threading.Lock()
_owned_ports = set()
_pool_lock = threading.Lock()
_default_pools = {}


_LOG_TIME = re.compile(r'(?P<stamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[,.]\d{3})')
_JOB_EVENT = re.compile(r'Job\s+(?P<job>[A-Za-z0-9_-]+)\s+(?P<event>started|finished)', re.I)


def _log_milliseconds(text):
    """Extract non-overlapping Automation Framework phase timings from ZAP logs."""
    events=[]
    for line in text.splitlines():
        stamp=_LOG_TIME.search(line);event=_JOB_EVENT.search(line)
        if not stamp or not event:
            continue
        try:
            value=datetime.strptime(stamp.group('stamp').replace('.',','),'%Y-%m-%d %H:%M:%S,%f').timestamp()*1000
        except ValueError:
            continue
        events.append((value,event.group('job'),event.group('event').lower()))
    starts={};durations={};occurrences=[]
    for value,job,event in events:
        if event=='started': starts.setdefault(job,[]).append(value)
        elif starts.get(job):
            began=starts[job].pop(0);duration=max(0,value-began)
            durations[job]=durations.get(job,0)+duration
            occurrences.append((job,began,value,duration))
    passive=[item[3] for item in occurrences if item[0]=='passiveScan-wait']
    report=sum(value for job,value in durations.items() if job in ('report','export'))
    return {'context_import_ms':durations.get('import',0),
            'policy_load_ms':durations.get('activeScan-policy',0),
            'scan_configuration_ms':durations.get('passiveScan-config',0),
            'script_load_ms':durations.get('script',0),
            'authentication_setup_ms':durations.get('authentication',0),
            'spider_wait_ms':durations.get('spider',0)+durations.get('spiderAjax',0),
            'passive_wait_ms':passive[0] if passive else 0,
            'passive_flush_ms':sum(passive[1:]),
            'active_scan_ms':durations.get('activeScan',0),
            'report_export_ms':durations.get('export',0),
            'report_finalize_ms':durations.get('report',0),
            'report_generation_ms':report,
            '_first_job_ms':min((value for value,_,event in events if event=='started'),default=None),
            '_last_job_ms':max((value for value,_,event in events if event=='finished'),default=None)}


def _timestamped_markers(text):
    """Return selected JVM lifecycle markers without guessing missing events."""
    markers={}
    patterns=(('java_started_ms','CommandLineBootstrap - ZAP '),
              ('extensions_loading_ms','ExtensionFactory - Loading extensions'),
              ('extensions_loaded_ms','ExtensionFactory - Extensions loaded'),
              ('network_setup_started_ms','ExtensionNetwork - Creating new root CA certificate.'),
              ('network_setup_finished_ms','ExtensionNetwork - New root CA certificate created.'),
              ('terminated_ms','CommandLineBootstrap - ZAP '))
    for line in text.splitlines():
        stamp=_LOG_TIME.search(line)
        if not stamp: continue
        try: value=datetime.strptime(stamp.group('stamp').replace('.',','),'%Y-%m-%d %H:%M:%S,%f').timestamp()*1000
        except ValueError: continue
        for key,needle in patterns:
            if needle not in line: continue
            if key=='java_started_ms' and ' started ' not in line: continue
            if key=='terminated_ms' and ' terminated.' not in line: continue
            markers.setdefault(key,value)
    return markers


def _startup_components(text, began_ms, first_job_ms):
    """Preserve coarse startup timing without inventing context markers."""
    ceiling=first_job_ms if first_job_ms is not None else began_ms
    addon=[]
    for line in text.splitlines():
        stamp=_LOG_TIME.search(line)
        if not stamp: continue
        try: value=datetime.strptime(stamp.group('stamp').replace('.',','),'%Y-%m-%d %H:%M:%S,%f').timestamp()*1000
        except ValueError: continue
        if value>ceiling: continue
        lower=line.lower()
        if ('add-on' in lower or 'addon' in lower) and any(word in lower for word in ('load','install','initial')):
            addon.append(value)
    def span(values): return max(values)-min(values) if len(values)>1 else 0
    addon_ms=span(addon);context_ms=0
    startup_total=max(0,ceiling-began_ms)
    return max(0,startup_total-addon_ms-context_ms),addon_ms,context_ms


def reserve_proxy_port():
    # ZAP versions may treat -port 0 as the configured default, not ephemeral.
    # Keep a process-local reservation until the owned JVM exits.
    with _port_lock:
        for _ in range(100):
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            if port not in _owned_ports:
                _owned_ports.add(port)
                return port
    raise RuntimeError('Unable to allocate a private ZAP proxy port')


def release_proxy_port(port):
    with _port_lock: _owned_ports.discard(port)


def worker_pool(config):
    """Create the pipeline-owned persistent pool without changing public APIs."""
    binary=executable(config)
    if not binary: raise ValueError('ZAP executable unavailable')
    from zap_pool import WorkerPool
    return WorkerPool(config,binary,launch_command(binary),reserve_proxy_port,release_proxy_port)


def default_worker_pool(config):
    """Backward-compatible direct adapter calls share a persistent pool too."""
    key=(str(Path(config.get('evidence_dir') or '.aixsec-evidence').resolve()),
         str(config.get('zap_executable') or 'zap.sh'),int(config.get('zap_workers',2)))
    with _pool_lock:
        pool=_default_pools.get(key)
        if pool is None:
            pool=worker_pool(config);_default_pools[key]=pool
        return pool


def shutdown_worker_pools():
    with _pool_lock:
        pools=list(_default_pools.values());_default_pools.clear()
    for pool in pools: pool.close()


atexit.register(shutdown_worker_pools)


def run_scan(config, url, *, active=False, rule_ids=(), auth_context='anonymous', ajax=False, timeout=None):
    total_started=time.perf_counter_ns()
    blocking={'subprocess_wait_ms':0.0,'subprocess_wait_calls':0,'polling_loop_iterations':0,
              'subprocess_wait_timeouts':0,'timeout_wait_ms':0.0,'timeout_wait_calls':0,
              'sleep_ms':0.0,'sleep_calls':0,
              'http_polling_ms':0.0,'http_polling_calls':0,'api_retry_ms':0.0,'api_retry_calls':0,
              'file_flush_ms':0.0,'file_flush_calls':0,'disk_sync_ms':0.0,'disk_sync_calls':0,
              'export_wait_ms':0.0,'export_wait_calls':0}
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
    started = time.monotonic();process_began_ms=time.time()*1000
    process_spawn_ms=0.0;stop_scan_ms=0.0;temporary_file_cleanup_ms=0.0
    # Do not inherit global header injection from an unrelated scan.
    env = {k: v for k, v in os.environ.items() if not k.startswith('ZAP_AUTH_HEADER')}
    proxy_port = None
    pool=config.get('_zap_worker_pool') or default_worker_pool(config)
    pool_worker=None;pool_metrics={};jvm_launches=1;engine_log_offset=0
    try:
        if pool is not None:
            acquire_started=time.perf_counter_ns()
            lease=pool.acquire(timeout=deadline)
            pool_worker=lease.__enter__()
            try:
                persistent_engine_log=pool_worker.workspace/'home'/'zap.log'
                engine_log_offset=persistent_engine_log.stat().st_size if persistent_engine_log.exists() else 0
                process_began_ms=time.time()*1000
                result=pool_worker.run_plan(plan_path,deadline,config.get('_zap_cancelled'))
                code=result['returncode'];process_ended_ms=time.time()*1000
                pool.metrics['worker_busy_ms']+=float(result.get('job_ms',0))
                pool_metrics={'worker_id':pool_worker.worker_id,
                    'worker_acquire_ms':(time.perf_counter_ns()-acquire_started)/1_000_000,
                    'worker_jobs':pool_worker.jobs,'worker_reused':pool_worker.jobs>1,
                    'worker_startup_ms':pool_worker.startup_ms,
                    'context_reused':bool(result.get('context_reused')),
                    'policy_reused':bool(result.get('policy_reused'))}
                jvm_launches=0
                log_path.write_text(json.dumps(result.get('progress') or {},default=str))
            except BaseException as exc:
                lease.__exit__(*sys.exc_info())
                from zap_pool import WorkerError
                if isinstance(exc,TimeoutError):
                    timed_out=True;code=-1;process_ended_ms=time.time()*1000
                    log_path.write_text(json.dumps({'error':str(exc),'status':'timeout'}))
                elif isinstance(exc,WorkerError) and not config.get('_zap_worker_retry'):
                    retry_config=dict(config);retry_config['_zap_worker_retry']=True
                    return run_scan(retry_config,url,active=active,rule_ids=rule_ids,
                                    auth_context=auth_context,ajax=ajax,timeout=timeout)
                else: raise
            else: lease.__exit__(None,None,None)
    finally:
        if proxy_port is not None: release_proxy_port(proxy_port)
        # Plan contains credentials resolved from operator environment.
        cleanup_started=time.perf_counter_ns();plan_path.unlink(missing_ok=True)
        temporary_file_cleanup_ms=(time.perf_counter_ns()-cleanup_started)/1_000_000
    evidence_started=time.perf_counter_ns();report_path = directory / 'report.json'
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
    from zap_active_evidence import analyze
    diagnostics, candidates = analyze(directory, url, rule_ids, auth_context, scan_id) if active else ({}, [])
    for candidate in candidates:
        candidate['auth_state'] = auth_state
    rows.extend(candidates)
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
    engine_log = (pool_worker.workspace/'home'/'zap.log') if pool_worker else home/'zap.log'
    if engine_log.exists() and pool_worker:
        with engine_log.open(errors='replace') as stream:
            stream.seek(engine_log_offset);engine_text=stream.read()
    else: engine_text = engine_log.read_text(errors='replace') if engine_log.exists() else ''
    phase_timing=_log_milliseconds(log_text+'\n'+engine_text)
    first_job_ms=phase_timing.pop('_first_job_ms')
    startup_ms,addon_ms,context_ms=_startup_components(log_text+'\n'+engine_text,
        process_began_ms,first_job_ms)
    last_job_ms=phase_timing.pop('_last_job_ms')
    shutdown_ms=0 if pool_worker else max(0,process_ended_ms-last_job_ms) if last_job_ms is not None else 0
    markers=_timestamped_markers(engine_text)
    java_started_ms=markers.get('java_started_ms')
    extensions_loading_ms=markers.get('extensions_loading_ms')
    extensions_loaded_ms=markers.get('extensions_loaded_ms')
    java_boot_ms=max(0,java_started_ms-(process_began_ms+process_spawn_ms)) if java_started_ms else 0
    addon_start=java_started_ms or extensions_loading_ms
    addon_end=markers.get('network_setup_started_ms') or extensions_loaded_ms
    addon_load_precise_ms=max(0,addon_end-addon_start) if addon_start and addon_end else addon_ms
    network_setup_ms=max(0,markers.get('network_setup_finished_ms',0)-
        markers.get('network_setup_started_ms',0)) if markers.get('network_setup_started_ms') else 0
    blocking['export_wait_ms']=phase_timing['report_export_ms']
    blocking['export_wait_calls']=sum(1 for line in engine_text.splitlines() if 'Job export started' in line)
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
    batch_size = len(config.get('_zap_seed_entries') or []) or 1
    evidence_parse_ms=(time.perf_counter_ns()-evidence_started)/1_000_000
    startup_total_ms=max(0,first_job_ms-process_began_ms) if first_job_ms is not None else 0
    startup_unattributed_ms=max(0,startup_total_ms-process_spawn_ms-java_boot_ms-
        addon_load_precise_ms-network_setup_ms)
    lifecycle_observability={'proxy_bind':'not_emitted_by_cmd_mode','api_ready':'not_applicable_no_http_api',
        'context_create':'not_emitted_by_automation_framework',
        'authentication_setup':'automation_job_only','alerts_download':'not_applicable_report_file_parsed',
        'api_shutdown':'not_applicable_process_exit','workspace_cleanup':'evidence_workspace_retained',
        'disk_sync':'not_called','http_polling':'not_used','api_retries':'not_used','sleep':'not_used'}
    performance={'scheduler_wait_ms':0,'scheduler_dispatch_ms':0,'prepare_ms':0,
        'process_spawn_ms':process_spawn_ms,'java_boot_ms':java_boot_ms,
        'proxy_bind_ms':0,'api_ready_ms':0,'script_load_ms':phase_timing['script_load_ms'],
        'network_setup_ms':network_setup_ms,'startup_unattributed_ms':startup_unattributed_ms,
        'authentication_setup_ms':phase_timing['authentication_setup_ms'],
        'scan_configuration_ms':phase_timing['scan_configuration_ms'],'startup_total_ms':startup_total_ms,
        'spider_wait_ms':phase_timing['spider_wait_ms'],'alerts_download_ms':0,
        'report_export_ms':phase_timing['report_export_ms'],
        'stop_scan_ms':stop_scan_ms,'passive_flush_ms':phase_timing['passive_flush_ms'],
        'report_finalize_ms':phase_timing['report_finalize_ms'],'api_shutdown_ms':0,
        'process_wait_ms':shutdown_ms,'workspace_cleanup_ms':0,
        'temporary_file_cleanup_ms':temporary_file_cleanup_ms,'shutdown_total_ms':shutdown_ms+temporary_file_cleanup_ms,
        'zap_startup_ms':startup_ms,'addon_load_ms':addon_ms,'context_create_ms':context_ms,
        **phase_timing,'evidence_parse_ms':evidence_parse_ms,'shutdown_ms':shutdown_ms,
        'total_job_ms':(time.perf_counter_ns()-total_started)/1_000_000,
        'batch_size':batch_size,'rules_executed':len(set(rule_ids)),
        'requests_executed':inventory['test_request_count'],'jvm_reused':max(0,batch_size-1),
        'jvm_launches':jvm_launches,'contexts_created':0 if pool_metrics.get('context_reused') else 1,
        'policies_created':1 if active and not pool_metrics.get('policy_reused') else 0,
        'blocking_operations':blocking,'lifecycle_observability':lifecycle_observability}
    performance.update(pool_metrics)
    performance['addon_load_ms']=addon_load_precise_ms
    measured_zap=sum(float(performance.get(key,0)) for key in ('zap_startup_ms','addon_load_ms',
        'context_create_ms','policy_load_ms','context_import_ms','passive_wait_ms','active_scan_ms',
        'report_generation_ms','shutdown_ms'))
    performance['unattributed_zap_ms']=max(0,(process_ended_ms-process_began_ms)-measured_zap)
    performance['job_duration']=performance['total_job_ms']/1000
    coverage = {'scan_id': scan_id, 'tool': 'zap_active_scan' if active else 'zap_baseline',
        'target': EvidenceRedactor().redact_url(canonical_url(url)), 'status': state,
        'auth_context': auth_context, 'auth_state': auth_state,
        'discovered_urls': len(urls), 'alerts': len(rows), 'active_requested': active,
        'requested_rule_ids': sorted(set(rule_ids)), 'ajax_requested': ajax,
        'openapi_requested': bool(config.get('zap_openapi_file')), 'returncode': code,
        'duration': round(time.monotonic() - started, 2), 'report_path': str(report_path),
        'log_path': str(log_path), 'error': parse_error, **metadata,
        'performance': performance}
    coverage['active_evidence'] = diagnostics
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
