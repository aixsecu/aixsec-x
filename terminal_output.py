"""CLI-only presentation. Diagnostic writes never enter normal scan output."""
from contextlib import redirect_stdout, redirect_stderr
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time

_active = None


def event(kind, *args):
    if _active is not None:
        getattr(_active, kind)(*args)


def prompt(text):
    """Keep operator interaction visible while diagnostics are captured."""
    if _active is None:
        sys.stderr.write(text)
        sys.stderr.flush()
        return input('')
    _active.clear()
    _active.screen.write(text)
    _active.screen.flush()
    return input('')


def clean(value):
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', str(value))


class TerminalOutput:
    def __init__(self, verbose=False, screen=None, log_dir=None):
        self.screen = screen or sys.stdout
        root = Path(log_dir or os.environ.get('WEBX_LOG_DIR', '.aixsec-evidence/logs'))
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, self.log_path = tempfile.mkstemp(prefix='cli-', suffix='.log', dir=root)
        self.log = os.fdopen(fd, 'w', encoding='utf-8')
        self.verbose = verbose
        self.lock = threading.RLock()
        self.started = time.monotonic()
        self.agent = None
        self.result = {}
        self.files = {}
        self.seen = set()
        self.stage_name = None
        self.closed_output = False
        self.tty = self.screen.isatty()

    def write(self, text):
        with self.lock:
            self.log.write(text)
            self.log.flush()
            if self.verbose and not self.closed_output:
                self.clear()
                self.screen.write(text)
                self.screen.flush()
        return len(text)

    def flush(self):
        self.log.flush()

    def isatty(self):
        return False

    def clear(self):
        if self.tty and self.stage_name:
            self.screen.write('\r\033[2K')

    def stage(self, name, status='running', reason=''):
        stages = {'discovery':'Discovery', 'route_family':'Route Family',
                  'zap_active':'Active Scan', 'nuclei':'Active Scan',
                  'verification':'Validation', 'planner':'Validation', 'report':'Reporting'}
        label = stages.get(name)
        if label is None or self.closed_output:
            return
        with self.lock:
            if self.tty:
                self.clear()
                self.screen.write(f'[{label}] {clean(status)}\r')
            elif label != self.stage_name:
                self.screen.write(f'[{label}]\n')
            self.stage_name = label
            self.screen.flush()

    def finding(self, finding):
        visible = finding.status == 'confirmed' or (
            finding.status in ('candidate','needs_validation')
            and finding.severity.lower() in ('critical','high'))
        marker = (finding.key, finding.status)
        if not visible or marker in self.seen or self.closed_output:
            return
        with self.lock:
            self.seen.add(marker)
            self.clear()
            suffix = '' if finding.status == 'confirmed' else ' [CANDIDATE — needs validation]'
            detail = f' — {clean(finding.method)} {clean(finding.url)}'
            if finding.parameter:
                detail += f' (param={clean(finding.parameter)})'
            line = f'[{clean(finding.severity.upper())}] {clean(finding.name)}{suffix}{detail}\n'
            self.log.write(line)
            self.screen.write(line)
            self.screen.flush()

    def bind(self, agent):
        self.agent = agent
        self.stage('discovery')

    def completed(self, result):
        self.result = result

    def output_file(self, label, path):
        if path:
            self.files[label] = path

    def summary(self, status=None):
        if self.agent is None:
            return
        agent = self.agent
        result = self.result or (agent.evidence_store.summary() if hasattr(agent, "evidence_store") else {})
        findings = agent.ledger.all()
        tasks = result.get('progress', {}).get('tasks', [])
        active = [t for t in tasks if t.get('stage') in ('zap_active', 'nuclei')]
        discovery = result.get('discovery', [])
        urls = {e.get('url') for d in discovery for e in d.get('endpoints', []) if e.get('url')}
        rows = ['=' * 50, 'AIXSEC-X Scan Summary', '=' * 50,
                'Target: ' + ', '.join(map(clean, agent.config.get('targets') or agent.config.get('src_dirs') or [])),
                f'Duration: {time.monotonic() - self.started:.1f}s',
                'Status: ' + (status or result.get('progress', {}).get('status') or ('Busy' if result.get('busy') else result.get('status', 'Finished'))),
                '', 'Discovery', f'  URLs: {len(urls) if discovery else "N/A"}',
                f'  Route Families: {result.get("route_families", {}).get("family_count", "N/A")}',
                f'  Representatives: {result.get("representatives", {}).get("scan_groups_after", "N/A")}',
                '', 'Active Scan', f'  Jobs: {len(active) if tasks else "N/A"}',
                f'  Success: {sum(t.get("status") in ("complete", "ok", "success") for t in active) if tasks else "N/A"}',
                f'  Failed: {sum(t.get("status") in ("error", "failed", "timeout", "interrupted") for t in active) if tasks else "N/A"}',
                '', 'Findings (confirmed)']
        for severity in ('critical', 'high', 'medium', 'low', 'info'):
            rows.append(f'  {severity.title()}: {sum(f.status == "confirmed" and f.severity.lower() == severity for f in findings)}')
        rows.append(f'  Awaiting validation: {sum(f.status in ("candidate", "needs_validation") for f in findings)}')
        priority = [f for f in findings if f.status in ('candidate','needs_validation')
                    and f.severity.lower() in ('critical','high')]
        rows += ['', 'High-priority candidates']
        if priority:
            for finding in priority:
                location = f'{clean(finding.method)} {clean(finding.url)}'
                if finding.parameter:
                    location += f' (param={clean(finding.parameter)})'
                rows.append(f'  [{clean(finding.severity.upper())}] {clean(finding.name)} — {location}')
        else:
            rows.append('  None')
        coverage = result.get('coverage', [])
        rows += ['', 'Coverage']
        if coverage:
            counts = {}
            for row in coverage:
                state = str(row.get('status', 'unknown'))
                counts[state] = counts.get(state, 0) + 1
            rows += [f'  {clean(k)}: {v}' for k, v in sorted(counts.items())]
        else:
            rows.append('  Not available')
        benchmark = result.get('technology_capability_benchmark')
        if benchmark:
            rows += ['', 'Technology Capability Benchmark',
                f'  Payload families before: {benchmark["payload_families_before_optimization"]}',
                f'  Payload families after: {benchmark["payload_families_after_optimization"]}',
                f'  Skipped payload families: {benchmark["skipped_payload_families"]}',
                f'  Executed payload families: {benchmark["executed_payload_families"]}',
                f'  Average planning time: {benchmark["average_planning_time_ms"]:.3f} ms',
                f'  Average scan duration: {benchmark["average_scan_duration_seconds"]:.3f}s',
                f'  Overall scan reduction: {benchmark["overall_scan_reduction_percent"]:.2f}%']
        rows += ['', 'Output Files']
        files = dict(self.files)
        files.update({k.removesuffix('_path').replace('_', ' ').title(): v
                      for k, v in result.items() if k.endswith('_path') and isinstance(v, str)})
        files['Diagnostic log'] = self.log_path
        rows += [f'  {clean(k)}: {clean(v)}' for k, v in files.items()]
        rows.append('=' * 50)
        with self.lock:
            self.clear()
            self.closed_output = True
            block = '\n' + '\n'.join(rows) + '\n'
            self.log.write(block)
            self.screen.write(block)
            self.screen.flush()

    def __enter__(self):
        global _active
        _active = self
        self.stdout = redirect_stdout(self)
        self.stderr = redirect_stderr(self)
        self.stdout.__enter__()
        self.stderr.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        global _active
        try:
            self.summary('Interrupted' if exc_type is KeyboardInterrupt else 'Failed' if exc_type else None)
        finally:
            _active = None
            self.stderr.__exit__(exc_type, exc, tb)
            self.stdout.__exit__(exc_type, exc, tb)
            self.log.close()
