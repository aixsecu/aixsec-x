"""Private atomic checkpoints and cross-scanner history. No target code is executed."""
import fcntl
from contextlib import contextmanager
import hashlib
import json
import os
import socket
from pathlib import Path
import sqlite3
import time


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def atomic(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False, default=str, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


class Journal:
    def __init__(self, directory, config):
        self.directory = Path(directory)
        self.path = self.directory / 'progress.json'
        # Resume cannot silently move old observations into another target/configuration.
        ignored = {'resume_session', 'retry_incomplete'}
        fingerprint = digest({k:v for k,v in config.items() if k not in ignored})
        if self.path.exists():
            self.data = json.loads(self.path.read_text())
            if self.data.get('fingerprint') != fingerprint:
                raise ValueError('Resume configuration differs from checkpoint; restore original configuration or start a new session')
        else:
            self.data = {'version':1, 'fingerprint':fingerprint, 'status':'running',
                         'stages':{}, 'tasks':{}}
        dependencies={}
        for key in ('zap_auth_file', 'zap_route_groups_file', 'zap_concurrency_file'):
            path=config.get(key)
            if path:
                dependencies[key]=hashlib.sha256(Path(path).read_bytes()).hexdigest()
        previous=self.data.get('dependencies')
        if previous is not None and previous!=dependencies:
            raise ValueError('Resume auth profile changed, route profile changed or concurrency profile changed; refresh discovery in a new session')
        self.data['dependencies']=dependencies
        self.retry = bool(config.get('retry_incomplete', False))
        self.interrupted = [t for t in self.data['tasks'].values() if t['status'] == 'running']
        for task in self.interrupted:
            task['status'] = 'interrupted'
        self.save()

    def save(self):
        self.data['updated_at'] = time.time()
        atomic(self.path, self.data)

    def stage(self, name, status, reason=''):
        self.data['stages'][name] = {**self.data['stages'].get(name, {}), 'status':status, 'reason':reason}
        self.save()
        print(f'[stage] {name}: {status}' + (f' — {reason}' if reason else ''), flush=True)

    def cached(self, key):
        task = self.data['tasks'].get(key)
        if not task or task['status'] in ('running', 'interrupted'):
            return None
        if self.retry and task['status'] not in ('complete', 'duplicate'):
            return None
        path = self.directory / ('checkpoint-' + key + '.json')
        return json.loads(path.read_text()) if path.exists() else None

    def start(self, key, name, args, stage):
        # Arguments stay in private checkpoint; public reports use summaries only.
        self.data['tasks'][key] = {'tool':name, 'args':args, 'stage':stage, 'status':'running', 'started_at':time.time()}
        self.save()

    def finish(self, key, result):
        atomic(self.directory / ('checkpoint-' + key + '.json'), result)
        task = self.data['tasks'][key]
        data=result.get('data')
        coverage=data.get('coverage') if isinstance(data,dict) else None
        status=(coverage.get('status') if isinstance(coverage,dict) else None) or result.get('outcome','error')
        task['status'] = 'complete' if status in ('ok', 'complete') else status
        task['outcome'] = result.get('outcome', 'error')
        task['finished_at'] = time.time()
        task['exec_time'] = result.get('exec_time')
        self.save()

    def summary(self):
        return {'path':str(self.path), 'status':self.data['status'], 'stages':self.data['stages'],
                'tasks':[{'tool':t['tool'], 'stage':t['stage'], 'status':t['status']}
                         for t in self.data['tasks'].values()]}


class ScanBusyError(ValueError):
    """Expected contention, not a scanner failure or permission to bypass history."""
    def __init__(self, path, owner=None):
        self.path = str(path)
        self.owner = owner or {}
        details = ''
        if self.owner.get('pid'):
            details = f" (PID {self.owner['pid']}, host {self.owner.get('host', 'unknown')})"
        super().__init__('Another scan is using this history namespace' + details +
                         '; wait for it to finish or stop that scan in its original terminal. '
                         'Do not delete the lock file or change namespace to bypass it. '
                         f'Lock: {self.path}')


class RunLock:
    def __init__(self, root, namespace):
        root = Path(root).resolve(); root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.stream = (root / ('run-' + digest(namespace)[:20] + '.lock')).open('a+')
        os.chmod(self.stream.name, 0o600)
    def __enter__(self):
        try:
            fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            try:
                self.stream.seek(0)
                owner = json.loads(self.stream.read(4096))
                if not isinstance(owner, dict):
                    owner = {}
            except (ValueError, OSError):
                owner = {}
            path = self.stream.name
            self.stream.close()
            raise ScanBusyError(path, owner) from None
        except BaseException:
            self.stream.close()
            raise
        try:
            self.stream.seek(0)
            self.stream.truncate()
            json.dump({'pid':os.getpid(), 'host':socket.gethostname(), 'started_at':time.time()}, self.stream)
            self.stream.flush()
        except BaseException:
            self.stream.close()
            raise
        return self
    def __exit__(self, *args):
        # Keep the inode: unlinking a held flock file allows a second lock.
        # The kernel releases flock when this descriptor/process closes.
        self.stream.close()


class ScannerHistory:
    def __init__(self, root, namespace):
        self.path = Path(root).resolve() / 'scanner-history.sqlite3'
        self.namespace = namespace
        with self.connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS tasks(namespace TEXT, scanner TEXT, family TEXT, rule TEXT, status TEXT, artifact TEXT, PRIMARY KEY(namespace,scanner,family,rule))')
        self.path.chmod(0o600)
    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db: yield db
        finally: db.close()
    def remaining(self, scanner, family, rules):
        with self.connection() as db:
            done = {r[0] for r in db.execute('SELECT rule FROM tasks WHERE namespace=? AND scanner=? AND family=?', (self.namespace, scanner, family))}
        return [r for r in rules if r not in done]
    def finish(self, scanner, family, rules, status, artifact=''):
        with self.connection() as db:
            for rule in rules:
                db.execute('INSERT OR REPLACE INTO tasks VALUES (?,?,?,?,?,?)', (self.namespace,scanner,family,rule,status,artifact))
    def summary(self):
        with self.connection() as db:
            rows = db.execute('SELECT scanner,family,rule,status,artifact FROM tasks WHERE namespace=?', (self.namespace,)).fetchall()
        return [dict(zip(('scanner','family','rule','status','artifact_ref'), row)) for row in rows]
