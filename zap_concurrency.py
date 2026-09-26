"""Operator-owned request independence declarations, never inferred from cookies."""
import fnmatch
import json
from pathlib import Path
from urllib.parse import urlsplit
from adapters.zap import origin


class ConcurrencyPolicy:
    def __init__(self, path=''):
        self.rules = []
        if not path:
            return
        document = json.loads(Path(path).read_text())
        if (not isinstance(document, dict) or set(document) != {'version', 'rules'}
                or type(document['version']) is not int or document['version'] != 1
                or not isinstance(document['rules'], list)):
            raise ValueError('ZAP concurrency policy requires version=1 and a rules array')
        ids = set()
        for rule in document['rules']:
            if (not isinstance(rule, dict)
                    or set(rule) != {'id', 'origin', 'auth_context', 'paths', 'mode'}
                    or not isinstance(rule['id'], str) or not rule['id'] or rule['id'] in ids
                    or rule['mode'] not in ('parallel_read', 'serial')
                    or not isinstance(rule['auth_context'], str) or not rule['auth_context']
                    or (rule['mode'] == 'parallel_read' and rule['auth_context'] == '*')
                    or not isinstance(rule['paths'], list) or not rule['paths']
                    or any(not isinstance(p, str) or not p.startswith('/') for p in rule['paths'])
                    or not isinstance(rule['origin'], str)):
                raise ValueError('Invalid ZAP concurrency rule: require unique id, origin, auth_context, paths and mode')
            parsed = urlsplit(rule['origin'])
            canonical = origin(rule['origin'])
            if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
                raise ValueError('Concurrency rule origin cannot contain a path, query or fragment')
            ids.add(rule['id'])
            self.rules.append({**rule, 'origin':canonical})

    def match(self, entry):
        request = entry['_entry']['request']
        parsed = urlsplit(request['url'])
        target_origin = origin(request['url'])
        auth = entry.get('auth_context', 'anonymous')
        matches = [r for r in self.rules if r['origin'] == target_origin
                   and r['auth_context'] in (auth, '*')
                   and any(fnmatch.fnmatchcase(parsed.path or '/', p) for p in r['paths'])]
        # Explicit serial rules always win, regardless of file order.
        serial = [r for r in matches if r['mode'] == 'serial']
        if serial:
            return serial[0]
        if len(matches) > 1:
            raise ValueError('Request matches multiple parallel_read concurrency rules')
        return matches[0] if matches else None
