"""Operator-owned constraints checked before approval and tool execution."""
from urllib.parse import urlsplit


def check_action(config, name, args, store=None):
    if not isinstance(args, dict):
        return 'Tool arguments must be an object'
    if any(str(k).startswith('_') for k in args):
        return 'Private executor arguments cannot be supplied by the planner'
    if name == 'evidence_replay' and not config.get('allow_active_scan', False):
        return 'Active replay disabled by WEBX_ALLOW_ACTIVE_SCAN'
    if name.startswith('zap_'):
        if name == 'zap_active_scan':
            selected = args.get('rule_ids') or []
            allowed = config.get('zap_allowed_rules', [])
            if allowed == 'all':
                allowed = [r['id'] for r in getattr(store, 'active_rules', [])]
            if not config.get('allow_active_scan', False):
                return 'Active scan disabled by WEBX_ALLOW_ACTIVE_SCAN'
            if (not isinstance(selected, list) or not selected
                    or any(type(value) is not int for value in selected)
                    or not set(selected) <= set(allowed)):
                return 'Requested ZAP rules are not in the operator allowlist'
    if name == 'sql_error_verify' and not config.get('allow_active_scan',False):
        return 'Active verification disabled by operator'
    if name == 'nuclei_scan' and (not config.get('nuclei_enabled', True) or not config.get('allow_active_scan', False)):
        return 'Nuclei disabled by operator scan policy'
    if name in ('sqlmap_runner', 'sqlmap_check'):
        if not config.get('allow_sqlmap', False):
            return 'sqlmap disabled by WEBX_ALLOW_SQLMAP'
        url = str(args.get('url') or '')
        # A DBMS guess is insufficient to escalate to sqlmap.
        supported = store and any('sql' in str(r.get('category', '')).lower()
            and urlsplit(str(r.get('url', ''))).netloc == urlsplit(url).netloc
            and urlsplit(str(r.get('url', ''))).path == urlsplit(url).path
            for r in store.records.values())
        if not supported:
            return 'sqlmap requires a SQL injection candidate for this endpoint'
    if name == 'ffuf_dir' and not config.get('allow_content_discovery', True):
        return 'Content discovery disabled by operator policy'
    if name == 'sqli_blind_extract':
        if args.get('action', 'detect') != 'detect' and not config.get('allow_extraction', False):
            return 'Data extraction is a separate permission (WEBX_ALLOW_EXTRACTION)'
        if args.get('known_confirmed'):
            return 'Planner cannot skip SQLi verification using known_confirmed'
    return None
