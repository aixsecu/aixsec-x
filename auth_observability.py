"""Non-secret authentication state diagnostics."""
from pathlib import Path
import json

AUTH_STATES = ('anonymous_stateless', 'guest_session', 'auth_configured',
               'auth_verified', 'auth_expired', 'auth_refreshing', 'auth_blocked')

def configured(config):
    context = str(config.get('zap_auth_context') or 'anonymous')
    return {'context': context,
            'state': 'anonymous_stateless' if context == 'anonymous' else 'auth_configured',
            'generation': 0,
            'reason': ('No authenticated ZAP context selected' if context == 'anonymous'
                       else 'Credentials configured; verification pending')}

def observe(config, coverages):
    status = configured(config); rows = [r for r in coverages if isinstance(r, dict)]
    if status['context'] != 'anonymous':
        states = {str(r.get('auth_state', '')) for r in rows}
        if 'verified' in states:
            status.update(state='auth_verified', generation=1,
                          reason='ZAP logged-in indicator verified')
        elif rows:
            status.update(state='auth_blocked', reason='Authenticated context was not verified')
        return status
    for row in rows:
        har = row.get('har_path')
        if not har or not Path(har).is_file(): continue
        try: data = json.loads(Path(har).read_text(encoding='utf-8'))
        except (OSError, ValueError, TypeError): continue
        for entry in data.get('log', {}).get('entries', []):
            request = entry.get('request') or {}; response = entry.get('response') or {}
            cookies = request.get('cookies', [])
            set_cookie = any(str(h.get('name', '')).lower() == 'set-cookie'
                             for h in response.get('headers', []))
            if cookies or set_cookie:
                status.update(state='guest_session', generation=1,
                              reason='Website-issued guest cookie/session observed')
                return status
    return status
