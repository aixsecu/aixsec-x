"""Operator-facing JSON configuration and terminal setup wizard.

Environment variables remain supported for automation.  This module exposes a
small, intentional set of choices that people should not have to remember as
WEBX_* names.
"""
import json
import os
from pathlib import Path

from config import SCAN_PROFILES, apply_scan_profile


DEFAULT_USER_CONFIG = Path('.aixsec-config.json')

# Do not accept arbitrary internal keys from a user-owned file. In particular,
# runtime objects and private credential values must never be deserialized here.
USER_CONFIG_KEYS = {
    'scan_profile', 'targets', 'src_dirs', 'scan_backend', 'planner_enabled',
    'allow_active_scan', 'nuclei_enabled', 'zap_ajax',
    'allow_content_discovery', 'advanced_coverage', 'allow_sqlmap',
    'allow_extraction', 'allow_oast', 'oast_callback_url', 'zap_workers',
    'zap_strength', 'zap_auth_file', 'zap_openapi_file', 'evidence_dir',
}


def load_user_config(path=DEFAULT_USER_CONFIG):
    path = Path(path)
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError(f'User config must be a JSON object: {path}')
    unknown = sorted(set(data) - USER_CONFIG_KEYS)
    if unknown:
        raise ValueError('Unknown user config settings: ' + ', '.join(unknown))
    return data


def apply_user_config(config, settings):
    resolved = dict(config)
    profile = str(settings.get('scan_profile', '')).lower()
    if profile:
        resolved = apply_scan_profile(resolved, profile)
    resolved.update({key: value for key, value in settings.items() if key != 'scan_profile'})
    if not isinstance(resolved.get('targets', []), list) or not isinstance(resolved.get('src_dirs', []), list):
        raise ValueError('targets and src_dirs in user config must be JSON arrays')
    workers = int(resolved.get('zap_workers', 2))
    if not 1 <= workers <= 8:
        raise ValueError('zap_workers in user config must be between 1 and 8')
    if resolved.get('scan_backend') not in ('auto', 'zap', 'http', 'wapiti', 'none', 'legacy'):
        raise ValueError('scan_backend in user config is invalid')
    if resolved.get('zap_strength') not in ('Low', 'Medium', 'High', 'Insane'):
        raise ValueError('zap_strength in user config is invalid')
    return resolved


def save_user_config(settings, path=DEFAULT_USER_CONFIG):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(settings, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    os.chmod(path, 0o600)
    return path.resolve()


def _choice(prompt, choices, default):
    labels = '/'.join(choices)
    while True:
        value = input(f'{prompt} [{labels}] (mặc định {default}): ').strip() or default
        if value in choices:
            return value
        print('[!] Lựa chọn không hợp lệ.')


def _yes_no(prompt, default):
    marker = 'Y/n' if default else 'y/N'
    while True:
        value = input(f'{prompt} [{marker}]: ').strip().lower()
        if not value:
            return default
        if value in ('y', 'yes', '1'):
            return True
        if value in ('n', 'no', '0'):
            return False
        print('[!] Vui lòng nhập y hoặc n.')


def configure_interactive(existing=None):
    """Collect the compact set of operator decisions; never collect secrets."""
    old = existing or {}
    profile_numbers = {'1': 'fast', '2': 'balanced', '3': 'full'}
    default_profile = old.get('scan_profile', 'balanced')
    default_number = next((n for n, p in profile_numbers.items() if p == default_profile), '2')
    print('\nAIXSEC-X — CÀI ĐẶT NGƯỜI DÙNG')
    print('Không lưu mật khẩu/token. Credential phải nằm trong auth profile hoặc secret env riêng.')
    number = _choice('Profile: 1 Fast, 2 Balanced, 3 Full', tuple(profile_numbers), default_number)
    targets_default = ','.join(old.get('targets', []))
    targets = input(f'Target được cấp quyền, cách nhau bằng dấu phẩy [{targets_default}]: ').strip()
    sources_default = ','.join(old.get('src_dirs', []))
    sources = input(f'Thư mục source, cách nhau bằng dấu phẩy [{sources_default}]: ').strip()
    backend = _choice('Scanner backend', ('auto', 'zap', 'http', 'none'), old.get('scan_backend', 'auto'))
    active = _yes_no('Cho phép active scan?', old.get('allow_active_scan', True))
    settings = {
        'scan_profile': profile_numbers[number],
        'targets': [v.strip() for v in (targets or targets_default).split(',') if v.strip()],
        'src_dirs': [v.strip() for v in (sources or sources_default).split(',') if v.strip()],
        'scan_backend': backend,
        'allow_active_scan': active,
        'zap_ajax': _yes_no('Bật browser/AJAX discovery?', old.get('zap_ajax', True)),
        'nuclei_enabled': _yes_no('Bật Nuclei?', old.get('nuclei_enabled', True)),
        'allow_content_discovery': _yes_no('Cho phép content discovery?', old.get('allow_content_discovery', True)),
        'planner_enabled': _yes_no('Bật AI analysis/planner?', old.get('planner_enabled', True)),
        'advanced_coverage': _yes_no('Tạo báo cáo advanced coverage?', old.get('advanced_coverage', True)),
        'allow_sqlmap': _yes_no('Cho phép SQLMap khi có candidate?', old.get('allow_sqlmap', False)),
        'allow_extraction': False,
        'allow_oast': _yes_no('Cho phép kiểm thử OAST?', old.get('allow_oast', False)),
    }
    if settings['allow_sqlmap']:
        settings['allow_extraction'] = _yes_no(
            'Cho phép extraction? (rủi ro cao)', old.get('allow_extraction', False))
    if settings['allow_oast']:
        callback = input(f"OAST callback URL [{old.get('oast_callback_url', '')}]: ").strip()
        settings['oast_callback_url'] = callback or old.get('oast_callback_url', '')
    return settings


def public_summary(config):
    """Small non-secret summary suitable for startup display."""
    return {
        'profile': config.get('scan_profile', 'custom'),
        'backend': config.get('scan_backend', 'auto'),
        'active': bool(config.get('allow_active_scan')),
        'ajax': bool(config.get('zap_ajax')),
        'nuclei': bool(config.get('nuclei_enabled')),
        'sqlmap': bool(config.get('allow_sqlmap')),
        'extraction': bool(config.get('allow_extraction')),
        'oast': bool(config.get('allow_oast')),
    }
