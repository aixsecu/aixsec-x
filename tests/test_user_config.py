import json
import os
from types import SimpleNamespace

import pytest

import agent as cli
from config import load_config, apply_scan_intensity
from user_config import (apply_user_config, load_user_config, public_summary,
                         save_user_config)


def test_saved_user_config_round_trip_and_private_permissions(tmp_path):
    path = tmp_path / 'operator.json'
    settings = {
        'scan_profile': 'balanced',
        'targets': ['https://example.test'],
        'src_dirs': [],
        'scan_backend': 'zap',
        'allow_active_scan': False,
    }
    saved = save_user_config(settings, path)
    assert load_user_config(saved) == settings
    assert os.stat(saved).st_mode & 0o777 == 0o600


def test_user_config_applies_profile_then_explicit_operator_choices():
    base = load_config()
    resolved = apply_user_config(base, {
        'scan_profile': 'full',
        'targets': ['https://example.test'],
        'allow_active_scan': False,
    })
    assert resolved['scan_profile'] == 'full'
    assert resolved['family_scan'] is True
    assert resolved['technology_filter_mode'] == 'priority'
    assert resolved['allow_active_scan'] is False


def test_intensity_is_independent_from_coverage_profile():
    full=apply_user_config(load_config(),{'scan_profile':'full','scan_intensity':'gentle',
        'targets':['https://example.test']})
    assert full['scan_profile']=='full'
    assert full['scan_intensity']=='gentle'
    assert (full['zap_workers'],full['zap_delay_ms'],full['zap_bootstrap_ceiling'])==(1,500,1)
    fast=apply_scan_intensity(full,'fast')
    assert (fast['zap_workers'],fast['nuclei_rate'])==(4,10)


def test_user_config_rejects_unknown_internal_keys(tmp_path):
    path = tmp_path / 'bad.json'
    path.write_text(json.dumps({'_zap_worker_pool': 'unsafe'}))
    with pytest.raises(ValueError, match='Unknown user config'):
        load_user_config(path)


@pytest.mark.parametrize('settings,message', [
    ({'zap_workers': 99}, 'between 1 and 8'),
    ({'scan_backend': 'mystery'}, 'scan_backend'),
    ({'zap_strength': 'Maximum'}, 'zap_strength'),
    ({'targets': 'https://example.test'}, 'JSON arrays'),
])
def test_user_config_validates_bounded_choices(settings, message):
    with pytest.raises(ValueError, match=message):
        apply_user_config(load_config(), settings)


def test_public_summary_excludes_targets_paths_and_callback():
    summary = public_summary({
        'scan_profile': 'fast', 'scan_backend': 'zap',
        'targets': ['https://private.test'], 'oast_callback_url': 'https://secret.test/x',
        'allow_active_scan': True, 'zap_ajax': True, 'nuclei_enabled': True,
        'allow_sqlmap': False, 'allow_extraction': False, 'allow_oast': False,
    })
    text = repr(summary)
    assert 'private.test' not in text
    assert 'secret.test' not in text
    assert summary['profile'] == 'fast'


def test_interactive_reconfigure_saves_and_returns_live_config(tmp_path, monkeypatch):
    path = tmp_path / 'operator.json'
    settings = {
        'scan_profile': 'fast', 'targets': ['https://new.example'],
        'src_dirs': [], 'scan_backend': 'http', 'allow_active_scan': False,
    }
    monkeypatch.setattr(cli, 'configure_interactive', lambda defaults: settings)
    refreshed, saved = cli.reconfigure_interactive(load_config(), path)
    assert saved == path.resolve()
    assert refreshed['targets'] == ['https://new.example']
    assert refreshed['scan_profile'] == 'fast'
    assert refreshed['allow_active_scan'] is False


def test_interactive_reconfigure_keeps_old_config_when_scope_is_empty(tmp_path, monkeypatch):
    settings = {'scan_profile': 'balanced', 'targets': [], 'src_dirs': [],
                'scan_backend': 'auto'}
    monkeypatch.setattr(cli, 'configure_interactive', lambda defaults: settings)
    path = tmp_path / 'operator.json'
    with pytest.raises(ValueError, match='target'):
        cli.reconfigure_interactive(load_config(), path)
    assert not path.exists()


def test_switch_target_archives_old_outputs_and_does_not_persist_user_config(monkeypatch):
    old = SimpleNamespace(
        config={'targets': ['https://a.example'], 'resume_session': '/old/session'},
        export_report=lambda: '/tmp/a-report.md',
        save_inventory=lambda: '/tmp/a-inventory.json',
    )
    captured = {}
    monkeypatch.setattr(cli, 'WebXAgent', lambda config: captured.setdefault('agent',
        SimpleNamespace(config=config)))
    replacement, report, inventory = cli.switch_scan_target(old, ['https://b.example'])
    assert replacement.config['targets'] == ['https://b.example']
    assert replacement.config['resume_session'] == ''
    assert old.config['targets'] == ['https://a.example']
    assert report == '/tmp/a-report.md'
    assert inventory == '/tmp/a-inventory.json'
