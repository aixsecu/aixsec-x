import pytest

from agent import _banner, _cli_option_value, select_scan_profile_interactive
from config import SCAN_PROFILES, apply_scan_profile, load_config


def test_cli_profile_accepts_split_and_equals_forms():
    assert _cli_option_value("--scan-profile", ["--scan-profile", "fast"]) == "fast"
    assert _cli_option_value("--scan-profile", ["--scan-profile=full"]) == "full"
    assert _cli_option_value("--scan-profile", ["-n"]) is None


def test_cli_profile_rejects_missing_value():
    with pytest.raises(ValueError, match="requires a value"):
        _cli_option_value("--scan-profile", ["--scan-profile"])


def test_profiles_have_increasing_scan_limits():
    fast = SCAN_PROFILES["fast"]
    balanced = SCAN_PROFILES["balanced"]
    full = SCAN_PROFILES["full"]
    assert fast["zap_max_urls"] < balanced["zap_max_urls"] < full["zap_max_urls"]
    assert fast["zap_ajax_states"] < balanced["zap_ajax_states"] < full["zap_ajax_states"]
    assert full["technology_filter_mode"] == "off"
    assert full["family_scan"] is False
    assert fast['zap_timeout'] >= 60 * (
        fast['zap_spider_minutes'] + fast['zap_ajax_minutes'] + fast['zap_passive_minutes'])
    assert balanced['zap_timeout'] >= 60 * (
        balanced['zap_spider_minutes'] + balanced['zap_ajax_minutes'] + balanced['zap_passive_minutes'])
    assert full['zap_timeout'] >= 60 * (
        full['zap_spider_minutes'] + full['zap_ajax_minutes'] + full['zap_passive_minutes'])
    assert fast['profile_session_seconds'] < balanced['profile_session_seconds'] < full['profile_session_seconds']


def test_profile_does_not_broaden_authorization_gates():
    config = {
        "allow_active_scan": False,
        "allow_oast": False,
        "allow_sqlmap": False,
        "allow_extraction": False,
    }
    resolved = apply_scan_profile(config, "full")
    for key in config:
        assert resolved[key] is False
    assert resolved["scan_profile"] == "full"


def test_profile_overrides_performance_values_without_mutating_source():
    config = {"zap_max_urls": 7, "technology_filter_mode": "strict"}
    resolved = apply_scan_profile(config, "balanced")
    assert resolved["zap_max_urls"] == 200
    assert resolved["technology_filter_mode"] == "priority"
    assert config == {"zap_max_urls": 7, "technology_filter_mode": "strict"}


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError, match="fast, balanced, full"):
        apply_scan_profile({}, "turbo")


def test_default_config_keeps_backward_compatible_custom_mode():
    assert load_config()["scan_profile"] == "custom"


def test_banner_displays_effective_profile():
    text = _banner({"scan_profile": "balanced", "targets": ["https://example.test"]},
                   missing={}, color=False)
    assert "scan-mode" in text
    assert "BALANCED" in text


def test_interactive_menu_maps_numeric_choice(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _: "3")
    resolved = select_scan_profile_interactive({"allow_oast": False})
    assert resolved["scan_profile"] == "full"
    assert resolved["allow_oast"] is False
    assert "SCAN MODE: FULL" in capsys.readouterr().out


def test_interactive_menu_retries_then_defaults_to_balanced(monkeypatch):
    answers = iter(["invalid", ""])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    resolved = select_scan_profile_interactive({})
    assert resolved["scan_profile"] == "balanced"
