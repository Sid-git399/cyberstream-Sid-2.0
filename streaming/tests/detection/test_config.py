import pytest
import yaml

from src.detection.config import (
    DetectionConfigError,
    DetectionEngineConfig,
    load_detection_config,
)


def test_explicit_missing_path_raises_clearly(tmp_path):
    """
    An explicit path is a caller's direct instruction - silently falling
    back to defaults if it's wrong would hide a real deployment mistake
    (e.g. a typo'd DETECTION_RULES_CONFIG_PATH). Only auto-discovery
    (no path given) falls back quietly - see the next test.
    """
    missing = tmp_path / "does-not-exist.yaml"
    with pytest.raises(DetectionConfigError):
        load_detection_config(missing)


def test_auto_discovery_falls_back_to_defaults_when_nothing_found(monkeypatch):
    import src.detection.config as config_module
    monkeypatch.setattr(config_module, "_CANDIDATE_CONFIG_PATHS", [])
    config = load_detection_config()  # no explicit path -> auto-discovery -> finds nothing -> defaults
    assert config.brute_force.enabled is True
    assert config.brute_force.failed_attempts == 10


def test_repo_yaml_file_loads_and_matches_documented_defaults():
    config = load_detection_config()  # finds infrastructure/spark/detection_rules.yaml
    assert config.brute_force.failed_attempts == 10
    assert config.brute_force.window_seconds == 300
    assert config.password_spraying.unique_users == 8
    assert config.port_scan.unique_ports == 20
    assert config.dns_anomaly.query_count_threshold == 50
    assert config.large_data_transfer.bytes_out_threshold == 5_000_000


def test_unknown_top_level_key_is_rejected():
    with pytest.raises(Exception):
        DetectionEngineConfig(not_a_real_rule={"enabled": True})


def test_unknown_field_within_a_rule_is_rejected():
    with pytest.raises(Exception):
        DetectionEngineConfig(brute_force={"faild_attempts": 5})  # typo


def test_disabling_a_rule_via_config():
    config = DetectionEngineConfig(brute_force={"enabled": False})
    assert config.brute_force.enabled is False
    assert config.password_spraying.enabled is True  # others unaffected


def test_severity_must_be_one_of_the_documented_values():
    with pytest.raises(Exception):
        DetectionEngineConfig(brute_force={"severity": "SUPER_HIGH"})


def test_malformed_yaml_raises_detection_config_error(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("brute_force: [this, is, not, a, mapping\n")  # unclosed bracket
    with pytest.raises(DetectionConfigError):
        load_detection_config(bad_yaml)


def test_valid_yaml_with_invalid_values_raises_detection_config_error(tmp_path):
    bad_config = tmp_path / "bad_values.yaml"
    bad_config.write_text(yaml.dump({"brute_force": {"failed_attempts": -5}}))
    with pytest.raises(DetectionConfigError):
        load_detection_config(bad_config)


def test_risk_points_bounded_zero_to_hundred():
    with pytest.raises(Exception):
        DetectionEngineConfig(brute_force={"risk_points": 150})


def test_partial_override_keeps_other_fields_at_default():
    config = DetectionEngineConfig(brute_force={"failed_attempts": 50})
    assert config.brute_force.failed_attempts == 50
    assert config.brute_force.window_seconds == 300  # untouched default
    assert config.brute_force.severity == "HIGH"  # untouched default
