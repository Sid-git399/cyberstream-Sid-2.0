import pytest

from config import Settings
from exceptions import UnknownScenarioError


def test_settings_defaults_match_env_example():
    s = Settings(_env_file=None)
    assert s.kafka_bootstrap_servers == "localhost:9092"
    assert s.generator_default_rate == 100
    assert s.generator_seed == 42


def test_settings_reads_from_environment(monkeypatch):
    monkeypatch.setenv("GENERATOR_SEED", "999")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
    s = Settings(_env_file=None)
    assert s.generator_seed == 999
    assert s.kafka_bootstrap_servers == "kafka:29092"


def test_unknown_scenario_error_lists_available_scenarios():
    err = UnknownScenarioError("does-not-exist", ["normal-traffic", "brute-force"])
    assert err.code == "UNKNOWN_SCENARIO"
    assert "does-not-exist" in err.message
    assert err.details["available"] == ["normal-traffic", "brute-force"]
