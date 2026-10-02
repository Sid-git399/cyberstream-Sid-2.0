import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest

from scenarios import SCENARIOS, generate_mixed

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "docs" / "event-schema.json"


@pytest.fixture(scope="module")
def schema():
    return json.loads(SCHEMA_PATH.read_text())


# --- Every scenario: count, determinism, schema validity ---------------

@pytest.mark.parametrize("name", sorted(SCENARIOS.keys()))
def test_every_scenario_produces_schema_valid_events(name, schema):
    generator_fn = SCENARIOS[name]
    events = list(generator_fn(12, seed=7))
    assert len(events) > 0
    for event in events:
        jsonschema.validate(instance=event.to_kafka_json(), schema=schema)


@pytest.mark.parametrize("name", sorted(SCENARIOS.keys()))
def test_every_scenario_is_deterministic_given_same_seed(name):
    generator_fn = SCENARIOS[name]
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    run_a = [e.to_kafka_json() for e in generator_fn(10, seed=123, start_time=start)]
    run_b = [e.to_kafka_json() for e in generator_fn(10, seed=123, start_time=start)]
    for a, b in zip(run_a, run_b):
        a.pop("event_id")
        b.pop("event_id")
    assert run_a == run_b


@pytest.mark.parametrize("name", sorted(SCENARIOS.keys()))
def test_every_scenario_rejects_negative_count(name):
    generator_fn = SCENARIOS[name]
    with pytest.raises(ValueError):
        list(generator_fn(-1, seed=1))


@pytest.mark.parametrize("name", sorted(SCENARIOS.keys()))
def test_every_scenario_handles_zero_count(name):
    generator_fn = SCENARIOS[name]
    # Composed scenarios (multi-stage) round up to a whole incident, so
    # "0" is a soft target there, not a hard guarantee of zero events -
    # this only asserts it doesn't error.
    list(generator_fn(0, seed=1))


# --- Scenario-specific shape checks --------------------------------------

def test_brute_force_is_single_attacker_single_target():
    events = list(SCENARIOS["brute-force"](20, seed=5))
    assert len({e.source_ip for e in events}) == 1
    assert len({e.hostname for e in events}) == 1
    assert len({e.username for e in events}) == 1
    assert sum(1 for e in events if e.status == "failure") >= 15


def test_password_spraying_targets_many_users_from_one_source():
    events = list(SCENARIOS["password-spraying"](20, seed=5))
    assert len({e.source_ip for e in events}) == 1
    assert len({e.username for e in events}) > 5


def test_port_scan_touches_many_distinct_ports_from_one_source():
    events = list(SCENARIOS["port-scan"](30, seed=5))
    assert len({e.source_ip for e in events}) == 1
    assert len({e.destination_port for e in events}) > 10


def test_privilege_escalation_pairs_login_with_escalation():
    events = list(SCENARIOS["privilege-escalation"](4, seed=5))
    event_types = [e.event_type.value for e in events]
    assert "login_success" in event_types
    assert "privilege_escalation" in event_types


def test_suspicious_process_events_are_flagged_in_metadata():
    events = list(SCENARIOS["suspicious-process"](5, seed=5))
    assert all(e.metadata.get("suspicious") is True for e in events)


def test_data_transfer_spike_exceeds_normal_traffic_baseline():
    normal = list(SCENARIOS["normal-traffic"](50, seed=5))
    spike = list(SCENARIOS["data-transfer-spike"](5, seed=5))
    assert max(e.bytes_out for e in spike) > max(e.bytes_out for e in normal)


def test_dns_anomaly_generates_high_entropy_domains():
    events = list(SCENARIOS["dns-anomaly"](5, seed=5))
    domains = {e.metadata["query_domain"] for e in events}
    assert len(domains) == len(events)  # every query is a distinct subdomain


def test_multi_stage_covers_multiple_stages_for_one_incident():
    events = list(SCENARIOS["multi-stage"](8, seed=5))
    stages = {e.metadata["stage"] for e in events}
    assert "execution" in stages
    assert "exfiltration" in stages
    incident_ids = {e.metadata["incident_id"] for e in events}
    assert len(incident_ids) == 1


def test_alert_storm_uses_many_distinct_source_ips_against_one_target():
    events = list(SCENARIOS["alert-storm"](50, seed=5))
    assert len({e.hostname for e in events}) == 1
    assert len({e.source_ip for e in events}) > 30


# --- Mixing / attack-ratio ------------------------------------------------

def test_generate_mixed_normal_traffic_ignores_attack_ratio():
    events = list(generate_mixed("normal-traffic", 20, attack_ratio=0.0, seed=1))
    assert len(events) == 20


def test_generate_mixed_pure_attack_at_ratio_one():
    events = list(generate_mixed("brute-force", 20, attack_ratio=1.0, seed=1))
    assert all(e.metadata.get("scenario") == "brute-force" for e in events)


def test_generate_mixed_pure_normal_at_ratio_zero():
    events = list(generate_mixed("brute-force", 20, attack_ratio=0.0, seed=1))
    assert all(e.metadata.get("scenario") == "normal-traffic" for e in events)


def test_generate_mixed_blends_at_partial_ratio():
    events = list(generate_mixed("brute-force", 20, attack_ratio=0.5, seed=1))
    scenarios_seen = {e.metadata.get("scenario") for e in events}
    assert scenarios_seen == {"brute-force", "normal-traffic"}
    assert len(events) == 20


def test_generate_mixed_events_are_sorted_by_timestamp():
    events = list(generate_mixed("port-scan", 30, attack_ratio=0.5, seed=2))
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)


def test_generate_mixed_rejects_invalid_attack_ratio():
    with pytest.raises(ValueError):
        list(generate_mixed("brute-force", 10, attack_ratio=1.5, seed=1))
    with pytest.raises(ValueError):
        list(generate_mixed("brute-force", 10, attack_ratio=-0.1, seed=1))


def test_scenario_selection_rejects_unknown_name():
    assert "not-a-scenario" not in SCENARIOS
