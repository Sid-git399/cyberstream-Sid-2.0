from datetime import datetime, timedelta, timezone

from src.detection.base import DETECTION_OUTPUT_COLUMNS
from src.detection.config import DetectionEngineConfig
from src.detection.engine import build_rules, run_detections
from src.detection.rules import ALL_RULES

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
WM = "2 minutes"


def test_build_rules_instantiates_one_per_registry_entry():
    config = DetectionEngineConfig()
    rules = build_rules(config)
    assert len(rules) == len(ALL_RULES)
    rule_ids = {r.rule_id for r in rules}
    assert rule_ids == {
        "brute-force", "password-spraying", "port-scan", "suspicious-authentication",
        "privilege-escalation", "suspicious-process", "large-data-transfer", "dns-anomaly",
    }


def test_run_detections_with_no_matching_events_returns_empty_but_typed(spark, make_enriched_df):
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "connection", "status": "success"}])
    config = DetectionEngineConfig()
    out = run_detections(df, config, WM)
    assert out.count() == 0
    assert out.columns == DETECTION_OUTPUT_COLUMNS


def test_run_detections_unions_multiple_rule_hits(spark, make_enriched_df):
    rows = [{
        "event_id": f"evt-pe-{i}", "event_type": "privilege_escalation", "category": "privilege",
        "event_time": BASE + timedelta(seconds=i),
    } for i in range(2)] + [{
        "event_id": "evt-ldt-1", "event_type": "connection", "bytes_out": 9_000_000,
        "event_time": BASE,
    }]
    df = make_enriched_df(rows)
    config = DetectionEngineConfig()
    out = run_detections(df, config, WM)
    rule_ids = {r["rule_id"] for r in out.collect()}
    assert "privilege-escalation" in rule_ids
    assert "large-data-transfer" in rule_ids
    assert out.count() == 3  # 2 privilege escalation events + 1 large transfer


def test_run_detections_disabled_rule_contributes_nothing(spark, make_enriched_df):
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "privilege_escalation"}])
    config = DetectionEngineConfig(privilege_escalation={"enabled": False})
    out = run_detections(df, config, WM)
    assert out.count() == 0


def test_run_detections_all_disabled_returns_empty_typed_df(spark, make_enriched_df):
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "privilege_escalation"}])
    all_off = {key: {"enabled": False} for key in ALL_RULES}
    config = DetectionEngineConfig(**all_off)
    out = run_detections(df, config, WM)
    assert out.count() == 0
    assert out.columns == DETECTION_OUTPUT_COLUMNS


def test_run_detections_output_schema_matches_contract(spark, make_enriched_df):
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "privilege_escalation"}])
    out = run_detections(df, DetectionEngineConfig(), WM)
    assert out.columns == DETECTION_OUTPUT_COLUMNS
    for field in out.schema.fields:
        if field.name in ("source_ip", "destination_ip", "hostname", "username"):
            assert field.nullable, f"{field.name} must be nullable - not every rule/event sets it"


def test_run_detections_is_deterministic_across_two_independent_runs(spark, make_enriched_df):
    rows = [{"event_id": "evt-1", "event_type": "privilege_escalation", "hostname": "srv-db-02"}]
    out1 = run_detections(make_enriched_df(rows), DetectionEngineConfig(), WM).collect()
    out2 = run_detections(make_enriched_df(rows), DetectionEngineConfig(), WM).collect()
    assert out1[0]["detection_id"] == out2[0]["detection_id"]
