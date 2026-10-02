"""
End-to-end (within this sandbox - no Kafka) proof that the detection
engine consumes Phase A's actual output, not a convenient test fixture:
real generator scenario functions produce real SecurityEvent JSON, which
goes through the REAL parse_raw_events -> validate_events ->
normalize_events -> enrich_events chain (not hand-built DataFrames),
and only then into run_detections(). If Phase A's column names or types
ever drift from what detection/base.py expects, this test - not the
per-rule unit tests, which use a hand-built fixture - is what catches it.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from pyspark.sql import functions as F

from src.detection.config import DetectionEngineConfig
from src.detection.engine import run_detections
from src.enrichment import enrich_events
from src.normalization import normalize_events
from src.parsing import parse_raw_events
from src.validation import validate_events

_GENERATOR_PATH = Path(__file__).resolve().parents[3] / "generator"
sys.path.insert(0, str(_GENERATOR_PATH))
from scenarios.brute_force import generate_brute_force  # noqa: E402
from scenarios.normal_traffic import generate_normal_traffic  # noqa: E402


def _raw_kafka_like_df(spark, events, topic="security-authentication"):
    rows = [{"topic": topic, "value": json.dumps(e.to_kafka_json())} for e in events]
    return spark.createDataFrame(rows)


def _run_phase_a(raw_df):
    parsed = parse_raw_events(raw_df)
    validated = validate_events(parsed)
    valid = validated.filter(F.col("_is_valid"))
    normalized = normalize_events(valid)
    return enrich_events(normalized)


def test_real_brute_force_scenario_produces_a_brute_force_detection(spark):
    # Explicit start_time, not datetime.now(): tumbling windows are
    # aligned to absolute wall-clock boundaries, and this test's burst
    # must not straddle one by chance - see
    # test_brute_force_events_spanning_a_window_boundary_can_be_missed
    # in test_rules_authentication.py for why that matters, documented as
    # a real, found-by-running-this-test limitation (docs/detection-engine.md).
    start = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    events = list(generate_brute_force(15, seed=1, succeed_at_end=False, start_time=start))
    raw = _raw_kafka_like_df(spark, events)
    enriched = _run_phase_a(raw)

    assert enriched.count() == 15  # Phase A didn't drop any of these real events

    detections = run_detections(enriched, DetectionEngineConfig(), watermark_delay="2 minutes")
    rows = detections.filter(F.col("rule_id") == "brute-force").collect()
    assert len(rows) == 1
    evidence = json.loads(rows[0]["evidence"])
    assert evidence["failed_attempts"] == 15
    assert rows[0]["source_ip"] == events[0].source_ip
    assert rows[0]["username"] == events[0].username


def test_real_normal_traffic_scenario_produces_no_detections(spark):
    """The baseline every detection rule must NOT fire against (see generator/scenarios/normal_traffic.py)."""
    events = list(generate_normal_traffic(200, seed=2))
    raw = _raw_kafka_like_df(spark, events, topic="security-network")
    enriched = _run_phase_a(raw)

    detections = run_detections(enriched, DetectionEngineConfig(), watermark_delay="2 minutes")
    assert detections.count() == 0


def test_malformed_raw_event_does_not_reach_detection_and_does_not_crash(spark):
    """A structurally invalid message must be excluded by Phase A's own validation, not reach the detection engine at all."""
    start = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    good_events = list(generate_brute_force(12, seed=3, succeed_at_end=False, start_time=start))
    good_rows = [{"topic": "security-authentication", "value": json.dumps(e.to_kafka_json())} for e in good_events]
    bad_rows = [{"topic": "security-authentication", "value": "{not valid json"}]
    raw = spark.createDataFrame(good_rows + bad_rows)

    enriched = _run_phase_a(raw)
    assert enriched.count() == 12  # malformed row excluded, 12 good ones pass through

    detections = run_detections(enriched, DetectionEngineConfig(), watermark_delay="2 minutes")
    assert detections.filter(F.col("rule_id") == "brute-force").count() == 1
