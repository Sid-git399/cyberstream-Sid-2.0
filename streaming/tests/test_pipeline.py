"""
Tests the parsing -> validation -> normalization -> enrichment chain
against DataFrames shaped exactly like Spark's real Kafka source output
(a `value` binary column plus `topic`), built here without a live broker.
This is real Spark (local[2], see conftest.py), running the actual
production transformation functions - only the Kafka *read* itself is
substituted.
"""
import json

from pyspark.sql.types import BinaryType, StringType, StructField, StructType

from src.dlq import build_dlq_rows
from src.enrichment import enrich_events
from src.normalization import normalize_events
from src.parsing import parse_raw_events
from src.validation import validate_events

_RAW_KAFKA_SCHEMA = StructType([
    StructField("topic", StringType()),
    StructField("value", BinaryType()),
])


def make_raw_df(spark, records: list[tuple[str, dict | str]]):
    """records: list of (topic, event_dict_or_raw_string)."""
    rows = []
    for topic, payload in records:
        value = payload if isinstance(payload, str) else json.dumps(payload)
        rows.append((topic, value.encode("utf-8")))
    return spark.createDataFrame(rows, schema=_RAW_KAFKA_SCHEMA)


def valid_event(**overrides) -> dict:
    base = dict(
        event_id="evt-0123456789ab",
        timestamp="2026-09-27T10:00:00.000Z",
        event_type="login_failed",
        category="authentication",
        source_ip="10.10.4.23",
        destination_ip="10.10.1.10",
        source_port=54231,
        destination_port=22,
        protocol="TCP",
        username="admin",
        hostname="srv-auth-01",
        action="login",
        status="failure",
        bytes_in=0,
        bytes_out=0,
        country="DZ",
        metadata={},
    )
    base.update(overrides)
    return base


# --- Parsing ---------------------------------------------------------------

def test_parse_valid_event_succeeds(spark):
    df = make_raw_df(spark, [("security-authentication", valid_event())])
    parsed = parse_raw_events(df)
    row = parsed.collect()[0]
    assert row["_parse_error"] is None
    assert row["parsed"]["event_id"] == "evt-0123456789ab"


def test_parse_malformed_json_is_flagged_not_dropped(spark):
    df = make_raw_df(spark, [("security-authentication", "{not valid json at all")])
    parsed = parse_raw_events(df)
    row = parsed.collect()[0]
    assert row["_parse_error"] is not None
    # NOTE: Spark's from_json (PERMISSIVE mode, the default) does NOT
    # null out the whole struct for malformed JSON - it returns a struct
    # with every field null instead. Confirmed by direct inspection, not
    # assumed (see docs/phases.md) - `_parse_error` detection in
    # parsing.py checks `parsed.event_id IS NULL`, not `parsed IS NULL`,
    # specifically because of this.
    assert row["parsed"]["event_id"] is None
    # The raw payload must still be present for the DLQ - never discarded.
    assert row["raw_value_str"] == "{not valid json at all"


def test_parse_null_value_is_flagged(spark):
    df = spark.createDataFrame([("security-authentication", None)], schema=_RAW_KAFKA_SCHEMA)
    parsed = parse_raw_events(df)
    row = parsed.collect()[0]
    assert row["_parse_error"] == "empty or null message value"


def test_parse_unknown_event_type_still_parses_structurally(spark):
    """
    Structural parsing only checks TYPES (string vs int), not enum
    membership - an unknown event_type still produces a struct (a string
    field got a string). validation.py, not parsing.py, catches this.
    """
    df = make_raw_df(spark, [("security-web", valid_event(event_type="not_a_real_type"))])
    parsed = parse_raw_events(df)
    row = parsed.collect()[0]
    assert row["_parse_error"] is None
    assert row["parsed"]["event_type"] == "not_a_real_type"


# --- Validation --------------------------------------------------------

def test_validation_accepts_a_fully_valid_event(spark):
    df = make_raw_df(spark, [("security-authentication", valid_event())])
    result = validate_events(parse_raw_events(df))
    row = result.collect()[0]
    assert row["_is_valid"] is True
    assert row["_validation_error"] is None


def test_validation_rejects_unknown_event_type(spark):
    df = make_raw_df(spark, [("security-web", valid_event(event_type="not_a_real_type"))])
    result = validate_events(parse_raw_events(df))
    row = result.collect()[0]
    assert row["_is_valid"] is False
    assert "event_type" in row["_validation_error"]


def test_validation_rejects_out_of_range_port(spark):
    df = make_raw_df(spark, [("security-network", valid_event(destination_port=70000))])
    result = validate_events(parse_raw_events(df))
    row = result.collect()[0]
    assert row["_is_valid"] is False
    assert "destination_port" in row["_validation_error"]


def test_validation_rejects_negative_bytes(spark):
    df = make_raw_df(spark, [("security-network", valid_event(bytes_out=-5))])
    result = validate_events(parse_raw_events(df))
    row = result.collect()[0]
    assert row["_is_valid"] is False
    assert "bytes_in/bytes_out" in row["_validation_error"]


def test_validation_rejects_bad_country_code(spark):
    df = make_raw_df(spark, [("security-web", valid_event(country="USA"))])
    result = validate_events(parse_raw_events(df))
    row = result.collect()[0]
    assert row["_is_valid"] is False
    assert "country" in row["_validation_error"]


def test_validation_rejects_bad_protocol(spark):
    df = make_raw_df(spark, [("security-network", valid_event(protocol="FTP"))])
    result = validate_events(parse_raw_events(df))
    row = result.collect()[0]
    assert row["_is_valid"] is False
    assert "protocol" in row["_validation_error"]


def test_validation_propagates_parse_errors_as_validation_errors(spark):
    df = make_raw_df(spark, [("security-web", "not json")])
    result = validate_events(parse_raw_events(df))
    row = result.collect()[0]
    assert row["_is_valid"] is False
    assert row["_validation_error"] == "payload is not valid JSON matching the event schema"


def test_validation_mixed_batch_flags_only_bad_rows(spark):
    df = make_raw_df(spark, [
        ("security-authentication", valid_event(event_id="evt-good0000001")),
        ("security-authentication", valid_event(event_id="evt-bad00000001", protocol="FTP")),
    ])
    result = validate_events(parse_raw_events(df)).orderBy("event_id").collect()
    assert result[0]["_is_valid"] is False   # evt-bad...
    assert result[1]["_is_valid"] is True    # evt-good...


# --- Normalization -------------------------------------------------------

def test_normalization_casts_timestamp_to_real_timestamp_type(spark):
    df = make_raw_df(spark, [("security-authentication", valid_event())])
    valid = validate_events(parse_raw_events(df)).filter("_is_valid")
    normalized = normalize_events(valid)
    field_types = {f.name: f.dataType.typeName() for f in normalized.schema.fields}
    assert field_types["event_time"] == "timestamp"
    row = normalized.collect()[0]
    assert row["event_time"] is not None


def test_normalization_preserves_original_timestamp_string(spark):
    df = make_raw_df(spark, [("security-authentication", valid_event(timestamp="2026-01-15T08:30:00.000Z"))])
    valid = validate_events(parse_raw_events(df)).filter("_is_valid")
    row = normalize_events(valid).collect()[0]
    assert row["timestamp"] == "2026-01-15T08:30:00.000Z"


# --- Enrichment ----------------------------------------------------------

def test_enrichment_flags_internal_source_ip(spark):
    df = make_raw_df(spark, [("security-network", valid_event(source_ip="10.1.2.3"))])
    normalized = normalize_events(validate_events(parse_raw_events(df)).filter("_is_valid"))
    row = enrich_events(normalized).collect()[0]
    assert row["is_source_internal"] is True


def test_enrichment_flags_external_source_ip(spark):
    df = make_raw_df(spark, [("security-network", valid_event(source_ip="203.0.113.5"))])
    normalized = normalize_events(validate_events(parse_raw_events(df)).filter("_is_valid"))
    row = enrich_events(normalized).collect()[0]
    assert row["is_source_internal"] is False


def test_enrichment_flags_172_16_31_range_correctly(spark):
    df = make_raw_df(spark, [
        ("security-network", valid_event(event_id="evt-in0000000a", source_ip="172.20.0.5")),
        ("security-network", valid_event(event_id="evt-out000000a", source_ip="172.40.0.5")),
    ])
    normalized = normalize_events(validate_events(parse_raw_events(df)).filter("_is_valid"))
    rows = {r["event_id"]: r["is_source_internal"] for r in enrich_events(normalized).collect()}
    assert rows["evt-in0000000a"] is True    # 172.20 is within 172.16-31
    assert rows["evt-out000000a"] is False   # 172.40 is outside that range


def test_enrichment_flags_privileged_user(spark):
    df = make_raw_df(spark, [("security-authentication", valid_event(username="admin"))])
    normalized = normalize_events(validate_events(parse_raw_events(df)).filter("_is_valid"))
    row = enrich_events(normalized).collect()[0]
    assert row["is_privileged_user"] is True


def test_enrichment_flags_non_privileged_user(spark):
    df = make_raw_df(spark, [("security-authentication", valid_event(username="jdoe"))])
    normalized = normalize_events(validate_events(parse_raw_events(df)).filter("_is_valid"))
    row = enrich_events(normalized).collect()[0]
    assert row["is_privileged_user"] is False


def test_enrichment_identifies_known_service_port(spark):
    df = make_raw_df(spark, [("security-network", valid_event(destination_port=22))])
    normalized = normalize_events(validate_events(parse_raw_events(df)).filter("_is_valid"))
    row = enrich_events(normalized).collect()[0]
    assert row["is_known_service_port"] is True
    assert row["known_service_name"] == "ssh"


def test_enrichment_unknown_port_has_null_service_name(spark):
    df = make_raw_df(spark, [("security-network", valid_event(destination_port=54321))])
    normalized = normalize_events(validate_events(parse_raw_events(df)).filter("_is_valid"))
    row = enrich_events(normalized).collect()[0]
    assert row["is_known_service_port"] is False
    assert row["known_service_name"] is None


def test_enrichment_uses_custom_privileged_users_list(spark):
    df = make_raw_df(spark, [("security-authentication", valid_event(username="custom-svc"))])
    normalized = normalize_events(validate_events(parse_raw_events(df)).filter("_is_valid"))
    row = enrich_events(normalized, privileged_users=["custom-svc"]).collect()[0]
    assert row["is_privileged_user"] is True


def test_enrichment_tags_environment(spark):
    df = make_raw_df(spark, [("security-authentication", valid_event())])
    normalized = normalize_events(validate_events(parse_raw_events(df)).filter("_is_valid"))
    row = enrich_events(normalized, environment="loadtest").collect()[0]
    assert row["environment"] == "loadtest"


# --- DLQ -------------------------------------------------------------------

def test_dlq_rows_wrap_non_json_payload_safely(spark):
    df = make_raw_df(spark, [("security-web", "{totally broken")])
    validated = validate_events(parse_raw_events(df))
    dlq_rows = build_dlq_rows(validated).collect()
    assert len(dlq_rows) == 1
    payload = json.loads(dlq_rows[0]["original_payload"])
    assert payload["raw"] == "{totally broken"
    assert dlq_rows[0]["error_reason"] == "payload is not valid JSON matching the event schema"
    assert dlq_rows[0]["source_topic"] == "security-web"


def test_dlq_rows_only_include_invalid_rows(spark):
    df = make_raw_df(spark, [
        ("security-authentication", valid_event()),
        ("security-authentication", valid_event(protocol="FTP")),
    ])
    validated = validate_events(parse_raw_events(df))
    dlq_rows = build_dlq_rows(validated).collect()
    assert len(dlq_rows) == 1  # only the FTP one


def test_dlq_row_to_postgres_params_roundtrips():
    from src.dlq import dlq_row_to_postgres_params

    class FakeRow(dict):
        pass

    row = FakeRow(original_payload='{"raw": "x"}', error_reason="bad", source_topic="security-web", timestamp="2026-01-01T00:00:00Z")
    params = dlq_row_to_postgres_params(row)
    assert params == ('{"raw": "x"}', "bad", "security-web", "2026-01-01T00:00:00Z")
