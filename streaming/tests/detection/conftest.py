"""
Shared fixtures for detection rule tests.

`make_enriched_df` builds a DataFrame with exactly the columns
enrich_events() produces (Phase A), by hand - fast and precise for
per-rule unit tests. `test_pipeline_integration.py` instead drives real
raw JSON through the actual parse->validate->normalize->enrich chain, so
both "does the rule logic work" and "does it work fed from Phase A's
real output" are covered, not just the former.
"""
from datetime import datetime, timezone

import pytest
from pyspark.sql.types import (
    BooleanType,
    LongType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

ENRICHED_COLUMNS = [
    "event_id", "event_time", "timestamp", "event_type", "category",
    "source_ip", "destination_ip", "source_port", "destination_port",
    "protocol", "username", "hostname", "action", "status",
    "bytes_in", "bytes_out", "country", "metadata", "topic",
    "is_source_internal", "is_destination_internal", "is_privileged_user",
    "known_service_name", "is_known_service_port", "environment",
]

# Explicit schema, matching normalization.py + enrichment.py's real output
# types exactly. Required, not cosmetic: spark.createDataFrame() infers a
# schema from Python values when none is given, and inference OUTRIGHT
# FAILS (PySparkValueError: CANNOT_DETERMINE_TYPE) whenever a column is
# `None` in every row of the batch - which single-row null-field tests
# (e.g. "missing hostname") do by construction. Found by running exactly
# such a test and watching it fail with that error instead of exercising
# the rule - see docs/phases.md / docs/detection-engine.md.
ENRICHED_SCHEMA = StructType([
    StructField("event_id", StringType(), True),
    StructField("event_time", TimestampType(), True),
    StructField("timestamp", StringType(), True),
    StructField("event_type", StringType(), True),
    StructField("category", StringType(), True),
    StructField("source_ip", StringType(), True),
    StructField("destination_ip", StringType(), True),
    StructField("source_port", LongType(), True),
    StructField("destination_port", LongType(), True),
    StructField("protocol", StringType(), True),
    StructField("username", StringType(), True),
    StructField("hostname", StringType(), True),
    StructField("action", StringType(), True),
    StructField("status", StringType(), True),
    StructField("bytes_in", LongType(), True),
    StructField("bytes_out", LongType(), True),
    StructField("country", StringType(), True),
    StructField("metadata", StringType(), True),
    StructField("topic", StringType(), True),
    StructField("is_source_internal", BooleanType(), True),
    StructField("is_destination_internal", BooleanType(), True),
    StructField("is_privileged_user", BooleanType(), True),
    StructField("known_service_name", StringType(), True),
    StructField("is_known_service_port", BooleanType(), True),
    StructField("environment", StringType(), True),
])

DEFAULTS = dict(
    event_id="evt-default", event_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    timestamp="2026-01-01T00:00:00.000Z", event_type="connection", category="network",
    source_ip="10.10.4.10", destination_ip="10.10.1.10", source_port=50000,
    destination_port=443, protocol="TCP", username="jdoe", hostname="ws-fin-014",
    action="connection", status="success", bytes_in=100, bytes_out=100,
    country="DZ", metadata="{}", topic="security-network",
    is_source_internal=True, is_destination_internal=True, is_privileged_user=False,
    known_service_name="https", is_known_service_port=True, environment="dev",
)


@pytest.fixture
def make_enriched_df(spark):
    def _make(rows: list[dict]):
        full_rows = []
        for row in rows:
            merged = {**DEFAULTS, **row}
            full_rows.append({col: merged[col] for col in ENRICHED_COLUMNS})
        return spark.createDataFrame(full_rows, schema=ENRICHED_SCHEMA)
    return _make
