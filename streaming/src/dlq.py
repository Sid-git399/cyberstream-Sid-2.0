"""
Dead-letter-queue row construction (cahier des charges §43). Malformed or
invalid events are never dropped - `build_dlq_rows` turns them into rows
carrying the original payload, the error reason, and the source topic,
ready for a sink to persist.

Production sinks (writing these rows to the `security-dlq` Kafka topic,
and/or the `dlq_entries` Postgres table the Alembic migration already
created - see backend/alembic/versions/0001_initial_schema.py, reused
rather than a second schema mechanism) are wired in main.py and are NOT
executable in this environment (no live Kafka/Postgres) - see
docs/phases.md. This module's row-construction logic is fully testable
without either.
"""
from __future__ import annotations

import json

from pyspark.sql import DataFrame
from pyspark.sql import functions as F


def build_dlq_rows(validated_df: DataFrame) -> DataFrame:
    """
    Input: output of validation.validate_events, NOT yet filtered - this
    selects only the invalid rows itself. `original_payload` is always
    wrapped as valid JSON (`{"raw": "..."}`) even when the source payload
    wasn't valid JSON at all, because the Postgres sink's column is JSONB
    and must never receive non-JSON text.
    """
    invalid = validated_df.filter(~F.col("_is_valid"))
    return invalid.select(
        F.to_json(F.struct(F.col("raw_value_str").alias("raw"))).alias("original_payload"),
        F.col("_validation_error").alias("error_reason"),
        F.col("topic").alias("source_topic"),
        F.current_timestamp().alias("timestamp"),
    )


def dlq_row_to_postgres_params(row) -> tuple:
    """
    Pure function: one DLQ row -> the parameter tuple for the
    `dlq_entries` INSERT (see backend/app/models/dlq_pipeline_benchmark.py
    for the target schema). Kept separate from the actual DB call so it's
    testable without a live connection.
    """
    # original_payload must already be a JSON string (build_dlq_rows
    # guarantees this) - validated here defensively rather than trusting
    # the caller, since a bad value here would break every row in a batch.
    json.loads(row["original_payload"])
    return (
        row["original_payload"],
        row["error_reason"],
        row["source_topic"],
        row["timestamp"],
    )


DLQ_INSERT_SQL = (
    "INSERT INTO dlq_entries (original_payload, error_reason, source_topic, \"timestamp\") "
    "VALUES (%s, %s, %s, %s)"
)


def write_dlq_batch_to_postgres(batch_df: DataFrame, batch_id: int, database_url: str) -> None:
    """
    foreachBatch sink: NOT executable without a live Postgres instance -
    see docs/phases.md (NOT VERIFIED). Imports psycopg lazily so this
    module stays importable (and its pure functions testable) even in an
    environment without psycopg installed.
    """
    import psycopg

    rows = batch_df.collect()
    if not rows:
        return
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.executemany(DLQ_INSERT_SQL, [dlq_row_to_postgres_params(r) for r in rows])
        conn.commit()


def write_dlq_batch_to_kafka(batch_df: DataFrame, batch_id: int, bootstrap_servers: str, topic: str = "security-dlq") -> None:
    """
    foreachBatch sink writing to the security-dlq Kafka topic (cahier des
    charges' primary DLQ destination). NOT executable without a live
    Kafka broker - see docs/phases.md (NOT VERIFIED).
    """
    (
        batch_df
        .select(F.col("original_payload").alias("value"))
        .write
        .format("kafka")
        .option("kafka.bootstrap.servers", bootstrap_servers)
        .option("topic", topic)
        .save()
    )
