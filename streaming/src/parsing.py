"""
Structural parsing stage: Kafka's raw `value` bytes -> typed columns per
schema.py's StructType. Only catches structural failures (not valid JSON,
or JSON that doesn't match the schema's field types) - business-rule
validation (port ranges, enum membership) is validation.py's job, kept
separate so each stage has one responsibility.
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from src.schema import build_security_event_struct_type

EVENT_STRUCT_TYPE = build_security_event_struct_type()


def parse_raw_events(raw_df: DataFrame, value_col: str = "value", topic_col: str = "topic") -> DataFrame:
    """
    `raw_df` is expected to have the shape Spark's Kafka source produces:
    at minimum a `value` column (bytes) and a `topic` column (string).
    Adds:
      - `raw_value_str`: the original payload as a string (kept for DLQ -
        a malformed payload must not be discarded, only routed elsewhere)
      - `parsed`: the struct per EVENT_STRUCT_TYPE, or null if the JSON
        was structurally invalid or didn't match the schema's field types
      - `_parse_error`: null if parsing succeeded, else a short reason
    Does not flatten `parsed` into top-level columns yet - validation.py
    does that once it has also checked the parsed fields are valid.
    """
    with_str = raw_df.withColumn("raw_value_str", F.col(value_col).cast("string"))

    parsed = with_str.withColumn(
        "parsed", F.from_json(F.col("raw_value_str"), EVENT_STRUCT_TYPE)
    )

    # Spark's from_json runs in PERMISSIVE mode by default: genuinely
    # malformed JSON does NOT make `parsed` null - it produces a struct
    # with every field null instead (verified directly, not assumed - see
    # docs/phases.md). So `parsed.isNull()` alone misses this case; the
    # required `event_id` field being null is the actual signal that
    # parsing produced nothing usable, whether the cause was invalid JSON
    # syntax or valid JSON missing required fields.
    return parsed.withColumn(
        "_parse_error",
        F.when(F.col("raw_value_str").isNull(), F.lit("empty or null message value"))
         .when(
             F.col("parsed").isNull() | F.col("parsed.event_id").isNull(),
             F.lit("payload is not valid JSON matching the event schema"),
         )
         .otherwise(F.lit(None).cast("string")),
    ).select(
        topic_col, "raw_value_str", "parsed", "_parse_error",
    )
