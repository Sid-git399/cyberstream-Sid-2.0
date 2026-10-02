"""
Business-rule validation stage. Structural parsing (parsing.py) already
guarantees field *types* match the schema; this stage checks the *values*
Spark's schema-on-read can't express - port ranges, enum membership,
non-negative byte counts, country code length. Anything failing either
stage is routed to the DLQ (dlq.py); nothing is silently dropped.
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from src.schema import event_type_enum

_ALLOWED_PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
_ALLOWED_STATUSES = ["success", "failure", "unknown"]
_EVENT_TYPES = event_type_enum()


def validate_events(parsed_df: DataFrame) -> DataFrame:
    """
    Input: output of parsing.parse_raw_events (has `parsed`, `_parse_error`,
    `raw_value_str`, `topic`). Flattens `parsed.*` into top-level columns
    and adds `_validation_error` (first failing rule, or null) plus
    `_is_valid` (True only if both parsing and validation succeeded).
    """
    flattened = parsed_df.select(
        "topic", "raw_value_str", "_parse_error", "parsed.*"
    )

    validation_error = (
        F.when(F.col("_parse_error").isNotNull(), F.col("_parse_error"))
         .when(F.col("event_type").isNull() | ~F.col("event_type").isin(_EVENT_TYPES),
               F.lit("event_type is missing or not a recognized value"))
         .when(~F.col("protocol").isin(_ALLOWED_PROTOCOLS),
               F.lit("protocol must be one of TCP/UDP/ICMP/HTTP/HTTPS/DNS"))
         .when(~F.col("status").isin(_ALLOWED_STATUSES),
               F.lit("status must be one of success/failure/unknown"))
         .when((F.col("source_port") < 0) | (F.col("source_port") > 65535),
               F.lit("source_port out of range 0-65535"))
         .when((F.col("destination_port") < 0) | (F.col("destination_port") > 65535),
               F.lit("destination_port out of range 0-65535"))
         .when((F.col("bytes_in") < 0) | (F.col("bytes_out") < 0),
               F.lit("bytes_in/bytes_out must be non-negative"))
         .when(F.length(F.col("country")) != 2,
               F.lit("country must be a 2-letter code"))
         .when(F.col("hostname").isNull() | (F.length(F.col("hostname")) == 0),
               F.lit("hostname is required"))
         .otherwise(F.lit(None).cast("string"))
    )

    return flattened.withColumn("_validation_error", validation_error).withColumn(
        "_is_valid", F.col("_validation_error").isNull()
    )
