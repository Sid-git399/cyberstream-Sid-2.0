"""
DetectionRule abstraction.

Every concrete rule (streaming/src/detection/rules/*.py) is a plain Spark
DataFrame transformation wrapped in a small class - never a Python loop
over collected rows, which would both be wrong (a streaming query can't
`.collect()`) and wouldn't distribute. `apply()` takes the enriched
DataFrame (Phase A's output) and returns a DataFrame already conforming
to DETECTION_OUTPUT_COLUMNS, or an empty-but-schema-conformant DataFrame
if the rule is disabled - callers never need an `if rule.enabled` branch
before calling `apply()`.

Two shapes of rule exist:
  - windowed (brute force, password spraying, port scan, DNS anomaly):
    aggregates events_in_a_window and compares a count against a
    threshold. `finalize_windowed()` handles the common column-building.
  - row-level (suspicious authentication, privilege escalation,
    suspicious process, large data transfer): each qualifying event is
    its own detection, no aggregation. `finalize_row_level()` handles it.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import (
    ArrayType,
    IntegerType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

# Stable output contract - every rule's apply() must produce exactly these
# columns, in this order. Tests assert this directly (test_engine.py).
DETECTION_OUTPUT_COLUMNS = [
    "detection_id", "timestamp", "rule_id", "rule_name", "category",
    "severity", "risk_points", "source_ip", "destination_ip", "hostname",
    "username", "evidence", "event_ids", "window_start", "window_end",
]

DETECTION_OUTPUT_SCHEMA = StructType([
    StructField("detection_id", StringType(), False),
    StructField("timestamp", TimestampType(), False),
    StructField("rule_id", StringType(), False),
    StructField("rule_name", StringType(), False),
    StructField("category", StringType(), False),
    StructField("severity", StringType(), False),
    StructField("risk_points", IntegerType(), False),
    StructField("source_ip", StringType(), True),
    StructField("destination_ip", StringType(), True),
    StructField("hostname", StringType(), True),
    StructField("username", StringType(), True),
    StructField("evidence", StringType(), False),   # JSON-encoded text (see docs/detection-engine.md)
    StructField("event_ids", ArrayType(StringType()), False),
    StructField("window_start", TimestampType(), False),
    StructField("window_end", TimestampType(), False),
])


def make_detection_id(*parts: Column) -> Column:
    """
    Deterministic (not random): the same rule firing on the same
    window/group twice - e.g. a reprocessed batch after a restart -
    produces the same detection_id both times, so a downstream Alert
    Engine (Phase G) can deduplicate on it directly rather than needing
    its own fingerprinting for this case.
    """
    return F.sha2(F.concat_ws("|", *[p.cast("string") for p in parts]), 256)


class DetectionRule(ABC):
    rule_id: str
    rule_name: str
    category: str

    def __init__(self, config):
        self.config = config

    @property
    def is_enabled(self) -> bool:
        return bool(self.config.enabled)

    @abstractmethod
    def _detect(self, enriched_df: DataFrame, watermark_delay: str) -> DataFrame:
        """Subclasses implement the actual detection logic, returning DETECTION_OUTPUT_COLUMNS-shaped rows."""
        raise NotImplementedError

    def apply(self, enriched_df: DataFrame, watermark_delay: str) -> DataFrame:
        if not self.is_enabled:
            return enriched_df.sparkSession.createDataFrame([], DETECTION_OUTPUT_SCHEMA)
        return self._detect(enriched_df, watermark_delay).select(*DETECTION_OUTPUT_COLUMNS)

    # --- shared column-building helpers for concrete rules ---

    def _common_columns(self, df: DataFrame, *, detection_id_parts: list[Column]) -> DataFrame:
        return (
            df
            .withColumn("detection_id", make_detection_id(F.lit(self.rule_id), *detection_id_parts))
            .withColumn("rule_id", F.lit(self.rule_id))
            .withColumn("rule_name", F.lit(self.rule_name))
            .withColumn("category", F.lit(self.category))
            .withColumn("severity", F.lit(self.config.severity))
            .withColumn("risk_points", F.lit(self.config.risk_points).cast("int"))
        )

    def finalize_windowed(
        self, df: DataFrame, *, group_key_cols: list[str], evidence_cols: dict[str, Column],
        source_ip_col="source_ip", destination_ip_col=None, hostname_col=None, username_col=None,
        event_ids_col="event_ids",
    ) -> DataFrame:
        """
        `df` must already have `window_start`/`window_end` (from
        windows.windowed_counts or an equivalent groupBy(F.window(...))
        aggregation) and every column referenced above.
        """
        out = self._common_columns(
            df, detection_id_parts=[F.col("window_start"), *[F.col(c) for c in group_key_cols]]
        )
        out = out.withColumn("timestamp", F.col("window_end"))
        out = out.withColumn("source_ip", F.col(source_ip_col))
        out = out.withColumn("destination_ip", F.col(destination_ip_col) if destination_ip_col else F.lit(None).cast("string"))
        out = out.withColumn("hostname", F.col(hostname_col) if hostname_col else F.lit(None).cast("string"))
        out = out.withColumn("username", F.col(username_col) if username_col else F.lit(None).cast("string"))
        out = out.withColumn("evidence", F.to_json(F.struct(*[c.alias(name) for name, c in evidence_cols.items()])))
        out = out.withColumn("event_ids", F.col(event_ids_col))
        return out

    def finalize_row_level(
        self, df: DataFrame, *, evidence_cols: dict[str, Column],
        source_ip_col="source_ip", destination_ip_col="destination_ip",
        hostname_col="hostname", username_col="username", event_id_col="event_id",
    ) -> DataFrame:
        """Each input row becomes exactly one detection row; window_start == window_end == event_time."""
        out = self._common_columns(df, detection_id_parts=[F.col(event_id_col)])
        out = out.withColumn("timestamp", F.col("event_time"))
        out = out.withColumn("source_ip", F.col(source_ip_col))
        out = out.withColumn("destination_ip", F.col(destination_ip_col))
        out = out.withColumn("hostname", F.col(hostname_col))
        out = out.withColumn("username", F.col(username_col))
        out = out.withColumn("evidence", F.to_json(F.struct(*[c.alias(name) for name, c in evidence_cols.items()])))
        out = out.withColumn("event_ids", F.array(F.col(event_id_col)))
        out = out.withColumn("window_start", F.col("event_time"))
        out = out.withColumn("window_end", F.col("event_time"))
        return out
