"""
Windowing infrastructure (cahier des charges §17/§18): reusable
event-time windowed counting that Phase B's detection rules (brute force,
password spraying, port scan, ...) will each configure differently
(different group-by columns, different window size) rather than each
rule re-implementing watermarking from scratch.

Watermarking (§18): `withWatermark(event_time_col, watermark_delay)`
tells Spark how long to keep state for a given window before considering
it final and evicting it - events arriving later than `watermark_delay`
behind the current max event_time are dropped from that aggregation
(NOT from the DLQ or storage - only from this specific windowed count).
A larger watermark_delay keeps more state in memory for longer (memory
cost) in exchange for tolerating later-arriving events; a smaller one is
cheaper but drops more late data. `SPARK_WATERMARK_DELAY_MINUTES` in
.env.example is the project-wide default (5 minutes).
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

# Cahier des charges §17's four required window sizes.
WINDOW_DURATIONS = ["1 minute", "5 minutes", "15 minutes", "1 hour"]


def windowed_counts(
    df: DataFrame,
    *,
    event_time_col: str,
    group_cols: list[str],
    window_duration: str,
    watermark_delay: str,
) -> DataFrame:
    """
    Returns one row per (window, *group_cols) with a `count` column.
    `window_duration`/`watermark_delay` are Spark interval-literal strings,
    e.g. "5 minutes". Requires event_time_col to be a real TimestampType
    column (normalization.py's `event_time`, not the raw ISO string).
    """
    watermarked = df.withWatermark(event_time_col, watermark_delay)
    return (
        watermarked
        .groupBy(F.window(F.col(event_time_col), window_duration), *group_cols)
        .count()
        .withColumn("window_start", F.col("window.start"))
        .withColumn("window_end", F.col("window.end"))
        .drop("window")
    )


def build_multi_window_counts(
    df: DataFrame,
    *,
    event_time_col: str,
    group_cols: list[str],
    watermark_delay: str,
) -> dict[str, DataFrame]:
    """One DataFrame per required window size (§17), all sharing the same watermark."""
    return {
        duration: windowed_counts(
            df, event_time_col=event_time_col, group_cols=group_cols,
            window_duration=duration, watermark_delay=watermark_delay,
        )
        for duration in WINDOW_DURATIONS
    }


def windowed_aggregate(
    df: DataFrame,
    *,
    event_time_col: str,
    window_duration: str,
    watermark_delay: str,
    group_cols: list[str],
    aggregations: dict[str, "F.Column"],
) -> DataFrame:
    """
    Generalization of windowed_counts() for Phase B's detection rules,
    which need richer per-window aggregates than a plain count (e.g.
    countDistinct(destination_port), collect_list(event_id)). Added
    alongside windowed_counts() rather than changing it, so Phase A's
    existing tests and callers are untouched.
    `aggregations` maps output column name -> a pyspark.sql.functions
    aggregate expression, e.g. {"unique_ports": F.countDistinct("destination_port")}.
    """
    watermarked = df.withWatermark(event_time_col, watermark_delay)
    agg_cols = [expr.alias(name) for name, expr in aggregations.items()]
    return (
        watermarked
        .groupBy(F.window(F.col(event_time_col), window_duration), *group_cols)
        .agg(*agg_cols)
        .withColumn("window_start", F.col("window.start"))
        .withColumn("window_end", F.col("window.end"))
        .drop("window")
    )
