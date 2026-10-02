"""
Brute force: repeated failed logins against the same account, from the
same source, within a configurable window (cahier des charges §22).
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from src.detection.base import DetectionRule
from src.windows import windowed_aggregate


class BruteForceRule(DetectionRule):
    rule_id = "brute-force"
    rule_name = "Brute Force"
    category = "authentication"

    def _detect(self, enriched_df: DataFrame, watermark_delay: str) -> DataFrame:
        window_duration = f"{self.config.window_seconds} seconds"

        # username/source_ip are essential group keys here - a null
        # username can't meaningfully be "the same account" across
        # events, so those rows are excluded rather than silently grouped
        # into a misleading "null user" bucket.
        candidates = enriched_df.filter(
            (F.col("event_type") == "login_failed")
            & F.col("username").isNotNull()
            & F.col("source_ip").isNotNull()
        )

        aggregated = windowed_aggregate(
            candidates,
            event_time_col="event_time",
            window_duration=window_duration,
            watermark_delay=watermark_delay,
            group_cols=["username", "source_ip"],
            aggregations={
                "failed_attempts": F.count("*"),
                "event_ids": F.collect_list("event_id"),
                "hostname": F.first("hostname"),
                "destination_ip": F.first("destination_ip"),
            },
        )

        triggered = aggregated.filter(F.col("failed_attempts") >= self.config.failed_attempts)

        return self.finalize_windowed(
            triggered,
            group_key_cols=["username", "source_ip"],
            evidence_cols={
                "failed_attempts": F.col("failed_attempts"),
                "threshold": F.lit(self.config.failed_attempts),
                "username": F.col("username"),
                "source_ip": F.col("source_ip"),
                "window_start": F.col("window_start"),
                "window_end": F.col("window_end"),
            },
            source_ip_col="source_ip",
            destination_ip_col="destination_ip",
            hostname_col="hostname",
            username_col="username",
        )
