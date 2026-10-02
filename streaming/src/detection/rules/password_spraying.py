"""
Password spraying: one source authenticating against many distinct
usernames within a window - the inverse shape from brute force (many
attempts/one user), so this groups by source_ip only and counts DISTINCT
usernames, not total attempts (cahier des charges §22).
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from src.detection.base import DetectionRule
from src.windows import windowed_aggregate


class PasswordSprayingRule(DetectionRule):
    rule_id = "password-spraying"
    rule_name = "Password Spraying"
    category = "authentication"

    def _detect(self, enriched_df: DataFrame, watermark_delay: str) -> DataFrame:
        window_duration = f"{self.config.window_seconds} seconds"

        candidates = enriched_df.filter(
            (F.col("event_type") == "login_failed")
            & F.col("source_ip").isNotNull()
            & F.col("username").isNotNull()
        )

        aggregated = windowed_aggregate(
            candidates,
            event_time_col="event_time",
            window_duration=window_duration,
            watermark_delay=watermark_delay,
            group_cols=["source_ip"],
            aggregations={
                "unique_users": F.countDistinct("username"),
                "attempts": F.count("*"),
                "usernames": F.collect_set("username"),
                "event_ids": F.collect_list("event_id"),
                "hostname": F.first("hostname"),
                "destination_ip": F.first("destination_ip"),
            },
        )

        triggered = aggregated.filter(F.col("unique_users") >= self.config.unique_users)

        return self.finalize_windowed(
            triggered,
            group_key_cols=["source_ip"],
            evidence_cols={
                "unique_users": F.col("unique_users"),
                "threshold": F.lit(self.config.unique_users),
                "attempts": F.col("attempts"),
                "usernames": F.col("usernames"),
                "source_ip": F.col("source_ip"),
                "window_start": F.col("window_start"),
                "window_end": F.col("window_end"),
            },
            source_ip_col="source_ip",
            destination_ip_col="destination_ip",
            hostname_col="hostname",
            username_col=None,  # many users targeted - no single username applies
        )
