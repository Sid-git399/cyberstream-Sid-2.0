"""
DNS anomaly: unusually high DNS query volume from one source within a
window - a volume/behavior signal using only canonical schema fields
(event_type, source_ip, event_time), not any generator-specific metadata
key, so this rule would behave the same against real DNS telemetry that
happened to use this schema (cahier des charges §22/§24).
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from src.detection.base import DetectionRule
from src.windows import windowed_aggregate


class DNSAnomalyRule(DetectionRule):
    rule_id = "dns-anomaly"
    rule_name = "DNS Anomaly"
    category = "network"

    def _detect(self, enriched_df: DataFrame, watermark_delay: str) -> DataFrame:
        window_duration = f"{self.config.window_seconds} seconds"

        candidates = enriched_df.filter(
            (F.col("event_type") == "dns_query") & F.col("source_ip").isNotNull()
        )

        aggregated = windowed_aggregate(
            candidates,
            event_time_col="event_time",
            window_duration=window_duration,
            watermark_delay=watermark_delay,
            group_cols=["source_ip"],
            aggregations={
                "query_count": F.count("*"),
                "event_ids": F.collect_list("event_id"),
                "hostname": F.first("hostname"),
                "username": F.first("username"),
            },
        )

        triggered = aggregated.filter(F.col("query_count") >= self.config.query_count_threshold)

        return self.finalize_windowed(
            triggered,
            group_key_cols=["source_ip"],
            evidence_cols={
                "query_count": F.col("query_count"),
                "threshold": F.lit(self.config.query_count_threshold),
                "source_ip": F.col("source_ip"),
                "window_start": F.col("window_start"),
                "window_end": F.col("window_end"),
            },
            source_ip_col="source_ip",
            destination_ip_col=None,
            hostname_col="hostname",
            username_col="username",
        )
