"""
Port scan: one source contacting many distinct destination ports within
a window (cahier des charges §22). Detected on network-category traffic
generally (not solely the generator's `port_scan` event_type label) so
the rule reflects the actual behavior rather than trusting a synthetic
"this is a scan" marker - see docs/detection-engine.md for the scope
this still leaves out.
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from src.detection.base import DetectionRule
from src.windows import windowed_aggregate


class PortScanRule(DetectionRule):
    rule_id = "port-scan"
    rule_name = "Port Scan"
    category = "network"

    def _detect(self, enriched_df: DataFrame, watermark_delay: str) -> DataFrame:
        window_duration = f"{self.config.window_seconds} seconds"

        candidates = enriched_df.filter(
            (F.col("category") == "network") & F.col("source_ip").isNotNull()
        )

        aggregated = windowed_aggregate(
            candidates,
            event_time_col="event_time",
            window_duration=window_duration,
            watermark_delay=watermark_delay,
            group_cols=["source_ip"],
            aggregations={
                "unique_ports": F.countDistinct("destination_port"),
                "event_ids": F.collect_list("event_id"),
                "hostname": F.first("hostname"),
                "destination_ip": F.first("destination_ip"),
            },
        )

        triggered = aggregated.filter(F.col("unique_ports") >= self.config.unique_ports)

        return self.finalize_windowed(
            triggered,
            group_key_cols=["source_ip"],
            evidence_cols={
                "unique_ports": F.col("unique_ports"),
                "threshold": F.lit(self.config.unique_ports),
                "source_ip": F.col("source_ip"),
                "window_start": F.col("window_start"),
                "window_end": F.col("window_end"),
            },
            source_ip_col="source_ip",
            destination_ip_col="destination_ip",
            hostname_col="hostname",
            username_col=None,
        )
