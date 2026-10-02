"""
Large data transfer: a single event's `bytes_out` exceeding a configured
threshold (cahier des charges §22). Deliberately per-event rather than
windowed/summed - a true baseline-relative comparison ("significantly
exceeding" what is normal for this host/user) is Phase C's job (moving
average / stddev / z-score); this rule is the simple, explainable
threshold check the cahier des charges itself distinguishes from
statistical anomaly detection.
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from src.detection.base import DetectionRule


class LargeDataTransferRule(DetectionRule):
    rule_id = "large-data-transfer"
    rule_name = "Large Data Transfer"
    category = "network"

    def _detect(self, enriched_df: DataFrame, watermark_delay: str) -> DataFrame:
        candidates = enriched_df.filter(
            F.col("bytes_out").isNotNull() & (F.col("bytes_out") >= self.config.bytes_out_threshold)
        )

        return self.finalize_row_level(
            candidates,
            evidence_cols={
                "bytes_out": F.col("bytes_out"),
                "threshold": F.lit(self.config.bytes_out_threshold),
                "event_type": F.col("event_type"),
            },
        )
