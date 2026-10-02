"""
Suspicious process (cahier des charges §22): flags `process_created`
events whose `metadata` (the canonical schema's free-form JSON bag - see
schema.py) carries `"suspicious": true`. In this project that key is set
by generator/scenarios/suspicious_process.py's synthetic
parent-process/child-process pairing (e.g. winword.exe -> powershell.exe).

This is explicitly NOT real endpoint malware analysis or behavioral
detection - it is reading a label the synthetic telemetry itself
provides. A real deployment feeding genuine EDR telemetry into this
schema would need its own process-anomaly logic (e.g. a real parent/child
allow-list, or a Phase C-style statistical baseline) writing into the
same `metadata` shape, or a dedicated rule reading real EDR fields
instead - documented here so this limitation isn't discovered later by
surprise. See docs/detection-engine.md.
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from src.detection.base import DetectionRule


class SuspiciousProcessRule(DetectionRule):
    rule_id = "suspicious-process"
    rule_name = "Suspicious Process"
    category = "endpoint"

    def _detect(self, enriched_df: DataFrame, watermark_delay: str) -> DataFrame:
        is_flagged_suspicious = F.get_json_object(F.col("metadata"), "$.suspicious") == "true"

        candidates = (
            enriched_df
            .filter((F.col("event_type") == "process_created") & is_flagged_suspicious)
            .withColumn("_process", F.get_json_object(F.col("metadata"), "$.process"))
            .withColumn("_parent_process", F.get_json_object(F.col("metadata"), "$.parent_process"))
        )

        return self.finalize_row_level(
            candidates,
            evidence_cols={
                "process": F.col("_process"),
                "parent_process": F.col("_parent_process"),
                "event_type": F.col("event_type"),
            },
        )
