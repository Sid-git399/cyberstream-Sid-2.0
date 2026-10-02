"""
Privilege escalation: flags `privilege_escalation` and `group_modified`
events directly - both are already explicit, canonical event_type values
(cahier des charges §22), so no additional heuristic is needed beyond
"this event type occurred".
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from src.detection.base import DetectionRule


class PrivilegeEscalationRule(DetectionRule):
    rule_id = "privilege-escalation"
    rule_name = "Privilege Escalation"
    category = "privilege"

    def _detect(self, enriched_df: DataFrame, watermark_delay: str) -> DataFrame:
        candidates = enriched_df.filter(
            F.col("event_type").isin("privilege_escalation", "group_modified")
        )

        return self.finalize_row_level(
            candidates,
            evidence_cols={
                "event_type": F.col("event_type"),
                "action": F.col("action"),
                "status": F.col("status"),
            },
        )
