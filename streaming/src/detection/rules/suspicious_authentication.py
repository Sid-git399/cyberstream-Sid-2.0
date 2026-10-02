"""
Suspicious authentication (cahier des charges §22): flags two
independently-explainable, canonical-schema-only patterns per event
(no external threat intel, no invented geo fields):

  1. A privileged account (enrichment.py's `is_privileged_user`)
     successfully authenticating from a source enrichment.py has already
     classified as non-internal (`is_source_internal == false`).
  2. Any `account_locked` event - always worth an analyst's attention
     regardless of who the account belongs to.

Both conditions rely only on fields Phase A already computes; this rule
adds no new enrichment of its own.
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from src.detection.base import DetectionRule


class SuspiciousAuthenticationRule(DetectionRule):
    rule_id = "suspicious-authentication"
    rule_name = "Suspicious Authentication"
    category = "authentication"

    def _detect(self, enriched_df: DataFrame, watermark_delay: str) -> DataFrame:
        privileged_external_login = (
            (F.col("event_type") == "login_success")
            & (F.col("is_privileged_user") == True)  # noqa: E712 - Spark Column comparison, not Python bool
            & (F.col("is_source_internal") == False)  # noqa: E712
        )
        account_locked = F.col("event_type") == "account_locked"

        candidates = enriched_df.filter(privileged_external_login | account_locked).withColumn(
            "_reason",
            F.when(account_locked, F.lit("account_locked"))
             .otherwise(F.lit("privileged_login_from_external_source")),
        )

        return self.finalize_row_level(
            candidates,
            evidence_cols={
                "reason": F.col("_reason"),
                "event_type": F.col("event_type"),
                "status": F.col("status"),
                "is_privileged_user": F.col("is_privileged_user"),
                "is_source_internal": F.col("is_source_internal"),
            },
        )
