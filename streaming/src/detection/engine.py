"""
Detection engine: turns Phase A's enriched DataFrame into a single
DataFrame of structured detections by running every enabled rule and
unioning the results. Disabled rules contribute zero rows (see
DetectionRule.apply's empty-but-schema-conformant DataFrame), so the
union is always well-typed regardless of which rules are on.
"""
from __future__ import annotations

from functools import reduce

from pyspark.sql import DataFrame

from src.detection.base import DETECTION_OUTPUT_SCHEMA
from src.detection.config import DetectionEngineConfig
from src.detection.rules import ALL_RULES


def build_rules(config: DetectionEngineConfig) -> list:
    """One instantiated rule per entry in ALL_RULES, each bound to its own validated config section."""
    return [
        rule_cls(getattr(config, config_key))
        for config_key, rule_cls in ALL_RULES.items()
    ]


def run_detections(enriched_df: DataFrame, config: DetectionEngineConfig, watermark_delay: str) -> DataFrame:
    """
    Runs every configured rule against `enriched_df` and returns one
    unioned DataFrame conforming to DETECTION_OUTPUT_SCHEMA. Safe to call
    with all rules disabled (returns an empty, correctly-typed DataFrame,
    never an error) and safe to call repeatedly with different configs.
    """
    rules = build_rules(config)
    outputs = [rule.apply(enriched_df, watermark_delay) for rule in rules]

    if not outputs:
        return enriched_df.sparkSession.createDataFrame([], DETECTION_OUTPUT_SCHEMA)

    return reduce(lambda a, b: a.unionByName(b), outputs)
