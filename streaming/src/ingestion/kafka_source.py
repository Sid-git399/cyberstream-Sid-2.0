"""
Kafka Structured Streaming source. NOT executable in this environment -
no live broker - see docs/phases.md. Reviewed, not run; kept intentionally
thin (a single readStream call) so there is as little untested logic here
as possible - everything else in this package (parsing, validation,
normalization, enrichment, windows, dlq) IS tested, against DataFrames
shaped like this source's real output (see tests/test_pipeline.py).
"""
from __future__ import annotations

from pyspark.sql import DataFrame, SparkSession

from src.config import Settings


def read_kafka_source(spark: SparkSession, settings: Settings, topics: list[str]) -> DataFrame:
    return (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", settings.kafka_bootstrap_servers)
        .option("subscribe", ",".join(topics))
        .option("kafka.group.id", settings.kafka_consumer_group)
        .option("startingOffsets", settings.kafka_starting_offsets)
        .option("failOnDataLoss", "false")  # tolerate topic compaction/retention deleting old data, don't crash the job
        .load()
    )
