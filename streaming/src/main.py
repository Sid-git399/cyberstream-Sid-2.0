"""
CyberStream Spark Structured Streaming entrypoint.

    Kafka (6 category topics)
        -> parse_raw_events        (structural JSON parse)
        -> validate_events         (business-rule checks)
        -> split: valid / invalid
              invalid -> build_dlq_rows -> security-dlq topic + dlq_entries table
              valid   -> normalize_events -> enrich_events -> Parquet (partitioned by date)

Every stage above is independently unit-tested against real Spark in
batch mode (tests/test_pipeline.py, tests/test_schema.py) without needing
a live broker. This file itself - the Kafka source, the two
foreachBatch sinks, and the Parquet sink - is NOT executable in this
environment (no live Kafka/Postgres) and has only been reviewed, not run.
See docs/phases.md for exactly what VERIFIED LOCALLY does and doesn't
cover here.

Run as: `python -m src.main` (see streaming/Dockerfile).
"""
from __future__ import annotations

import logging

from pyspark.sql import functions as F

from common.logging_utils import configure_logging
from src.config import get_settings
from src.detection.config import load_detection_config
from src.detection.engine import run_detections
from src.dlq import build_dlq_rows, write_dlq_batch_to_kafka, write_dlq_batch_to_postgres
from src.enrichment import enrich_events
from src.ingestion.kafka_source import read_kafka_source
from src.normalization import normalize_events
from src.parsing import parse_raw_events
from src.schema import build_category_topic_map
from src.spark_session import build_spark_session
from src.validation import validate_events

logger = logging.getLogger("streaming")


def build_pipeline(spark, settings):
    """
    Returns (normalized_and_enriched_df, dlq_rows_df) - the two output
    streams main() attaches sinks to. Split out from main() so future
    phases (detection, anomaly, correlation - Phase B+) can import this
    function and attach additional sinks/queries to the same DataFrames
    without re-reading Kafka a second time.
    """
    topics = list(build_category_topic_map().values())
    raw = read_kafka_source(spark, settings, topics)

    parsed = parse_raw_events(raw)
    validated = validate_events(parsed)

    dlq_rows = build_dlq_rows(validated)

    valid = validated.filter(F.col("_is_valid"))
    normalized = normalize_events(valid)
    enriched = enrich_events(normalized, privileged_users=settings.privileged_users_list, environment=settings.cyberstream_mode)

    return enriched, dlq_rows


def main() -> None:
    settings = get_settings()
    configure_logging(service="streaming", level=settings.log_level)
    logger.info(
        "starting streaming pipeline: bootstrap=%s consumer_group=%s trigger=%ss checkpoint_dir=%s",
        settings.kafka_bootstrap_servers, settings.kafka_consumer_group,
        settings.spark_trigger_interval_seconds, settings.spark_checkpoint_dir,
    )

    spark = build_spark_session(settings)
    enriched, dlq_rows = build_pipeline(spark, settings)

    dated = enriched.withColumn("year", F.year("event_time")) \
                     .withColumn("month", F.month("event_time")) \
                     .withColumn("day", F.dayofmonth("event_time"))

    events_query = (
        dated.writeStream
        .format("parquet")
        .option("path", f"{settings.parquet_data_dir}/processed")
        .option("checkpointLocation", f"{settings.spark_checkpoint_dir}/processed_events")
        .partitionBy("year", "month", "day")
        .trigger(processingTime=f"{settings.spark_trigger_interval_seconds} seconds")
        .outputMode("append")
        .start()
    )

    dlq_kafka_query = (
        dlq_rows.writeStream
        .foreachBatch(lambda batch_df, batch_id: write_dlq_batch_to_kafka(batch_df, batch_id, settings.kafka_bootstrap_servers))
        .option("checkpointLocation", f"{settings.spark_checkpoint_dir}/dlq_kafka")
        .trigger(processingTime=f"{settings.spark_trigger_interval_seconds} seconds")
        .start()
    )

    dlq_postgres_query = (
        dlq_rows.writeStream
        .foreachBatch(lambda batch_df, batch_id: write_dlq_batch_to_postgres(batch_df, batch_id, settings.psycopg_dsn))
        .option("checkpointLocation", f"{settings.spark_checkpoint_dir}/dlq_postgres")
        .trigger(processingTime=f"{settings.spark_trigger_interval_seconds} seconds")
        .start()
    )

    # Phase B: detection engine. Additive - reuses the same `enriched`
    # DataFrame build_pipeline() already produced; does not re-read Kafka
    # or change the three queries above. Guarded by a settings flag so
    # Phase A's pipeline can still run with detection off if needed.
    if settings.detection_engine_enabled:
        detection_config = load_detection_config(settings.detection_rules_config_path)
        detections = run_detections(enriched, detection_config, settings.watermark_delay_interval)

        detections_query = (
            detections.writeStream
            .format("parquet")
            .option("path", f"{settings.parquet_data_dir}/detections")
            .option("checkpointLocation", f"{settings.spark_checkpoint_dir}/detections")
            .trigger(processingTime=f"{settings.spark_trigger_interval_seconds} seconds")
            .outputMode("append")
            .start()
        )

    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    main()
