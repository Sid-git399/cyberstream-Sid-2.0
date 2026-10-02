from __future__ import annotations

from pyspark.sql import SparkSession

from src.config import Settings


def build_spark_session(settings: Settings, include_kafka_connector: bool = True) -> SparkSession:
    """
    `include_kafka_connector=False` skips adding the spark-sql-kafka Maven
    coordinate, which otherwise triggers a Maven Central download at
    session-creation time - useful for tests in a network-restricted
    environment (see streaming/tests/test_spark_session.py), and for any
    future batch-only job that never touches Kafka. Production (main.py)
    always uses the default (True).
    """
    builder = (
        SparkSession.builder
        .appName("cyberstream-streaming")
        .master(settings.spark_master)
        .config("spark.sql.shuffle.partitions", str(settings.shuffle_partitions))
    )
    if include_kafka_connector:
        builder = builder.config(
            "spark.jars.packages",
            "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.3",
        )
    return builder.getOrCreate()
