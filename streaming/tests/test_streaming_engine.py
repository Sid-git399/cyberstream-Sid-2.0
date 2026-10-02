"""
Everything else in this test suite runs Spark in BATCH mode - correct for
verifying transformation logic, but it never actually exercises the
streaming engine itself (micro-batch triggers, watermark state eviction,
checkpoint writes). This module starts one real streaming query, using
Spark's built-in `rate` source (generates monotonically increasing rows
with real timestamps - no external dependency, no Kafka broker needed),
lets it run for a few real seconds, stops it, and inspects what it
actually produced and actually wrote to disk. This is the closest this
environment can get to proving the streaming plumbing works without a
live Kafka broker.
"""
import os
import time

from pyspark.sql import functions as F


def test_streaming_query_runs_triggers_and_checkpoints(spark, tmp_path):
    checkpoint_dir = str(tmp_path / "checkpoint")

    rate_df = spark.readStream.format("rate").option("rowsPerSecond", 10).load()

    # Watermark and window both short relative to the test's wall-clock
    # budget - a window is only emitted in append mode once the watermark
    # has advanced past its end, so a 10s watermark (as used above) with
    # only ~6s of real run time never finalizes anything: found by
    # actually running this test and getting zero rows back, not by
    # reasoning about it in advance (see docs/phases.md).
    windowed = (
        rate_df
        .withWatermark("timestamp", "2 seconds")
        .groupBy(F.window(F.col("timestamp"), "2 seconds"), (F.col("value") % 3).alias("bucket"))
        .count()
    )

    query = (
        windowed.writeStream
        .format("memory")
        .queryName("streaming_smoke_test")
        .outputMode("append")
        .trigger(processingTime="1 second")
        .option("checkpointLocation", checkpoint_dir)
        .start()
    )

    try:
        # Real wall-clock wait for several real micro-batches AND enough
        # time for the watermark to advance past at least one window's end.
        time.sleep(9)
        assert query.isActive, "streaming query stopped unexpectedly"
        progress = query.lastProgress
        assert progress is not None, "query never reported any progress - no micro-batch ran"
    finally:
        query.stop()

    # The query actually produced output via the memory sink.
    result = spark.sql("SELECT * FROM streaming_smoke_test").collect()
    assert len(result) > 0, "no windowed rows were produced by the real streaming query"

    # Checkpointing genuinely wrote state to disk - not asserted from
    # config, checked on the real filesystem.
    assert os.path.isdir(checkpoint_dir)
    checkpoint_subdirs = set(os.listdir(checkpoint_dir))
    assert "offsets" in checkpoint_subdirs
    assert "commits" in checkpoint_subdirs
    offset_files = os.listdir(os.path.join(checkpoint_dir, "offsets"))
    assert len(offset_files) > 0, "no offset files were checkpointed"


def test_trigger_interval_is_actually_respected(spark, tmp_path):
    """
    A coarser trigger (2s) should produce noticeably fewer micro-batches
    than a fine one (0.2s) over the same real wall-clock duration - proves
    the configured trigger interval, not just its presence in config, has
    a real effect on the running query.
    """
    def run_and_count_batches(trigger_seconds: float, checkpoint_subdir: str) -> int:
        rate_df = spark.readStream.format("rate").option("rowsPerSecond", 5).load()
        query = (
            rate_df.writeStream
            .format("memory")
            .queryName(f"trigger_test_{checkpoint_subdir}")
            .outputMode("append")
            .trigger(processingTime=f"{trigger_seconds} seconds")
            .option("checkpointLocation", str(tmp_path / checkpoint_subdir))
            .start()
        )
        try:
            time.sleep(4)
        finally:
            query.stop()
        return len(os.listdir(tmp_path / checkpoint_subdir / "offsets"))

    fine_batches = run_and_count_batches(0.2, "fine")
    coarse_batches = run_and_count_batches(2.0, "coarse")

    assert fine_batches > coarse_batches, (
        f"expected the 0.2s trigger ({fine_batches} batches) to run more "
        f"micro-batches than the 2s trigger ({coarse_batches} batches) "
        f"over the same wall-clock duration"
    )
