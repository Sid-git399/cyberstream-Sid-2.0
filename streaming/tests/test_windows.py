"""
Windowing correctness, tested in BATCH mode: groupBy(window(...)) bucket
math is deterministic and doesn't need a live streaming query to verify -
only withWatermark's *effect on late data in an actually-running stream*
does (covered separately in test_streaming_engine.py). Batch mode here
gives exact, reproducible counts per window bucket, which is what these
tests check.
"""
from datetime import datetime, timedelta, timezone

from src.windows import WINDOW_DURATIONS, build_multi_window_counts, windowed_counts


def make_events_df(spark, timestamps_and_keys: list[tuple[datetime, str]]):
    rows = [(ts, key) for ts, key in timestamps_and_keys]
    df = spark.createDataFrame(rows, schema=["event_time", "source_ip"])
    return df


def test_windowed_counts_buckets_events_correctly(spark):
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        (base, "1.2.3.4"),
        (base + timedelta(seconds=10), "1.2.3.4"),
        (base + timedelta(seconds=20), "1.2.3.4"),
        (base + timedelta(minutes=2), "1.2.3.4"),  # falls in the NEXT 1-minute window
    ]
    df = make_events_df(spark, events)
    result = windowed_counts(
        df, event_time_col="event_time", group_cols=["source_ip"],
        window_duration="1 minute", watermark_delay="10 minutes",
    )
    rows = {r["window_start"]: r["count"] for r in result.collect()}
    assert len(rows) == 2
    assert sorted(rows.values()) == [1, 3]


def test_windowed_counts_groups_by_multiple_keys_separately(spark):
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        (base, "1.2.3.4"),
        (base, "5.6.7.8"),
        (base + timedelta(seconds=5), "1.2.3.4"),
    ]
    df = make_events_df(spark, events)
    result = windowed_counts(
        df, event_time_col="event_time", group_cols=["source_ip"],
        window_duration="1 minute", watermark_delay="10 minutes",
    )
    rows = {r["source_ip"]: r["count"] for r in result.collect()}
    assert rows["1.2.3.4"] == 2
    assert rows["5.6.7.8"] == 1


def test_build_multi_window_counts_returns_all_four_durations(spark):
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    df = make_events_df(spark, [(base, "1.2.3.4")])
    results = build_multi_window_counts(
        df, event_time_col="event_time", group_cols=["source_ip"], watermark_delay="10 minutes",
    )
    assert set(results.keys()) == set(WINDOW_DURATIONS)
    assert len(WINDOW_DURATIONS) == 4
    for duration, result_df in results.items():
        assert result_df.collect()[0]["count"] == 1


def test_five_minute_window_groups_events_within_span(spark):
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = [(base + timedelta(minutes=m), "1.2.3.4") for m in range(4)]  # 0,1,2,3 min - all within one 5m window
    df = make_events_df(spark, events)
    result = windowed_counts(
        df, event_time_col="event_time", group_cols=["source_ip"],
        window_duration="5 minutes", watermark_delay="10 minutes",
    )
    rows = result.collect()
    assert len(rows) == 1
    assert rows[0]["count"] == 4
