# Spark Structured Streaming

## Pipeline

```text
Kafka (6 category topics, subscribed together)
    -> parse_raw_events        structural JSON parse against schema.py's StructType
    -> validate_events         business-rule checks (ranges, enums)
    -> split on `_is_valid`
         invalid -> build_dlq_rows -> security-dlq topic + dlq_entries table (2 sinks, same rows)
         valid   -> normalize_events -> enrich_events -> Parquet (partitioned by year/month/day)
```

Every arrow above except the first ("Kafka ->") and the two DLQ/Parquet
sinks is implemented as a plain, independently-testable function taking
and returning a Spark `DataFrame` - see `streaming/src/{parsing,
validation, normalization, enrichment, dlq}.py`. `main.py`'s
`build_pipeline()` wires them together and is the only place that knows
the full chain, so Phase B (detection) can import `build_pipeline()` and
attach more queries to its output without re-reading Kafka.

## Why this is testable without a live Kafka broker

Only `streaming/src/ingestion/kafka_source.py` (a single `readStream`
call) actually needs a broker. Every other stage takes a `DataFrame`
shaped like Kafka's connector output (`value`, `topic`, ... columns) -
tests build that exact shape by hand with `spark.createDataFrame(...)`
and feed it through the real functions, running under a real local Spark
session (`streaming/tests/conftest.py`, `local[2]`, no Docker needed -
only a JVM, which this environment has). This proves the transformation
logic is correct; it does NOT prove Kafka connectivity, checkpoint
recovery under real failure, or throughput at any particular rate - see
`docs/phases.md` for what's explicitly NOT VERIFIED.

## Schema: derived, not duplicated

`schema.py` builds the Spark `StructType` (and the category->topic map)
directly from `docs/event-schema.json` at import time, rather than
hand-copying field names into Spark type declarations a second time.
`tests/test_schema.py` cross-checks the result against
`generator/models/event.py`'s independently-defined Pydantic model and
`CATEGORY_TOPIC`, proving the two sources of truth actually agree rather
than just each being internally consistent.

Two intentional exceptions to "use the natural Spark type": `timestamp`
stays a `StringType` until `normalize_events()` casts it to a real
`TimestampType` (`event_time`) - parsing and event-time interpretation
are different pipeline stages, not one step. `metadata` stays a raw JSON
string (`StringType`), never a Spark `MapType`, because scenario metadata
mixes strings/bools/ints in the same object; rules needing a specific key
parse it narrowly with `get_json_object()` rather than the whole pipeline
paying for an `Any`-typed schema.

## Validation

Spark's `from_json()` enforces field *types* but not field *values* - it
happily parses `"source_port": 99999` as a `Long`. `validation.py` checks
what the schema can't: port ranges, `protocol`/`status`/`event_type` enum
membership, non-negative byte counts, 2-letter country codes, non-empty
hostname. This deliberately mirrors the constraints
`generator/models/event.py`'s Pydantic validators already enforce at
generation time - not redundant, but this pipeline's own defense, since a
message could reach these topics without going through the generator at
all (a hostile or buggy direct producer).

**Real bug found by running this, not by reading Spark's docs**:
`from_json()`'s default `PERMISSIVE` mode does not return a null struct
for malformed/schema-violating JSON - it returns a struct with every
field null. `parsing.py` originally checked only `parsed.isNull()`, which
would have silently treated a malformed message as "valid, all fields
null" rather than routing it to the DLQ. Fixed by additionally checking
whether the required `event_id` came back null (see ADR-15).

## Event-time processing, windows, and watermarking

`normalize_events()` casts the ISO-8601 `timestamp` string to a real
`event_time` `TimestampType` column - every window/watermark operation in
`windows.py` operates on `event_time`, never on Kafka's own message
arrival timestamp, so a batch of events replayed hours later (e.g. after
an outage) still buckets into the windows they actually happened in.

`windows.py` implements the four window sizes the cahier des charges
requires (1 minute / 5 minutes / 15 minutes / 1 hour) as one reusable
function, `windowed_counts(df, event_time_col, group_cols, window_duration,
watermark_delay)`, rather than four copies of near-identical groupBy
logic. `build_multi_window_counts()` returns all four at once, sharing
one watermark. Phase B's detection rules will each call `windowed_counts`
with their own `group_cols` (e.g. brute force: `source_ip`, 5-minute
window) rather than re-implementing windowing themselves.

Watermark delay is configurable (`SPARK_WATERMARK_DELAY_MINUTES`, default
5) via `settings.watermark_delay_interval`. A larger delay tolerates
later-arriving events at the cost of holding more aggregation state in
memory longer; late events beyond the watermark are dropped from that
*specific windowed aggregation* only - never from the DLQ or from
storage.

**Real timing lesson, found by running the streaming-engine test, not by
calculation**: a window is only emitted (in `append` output mode) once
the watermark has advanced past the window's end. An early version of
`test_streaming_query_runs_triggers_and_checkpoints` used a 10-second
watermark with only ~6 seconds of test wall-clock time and got zero rows
back - not because anything was broken, but because nothing had crossed
the watermark yet. Fixed by shortening the watermark/window to 2 seconds
relative to a 9-second test run.

## Checkpointing

Every streaming query gets its own checkpoint subdirectory under
`SPARK_CHECKPOINT_DIR` (default `/data/checkpoints`): `processed_events`,
`dlq_kafka`, `dlq_postgres`. `test_streaming_query_runs_triggers_and_checkpoints`
verifies - on the real filesystem, not from configuration - that a real
streaming query actually writes `offsets/` and `commits/` subdirectories
with real offset files, proving checkpointing genuinely persists state
rather than only appearing to be configured.

## Trigger interval

`SPARK_TRIGGER_INTERVAL_SECONDS` (default 10) controls
`.trigger(processingTime=...)` for every query. Verified for real
(`test_trigger_interval_is_actually_respected`): a 0.2-second trigger
produces measurably more checkpointed micro-batches than a 2-second
trigger over the same wall-clock window, proving the configured value
has a real effect rather than just being present in config.

## Consumer group and starting offsets

`KAFKA_CONSUMER_GROUP` (`kafka.group.id`) and `KAFKA_STARTING_OFFSETS`
(`latest`/`earliest`) are both configurable via `.env.example` and read
by `read_kafka_source()`. `failOnDataLoss` is set to `false` so topic
retention/compaction deleting old data doesn't crash the job - an
explicit choice for a dev/demo system, not a production default (a
production deployment losing data silently is a different risk
trade-off than a local demo crash-looping on startup).

## DLQ routing

Malformed/invalid rows are never dropped. `build_dlq_rows()` wraps the
original payload as JSON-safe text (even when the source wasn't valid
JSON at all - `{"raw": "<original text>"}`) alongside the error reason
and source topic. `main.py` attaches two `foreachBatch` sinks to the same
DLQ `DataFrame`: one writes to the `security-dlq` Kafka topic (the cahier
des charges' literal destination), one inserts into the `dlq_entries`
Postgres table Phase 1's Alembic migration already created - reusing
existing storage instead of a second schema mechanism (ADR-18). Both
sinks are NOT VERIFIED (no live Kafka/Postgres here); the row-construction
logic they both consume (`build_dlq_rows`, `dlq_row_to_postgres_params`)
is fully tested.

## Configuration

`streaming/src/config.py` mirrors `backend/app/core/config.py` and
`generator/config.py`'s pattern - one `pydantic-settings` `Settings`
class, same field names as `.env.example`. One streaming-specific wrinkle
documented in ADR-16: `database_url` (SQLAlchemy-style,
`postgresql+psycopg://`) and `psycopg_dsn` (plain `postgresql://`,
required by `psycopg.connect()` directly) are separate properties -
conflating them was an actual bug caught by a test that calls psycopg's
own DSN parser.

## What is NOT yet true

- No Kafka source has ever read from a live broker.
- No checkpoint has ever recovered from an actual failure (only proven to
  be *written* - recovery is Phase T, Failure Lab).
- No DLQ row has ever reached Kafka or Postgres for real.
- Detection, anomaly detection, correlation, and risk scoring (Phase B-E)
  don't exist yet - `build_pipeline()`'s output (`enriched`) is exactly
  where they attach.
