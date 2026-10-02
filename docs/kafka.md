# Kafka

## Topics

One topic per event `category` (not per `event_type` - see `event.kafka_topic()`
in `generator/models/event.py`, the single routing rule in the project):

| Topic | Category | Populated by |
|---|---|---|
| `security-authentication` | authentication | generator (Phase 3), Spark (Phase 5+) |
| `security-network` | network | generator, Spark |
| `security-endpoint` | endpoint | generator, Spark |
| `security-privilege` | privilege | generator, Spark |
| `security-cloud` | cloud | generator, Spark |
| `security-web` | web | generator, Spark |
| `security-normalized` | - | Spark output (Phase 6) - not yet produced to |
| `security-alerts` | - | Spark output (Phase 7+) - not yet produced to |
| `security-dlq` | - | Spark dead-letter sink (Phase 6+) - not yet produced to |

Created idempotently by `infrastructure/kafka/create_topics.sh`
(`--create --if-not-exists`) via the one-shot `kafka-init` compose service.
**Not verified against a live broker in this environment** - no Docker
here (see `docs/phases.md`). The script itself was reviewed but not run.

## Partition count and retention

Partition count is env-driven (`KAFKA_NUM_PARTITIONS_DEV=3` /
`KAFKA_NUM_PARTITIONS_LOADTEST=12`, see `.env.example`), passed to
`create_topics.sh` as `KAFKA_NUM_PARTITIONS`. Retention is currently a
flat `retention.ms=604800000` (7 days) for every topic in the bootstrap
script - the cahier des charges' per-data-type retention table (§61: raw
7d / processed 30d / alerts 90d / incidents 180d) applies to *stored*
data (Postgres/Parquet), not topic retention, and is not yet implemented
anywhere (Phase 11).

## Partition key: hostname -> username -> source_ip

`SecurityEvent.partition_key()` (see ADR-7 in
`docs/architecture-decisions.md`) tries `hostname` first, falling back to
`username` then `source_ip`. In practice `hostname` is a required,
non-empty field today, so the fallback branches are defensive rather than
commonly exercised - covered directly in
`generator/tests/test_event_contract.py::test_partition_key_falls_back_to_username_then_source_ip`
via `object.__setattr__` since the public API can't construct an event
with an empty hostname.

This keeps every event from one host in the same partition, preserving
per-host ordering - several Phase 7 detections (e.g. `login ->
privilege_escalation` sequences) depend on seeing same-host events in order.

## Producer behavior (`generator/kafka_producer.py`)

- **Client**: real `confluent_kafka.Producer`, not a mock, wrapped in
  `EventProducer`. `producer_factory` is injectable for tests only -
  production code always uses the real client.
- **Acks**: `all` by default (wait for every in-sync replica) -
  configurable via `--acks` / `KAFKA_PRODUCER_ACKS`.
- **Idempotence**: `enable.idempotence: True` is always set, preventing
  duplicate delivery from the producer's own internal retries.
- **Batching**: `linger.ms=20`, `batch.num.messages=500` by default -
  real batching, not one message per request.
- **Compression**: `snappy` by default (good CPU/ratio trade-off for JSON).
- **Delivery callback**: every message's outcome (delivered or failed) is
  recorded in `DeliveryStats` and logged; nothing is silently dropped.
- **Serialization errors**: `event.to_kafka_json()` can raise Pydantic's
  own `PydanticSerializationError` for values it can't convert (not just
  `json.dumps` raising `TypeError`/`ValueError`) - both are caught and
  re-raised as `SerializationError`. Found by actually constructing such
  an event in a test, not by inspection (see `docs/phases.md`).
- **Broker-unavailable handling**: verified for real (not just reasoned
  about) - see `docs/phases.md` "Bugs found" and
  `generator/tests/test_kafka_producer.py::test_real_producer_reports_failure_when_broker_unreachable`,
  which points the real client at a closed local port and confirms
  `flush()` returns 0 undelivered-after-timeout while `stats.failed`
  correctly reflects every message, rather than hanging or silently
  losing messages.
- **librdkafka's own internal logs** (broker connection failures, etc.)
  are routed through Python's `logging` via `Producer(..., logger=...)`,
  so they follow the same structured-JSON-to-stderr convention as
  everything else instead of bypassing it with raw text - this was a real
  bug, found by running `produce` against an unreachable broker and
  inspecting stderr line by line (see `docs/logging.md`).

## CLI: `generate` vs `produce`

Deliberately two commands, not one with a `--publish` flag:

```powershell
python cli.py generate --events 100                      # local NDJSON only, never touches Kafka
python cli.py produce  --events 100 --bootstrap-servers localhost:9092   # publishes to Kafka
```

`generate` writes NDJSON to stdout (or `--output FILE`) and never imports
`kafka_producer`. `produce` never writes event data to stdout - only a
single JSON delivery-summary line at the end - so a broker outage cannot
corrupt a data pipeline that expected clean NDJSON, and a `generate`
pipeline never silently depends on Kafka being up. Both share generation
options (`--events`/`--rate`/`--duration`/`--scenario`/`--attack-ratio`/
`--hosts`/`--users`/`--source-ips`/`--seed`) via `_generation_options` in
`cli.py`, so behavior is identical except for the destination.

## What is NOT yet true

- No event has ever reached a real Kafka broker from this codebase - only
  a real client talking to a deliberately-closed port has been exercised.
- Topic creation has never run against a live broker.
- Consumer-side behavior (Spark reading these topics) doesn't exist yet -
  Phase 5.
