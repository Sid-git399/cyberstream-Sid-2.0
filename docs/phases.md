# Implementation phases

Authoritative progress tracker. Every deliverable is tagged with exactly
one status:

- **IMPLEMENTED** - code exists and is believed correct, but has not been
  executed/tested.
- **VERIFIED LOCALLY** - actually executed in this authoring environment
  (pytest, direct CLI invocation, etc.), without Docker/a live broker/DB.
- **VERIFIED WITH DOCKER** - actually executed against live Kafka/Postgres/
  Spark via `docker compose`. **Nothing in this project currently has this
  status** - Docker is unavailable in this authoring environment (checked:
  `docker: not found`). Anything that sounds like it needs a broker or a
  database is NOT VERIFIED, however confident the code looks.
- **NOT VERIFIED** - implemented but genuinely unproven; needs Docker on
  your machine.
- **NOT STARTED** - no code.

No phase below is marked done unless every one of its listed deliverables
is at least VERIFIED LOCALLY (and explicitly NOT VERIFIED WITH DOCKER
where that matters). A previous status report described this project as
both "Phases 1-3 done" and "Phase 3 is next" in different places - that
was an inconsistency in how progress was communicated, not a change in
what's actually built. This file is the single source of truth going
forward; prose summaries elsewhere must match it.

## Phase 1 - Foundation: DONE

Repo structure, shared `libs/common`, `.env.example`/`.gitignore`,
canonical event schema, backend core (FastAPI + config + middleware +
error handling + SQLAlchemy models + Alembic migration), streaming config,
`docker-compose.yml`, Postgres dev config, Kafka topic bootstrap script.

| Deliverable | Status |
|---|---|
| Repo structure, `.gitignore`, `.env.example` | VERIFIED LOCALLY (inspected) |
| `libs/common` (logging, errors) | VERIFIED LOCALLY (113 tests across 3 services depend on it) |
| `docs/event-schema.json` | VERIFIED LOCALLY (99 generator tests validate against it) |
| Backend: FastAPI app, config, middleware, error handling | VERIFIED LOCALLY (10/10 pytest) |
| Backend: SQLAlchemy models (6 tables) | VERIFIED LOCALLY, dialect-level DDL compile only - NOT VERIFIED against live Postgres |
| Alembic migration `0001_initial_schema` | IMPLEMENTED - imports cleanly; NOT VERIFIED (never run against live Postgres) |
| Streaming: config only | VERIFIED LOCALLY (4/4 pytest) |
| `docker-compose.yml`, Kafka topic bootstrap script | IMPLEMENTED - NOT VERIFIED (no Docker here) |

## Phase 2/3 - Generator + Kafka integration layer: DONE (this delivery)

This merges what earlier notes called "Phase 2" (generator) and "Phase 3"
(Kafka wiring) into one phase, matching the actual unit of work requested:
generator -> SecurityEvent -> Kafka producer -> topics -> partition key.
**Spark has not been started - see Phase 5.**

| Deliverable | Status |
|---|---|
| `SecurityEvent.kafka_topic()` (category -> topic routing) | VERIFIED LOCALLY (6 parametrized cases) |
| `SecurityEvent.partition_key()` (hostname -> username -> source_ip) | VERIFIED LOCALLY |
| Normal-traffic scenario (auth/network/endpoint/web+cloud mix) | VERIFIED LOCALLY |
| 9 attack scenarios (brute-force, password-spraying, port-scan, privilege-escalation, suspicious-process, data-transfer-spike, dns-anomaly, multi-stage, alert-storm) | VERIFIED LOCALLY, all 9 individually tested for shape, determinism, schema validity |
| Attack-ratio mixing (`generate_mixed`) | VERIFIED LOCALLY |
| `--events`/`--rate`/`--duration`/`--hosts`/`--users`/`--source-ips`/`--seed` CLI options | VERIFIED LOCALLY |
| Real Kafka producer (`kafka_producer.py`, confluent-kafka) | VERIFIED LOCALLY against a real client + deliberately unreachable broker; NOT VERIFIED against a live Kafka broker |
| `cli.py generate` (local NDJSON, never touches Kafka) | VERIFIED LOCALLY |
| `cli.py produce` (publishes to Kafka) | VERIFIED LOCALLY that it correctly reports failure when no broker is reachable; NOT VERIFIED that it can successfully deliver to a real broker |
| Kafka topic bootstrap / topic creation | NOT VERIFIED (no Docker) |
| Message actually received by a live Kafka broker | NOT VERIFIED - **no broker has ever run in this environment** |

**Total tests executed and passing in this environment: 113**
(99 generator + 10 backend + 4 streaming). See "Test breakdown" below.

## Phase A - Spark Structured Streaming: DONE

Kafka -> parse -> validate -> normalize -> enrich -> window/watermark,
with DLQ routing for anything invalid. Schema derived from
`docs/event-schema.json` (not duplicated). See `docs/spark.md` for the
full pipeline description.

| Deliverable | Status |
|---|---|
| Spark `StructType` derived from `docs/event-schema.json` | VERIFIED LOCALLY - cross-checked against generator's Pydantic model, both agree |
| JSON parsing (`parsing.py`) | VERIFIED LOCALLY, including the PERMISSIVE-mode bug fix (ADR-15) |
| Business-rule validation (`validation.py`) | VERIFIED LOCALLY (port ranges, enums, byte counts, country code, hostname) |
| Normalization - event-time casting (`normalization.py`) | VERIFIED LOCALLY |
| Enrichment - internal IP, privileged user, known service port, environment (`enrichment.py`) | VERIFIED LOCALLY |
| Windowing - 1m/5m/15m/1h with watermark (`windows.py`) | VERIFIED LOCALLY in batch mode (bucketing correctness) |
| Watermark/trigger/checkpoint mechanics | VERIFIED LOCALLY - a REAL streaming query (Spark's `rate` source, no Kafka needed) actually run for real wall-clock seconds, actually checkpointed to a real filesystem path, actually produced windowed output via a memory sink |
| DLQ row construction (`dlq.py`) | VERIFIED LOCALLY (payload wrapping, Postgres param construction) |
| Kafka source (`ingestion/kafka_source.py`) | IMPLEMENTED - reviewed only, NOT VERIFIED (no live broker) |
| DLQ Kafka sink (`write_dlq_batch_to_kafka`) | IMPLEMENTED - NOT VERIFIED |
| DLQ Postgres sink (`write_dlq_batch_to_postgres`) | IMPLEMENTED - NOT VERIFIED |
| Parquet sink, partitioned by year/month/day | IMPLEMENTED in `main.py` - NOT VERIFIED (never run against live Kafka input) |
| `spark` service added to `docker-compose.yml` | IMPLEMENTED - NOT VERIFIED (no Docker here) |
| Configurable consumer group / starting offsets / trigger interval / checkpoint dir | VERIFIED LOCALLY (config tests) + trigger interval's real effect VERIFIED LOCALLY via the streaming-engine test |

**This environment has real Java 21 + PySpark 3.5.3 and can run actual
local Spark** (`local[2]`) - unlike Kafka/Postgres/Docker, Spark itself
needed no broker, container, or database to execute for real. This is
why Phase A has substantially more "VERIFIED LOCALLY" (as opposed to
"IMPLEMENTED only") coverage than Phase 1/2-3's Kafka-dependent pieces:
the transformation logic genuinely ran under Spark's real distributed
execution engine, just without a live Kafka *source* feeding it.

**47/47 streaming tests passing** (up from 4 in Phase 1's config-only
delivery). Total across the whole project: **156 tests passing**
(99 generator + 10 backend + 47 streaming).

## Phase 5 - Spark Structured Streaming: MERGED INTO PHASE A ABOVE

## Phase 6 - Normalization & enrichment: MERGED INTO PHASE A ABOVE

## Phase B - Security Detection Engine: DONE

```text
Phase B
IMPLEMENTED: yes
LOCALLY VERIFIED: yes (72/72 new tests, real Spark, including a real
    generator-scenario-to-detection integration test)
DOCKER VERIFIED: no - no Docker in this environment
END-TO-END VERIFIED: no - no live Kafka/Postgres, no running main.py
```

Eight rules (`streaming/src/detection/rules/`), a `DetectionRule`
abstract base, YAML-driven strictly-validated config
(`infrastructure/spark/detection_rules.yaml` +
`streaming/src/detection/config.py`), and an engine
(`streaming/src/detection/engine.py`) that unions every enabled rule's
output into one stable detection schema. Wired additively into
`streaming/src/main.py` (Phase A's `build_pipeline()` untouched). Full
detail: `docs/detection-engine.md`.

| Deliverable | Status |
|---|---|
| `DetectionRule` abstract base + windowed/row-level finalize helpers | VERIFIED LOCALLY |
| 8 rules (brute force, password spraying, port scan, suspicious auth, privilege escalation, suspicious process, large data transfer, DNS anomaly) | VERIFIED LOCALLY - each with positive/negative/boundary/disabled/null-field tests |
| YAML config + strict Pydantic validation | VERIFIED LOCALLY (11 tests: defaults, real file, typo rejection, invalid severity/risk_points, explicit-vs-auto-discovery path handling) |
| Detection engine (union, disabled-rule handling, determinism) | VERIFIED LOCALLY (7 tests) |
| Full Phase A -> Phase B integration (real generator scenarios through real parse/validate/normalize/enrich/detect) | VERIFIED LOCALLY (3 tests) - this is what found the window-boundary bug below |
| `main.py` detections sink (Parquet, checkpointed) | IMPLEMENTED - NOT VERIFIED (no live Kafka to feed it) |
| Phase A regression (47 tests) | VERIFIED LOCALLY - re-ran clean, all still pass, confirming the one additive `windows.py` function and two new `config.py`/`main.py` fields didn't break anything existing |

**Total streaming tests: 119/119 passing** (47 Phase A + 72 Phase B).
Combined with generator (99) and backend (10): **228 tests passing
project-wide**.

### Bugs found by actually running things (Phase B)

1. **Pydantic subclass field overrides silently drop the parent's
   `Field(pattern=..., ge=..., le=...)` constraints.** Every rule config
   subclass that overrode `severity`/`risk_points` with a bare
   `severity: str = "HIGH"` lost the base class's validation entirely -
   `DetectionEngineConfig(brute_force={"severity": "SUPER_HIGH"})` and
   `{"risk_points": 150}` both silently succeeded instead of raising.
   Found by the validation tests actually failing, not by code review.
   Fixed by redeclaring the full `Field(...)` constraint in every
   subclass override.
2. **An explicit-but-missing config path silently fell back to
   defaults**, which is more dangerous than failing loudly (masks a
   deployment typo). Fixed: an explicit `path` argument that doesn't
   exist now raises `DetectionConfigError`; only auto-discovery (no path
   given) falls back quietly. Caught by writing a test for the
   old (wrong) behavior and getting a real `FileNotFoundError` instead of
   the expected graceful default.
3. **`spark.createDataFrame()` cannot infer a schema when a column is
   `None` in every row of the batch** (`PySparkValueError:
   CANNOT_DETERMINE_TYPE`) - exactly what single-row "missing field"
   tests do by construction (e.g. "missing hostname"). Fixed by giving
   the test fixture (`tests/detection/conftest.py`) an explicit
   `StructType` instead of relying on inference.
4. **Tumbling windows can split a real burst across a boundary and miss
   it entirely** - not a code bug but a genuine, now-documented detection
   gap (see `docs/detection-engine.md` limitation #1). Found when the
   full-chain integration test became flaky: `generate_brute_force`
   defaulted to `datetime.now()`, and roughly 1-in-N runs happened to
   straddle a 5-minute window boundary, splitting 15 failed attempts into
   two sub-threshold halves and missing the detection entirely. Fixed the
   test (pin `start_time` explicitly - tests must not depend on wall-
   clock timing) and added a dedicated test
   (`test_brute_force_events_spanning_a_window_boundary_can_be_missed`)
   that proves and documents the gap on purpose, rather than leaving it
   as an intermittent test failure nobody understood.

### What remains explicitly unverified (Phase B)

- `main.py`'s new detections Parquet sink - implemented, reviewed,
  import-checked, never run (no live Kafka source to feed it).
- Whether the detection engine performs acceptably at any real volume -
  `collect_list`/`collect_set` state cost is a documented concern
  (`docs/detection-engine.md` limitation #4), not measured.
- Everything downstream: anomaly detection (Phase C), correlation
  (Phase D), risk scoring (Phase E), MITRE mapping (Phase F), the Alert
  Engine (Phase G), and all phases after that - none of this exists yet.

## Phase 7 - Detection engine + remaining FastAPI endpoints: DETECTION ENGINE MOVED TO PHASE B ABOVE; REMAINING FASTAPI ENDPOINTS NOT STARTED
## Phase 8 - Anomaly detection: NOT STARTED
## Phase 9 - Correlation engine: NOT STARTED
## Phase 10 - Risk scoring & incident creation: NOT STARTED
## Phase 11 - Parquet storage: PARTIALLY IMPLEMENTED (Phase A writes a Parquet sink; full retention/lifecycle policy not yet built)
## Phase 12 - Remaining FastAPI (pagination, filtering, threat hunting): NOT STARTED
## Phase 13 - React SOC console: NOT STARTED (`frontend/` intentionally empty)
## Phase 14 - Observability: NOT STARTED
## Phase 15 - Load Lab & benchmarking: NOT STARTED
## Phase 16 - Failure Lab & recovery: NOT STARTED
## Phase 17 - Testing beyond current coverage: ongoing, folded into each phase
## Phase 18 - Remaining documentation: ongoing (`event-schema.json`, `logging.md`,
      `architecture-decisions.md`, `kafka.md`, `spark.md` exist;
      `architecture.md`, `streaming.md`, `detection-engine.md`,
      `anomaly-detection.md`, `correlation.md`, `scalability.md`,
      `benchmarking.md`, `security.md`, `troubleshooting.md`,
      `deployment.md` do not yet)
## Phase 19 - End-to-end validation: NOT STARTED

## Test breakdown (cumulative)

| Service | File | Tests |
|---|---|---|
| generator | test_event_contract.py | 18 |
| generator | test_scenarios.py | 56 |
| generator | test_kafka_producer.py | 11 |
| generator | test_cli.py | 11 |
| generator | test_config.py | 3 |
| **generator total** | | **99** |
| backend | test_health.py + test_models.py | 10 |
| streaming | test_schema.py | 8 |
| streaming | test_config.py | 7 |
| streaming | test_pipeline.py | 26 |
| streaming | test_windows.py | 4 |
| streaming | test_streaming_engine.py | 2 (real live streaming queries) |
| **streaming (Phase A) subtotal** | | **47** |
| streaming | detection/test_config.py | 11 |
| streaming | detection/test_engine.py | 7 |
| streaming | detection/test_pipeline_integration.py | 3 (real generator scenarios, full chain) |
| streaming | detection/test_rules_authentication.py | 26 |
| streaming | detection/test_rules_endpoint.py | 7 |
| streaming | detection/test_rules_network.py | 18 |
| **streaming (Phase B) subtotal** | | **72** |
| **streaming total** | | **119** |
| **grand total** | | **228, all passing** |

(Streaming grew from 4 tests, config-only, in Phase 1, to 47 covering the
full pipeline in Phase A, to 119 with Phase B's detection engine added.
Every count above was obtained by running `pytest -v` and counting
`PASSED` lines per file, not by arithmetic alone - see the Phase B report
for the exact command.)

## Bugs found and fixed by actually running things (Phase A)

1. **Spark's `from_json` PERMISSIVE mode returns an all-null struct for
   malformed JSON, not a null struct.** `parsing.py`'s first version
   checked only `parsed.isNull()`, which would have silently classified
   every malformed message as "successfully parsed, all fields null"
   instead of routing it to the DLQ. Found by actually running malformed
   JSON through the function. Fixed by also checking whether the
   required `event_id` field came back null (ADR-15).
2. **A 10-second watermark cannot emit anything in a 6-second test.** The
   first version of the real streaming-engine smoke test used a window/
   watermark duration that never let the watermark advance past a
   window's end within the test's wall-clock budget, so it asserted on an
   empty result and looked broken. Not a pipeline bug - a test-timing bug,
   found only by actually running the streaming query and getting zero
   rows back. Fixed by shortening the watermark/window to 2 seconds
   against a 9-second run (ADR-15's sibling lesson in `docs/spark.md`).
3. **`psycopg.connect()` cannot parse `database_url`'s SQLAlchemy-style
   `postgresql+psycopg://` scheme.** Found by writing a test that calls
   `psycopg.conninfo.conninfo_to_dict()` directly against it, not by
   inspection. Fixed by adding a separate `psycopg_dsn` property with the
   plain `postgresql://` scheme for `dlq.py`'s direct `psycopg.connect()`
   call (ADR-16).

(Phase 1's three bugs and Phase 2/3's three bugs are unchanged and still
fixed - not repeated here, see prior reports / git history.)

## What remains explicitly unverified

- Phase 1's NOT VERIFIED items (Alembic against live Postgres, Kafka
  topic bootstrap, `docker-compose.yml` build/up).
- Phase 2/3's NOT VERIFIED items (Kafka producer against a live broker).
- Phase A's Kafka source, both DLQ sinks, and the Parquet sink - all
  reviewed, none executed against live infrastructure.
- Checkpoint *recovery* specifically (as opposed to checkpoint *writing*,
  which IS verified) - recovering from an actual failure is Phase T
  (Failure Lab), not yet started.
- Phase B's detections Parquet sink in `main.py` - implemented, never run
  (no live Kafka source to feed it). Detection logic itself IS verified,
  extensively, in batch mode with both hand-built and real generator data.
- Everything from Phase C onward: anomaly detection, correlation, risk
  scoring, MITRE mapping, alerts, the rest of the API, the entire
  frontend, observability, load testing, benchmarking, and the final
  end-to-end demonstration. None of this exists yet.
