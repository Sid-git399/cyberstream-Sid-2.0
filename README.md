# CyberStream

A distributed Big Data cybersecurity analytics platform: synthetic security
telemetry flows through Kafka, is processed by Spark Structured Streaming
(detection, correlation, anomaly detection, risk scoring), stored in
PostgreSQL + Parquet, and served to a React SOC console via FastAPI.

No mocked Kafka, Spark, or metrics - real components throughout, run
locally via Docker Compose.

## Build status

**`docs/phases.md` is the authoritative progress tracker** - it uses a
5-state taxonomy (IMPLEMENTED / VERIFIED LOCALLY / VERIFIED WITH DOCKER /
NOT VERIFIED / NOT STARTED) precisely so "the code exists" and "the code
has been proven to work" are never conflated. Read it before trusting any
summary here or elsewhere.

**Current milestone: the Security Detection Engine (Phase B) - 8 rules
(brute force, password spraying, port scan, suspicious authentication,
privilege escalation, suspicious process, large data transfer, DNS
anomaly) consuming Phase A's enriched stream.** Anomaly detection,
correlation, and risk scoring do not exist yet.

**228 tests passing** in this environment (99 generator + 10 backend +
119 streaming: 47 Phase A + 72 Phase B) - see `docs/phases.md` for the
full breakdown, including **two real live Spark Structured Streaming
queries** and a **full-chain integration test that feeds the real
generator's brute-force scenario through real parsing, validation,
normalization, enrichment, and detection** and gets a real detection
back. **Zero tests against a live Kafka broker or Postgres instance** -
this authoring environment has no Docker daemon (`docker: not found`),
so anything needing a live broker/DB is explicitly NOT VERIFIED.

## What's real right now

- **Generator**: `SecurityEvent` model with real Kafka topic routing and
  partition-key selection. Ten scenarios (normal traffic + 9 attack
  simulations), all synthetic telemetry. `--attack-ratio` blending.
- **Kafka producer**: real `confluent-kafka` `Producer`, verified to
  correctly report failure against a deliberately unreachable broker.
- **CLI**: `generate` (local NDJSON) and `produce` (Kafka) as separate commands.
- **Backend**: FastAPI + SQLAlchemy models + Alembic migration.
- **Spark Structured Streaming** (`streaming/src/`): schema derivation
  from `docs/event-schema.json`, JSON parsing, business-rule validation,
  event-time normalization, enrichment, 1m/5m/15m/1h windowing with
  watermarking, DLQ routing. See `docs/spark.md`.
- **Detection engine** (`streaming/src/detection/`): 8 independently
  configurable/testable rules behind a `DetectionRule` abstract base,
  YAML-driven thresholds (`infrastructure/spark/detection_rules.yaml`,
  strictly validated), deterministic detection IDs, a stable output
  schema with full evidence and traceable `event_ids`. See
  `docs/detection-engine.md` - including a real, documented limitation
  (tumbling windows can miss a boundary-straddling burst) found by a test
  becoming flaky, not by design review.

## Run what's real right now (no Docker required)

```bash
cd generator
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest tests/ -v                           # 99 tests
python cli.py generate --events 20 --scenario brute-force --seed 1
python cli.py produce --events 10 --bootstrap-servers localhost:9092   # fails honestly without a broker

cd ../backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/ -v      # 10 tests
uvicorn app.main:app --reload

cd ../streaming
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # needs a JDK on PATH for PySpark - this env has OpenJDK 21
python -m pytest tests/ -v      # 119 tests: 47 Phase A + 72 Phase B (detection engine)
```

## Windows PowerShell: full validation sequence

**None of this has been run in this authoring environment - no Docker
daemon exists here.** Please run it and report back what you see.

```powershell
# 1. Environment
copy .env.example .env

# 2. Validate compose config parses correctly
docker compose config

# 3. Build every image
docker compose build

# 4. Apply the database schema (Alembic - see ADR-2)
docker compose run --rm migrate

# 5. Start infrastructure
docker compose up -d kafka kafka-init postgres backend spark
docker compose ps

# 6. Inspect service health
docker compose logs kafka
docker compose logs kafka-init
docker compose logs postgres
docker compose logs spark
curl http://localhost:8000/health
curl http://localhost:8000/api/health

# 7. Inspect Kafka topics (should list all 9 from docs/kafka.md)
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:29092 --list

# 8. Run the generator inside the network, writing locally first
docker compose run --rm generator generate --events 100 --scenario multi-stage

# 9. Publish events to the real broker
docker compose run --rm generator produce --events 500 --scenario brute-force --bootstrap-servers kafka:29092

# 10. Inspect messages actually on the topic (proves real delivery, not just a 0-exit-code)
docker compose exec kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:29092 --topic security-authentication --from-beginning --max-messages 5

# 10b. Check Spark actually consumed and wrote something
docker compose logs spark --tail 50
docker compose exec spark ls -la /data/checkpoints
docker compose exec spark ls -la /data/parquet/processed

# 11. Stop the generator (it's a one-shot `run`, nothing to stop unless you used `up`)
docker compose stop generator

# 12. Stop everything
docker compose down
```

Please report: whether step 3 built all images cleanly (including
`spark`, which builds from `bitnami/spark:3.5.3`), whether step 5 shows
`kafka`/`postgres`/`backend`/`spark` healthy or running and
`kafka-init`/`migrate` exited 0, whether step 9's JSON summary shows
`"failed": 0`, whether step 10 actually printed 5 real messages, and
whether step 10b shows checkpoint subdirectories and at least one Parquet
file under `/data/parquet/processed`. Only that would move Kafka and
Spark to VERIFIED WITH DOCKER in `docs/phases.md` - I won't claim it otherwise.

## Repository structure

```
cyberstream/
├── libs/common/     Shared logging + error conventions (all 3 services)
├── backend/          FastAPI + SQLAlchemy models + Alembic migrations
├── streaming/         Spark Structured Streaming pipeline (schema through DLQ)
├── generator/         Event model, 10 scenarios, Kafka producer, CLI
├── frontend/          Empty - Phase 13
├── infrastructure/    Kafka topic bootstrap, Postgres dev config
├── data/              raw / processed / parquet / dlq (gitignored, .gitkeep only)
├── docs/              event schema, logging, ADRs, Kafka + Spark design, phase tracker
└── docker-compose.yml
```

## Configuration

Copy `.env.example` to `.env`. Never commit `.env`. Every variable is read
by name from `backend/app/core/config.py`, `generator/config.py`, and
`streaming/src/config.py` - kept in sync deliberately (ADR-3); update all
three plus `.env.example` plus `docker-compose.yml` together.

## Documentation

- `docs/event-schema.json` - canonical event schema
- `docs/kafka.md` - topics, partitioning, retention, producer design, CLI split
- `docs/spark.md` - Structured Streaming pipeline, what's verified vs. not
- `docs/detection-engine.md` - 8 detection rules, config, evidence model, known limitations
- `docs/logging.md` - structured logging convention, real bugs it caught
- `docs/architecture-decisions.md` - ADRs future phases must preserve (22 so far)
- `docs/phases.md` - authoritative phase-by-phase status
