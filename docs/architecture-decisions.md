# Architecture decisions - Phase 1

Decisions future phases must preserve (or explicitly revisit, not silently
break).

## ADR-1: Kafka runs in KRaft mode, no Zookeeper

`apache/kafka:3.8.0` supports KRaft (combined broker+controller) natively.
Zookeeper is legacy as of Kafka 4.0 and adds a whole extra service to run
on a "normal development laptop" (cahier des charges §6) for no benefit
here. `CLUSTER_ID` is a fixed dev value - fine for local dev, would need
to be generated properly (`kafka-storage.sh random-uuid`) for anything
resembling production.

## ADR-2: Alembic is the single source of truth for the Postgres schema

Earlier draft of this phase had both a raw `init.sql` (run via
`docker-entrypoint-initdb.d`) *and* SQLAlchemy models - two descriptions
of the same schema that would inevitably drift. Alembic migrations
(`backend/alembic/versions/`) are now the only schema definition; a
`migrate` one-shot compose service runs `alembic upgrade head` before
`backend` starts. Consequence: **the schema does not exist until you run
Docker** - there is no "quick start without migrations" path, by design.

## ADR-3: `libs/common` is a plain, dependency-free shared package

Backend, generator, and streaming are three separately-built Docker
images, but all three need the same logging and error-handling
convention. Rather than three copies (which drift) or a versioned/published
package (overkill for one repo), `libs/common` is copied verbatim into
each image's build context (`COPY libs/common ./common`) and each
service's Docker build context is the **repo root**, not the service
subdirectory - see every `Dockerfile` and the `context: .` entries in
`docker-compose.yml`. Local (non-Docker) test runs add `../libs` to
`sys.path` via each service's `pytest.ini`.

## ADR-4: Logs to stderr, data to stdout

See `docs/logging.md`. Found by actually running the generator CLI and
observing corrupted NDJSON output - not a hypothetical concern.

## ADR-5: Postgres array columns use native `ARRAY`, not JSON

`incidents.hosts/users/source_ips/mitre_techniques` use
`postgresql.ARRAY(String)` rather than a JSON list, so future phases can
use Postgres's native array operators (`@>`, `&&`) for incident queries
("find incidents touching this host"). Trade-off: these columns are
Postgres-specific (already true of `JSONB` elsewhere in this schema, so
this doesn't introduce a new constraint) and cannot be verified against
SQLite in tests - verification is dialect-level DDL compilation only (see
`backend/tests/test_models.py` and the Phase 1 report), not a live
`CREATE TABLE`.

## ADR-6: Frontend is not in `docker-compose.yml` yet (Spark was added in Phase A)

Per explicit instruction: don't build the frontend first, don't ship
placeholder implementations. A `frontend` compose service pointing at a
Dockerfile with no real app behind it would be exactly that -
`frontend/` stays an empty, tracked directory until Phase 13.

This ADR originally also covered `spark`, deferred at the time because
`streaming/` had only `config.py`. Phase A (see `docs/phases.md`) wrote
the real pipeline (`schema.py` through `main.py`) and 47 passing tests
against it, so the `spark` service was added to `docker-compose.yml` at
that point, per this ADR's own rule: wire in a service alongside the
code that makes it real, not before. Its Kafka *source* and both DLQ
sinks remain NOT VERIFIED (no live broker/DB in this environment) - see
`docs/phases.md` for exactly what is and isn't proven.

## ADR-7: Kafka partition key defaults to `hostname`

`SecurityEvent.partition_key()` defaults to `hostname` (cahier des
charges §12 lists hostname/username/source_ip as candidates). Hostname
keeps all events from one host in the same partition, preserving
per-host ordering, which several Phase 7 detections (sequences like
`login → privilege change` on the same host) will depend on. Documented
here so Phase 3 (Kafka producer wiring) doesn't pick a different key
without a reason.

## ADR-8: Routing lives on SecurityEvent itself, not in the producer

`kafka_topic()` and `partition_key()` are methods on `SecurityEvent`
(`generator/models/event.py`), not logic inside `kafka_producer.py` or the
CLI. This is the *only* routing rule in the project - the producer just
calls `event.kafka_topic()` / `event.partition_key()` and must never grow
a second, parallel routing scheme (e.g. routing by scenario name, or by a
CLI flag). When Spark and the backend eventually need the same routing
(e.g. to know which topic a given event type came from), they import the
same model rather than re-implementing the mapping.

## ADR-9: `generate` and `produce` are separate CLI commands

Considered a single `generate --publish-to-kafka` flag instead. Rejected:
a boolean flag buried among a dozen other options is easy to miss, and
the two modes have fundamentally different failure semantics (`generate`
cannot fail past a bad `--output` path; `produce` can fail per-message
against a broker). Two verbs make the distinction impossible to miss at
the call site, and let `produce`-specific options (`--bootstrap-servers`,
`--acks`, `--compression`, ...) be added without cluttering `generate`.

## ADR-10: `--attack-ratio` mixes by generating both and merging by timestamp

`generate_mixed()` (`generator/scenarios/__init__.py`) generates
`round(count * attack_ratio)` events from the chosen attack scenario and
`count - that` from `normal-traffic`, then sorts the combined list by
timestamp. Alternative designs considered: interleaving attack events
into an existing normal-traffic stream at fixed intervals (rejected -
less naturally random) or having every scenario accept a `background_noise`
parameter (rejected - would duplicate normal-traffic's logic into every
attack scenario). The chosen approach keeps every scenario generator
single-purpose and puts all mixing logic in one place.

## ADR-11: `multi-stage` composes other scenario generators rather than duplicating their logic

`generate_multi_stage()` calls `generate_brute_force()`,
`generate_suspicious_process()`, and `generate_data_transfer_spike()`
directly (with a shared host/user/attacker IP) and relabels their
metadata, rather than re-implementing "a few failed logins then a
success" etc. from scratch. Consequence: a bug fix or behavior change in
any of those three scenarios automatically propagates into multi-stage
incidents too - this is intentional, not a coupling risk to avoid.

## ADR-12: librdkafka's own logs are routed through Python logging

`confluent_kafka.Producer` is constructed with `logger=<python logger>`
so that librdkafka's internal diagnostics (broker connection failures,
etc.) go through `common.logging_utils`'s JSON formatter on stderr, like
every other log line in the project, instead of librdkafka printing raw
text directly to the stderr file descriptor. Found necessary by actually
running `produce` against an unreachable broker and inspecting stderr
line-by-line (see `docs/phases.md`).

## ADR-13: Normalization does not re-derive `category` from `event_type`

`normalize_events()` (`streaming/src/normalization.py`) trusts the
`category` field as parsed, rather than recomputing it from `event_type`
via a second copy of `EVENT_TYPE_CATEGORY` (which lives in
`generator/models/event.py` and is enforced there at generation time via
Pydantic's `model_post_init`). Duplicating that mapping in Spark would be
exactly the "second copy of the same business rule" the cahier des
charges warns against. This is a documented trust boundary: a hostile or
buggy producer writing directly to Kafka (bypassing the generator
entirely) could send a mismatched category/event_type pair and it would
pass through uncaught. Accepted for now; revisit if Phase B's detection
rules turn out to need category to be authoritative rather than
producer-supplied.

## ADR-14: Enrichment's service-port lookup is independent from the generator's port tables

`streaming/src/enrichment.py`'s `_KNOWN_SERVICE_PORTS` dict is a separate,
smaller table from the port lists in `generator/scenarios/*.py` (e.g.
`port_scan.py`'s `_COMMON_PORTS`). These answer different questions -
"what port does this scenario plausibly emit" vs. "what service name
should an analyst see for this port" - so a shared table would couple two
things that change for different reasons. Deliberate small duplication of
the well-known port->service mapping, not an oversight.

## ADR-15: Spark's `from_json` is PERMISSIVE by default - required checking `event_id`, not just struct-nullness

Discovered by actually running malformed JSON through `parse_raw_events`
and inspecting the result, not by reading Spark's docs: `from_json()`'s
default `PERMISSIVE` mode does NOT return a null struct for malformed or
schema-violating JSON - it returns a struct with every field null. Code
that only checked `parsed.isNull()` would have silently treated every
malformed message as "valid, all-null fields" instead of routing it to
DLQ. Fixed by additionally checking whether the required `event_id`
field came back null. `docs/phases.md` records this as a bug found by
execution, not by review.

## ADR-16: `psycopg_dsn` is a separate property from `database_url`

`streaming/src/config.py`'s `database_url` uses the
`postgresql+psycopg://` scheme SQLAlchemy expects (matching
`backend/app/core/config.py` for consistency); `psycopg.connect()` cannot
parse that `+psycopg` dialect suffix and raises on it. Found by writing a
test that calls `psycopg.conninfo.conninfo_to_dict()` directly, not by
inspection. Rather than stripping the suffix at every call site, a second
property (`psycopg_dsn`, plain `postgresql://`) exists specifically for
`dlq.py`'s `psycopg.connect()` call. SQLAlchemy-facing code (if streaming
ever needs it) should keep using `database_url`.

## ADR-17: The Kafka connector is toggled off for most tests

`build_spark_session(settings, include_kafka_connector=True)` accepts a
flag to skip adding the `spark-sql-kafka` Maven coordinate, because
adding it triggers a Maven Central download the first time a session is
built - undesirable (slow, and would fail outright) in a network-
restricted test environment, and irrelevant for tests that never touch
Kafka. Production (`main.py`) always uses the default. The shared
`spark` fixture in `streaming/tests/conftest.py` builds a plain session
without the connector, since every current test drives the pipeline with
hand-built DataFrames rather than a real Kafka source.

## ADR-18: DLQ writes to both Kafka (`security-dlq`) and Postgres (`dlq_entries`), from the same rows

`build_dlq_rows()` produces one DataFrame; `main.py` attaches two
`foreachBatch` sinks to it - one to the `security-dlq` Kafka topic (the
cahier des charges' literal destination), one to the `dlq_entries`
Postgres table Phase 1's Alembic migration already created. This
reuses existing infrastructure instead of inventing a second
schema-management mechanism (per the cahier des charges' explicit
instruction), while still giving the eventual API/UI (Phase J/L) a
queryable table rather than requiring it to consume a Kafka topic itself.

## ADR-19: `DetectionRule` is a class hierarchy, not a function registry

Every other Phase A/B transformation (`parsing.py`, `validation.py`,
`normalization.py`, `enrichment.py`, the generator's scenario functions)
is a plain function, deliberately. Detection rules are the one exception:
`DetectionRule` is an abstract base class with `BruteForceRule`,
`PortScanRule`, etc. as subclasses (`streaming/src/detection/rules/`).
This was an explicit instruction, not a stylistic drift - and it earns
its keep here specifically because every rule needs the *same* nontrivial
shared behavior (disabled-rule short-circuiting, deterministic
detection-ID construction, the windowed-vs-row-level output finalization)
that would otherwise be copy-pasted eight times as free functions. The
rule registry (`detection/rules/__init__.py::ALL_RULES`) still follows
the project's established dict-registry pattern (mirrors
`generator/scenarios/__init__.py::SCENARIOS`), mapping config keys to
classes rather than instances, so `engine.py` controls instantiation.

## ADR-20: Windowed rules use a new `windowed_aggregate()`, not the existing `windowed_counts()`

`windows.py`'s `windowed_counts()` (Phase A) returns only a count - brute
force, password spraying, port scan, and DNS anomaly all need richer
per-window aggregates (`collect_list(event_id)` for evidence,
`countDistinct(...)` for password spraying/port scan). Rather than
changing `windowed_counts()`'s signature (which Phase A's own tests
exercise and which the instruction explicitly said not to rewrite),
`windowed_aggregate()` was added as a new, more general function in the
same module, accepting an arbitrary `{output_name: aggregate_expression}`
dict. `windowed_counts()` could be reimplemented in terms of it, but
wasn't - that refactor isn't needed and would be exactly the kind of
"unnecessary refactor" avoided here.

## ADR-21: Suspicious Authentication and Port Scan deliberately don't trust a scenario's own "this is an attack" label

`generator/scenarios/port_scan.py` tags its events
`metadata.scenario == "port-scan"`, but `PortScanRule` never reads that
field - it detects the actual behavioral pattern (many distinct
destination ports from one source) against the `category == "network"`
population generally. The one deliberate exception is
`SuspiciousProcessRule`, which *does* read a metadata marker
(`metadata.suspicious`), because no behavioral signal is available in
this schema to distinguish a suspicious process spawn from a normal one
without it - documented explicitly as a limitation (`docs/detection-engine.md`,
limitation #2) rather than presented as equivalent to the other rules'
approach.

## ADR-22: Tumbling windows are kept as-is for Phase B; the boundary-miss gap is documented, not patched around

Discovering that a burst straddling a tumbling-window boundary can be
missed entirely (`docs/detection-engine.md` limitation #1) raised an
obvious question: should Phase B switch to sliding windows, or add a
grace-period merge step? Neither was done. Sliding windows cost real
additional state/compute for every rule, not just brute force, and the
cahier des charges doesn't specify sliding windows for Phase A/B. Given
the explicit instruction not to rewrite Phase A's windowing and to keep
Phase B scoped, this is recorded as a known, tested, documented
limitation for a future phase to address (e.g. Phase C's statistical
baselines may be a more natural place to catch slow/split bursts than a
windowing change here) rather than an undocumented scope expansion now.
