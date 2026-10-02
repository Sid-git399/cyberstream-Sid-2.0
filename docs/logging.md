# Logging convention

All three services (backend, generator, streaming) call
`common.logging_utils.configure_logging(service=..., level=...)` once at
startup. This is copied from `libs/common` into each service's Docker
image (as `./common`) and onto `sys.path` for local/test runs, so all
three share one implementation instead of three that can drift.

## Format

Single-line JSON per record:

```json
{"timestamp": "2026-09-25T23:59:32.873Z", "service": "generator", "level": "INFO",
 "message": "generation complete: written=5 scenario=normal-traffic",
 "correlation_id": "-", "logger": "generator"}
```

Fields, per cahier des charges §75: `timestamp`, `service`, `level`,
`message`, `event_id` (only present when relevant), `correlation_id`.

## Stream: stderr, not stdout

Logs are written to **stderr**. This matters most for the generator CLI,
which can write event data (NDJSON) to **stdout**; if logs also went to
stdout they would interleave with and corrupt that data stream for anyone
piping `generate` output into a file or another process. This was caught
by actually running the CLI end-to-end (see docs/phases.md) - the first
version had this bug.

Docker/Compose capture both stdout and stderr into the same `docker compose
logs` output, so the backend loses nothing by following the same rule.

## Correlation IDs

- **Backend**: `CorrelationIdMiddleware` reads `X-Correlation-ID` from the
  inbound request (or mints a UUID4), sets it via a contextvar for the
  duration of the request, and echoes it back in the response header.
- **Generator / streaming**: not yet wired to a per-run correlation ID.
  Phase 4 (generator) and Phase 5 (streaming) should set one per
  generation run / per micro-batch respectively.

## Third-party libraries that bypass Python logging by default

`confluent-kafka`'s underlying C library, librdkafka, writes its own
internal diagnostics (broker connection state, errors) directly to a raw
stderr file descriptor by default - completely bypassing Python's
`logging` module and this project's JSON formatter. `generator/kafka_producer.py`
passes `logger=<python logger>` to `confluent_kafka.Producer(...)`
specifically to opt into routing those messages through
`common.logging_utils` instead. This was found, not assumed: running
`produce` against a deliberately unreachable broker and checking that
every line of stderr parsed as JSON initially failed until this was
added. Any future code wrapping another C-extension-backed client
(e.g. a Postgres or Spark driver with similar behavior) should check for
the same issue rather than assuming Python's `logging` module is the only
thing writing to stderr.

## What must never be logged

Per cahier des charges §75: passwords, secrets, tokens, credentials. No
current code path logs request/event bodies wholesale, which keeps this
safe by construction rather than by discipline - but future phases adding
raw event logging must not log `metadata` fields verbatim without review.

## Levels

Standard Python levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.
Controlled via the `LOG_LEVEL` env var (see `.env.example`).
