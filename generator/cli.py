"""
CyberStream synthetic event generator CLI.

Two commands, deliberately kept separate rather than one command with a
"publish to Kafka?" flag, so the intent at the call site is unambiguous:

    generate   -> local output only (stdout NDJSON or --output file).
                  Never touches Kafka. Safe to pipe.
    produce    -> publishes to Kafka via the real confluent-kafka producer
                  (kafka_producer.py). Never writes event data to stdout;
                  prints one JSON delivery summary line at the end instead.

Both share the same scenario/count/pacing resolution logic (see
_resolve_generation_args) so `generate --scenario X ...` and
`produce --scenario X ...` behave identically except for the destination.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

# Must run before any local import that transitively imports `common`
# (exceptions.py and kafka_producer.py both do). Resolved from this file's
# own location, not cwd, so `python cli.py` works regardless of the
# caller's working directory. Inside Docker, libs/common is copied to
# ./common instead, so this path simply won't exist there and the insert
# is a harmless no-op.
_LIBS_DIR = Path(__file__).resolve().parent.parent / "libs"
if _LIBS_DIR.exists():
    sys.path.insert(0, str(_LIBS_DIR))

import click  # noqa: E402

from config import get_settings  # noqa: E402
from exceptions import UnknownScenarioError  # noqa: E402
from kafka_producer import EventProducer, ProducerConfig  # noqa: E402
from scenarios import SCENARIOS, generate_mixed  # noqa: E402
from common.logging_utils import configure_logging  # noqa: E402

logger = logging.getLogger("generator")


def _generation_options(f):
    """Shared --events/--rate/--duration/--scenario/... options for both commands."""
    f = click.option("--events", "event_count", default=None, type=int,
                      help="Total number of events. Takes priority over --rate/--duration.")(f)
    f = click.option("--rate", default=None, type=float,
                      help="Target events/sec. Paired with --duration to compute --events; also paces timestamps.")(f)
    f = click.option("--duration", default=None, type=float,
                      help="Duration in seconds. Requires --rate.")(f)
    f = click.option("--scenario", default="normal-traffic",
                      type=click.Choice(sorted(SCENARIOS.keys())), help="Scenario to generate.")(f)
    f = click.option("--attack-ratio", default=1.0, type=float,
                      help="Fraction (0.0-1.0) of events from the attack scenario; remainder is normal-traffic background. Ignored for --scenario normal-traffic.")(f)
    f = click.option("--hosts", default=None, help="Comma-separated hostnames.")(f)
    f = click.option("--users", default=None, help="Comma-separated usernames.")(f)
    f = click.option("--source-ips", default=None, help="Comma-separated source IPs.")(f)
    f = click.option("--seed", default=None, type=int, help="Random seed for reproducibility.")(f)
    return f


def _resolve_generation_args(
    event_count, rate, duration, scenario, attack_ratio, hosts, users, source_ips, seed,
):
    settings = get_settings()

    if event_count is not None:
        count = event_count
    elif rate is not None and duration is not None:
        count = round(rate * duration)
    elif rate is not None:
        raise click.UsageError("--rate requires --duration (or use --events for a fixed total).")
    else:
        count = settings.generator_default_rate

    avg_interval_ms = int(1000 / rate) if rate else None
    resolved_seed = seed if seed is not None else settings.generator_seed

    kwargs = {"attack_ratio": attack_ratio, "seed": resolved_seed}
    if hosts:
        kwargs["hosts"] = [h.strip() for h in hosts.split(",")]
    if users:
        kwargs["users"] = [u.strip() for u in users.split(",")]
    if source_ips:
        kwargs["source_ips"] = [ip.strip() for ip in source_ips.split(",")]
    if avg_interval_ms is not None:
        kwargs["avg_interval_ms"] = avg_interval_ms

    return count, kwargs, resolved_seed


@click.group()
def cli() -> None:
    """CyberStream synthetic security event generator."""


@cli.command()
@_generation_options
@click.option("--output", default=None, type=click.Path(),
              help="Output file (NDJSON). Defaults to stdout. Never mixed with log output (logs go to stderr).")
def generate(event_count, rate, duration, scenario, attack_ratio, hosts, users, source_ips, seed, output) -> None:
    """Generate synthetic security events locally as NDJSON. Never touches Kafka."""
    settings = get_settings()
    configure_logging(service="generator", level=settings.log_level)

    if scenario not in SCENARIOS:
        raise UnknownScenarioError(scenario, list(SCENARIOS.keys()))

    count, kwargs, resolved_seed = _resolve_generation_args(
        event_count, rate, duration, scenario, attack_ratio, hosts, users, source_ips, seed
    )

    logger.info("starting generation: scenario=%s count=%d seed=%d attack_ratio=%.2f",
                scenario, count, resolved_seed, attack_ratio)

    stream = sys.stdout if output is None else open(output, "w")
    written = 0
    try:
        for event in generate_mixed(scenario, count, **kwargs):
            stream.write(json.dumps(event.to_kafka_json()) + "\n")
            written += 1
    finally:
        if output is not None:
            stream.close()

    logger.info("generation complete: written=%d scenario=%s", written, scenario)
    if output:
        click.echo(f"Wrote {written} events to {output}", err=True)


@cli.command()
@_generation_options
@click.option("--bootstrap-servers", default=None, help="Overrides KAFKA_BOOTSTRAP_SERVERS from config/.env.")
@click.option("--client-id", default=None, help="Overrides KAFKA_CLIENT_ID.")
@click.option("--acks", default=None, type=click.Choice(["0", "1", "all"]), help="Overrides KAFKA_PRODUCER_ACKS.")
@click.option("--compression", default=None, type=click.Choice(["none", "gzip", "snappy", "lz4", "zstd"]), help="Overrides KAFKA_PRODUCER_COMPRESSION.")
@click.option("--retries", default=5, type=int, help="Producer-level retries before giving up on a message.")
@click.option("--delivery-timeout-ms", default=30_000, type=int, help="Max time a message may take to be acked or fail.")
@click.option("--linger-ms", default=20, type=int, help="Batching window in milliseconds.")
@click.option("--batch-num-messages", default=500, type=int, help="Max messages per batch.")
@click.option("--flush-timeout", default=30.0, type=float, help="Seconds to wait for final flush at shutdown.")
def produce(
    event_count, rate, duration, scenario, attack_ratio, hosts, users, source_ips, seed,
    bootstrap_servers, client_id, acks, compression, retries, delivery_timeout_ms,
    linger_ms, batch_num_messages, flush_timeout,
) -> None:
    """Generate synthetic security events and publish them to Kafka. Never writes event data to stdout."""
    settings = get_settings()
    configure_logging(service="generator", level=settings.log_level)

    if scenario not in SCENARIOS:
        raise UnknownScenarioError(scenario, list(SCENARIOS.keys()))

    count, kwargs, resolved_seed = _resolve_generation_args(
        event_count, rate, duration, scenario, attack_ratio, hosts, users, source_ips, seed
    )

    producer_config = ProducerConfig(
        bootstrap_servers=bootstrap_servers or settings.kafka_bootstrap_servers,
        client_id=client_id or settings.kafka_client_id,
        acks=acks or settings.kafka_producer_acks,
        compression_type=compression or settings.kafka_producer_compression,
        retries=retries,
        delivery_timeout_ms=delivery_timeout_ms,
        linger_ms=linger_ms,
        batch_num_messages=batch_num_messages,
    )

    logger.info("starting produce: scenario=%s count=%d seed=%d bootstrap=%s",
                scenario, count, resolved_seed, producer_config.bootstrap_servers)

    producer = EventProducer(producer_config)
    topics_seen: dict[str, int] = {}
    queued = 0
    try:
        for event in generate_mixed(scenario, count, **kwargs):
            producer.produce(event)
            topics_seen[event.kafka_topic()] = topics_seen.get(event.kafka_topic(), 0) + 1
            queued += 1
    finally:
        remaining = producer.flush(timeout=flush_timeout)

    summary = {
        "scenario": scenario,
        "queued": queued,
        "delivered": producer.stats.delivered,
        "failed": producer.stats.failed,
        "undelivered_after_flush_timeout": remaining,
        "topics": topics_seen,
        "bootstrap_servers": producer_config.bootstrap_servers,
    }
    click.echo(json.dumps(summary))
    logger.info("produce complete: %s", summary)

    if producer.stats.failed > 0 or remaining > 0:
        sys.exit(1)


@cli.command(name="list-scenarios")
def list_scenarios() -> None:
    """List available scenarios."""
    for name in SCENARIOS:
        click.echo(name)


if __name__ == "__main__":
    cli()
