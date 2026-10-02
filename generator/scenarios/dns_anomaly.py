"""
DNS anomaly scenario (cahier des charges §10/§22): unusually frequent DNS
queries to high-entropy-looking subdomains from one host, the classic
DNS-tunneling / C2-beaconing telemetry shape.
"""
from __future__ import annotations

import random
import string
from datetime import datetime
from typing import Iterator

from models.event import EventType, SecurityEvent
from scenarios.common import (
    DEFAULT_COUNTRIES,
    DEFAULT_HOSTS,
    DEFAULT_USERS,
    advance_time,
    resolve_start_time,
)

_BASE_DOMAINS = ["example-cdn.net", "telemetry-sync.io", "cloud-assets.co"]


def _random_label(rng: random.Random, length: int = 24) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def generate_dns_anomaly(
    count: int,
    *,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int = 400,
) -> Iterator[SecurityEvent]:
    """`avg_interval_ms` defaults low - beaconing/tunneling is high-frequency by nature."""
    if count < 0:
        raise ValueError("count must be >= 0")

    rng = random.Random(seed)
    host = rng.choice(hosts or DEFAULT_HOSTS)
    user = rng.choice(users or DEFAULT_USERS)
    source_ip = rng.choice(source_ips or [f"10.10.4.{rng.randint(10, 39)}"])
    country = rng.choice(DEFAULT_COUNTRIES)

    current_time = resolve_start_time(start_time)

    for i in range(count):
        current_time = advance_time(rng, current_time, avg_interval_ms)
        query_domain = f"{_random_label(rng)}.{rng.choice(_BASE_DOMAINS)}"

        yield SecurityEvent(
            timestamp=current_time,
            event_type=EventType.DNS_QUERY,
            category="network",
            source_ip=source_ip,
            destination_ip="10.10.1.10",
            source_port=rng.randint(1024, 65000),
            destination_port=53,
            protocol="DNS",
            username=user,
            hostname=host,
            action="dns_query",
            status="success",
            bytes_in=rng.randint(64, 512),
            bytes_out=rng.randint(64, 512),
            country=country,
            metadata={"scenario": "dns-anomaly", "query_domain": query_domain, "query_index": i + 1},
        )
