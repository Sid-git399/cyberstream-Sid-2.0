"""
Data transfer spike scenario (cahier des charges §10/§22): outbound
volume far above the normal-traffic baseline (which stays under ~2KB per
event, see normal_traffic.py), simulating exfiltration-shaped telemetry.
"""
from __future__ import annotations

import random
from datetime import datetime
from typing import Iterator

from models.event import EventType, SecurityEvent
from scenarios.common import (
    DEFAULT_COUNTRIES,
    DEFAULT_DESTINATION_IPS,
    DEFAULT_HOSTS,
    DEFAULT_SOURCE_IPS,
    DEFAULT_USERS,
    advance_time,
    resolve_start_time,
)

# Far above normal_traffic.py's bytes_out ceiling of 2048, so a simple
# threshold/baseline comparison in a later phase can tell them apart.
_SPIKE_BYTES_OUT_RANGE = (5_000_000, 250_000_000)


def generate_data_transfer_spike(
    count: int,
    *,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int = 4000,
) -> Iterator[SecurityEvent]:
    if count < 0:
        raise ValueError("count must be >= 0")

    rng = random.Random(seed)
    hosts = hosts or DEFAULT_HOSTS
    users = users or DEFAULT_USERS
    source_ips = source_ips or DEFAULT_SOURCE_IPS
    destination_ips = DEFAULT_DESTINATION_IPS
    countries = DEFAULT_COUNTRIES

    # One host/user pair drives the spike - a distributed spike with a
    # different host every event wouldn't read as one incident.
    host = rng.choice(hosts)
    user = rng.choice(users)

    current_time = resolve_start_time(start_time)

    for i in range(count):
        current_time = advance_time(rng, current_time, avg_interval_ms)

        yield SecurityEvent(
            timestamp=current_time,
            event_type=EventType.CONNECTION,
            category="network",
            source_ip=rng.choice(source_ips),
            destination_ip=rng.choice(destination_ips),
            source_port=rng.randint(1024, 65000),
            destination_port=443,
            protocol="TCP",
            username=user,
            hostname=host,
            action="connection",
            status="success",
            bytes_in=rng.randint(0, 4096),
            bytes_out=rng.randint(*_SPIKE_BYTES_OUT_RANGE),
            country=rng.choice(countries),
            metadata={"scenario": "data-transfer-spike", "transfer_index": i + 1},
        )
