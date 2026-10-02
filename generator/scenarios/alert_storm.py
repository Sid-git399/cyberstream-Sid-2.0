"""
Alert storm scenario (cahier des charges §10/§29): deliberately generates
a large volume of near-identical brute-force-shaped events against one
target from many distinct source IPs, arriving in a tight time window.
Exists to exercise deduplication/aggregation logic downstream (Phase 7+),
not to represent a plausible single attacker.
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
    advance_time,
    resolve_start_time,
)

_STORM_SOURCE_IPS = [f"198.51.100.{i}" for i in range(1, 255)]  # RFC 5737 TEST-NET-2


def generate_alert_storm(
    count: int,
    *,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int = 50,
) -> Iterator[SecurityEvent]:
    """`avg_interval_ms` defaults very low - a storm is many alerts in a tight window by definition."""
    if count < 0:
        raise ValueError("count must be >= 0")

    rng = random.Random(seed)
    target_host = rng.choice(hosts or DEFAULT_HOSTS)
    target_user = rng.choice(users or ["admin"])
    destination_ip = rng.choice(DEFAULT_DESTINATION_IPS)
    country = rng.choice(DEFAULT_COUNTRIES)
    storm_ips = source_ips or _STORM_SOURCE_IPS

    current_time = resolve_start_time(start_time)

    for i in range(count):
        current_time = advance_time(rng, current_time, avg_interval_ms)

        yield SecurityEvent(
            timestamp=current_time,
            event_type=EventType.LOGIN_FAILED,
            category="authentication",
            source_ip=storm_ips[i % len(storm_ips)],
            destination_ip=destination_ip,
            source_port=rng.randint(1024, 65000),
            destination_port=22,
            protocol="TCP",
            username=target_user,
            hostname=target_host,
            action="login",
            status="failure",
            bytes_in=0,
            bytes_out=0,
            country=country,
            metadata={"scenario": "alert-storm", "storm_index": i + 1},
        )
