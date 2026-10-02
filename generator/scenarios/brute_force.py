"""
Brute force scenario (cahier des charges §10/§22): one source hammering
one account with failed logins in a short window, optionally succeeding
at the end. This generates SecurityEvent telemetry only - it never
performs a real authentication attempt against anything.
"""
from __future__ import annotations

import random
from datetime import datetime
from typing import Iterator

from models.event import EventType, SecurityEvent
from scenarios.common import (
    ATTACKER_SOURCE_IPS,
    DEFAULT_COUNTRIES,
    DEFAULT_DESTINATION_IPS,
    DEFAULT_HOSTS,
    DEFAULT_USERS,
    advance_time,
    resolve_start_time,
)


def generate_brute_force(
    count: int,
    *,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int = 2000,
    succeed_at_end: bool = True,
) -> Iterator[SecurityEvent]:
    """
    `avg_interval_ms=2000` keeps a default 30-event run within roughly the
    cahier des charges' 2-minute brute-force detection window
    (30 * ~2s ≈ 1 minute, comfortably inside 120s even with jitter).
    """
    if count < 0:
        raise ValueError("count must be >= 0")

    rng = random.Random(seed)
    attacker_ip = rng.choice(source_ips or ATTACKER_SOURCE_IPS)
    target_host = rng.choice(hosts or DEFAULT_HOSTS)
    target_user = rng.choice(users or DEFAULT_USERS)
    destination_ip = rng.choice(DEFAULT_DESTINATION_IPS)
    country = rng.choice(DEFAULT_COUNTRIES)

    current_time = resolve_start_time(start_time)

    for i in range(count):
        current_time = advance_time(rng, current_time, avg_interval_ms)
        is_last = i == count - 1
        success = succeed_at_end and is_last and count >= 5

        yield SecurityEvent(
            timestamp=current_time,
            event_type=EventType.LOGIN_SUCCESS if success else EventType.LOGIN_FAILED,
            category="authentication",
            source_ip=attacker_ip,
            destination_ip=destination_ip,
            source_port=rng.randint(1024, 65000),
            destination_port=22,
            protocol="TCP",
            username=target_user,
            hostname=target_host,
            action="login",
            status="success" if success else "failure",
            bytes_in=0,
            bytes_out=0,
            country=country,
            metadata={"scenario": "brute-force", "attempt": i + 1, "total_attempts": count},
        )
