"""
Privilege escalation scenario (cahier des charges §10/§22): a login
followed shortly by a privilege change on the same host/user - the
sequence later phases' correlation engine must be able to link.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
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


def generate_privilege_escalation(
    count: int,
    *,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int = 15000,
) -> Iterator[SecurityEvent]:
    """
    `count` is the number of events requested; each incident is a
    login_success + privilege_escalation pair, so this yields
    `2 * ceil(count / 2)` events (never fewer than requested).
    """
    if count < 0:
        raise ValueError("count must be >= 0")

    rng = random.Random(seed)
    hosts = hosts or DEFAULT_HOSTS
    users = users or DEFAULT_USERS
    source_ips = source_ips or DEFAULT_SOURCE_IPS
    destination_ips = DEFAULT_DESTINATION_IPS
    countries = DEFAULT_COUNTRIES

    current_time = resolve_start_time(start_time)
    incidents = (count + 1) // 2

    for i in range(incidents):
        host = rng.choice(hosts)
        user = rng.choice(users)
        source_ip = rng.choice(source_ips)
        destination_ip = rng.choice(destination_ips)
        country = rng.choice(countries)

        current_time = advance_time(rng, current_time, avg_interval_ms)
        yield SecurityEvent(
            timestamp=current_time,
            event_type=EventType.LOGIN_SUCCESS,
            category="authentication",
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=rng.randint(1024, 65000),
            destination_port=22,
            protocol="TCP",
            username=user,
            hostname=host,
            action="login",
            status="success",
            bytes_in=0,
            bytes_out=0,
            country=country,
            metadata={"scenario": "privilege-escalation", "incident": i + 1, "stage": "login"},
        )

        # Privilege change follows quickly - a few seconds to a couple of
        # minutes, not the full avg_interval_ms gap between incidents.
        current_time = current_time + timedelta(seconds=rng.randint(3, 90))
        yield SecurityEvent(
            timestamp=current_time,
            event_type=EventType.PRIVILEGE_ESCALATION,
            category="privilege",
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=rng.randint(1024, 65000),
            destination_port=0,
            protocol="TCP",
            username=user,
            hostname=host,
            action="privilege_escalation",
            status="success",
            bytes_in=0,
            bytes_out=0,
            country=country,
            metadata={"scenario": "privilege-escalation", "incident": i + 1, "stage": "escalation"},
        )
