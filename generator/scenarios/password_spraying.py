"""
Password spraying scenario (cahier des charges §10/§22): one source tries
many different usernames with few attempts per user, to avoid per-account
lockout thresholds - the opposite shape from brute force.
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
    advance_time,
    resolve_start_time,
)

# A wider user pool than DEFAULT_USERS so spraying visibly touches many
# distinct accounts rather than cycling through 5 names repeatedly.
_SPRAY_USER_POOL = [
    "admin", "backup", "jdoe", "asmith", "svc-web", "mgarcia", "khassan",
    "lmartin", "rkumar", "tsingh", "obrown", "pnielsen", "svc-batch", "guest",
]


def generate_password_spraying(
    count: int,
    *,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int = 6000,
) -> Iterator[SecurityEvent]:
    """`avg_interval_ms` defaults higher than brute force - spraying is deliberately slow to stay under per-account thresholds."""
    if count < 0:
        raise ValueError("count must be >= 0")

    rng = random.Random(seed)
    attacker_ip = rng.choice(source_ips or ATTACKER_SOURCE_IPS)
    target_host = rng.choice(hosts or DEFAULT_HOSTS)
    user_pool = users or _SPRAY_USER_POOL
    destination_ip = rng.choice(DEFAULT_DESTINATION_IPS)
    country = rng.choice(DEFAULT_COUNTRIES)

    current_time = resolve_start_time(start_time)

    for i in range(count):
        current_time = advance_time(rng, current_time, avg_interval_ms)
        # Cycle rather than random-choice so `count > len(user_pool)` still
        # guarantees broad coverage instead of clustering by chance.
        target_user = user_pool[i % len(user_pool)]

        yield SecurityEvent(
            timestamp=current_time,
            event_type=EventType.LOGIN_FAILED,
            category="authentication",
            source_ip=attacker_ip,
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
            metadata={"scenario": "password-spraying", "attempt": i + 1, "unique_users_targeted": len(user_pool)},
        )
