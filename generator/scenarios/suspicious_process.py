"""
Suspicious process scenario (cahier des charges §10/§22): process_created
events flagged as unusual (off-hours, uncommon parent/binary combination),
tagged explicitly in metadata so later detection-engine phases have a
ground truth to check their own logic against.
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

# (parent process, suspicious child) pairs - a child spawned from an
# office/document app or a script interpreter is the classic
# living-off-the-land pattern.
_SUSPICIOUS_PAIRS = [
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "wscript.exe"),
    ("chrome.exe", "powershell.exe"),
    ("explorer.exe", "rundll32.exe"),
]


def generate_suspicious_process(
    count: int,
    *,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int = 10000,
) -> Iterator[SecurityEvent]:
    if count < 0:
        raise ValueError("count must be >= 0")

    rng = random.Random(seed)
    hosts = hosts or DEFAULT_HOSTS
    users = users or DEFAULT_USERS
    source_ips = source_ips or DEFAULT_SOURCE_IPS
    destination_ips = DEFAULT_DESTINATION_IPS
    countries = DEFAULT_COUNTRIES

    current_time = resolve_start_time(start_time)

    for i in range(count):
        current_time = advance_time(rng, current_time, avg_interval_ms)
        parent, child = rng.choice(_SUSPICIOUS_PAIRS)

        yield SecurityEvent(
            timestamp=current_time,
            event_type=EventType.PROCESS_CREATED,
            category="endpoint",
            source_ip=rng.choice(source_ips),
            destination_ip=rng.choice(destination_ips),
            source_port=0,
            destination_port=0,
            protocol="TCP",
            username=rng.choice(users),
            hostname=rng.choice(hosts),
            action="process_created",
            status="success",
            bytes_in=0,
            bytes_out=0,
            country=rng.choice(countries),
            metadata={
                "scenario": "suspicious-process",
                "parent_process": parent,
                "process": child,
                "suspicious": True,
            },
        )
