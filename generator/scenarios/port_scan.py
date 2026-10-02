"""
Port scan scenario (cahier des charges §10/§22): one source contacting
many distinct destination ports on one host in a short window. This
generates telemetry describing what a scan would look like - it never
opens a real socket or probes anything.
"""
from __future__ import annotations

import random
from datetime import datetime
from typing import Iterator

from models.event import EventType, SecurityEvent
from scenarios.common import (
    ATTACKER_SOURCE_IPS,
    DEFAULT_COUNTRIES,
    DEFAULT_HOSTS,
    advance_time,
    resolve_start_time,
)

_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
                 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]


def generate_port_scan(
    count: int,
    *,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int = 300,
) -> Iterator[SecurityEvent]:
    """`avg_interval_ms` defaults low - a scan probes ports quickly."""
    if count < 0:
        raise ValueError("count must be >= 0")

    rng = random.Random(seed)
    attacker_ip = rng.choice(source_ips or ATTACKER_SOURCE_IPS)
    target_host = rng.choice(hosts or DEFAULT_HOSTS)
    target_ip = f"10.10.1.{rng.randint(10, 19)}"
    country = rng.choice(DEFAULT_COUNTRIES)

    # Extend beyond the common-port list deterministically if count is
    # large, rather than repeating the same 24 ports.
    ports = list(_COMMON_PORTS)
    extra_needed = max(0, count - len(ports))
    ports.extend(rng.sample(range(1, 65536), min(extra_needed, 65535 - len(ports))))
    rng.shuffle(ports)

    current_time = resolve_start_time(start_time)

    for i in range(count):
        current_time = advance_time(rng, current_time, avg_interval_ms)
        port = ports[i % len(ports)]

        yield SecurityEvent(
            timestamp=current_time,
            event_type=EventType.PORT_SCAN,
            category="network",
            source_ip=attacker_ip,
            destination_ip=target_ip,
            source_port=rng.randint(1024, 65000),
            destination_port=port,
            protocol="TCP",
            username=None,
            hostname=target_host,
            action="port_scan",
            status="unknown",
            bytes_in=0,
            bytes_out=0,
            country=country,
            metadata={"scenario": "port-scan", "probe_index": i + 1, "unique_ports_probed": len(set(ports[: i + 1]))},
        )
