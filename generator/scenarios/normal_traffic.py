"""
Normal traffic scenario (cahier des charges §10 "Normal Traffic").

Covers all four "normal" sub-categories the cahier des charges asks for:
normal authentication, normal network activity, normal endpoint activity,
and normal web/cloud activity - as one weighted mix, since in a real
environment these interleave rather than arriving in separate blocks.
This is the baseline every detection rule in later phases must NOT fire
against.
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

# authentication, network, endpoint, web/cloud - all represented, weighted
# toward what a normal enterprise mix looks like.
_EVENT_WEIGHTS: dict[EventType, float] = {
    EventType.LOGIN_SUCCESS: 0.10,
    EventType.LOGOUT: 0.06,
    EventType.CONNECTION: 0.16,
    EventType.DNS_QUERY: 0.16,
    EventType.FIREWALL_ALLOW: 0.08,
    EventType.HTTP_REQUEST: 0.16,
    EventType.HTTP_ERROR: 0.02,
    EventType.FILE_CREATED: 0.05,
    EventType.FILE_MODIFIED: 0.05,
    EventType.PROCESS_CREATED: 0.06,
    EventType.PROCESS_TERMINATED: 0.04,
    EventType.CLOUD_LOGIN: 0.03,
    EventType.API_CALL: 0.03,
}

_PORT_BY_EVENT_TYPE: dict[EventType, int] = {
    EventType.LOGIN_SUCCESS: 22,
    EventType.LOGOUT: 22,
    EventType.CONNECTION: 443,
    EventType.DNS_QUERY: 53,
    EventType.FIREWALL_ALLOW: 443,
    EventType.HTTP_REQUEST: 443,
    EventType.HTTP_ERROR: 443,
    EventType.FILE_CREATED: 445,
    EventType.FILE_MODIFIED: 445,
    EventType.PROCESS_CREATED: 0,
    EventType.PROCESS_TERMINATED: 0,
    EventType.CLOUD_LOGIN: 443,
    EventType.API_CALL: 443,
}

_PROTOCOL_BY_EVENT_TYPE: dict[EventType, str] = {
    EventType.LOGIN_SUCCESS: "TCP",
    EventType.LOGOUT: "TCP",
    EventType.CONNECTION: "TCP",
    EventType.DNS_QUERY: "DNS",
    EventType.FIREWALL_ALLOW: "TCP",
    EventType.HTTP_REQUEST: "HTTPS",
    EventType.HTTP_ERROR: "HTTPS",
    EventType.FILE_CREATED: "TCP",
    EventType.FILE_MODIFIED: "TCP",
    EventType.PROCESS_CREATED: "TCP",
    EventType.PROCESS_TERMINATED: "TCP",
    EventType.CLOUD_LOGIN: "HTTPS",
    EventType.API_CALL: "HTTPS",
}


def _weighted_choice(rng: random.Random) -> EventType:
    types = list(_EVENT_WEIGHTS.keys())
    weights = list(_EVENT_WEIGHTS.values())
    return rng.choices(types, weights=weights, k=1)[0]


def generate_normal_traffic(
    count: int,
    *,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int = 800,
) -> Iterator[SecurityEvent]:
    """
    Deterministic given identical arguments (cahier des charges §62 -
    reproducible demo data): two runs with the same (count, seed, hosts,
    users, source_ips, start_time) produce an identical sequence.
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

    for _ in range(count):
        event_type = _weighted_choice(rng)
        current_time = advance_time(rng, current_time, avg_interval_ms)

        yield SecurityEvent(
            timestamp=current_time,
            event_type=event_type,
            category="authentication",  # corrected by model_post_init
            source_ip=rng.choice(source_ips),
            destination_ip=rng.choice(destination_ips),
            source_port=rng.randint(1024, 65000),
            destination_port=_PORT_BY_EVENT_TYPE[event_type],
            protocol=_PROTOCOL_BY_EVENT_TYPE[event_type],
            username=rng.choice(users),
            hostname=rng.choice(hosts),
            action=event_type.value,
            status="success",
            bytes_in=rng.randint(0, 4096),
            bytes_out=rng.randint(0, 2048),
            country=rng.choice(countries),
            metadata={"scenario": "normal-traffic"},
        )
