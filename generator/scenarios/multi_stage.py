"""
Multi-stage incident scenario (cahier des charges §10/§22): chains
several attack stages into one coherent incident on the same host/user/
source IP, mirroring the cahier des charges' example chain:

    failed login -> successful login -> privilege escalation
    -> suspicious process -> large outbound transfer

Built by composing the other scenario generators rather than duplicating
their logic, then relabeling metadata so every event is traceable to both
its original stage type and this incident.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Iterator

from models.event import EventType, SecurityEvent
from scenarios.brute_force import generate_brute_force
from scenarios.common import DEFAULT_HOSTS, DEFAULT_USERS, resolve_start_time
from scenarios.data_transfer_spike import generate_data_transfer_spike
from scenarios.suspicious_process import generate_suspicious_process


def _relabel(events: Iterator[SecurityEvent], incident_id: str, stage: str) -> Iterator[SecurityEvent]:
    for event in events:
        event.metadata = {**event.metadata, "scenario": "multi-stage", "incident_id": incident_id, "stage": stage}
        yield event


def generate_multi_stage(
    count: int,
    *,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int = 2000,
) -> Iterator[SecurityEvent]:
    """
    `count` is a soft target: each incident is a fixed-shape chain (brute
    force attempts + 1 successful login + 1 suspicious process +
    1-3 large transfers), so the actual event count is rounded up to the
    nearest whole incident rather than truncating a chain mid-sequence.
    """
    if count < 0:
        raise ValueError("count must be >= 0")

    rng = random.Random(seed)
    hosts = hosts or DEFAULT_HOSTS
    users = users or DEFAULT_USERS

    events_per_incident = 8  # ~5 brute-force attempts + login + process + transfer
    incidents = max(1, (count + events_per_incident - 1) // events_per_incident) if count > 0 else 0

    current_time = resolve_start_time(start_time)

    for i in range(incidents):
        incident_id = f"multi-stage-{i + 1:04d}"
        host = [rng.choice(hosts)]
        user = [rng.choice(users)]
        attacker_ip = [f"203.0.113.{rng.randint(1, 19)}"]

        brute_force_events = list(generate_brute_force(
            5, seed=seed + i, hosts=host, users=user, source_ips=attacker_ip,
            start_time=current_time, avg_interval_ms=avg_interval_ms, succeed_at_end=True,
        ))
        for event in brute_force_events:
            stage = "credential_access_success" if event.event_type == EventType.LOGIN_SUCCESS else "credential_access_attempt"
            yield from _relabel(iter([event]), incident_id, stage)
        current_time = brute_force_events[-1].timestamp + timedelta(seconds=rng.randint(5, 60))

        suspicious = list(generate_suspicious_process(
            1, seed=seed + i, hosts=host, users=user, source_ips=attacker_ip,
            start_time=current_time, avg_interval_ms=1,
        ))
        yield from _relabel(iter(suspicious), incident_id, "execution")
        current_time = suspicious[-1].timestamp + timedelta(seconds=rng.randint(10, 120))

        transfer_count = rng.randint(1, 3)
        transfers = list(generate_data_transfer_spike(
            transfer_count, seed=seed + i, hosts=host, users=user, source_ips=attacker_ip,
            start_time=current_time, avg_interval_ms=avg_interval_ms,
        ))
        yield from _relabel(iter(transfers), incident_id, "exfiltration")
        current_time = transfers[-1].timestamp + timedelta(seconds=rng.randint(30, 300))
