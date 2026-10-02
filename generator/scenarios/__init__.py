"""
Scenario registry and attack/normal-traffic mixing.

SCENARIOS maps every scenario name the CLI accepts to its generator
function. `generate_mixed` blends a chosen attack scenario with
normal-traffic background noise at a configurable ratio (`--attack-ratio`),
which is what the cahier des charges' `--attack-ratio` parameter (§9)
controls: 1.0 means pure attack traffic, 0.0 means pure normal traffic,
values in between interleave both by timestamp.
"""
from __future__ import annotations

import random
from datetime import datetime
from typing import Iterator

from models.event import SecurityEvent
from scenarios.alert_storm import generate_alert_storm
from scenarios.brute_force import generate_brute_force
from scenarios.data_transfer_spike import generate_data_transfer_spike
from scenarios.dns_anomaly import generate_dns_anomaly
from scenarios.multi_stage import generate_multi_stage
from scenarios.normal_traffic import generate_normal_traffic
from scenarios.password_spraying import generate_password_spraying
from scenarios.port_scan import generate_port_scan
from scenarios.privilege_escalation import generate_privilege_escalation
from scenarios.suspicious_process import generate_suspicious_process

SCENARIOS = {
    "normal-traffic": generate_normal_traffic,
    "brute-force": generate_brute_force,
    "password-spraying": generate_password_spraying,
    "port-scan": generate_port_scan,
    "privilege-escalation": generate_privilege_escalation,
    "suspicious-process": generate_suspicious_process,
    "data-transfer-spike": generate_data_transfer_spike,
    "dns-anomaly": generate_dns_anomaly,
    "multi-stage": generate_multi_stage,
    "alert-storm": generate_alert_storm,
}


def generate_mixed(
    scenario: str,
    count: int,
    *,
    attack_ratio: float = 1.0,
    seed: int = 42,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    start_time: datetime | None = None,
    avg_interval_ms: int | None = None,
) -> Iterator[SecurityEvent]:
    """
    scenario="normal-traffic" ignores attack_ratio entirely (there is no
    "attack" to blend in). For any attack scenario, attack_ratio in [0, 1]
    controls what fraction of `count` comes from that scenario, with the
    remainder filled by normal-traffic background noise; both are
    generated with the same seed family and merged sorted by timestamp so
    a downstream consumer sees one plausible, interleaved stream rather
    than two blocks back-to-back.
    """
    if not (0.0 <= attack_ratio <= 1.0):
        raise ValueError("attack_ratio must be between 0.0 and 1.0")

    if scenario == "normal-traffic" or count == 0:
        kwargs = {"seed": seed, "hosts": hosts, "users": users, "source_ips": source_ips, "start_time": start_time}
        if avg_interval_ms is not None:
            kwargs["avg_interval_ms"] = avg_interval_ms
        yield from SCENARIOS["normal-traffic"](count, **kwargs)
        return

    attack_count = round(count * attack_ratio)
    normal_count = count - attack_count

    attack_fn = SCENARIOS[scenario]
    attack_kwargs = {"seed": seed, "hosts": hosts, "users": users, "source_ips": source_ips, "start_time": start_time}
    if avg_interval_ms is not None:
        attack_kwargs["avg_interval_ms"] = avg_interval_ms
    attack_events = list(attack_fn(attack_count, **attack_kwargs)) if attack_count > 0 else []

    normal_kwargs = {"seed": seed + 1, "hosts": hosts, "users": users, "start_time": start_time}
    if avg_interval_ms is not None:
        normal_kwargs["avg_interval_ms"] = avg_interval_ms
    normal_events = list(generate_normal_traffic(normal_count, **normal_kwargs)) if normal_count > 0 else []

    merged = sorted(attack_events + normal_events, key=lambda e: e.timestamp)
    yield from merged
