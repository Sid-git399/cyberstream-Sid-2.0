"""
Shared building blocks for scenario generators.

Every scenario (normal traffic and each attack simulation) draws hosts,
users, and source IPs from the same default pools unless the caller
overrides them, and paces event timestamps the same way, so scenarios can
be mixed together (see mixer.py) and still look like they belong to one
coherent environment.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

DEFAULT_HOSTS = ["srv-auth-01", "srv-db-02", "srv-web-01", "ws-fin-014", "ws-hr-003"]
DEFAULT_USERS = ["admin", "backup", "jdoe", "asmith", "svc-web"]
DEFAULT_SOURCE_IPS = [f"10.10.4.{i}" for i in range(10, 40)]
DEFAULT_DESTINATION_IPS = [f"10.10.1.{i}" for i in range(10, 20)]
DEFAULT_COUNTRIES = ["DZ", "FR", "US", "DE"]

# A source IP pool clearly outside the internal ranges above, for
# scenarios that need an "external attacker" (brute force, port scan,
# password spraying, DNS anomaly). Still fully synthetic (RFC 5737
# TEST-NET-1, reserved for documentation - never a real routable host).
ATTACKER_SOURCE_IPS = [f"203.0.113.{i}" for i in range(1, 20)]


def advance_time(rng: random.Random, current: datetime, avg_interval_ms: int) -> datetime:
    """
    Jittered step forward in time: uniformly distributed between 20% and
    180% of avg_interval_ms, so the average interval over many events
    converges on avg_interval_ms (used to translate --rate into spacing).
    """
    low = max(1, int(avg_interval_ms * 0.2))
    high = max(low + 1, int(avg_interval_ms * 1.8))
    return current + timedelta(milliseconds=rng.randint(low, high))


def resolve_start_time(start_time: datetime | None) -> datetime:
    return start_time or datetime.now(timezone.utc)
