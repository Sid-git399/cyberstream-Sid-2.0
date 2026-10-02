"""
Enrichment stage (cahier des charges §20): adds derived fields that don't
change the event's meaning but make downstream detection/scoring rules
simpler to write. No external API calls - everything here is a pure,
local computation, so this stage has no availability dependency of its
own (only its input stream does).
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

# Small local lookup, independent from generator/scenarios' port tables -
# a service-name lookup for enrichment is a different concern from
# "what port does this scenario emit", so a little duplication here is a
# deliberate choice, not an oversight (see docs/architecture-decisions.md ADR-14).
_KNOWN_SERVICE_PORTS = {
    22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "rpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
}

DEFAULT_PRIVILEGED_USERS = ["admin", "root", "backup", "administrator"]

# RFC 1918 private ranges, checked as string prefixes - adequate for this
# project's synthetic IPv4 addresses; not a general-purpose CIDR matcher.
_PRIVATE_PREFIXES = ["10.", "192.168."]


def _is_internal_ip_expr(col_name: str):
    col = F.col(col_name)
    is_10 = col.startswith("10.")
    is_192 = col.startswith("192.168.")
    # 172.16.0.0 - 172.31.255.255
    octets = F.split(col, "\\.")
    is_172 = (
        (octets.getItem(0) == "172")
        & (octets.getItem(1).cast("int") >= 16)
        & (octets.getItem(1).cast("int") <= 31)
    )
    return is_10 | is_192 | is_172


def enrich_events(
    normalized_df: DataFrame,
    *,
    privileged_users: list[str] | None = None,
    environment: str = "dev",
) -> DataFrame:
    privileged_users = privileged_users or DEFAULT_PRIVILEGED_USERS

    service_port_map = F.create_map(
        *[item for port, name in _KNOWN_SERVICE_PORTS.items() for item in (F.lit(port), F.lit(name))]
    )

    return (
        normalized_df
        .withColumn("is_source_internal", _is_internal_ip_expr("source_ip"))
        .withColumn("is_destination_internal", _is_internal_ip_expr("destination_ip"))
        .withColumn("is_privileged_user", F.col("username").isin(privileged_users))
        .withColumn("known_service_name", service_port_map[F.col("destination_port")])
        .withColumn("is_known_service_port", F.col("known_service_name").isNotNull())
        .withColumn("environment", F.lit(environment))
    )
