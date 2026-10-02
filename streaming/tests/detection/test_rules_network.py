import json
from datetime import datetime, timedelta, timezone

from src.detection.config import (
    DNSAnomalyConfig,
    LargeDataTransferConfig,
    PortScanConfig,
)
from src.detection.rules.dns_anomaly import DNSAnomalyRule
from src.detection.rules.large_data_transfer import LargeDataTransferRule
from src.detection.rules.port_scan import PortScanRule

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
WM = "2 minutes"


def port_probes(n, *, start=BASE, source_ip="203.0.113.7", hostname="srv-db-02", step_s=1):
    return [
        {
            "event_id": f"evt-scan-{i:04d}", "event_time": start + timedelta(seconds=i * step_s),
            "event_type": "port_scan", "category": "network", "status": "unknown",
            "source_ip": source_ip, "destination_port": 1000 + i, "hostname": hostname,
            "username": None,
        }
        for i in range(n)
    ]


# --- Port scan -----------------------------------------------------------

def test_port_scan_positive(spark, make_enriched_df):
    rule = PortScanRule(PortScanConfig(unique_ports=20, window_seconds=60))
    df = make_enriched_df(port_probes(25))
    out = rule.apply(df, WM)
    rows = out.collect()
    assert len(rows) == 1
    evidence = json.loads(rows[0]["evidence"])
    assert evidence["unique_ports"] == 25


def test_port_scan_negative_too_few_ports(spark, make_enriched_df):
    rule = PortScanRule(PortScanConfig(unique_ports=20))
    df = make_enriched_df(port_probes(5))
    assert rule.apply(df, WM).count() == 0


def test_port_scan_boundary_exact_threshold(spark, make_enriched_df):
    rule = PortScanRule(PortScanConfig(unique_ports=20))
    assert rule.apply(make_enriched_df(port_probes(20)), WM).count() == 1
    assert rule.apply(make_enriched_df(port_probes(19)), WM).count() == 0


def test_port_scan_repeated_port_does_not_inflate_unique_count(spark, make_enriched_df):
    rule = PortScanRule(PortScanConfig(unique_ports=5))
    rows = port_probes(10)
    for r in rows:
        r["destination_port"] = 443  # same port every time
    df = make_enriched_df(rows)
    assert rule.apply(df, WM).count() == 0  # only 1 unique port, threshold 5


def test_port_scan_ignores_non_network_category(spark, make_enriched_df):
    rule = PortScanRule(PortScanConfig(unique_ports=5))
    rows = port_probes(10)
    for r in rows:
        r["category"] = "authentication"
    df = make_enriched_df(rows)
    assert rule.apply(df, WM).count() == 0


def test_port_scan_disabled(spark, make_enriched_df):
    rule = PortScanRule(PortScanConfig(enabled=False, unique_ports=1))
    df = make_enriched_df(port_probes(25))
    assert rule.apply(df, WM).count() == 0


def test_port_scan_missing_source_ip_excluded_not_crashed(spark, make_enriched_df):
    rule = PortScanRule(PortScanConfig(unique_ports=5))
    rows = port_probes(10)
    for r in rows:
        r["source_ip"] = None
    df = make_enriched_df(rows)
    assert rule.apply(df, WM).count() == 0


# --- DNS anomaly -----------------------------------------------------------

def dns_queries(n, *, start=BASE, source_ip="10.10.4.15", hostname="ws-fin-014", step_s=1):
    return [
        {
            "event_id": f"evt-dns-{i:04d}", "event_time": start + timedelta(seconds=i * step_s),
            "event_type": "dns_query", "category": "network", "source_ip": source_ip,
            "hostname": hostname, "username": "jdoe",
        }
        for i in range(n)
    ]


def test_dns_anomaly_positive(spark, make_enriched_df):
    rule = DNSAnomalyRule(DNSAnomalyConfig(query_count_threshold=50, window_seconds=60))
    df = make_enriched_df(dns_queries(60))
    out = rule.apply(df, WM)
    rows = out.collect()
    assert len(rows) == 1
    assert json.loads(rows[0]["evidence"])["query_count"] == 60


def test_dns_anomaly_negative_normal_volume(spark, make_enriched_df):
    rule = DNSAnomalyRule(DNSAnomalyConfig(query_count_threshold=50))
    df = make_enriched_df(dns_queries(10))
    assert rule.apply(df, WM).count() == 0


def test_dns_anomaly_boundary(spark, make_enriched_df):
    rule = DNSAnomalyRule(DNSAnomalyConfig(query_count_threshold=50))
    assert rule.apply(make_enriched_df(dns_queries(50)), WM).count() == 1
    assert rule.apply(make_enriched_df(dns_queries(49)), WM).count() == 0


def test_dns_anomaly_only_counts_dns_query_event_type(spark, make_enriched_df):
    rule = DNSAnomalyRule(DNSAnomalyConfig(query_count_threshold=5))
    rows = dns_queries(10)
    for r in rows:
        r["event_type"] = "connection"
    df = make_enriched_df(rows)
    assert rule.apply(df, WM).count() == 0


def test_dns_anomaly_disabled(spark, make_enriched_df):
    rule = DNSAnomalyRule(DNSAnomalyConfig(enabled=False, query_count_threshold=1))
    df = make_enriched_df(dns_queries(60))
    assert rule.apply(df, WM).count() == 0


# --- Large data transfer ----------------------------------------------

def test_large_transfer_positive(spark, make_enriched_df):
    rule = LargeDataTransferRule(LargeDataTransferConfig(bytes_out_threshold=5_000_000))
    df = make_enriched_df([{"event_id": "evt-1", "bytes_out": 10_000_000, "event_type": "connection"}])
    out = rule.apply(df, WM)
    rows = out.collect()
    assert len(rows) == 1
    assert json.loads(rows[0]["evidence"])["bytes_out"] == 10_000_000


def test_large_transfer_negative_below_threshold(spark, make_enriched_df):
    rule = LargeDataTransferRule(LargeDataTransferConfig(bytes_out_threshold=5_000_000))
    df = make_enriched_df([{"event_id": "evt-1", "bytes_out": 1000}])
    assert rule.apply(df, WM).count() == 0


def test_large_transfer_boundary_exact_threshold_triggers(spark, make_enriched_df):
    rule = LargeDataTransferRule(LargeDataTransferConfig(bytes_out_threshold=5_000_000))
    df = make_enriched_df([{"event_id": "evt-1", "bytes_out": 5_000_000}])
    assert rule.apply(df, WM).count() == 1


def test_large_transfer_null_bytes_out_does_not_crash(spark, make_enriched_df):
    rule = LargeDataTransferRule(LargeDataTransferConfig(bytes_out_threshold=5_000_000))
    df = make_enriched_df([{"event_id": "evt-1", "bytes_out": None}])
    assert rule.apply(df, WM).count() == 0


def test_large_transfer_disabled(spark, make_enriched_df):
    rule = LargeDataTransferRule(LargeDataTransferConfig(enabled=False, bytes_out_threshold=1))
    df = make_enriched_df([{"event_id": "evt-1", "bytes_out": 10_000_000}])
    assert rule.apply(df, WM).count() == 0


def test_large_transfer_each_event_independent_no_aggregation(spark, make_enriched_df):
    rule = LargeDataTransferRule(LargeDataTransferConfig(bytes_out_threshold=5_000_000))
    rows = [{"event_id": f"evt-{i}", "bytes_out": 6_000_000, "event_time": BASE + timedelta(seconds=i)} for i in range(3)]
    df = make_enriched_df(rows)
    assert rule.apply(df, WM).count() == 3
