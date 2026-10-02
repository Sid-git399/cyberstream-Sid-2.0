import json
from datetime import datetime, timedelta, timezone

from src.detection.config import (
    BruteForceConfig,
    PasswordSprayingConfig,
    PrivilegeEscalationConfig,
    SuspiciousAuthenticationConfig,
)
from src.detection.rules.brute_force import BruteForceRule
from src.detection.rules.password_spraying import PasswordSprayingRule
from src.detection.rules.privilege_escalation import PrivilegeEscalationRule
from src.detection.rules.suspicious_authentication import SuspiciousAuthenticationRule

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
WM = "2 minutes"


def failed_logins(n, *, start=BASE, source_ip="203.0.113.5", username="admin", hostname="srv-auth-01", step_s=5):
    return [
        {
            "event_id": f"evt-{i:04d}", "event_time": start + timedelta(seconds=i * step_s),
            "event_type": "login_failed", "category": "authentication", "status": "failure",
            "source_ip": source_ip, "username": username, "hostname": hostname,
        }
        for i in range(n)
    ]


# --- Brute force -----------------------------------------------------------

def test_brute_force_positive_above_threshold(spark, make_enriched_df):
    rule = BruteForceRule(BruteForceConfig(failed_attempts=10, window_seconds=300))
    df = make_enriched_df(failed_logins(12))
    out = rule.apply(df, WM)
    rows = out.collect()
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "brute-force"
    assert rows[0]["source_ip"] == "203.0.113.5"
    assert rows[0]["username"] == "admin"
    evidence = json.loads(rows[0]["evidence"])
    assert evidence["failed_attempts"] == 12
    assert len(rows[0]["event_ids"]) == 12


def test_brute_force_negative_below_threshold(spark, make_enriched_df):
    rule = BruteForceRule(BruteForceConfig(failed_attempts=10, window_seconds=300))
    df = make_enriched_df(failed_logins(5))
    out = rule.apply(df, WM)
    assert out.count() == 0


def test_brute_force_threshold_boundary_exact_match_triggers(spark, make_enriched_df):
    rule = BruteForceRule(BruteForceConfig(failed_attempts=10, window_seconds=300))
    df = make_enriched_df(failed_logins(10))
    assert rule.apply(df, WM).count() == 1


def test_brute_force_threshold_boundary_one_below_does_not_trigger(spark, make_enriched_df):
    rule = BruteForceRule(BruteForceConfig(failed_attempts=10, window_seconds=300))
    df = make_enriched_df(failed_logins(9))
    assert rule.apply(df, WM).count() == 0


def test_brute_force_disabled_rule_produces_no_rows(spark, make_enriched_df):
    rule = BruteForceRule(BruteForceConfig(enabled=False, failed_attempts=1))
    df = make_enriched_df(failed_logins(50))
    out = rule.apply(df, WM)
    assert out.count() == 0
    assert out.columns == rule.apply(df, WM).columns  # still schema-conformant


def test_brute_force_ignores_null_username(spark, make_enriched_df):
    rows = failed_logins(20)
    for r in rows:
        r["username"] = None
    rule = BruteForceRule(BruteForceConfig(failed_attempts=10))
    df = make_enriched_df(rows)
    assert rule.apply(df, WM).count() == 0  # null-username rows excluded, never crashes


def test_brute_force_login_success_events_do_not_count(spark, make_enriched_df):
    rows = failed_logins(12)
    for r in rows:
        r["event_type"] = "login_success"
        r["status"] = "success"
    rule = BruteForceRule(BruteForceConfig(failed_attempts=10))
    df = make_enriched_df(rows)
    assert rule.apply(df, WM).count() == 0


def test_brute_force_two_independent_windows_both_trigger(spark, make_enriched_df):
    rule = BruteForceRule(BruteForceConfig(failed_attempts=10, window_seconds=60))
    window_1 = failed_logins(12, start=BASE)
    window_2 = failed_logins(12, start=BASE + timedelta(minutes=10))
    df = make_enriched_df(window_1 + window_2)
    out = rule.apply(df, WM)
    assert out.count() == 2


def test_brute_force_duplicate_events_still_count_each_occurrence(spark, make_enriched_df):
    # Exact duplicate event_ids (e.g. an at-least-once Kafka redelivery) -
    # this rule does not deduplicate; that is explicitly out of scope
    # here (see docs/detection-engine.md limitations).
    one = failed_logins(1)[0]
    rows = [dict(one) for _ in range(10)]
    rule = BruteForceRule(BruteForceConfig(failed_attempts=10))
    df = make_enriched_df(rows)
    assert rule.apply(df, WM).count() == 1


def test_brute_force_deterministic_detection_id(spark, make_enriched_df):
    rule = BruteForceRule(BruteForceConfig(failed_attempts=10))
    df1 = make_enriched_df(failed_logins(12))
    df2 = make_enriched_df(failed_logins(12))
    id1 = rule.apply(df1, WM).collect()[0]["detection_id"]
    id2 = rule.apply(df2, WM).collect()[0]["detection_id"]
    assert id1 == id2


def test_brute_force_events_spanning_a_window_boundary_can_be_missed(spark, make_enriched_df):
    """
    KNOWN, DOCUMENTED LIMITATION (see docs/detection-engine.md) - found by
    an integration test becoming flaky, not by design review.

    Tumbling windows (windows.py's windowed_aggregate -> F.window()) are
    non-overlapping and aligned to absolute time boundaries, not to each
    burst's own start. A burst that straddles a boundary splits across
    two windows, and if neither half alone reaches the threshold, the
    attack is missed entirely - even though every event is well within
    any reasonable N-second span of each other. This test pins the
    scenario precisely to prove the gap exists, not to assert it as
    desired behavior.
    """
    rule = BruteForceRule(BruteForceConfig(failed_attempts=10, window_seconds=300))
    boundary = datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc)  # a 5-minute tumbling boundary
    before = failed_logins(8, start=boundary - timedelta(seconds=20), step_s=2)   # 8 events just before
    after = failed_logins(8, start=boundary + timedelta(seconds=5), step_s=2)     # 8 events just after
    df = make_enriched_df(before + after)  # 16 failed attempts in under 40 seconds, one attacker, one account
    out = rule.apply(df, WM)
    # Documents the gap: neither 8-event half reaches the threshold of 10,
    # so this well within any reasonable "brute force" window is missed.
    assert out.count() == 0


# --- Password spraying -------------------------------------------------

def _spray_rows(n_users, *, attempts_per_user=1, source_ip="203.0.113.9", start=BASE):
    rows = []
    t = start
    for u in range(n_users):
        for _ in range(attempts_per_user):
            rows.append({
                "event_id": f"evt-spray-{u}-{_}", "event_time": t, "event_type": "login_failed",
                "category": "authentication", "status": "failure", "source_ip": source_ip,
                "username": f"user{u}", "hostname": "srv-auth-01",
            })
            t += timedelta(seconds=2)
    return rows


def test_password_spraying_positive(spark, make_enriched_df):
    rule = PasswordSprayingRule(PasswordSprayingConfig(unique_users=8, window_seconds=300))
    df = make_enriched_df(_spray_rows(10))
    out = rule.apply(df, WM)
    rows = out.collect()
    assert len(rows) == 1
    assert rows[0]["username"] is None  # no single username applies
    evidence = json.loads(rows[0]["evidence"])
    assert evidence["unique_users"] == 10


def test_password_spraying_negative_too_few_distinct_users(spark, make_enriched_df):
    rule = PasswordSprayingRule(PasswordSprayingConfig(unique_users=8))
    df = make_enriched_df(_spray_rows(5))
    assert rule.apply(df, WM).count() == 0


def test_password_spraying_distinguishes_from_brute_force(spark, make_enriched_df):
    """Many attempts against ONE user must not trigger password spraying."""
    rule = PasswordSprayingRule(PasswordSprayingConfig(unique_users=8))
    df = make_enriched_df(failed_logins(20))  # one username, many attempts
    assert rule.apply(df, WM).count() == 0


def test_password_spraying_disabled(spark, make_enriched_df):
    rule = PasswordSprayingRule(PasswordSprayingConfig(enabled=False, unique_users=1))
    df = make_enriched_df(_spray_rows(10))
    assert rule.apply(df, WM).count() == 0


# --- Suspicious authentication -------------------------------------------

def test_suspicious_auth_positive_privileged_external_login(spark, make_enriched_df):
    rule = SuspiciousAuthenticationRule(SuspiciousAuthenticationConfig())
    df = make_enriched_df([{
        "event_id": "evt-1", "event_type": "login_success", "status": "success",
        "is_privileged_user": True, "is_source_internal": False, "username": "admin",
    }])
    out = rule.apply(df, WM)
    rows = out.collect()
    assert len(rows) == 1
    assert json.loads(rows[0]["evidence"])["reason"] == "privileged_login_from_external_source"


def test_suspicious_auth_positive_account_locked(spark, make_enriched_df):
    rule = SuspiciousAuthenticationRule(SuspiciousAuthenticationConfig())
    df = make_enriched_df([{
        "event_id": "evt-1", "event_type": "account_locked", "status": "failure",
        "is_privileged_user": False, "is_source_internal": True,
    }])
    out = rule.apply(df, WM)
    assert out.count() == 1
    assert json.loads(out.collect()[0]["evidence"])["reason"] == "account_locked"


def test_suspicious_auth_negative_internal_privileged_login(spark, make_enriched_df):
    rule = SuspiciousAuthenticationRule(SuspiciousAuthenticationConfig())
    df = make_enriched_df([{
        "event_id": "evt-1", "event_type": "login_success", "status": "success",
        "is_privileged_user": True, "is_source_internal": True,
    }])
    assert rule.apply(df, WM).count() == 0


def test_suspicious_auth_negative_nonprivileged_external_login(spark, make_enriched_df):
    rule = SuspiciousAuthenticationRule(SuspiciousAuthenticationConfig())
    df = make_enriched_df([{
        "event_id": "evt-1", "event_type": "login_success", "status": "success",
        "is_privileged_user": False, "is_source_internal": False,
    }])
    assert rule.apply(df, WM).count() == 0


def test_suspicious_auth_disabled(spark, make_enriched_df):
    rule = SuspiciousAuthenticationRule(SuspiciousAuthenticationConfig(enabled=False))
    df = make_enriched_df([{
        "event_id": "evt-1", "event_type": "account_locked",
        "is_privileged_user": False, "is_source_internal": True,
    }])
    assert rule.apply(df, WM).count() == 0


def test_suspicious_auth_each_qualifying_event_is_its_own_detection(spark, make_enriched_df):
    rule = SuspiciousAuthenticationRule(SuspiciousAuthenticationConfig())
    rows = [{
        "event_id": f"evt-{i}", "event_type": "account_locked",
        "is_privileged_user": False, "is_source_internal": True,
        "event_time": BASE + timedelta(seconds=i),
    } for i in range(3)]
    df = make_enriched_df(rows)
    assert rule.apply(df, WM).count() == 3  # row-level, not aggregated


# --- Privilege escalation -------------------------------------------------

def test_privilege_escalation_positive(spark, make_enriched_df):
    rule = PrivilegeEscalationRule(PrivilegeEscalationConfig())
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "privilege_escalation", "category": "privilege"}])
    out = rule.apply(df, WM)
    assert out.count() == 1
    assert out.collect()[0]["category"] == "privilege"


def test_privilege_escalation_group_modified_also_triggers(spark, make_enriched_df):
    rule = PrivilegeEscalationRule(PrivilegeEscalationConfig())
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "group_modified", "category": "privilege"}])
    assert rule.apply(df, WM).count() == 1


def test_privilege_escalation_negative_unrelated_event(spark, make_enriched_df):
    rule = PrivilegeEscalationRule(PrivilegeEscalationConfig())
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "login_success", "category": "authentication"}])
    assert rule.apply(df, WM).count() == 0


def test_privilege_escalation_disabled(spark, make_enriched_df):
    rule = PrivilegeEscalationRule(PrivilegeEscalationConfig(enabled=False))
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "privilege_escalation"}])
    assert rule.apply(df, WM).count() == 0


def test_privilege_escalation_missing_hostname_does_not_crash(spark, make_enriched_df):
    rule = PrivilegeEscalationRule(PrivilegeEscalationConfig())
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "privilege_escalation", "hostname": None}])
    out = rule.apply(df, WM)
    assert out.count() == 1
    assert out.collect()[0]["hostname"] is None
