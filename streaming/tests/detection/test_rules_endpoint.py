import json

from src.detection.config import SuspiciousProcessConfig
from src.detection.rules.suspicious_process import SuspiciousProcessRule

WM = "2 minutes"


def test_suspicious_process_positive(spark, make_enriched_df):
    rule = SuspiciousProcessRule(SuspiciousProcessConfig())
    df = make_enriched_df([{
        "event_id": "evt-1", "event_type": "process_created",
        "metadata": '{"scenario": "suspicious-process", "parent_process": "winword.exe", "process": "powershell.exe", "suspicious": true}',
    }])
    out = rule.apply(df, WM)
    rows = out.collect()
    assert len(rows) == 1
    evidence = json.loads(rows[0]["evidence"])
    assert evidence["process"] == "powershell.exe"
    assert evidence["parent_process"] == "winword.exe"


def test_suspicious_process_negative_not_flagged(spark, make_enriched_df):
    rule = SuspiciousProcessRule(SuspiciousProcessConfig())
    df = make_enriched_df([{
        "event_id": "evt-1", "event_type": "process_created",
        "metadata": '{"scenario": "normal-traffic"}',
    }])
    assert rule.apply(df, WM).count() == 0


def test_suspicious_process_negative_wrong_event_type(spark, make_enriched_df):
    rule = SuspiciousProcessRule(SuspiciousProcessConfig())
    df = make_enriched_df([{
        "event_id": "evt-1", "event_type": "login_success",
        "metadata": '{"suspicious": true}',
    }])
    assert rule.apply(df, WM).count() == 0


def test_suspicious_process_empty_metadata_does_not_crash(spark, make_enriched_df):
    rule = SuspiciousProcessRule(SuspiciousProcessConfig())
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "process_created", "metadata": "{}"}])
    assert rule.apply(df, WM).count() == 0


def test_suspicious_process_malformed_metadata_does_not_crash(spark, make_enriched_df):
    rule = SuspiciousProcessRule(SuspiciousProcessConfig())
    df = make_enriched_df([{"event_id": "evt-1", "event_type": "process_created", "metadata": "not valid json{{{"}])
    out = rule.apply(df, WM)
    assert out.count() == 0  # get_json_object returns null for malformed JSON rather than raising


def test_suspicious_process_disabled(spark, make_enriched_df):
    rule = SuspiciousProcessRule(SuspiciousProcessConfig(enabled=False))
    df = make_enriched_df([{
        "event_id": "evt-1", "event_type": "process_created",
        "metadata": '{"suspicious": true}',
    }])
    assert rule.apply(df, WM).count() == 0


def test_suspicious_process_each_event_independent(spark, make_enriched_df):
    rule = SuspiciousProcessRule(SuspiciousProcessConfig())
    rows = [{
        "event_id": f"evt-{i}", "event_type": "process_created",
        "metadata": '{"suspicious": true, "process": "cmd.exe"}',
    } for i in range(4)]
    df = make_enriched_df(rows)
    assert rule.apply(df, WM).count() == 4
