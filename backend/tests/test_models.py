"""
These tests inspect SQLAlchemy metadata objects directly. They do NOT
connect to, or create tables in, any database - so they run without
Docker/Postgres, but also don't prove the DDL is valid Postgres SQL.
That proof only comes from running `alembic upgrade head` against a real
Postgres instance (NOT VERIFIED in this environment - see README).
"""
from app.models import Alert, BenchmarkRun, Base, DetectionRule, DlqEntry, Incident, PipelineState


def test_all_expected_tables_are_registered():
    expected = {
        "detection_rules",
        "incidents",
        "alerts",
        "dlq_entries",
        "pipeline_state",
        "benchmark_runs",
    }
    assert expected.issubset(set(Base.metadata.tables.keys()))


def test_alert_table_has_expected_columns():
    columns = set(Base.metadata.tables["alerts"].columns.keys())
    for expected_col in [
        "alert_id", "incident_id", "fingerprint", "occurrence_count",
        "timestamp", "title", "category", "severity", "risk_score",
        "source_ip", "destination_ip", "hostname", "username",
        "detection_rule_id", "evidence", "mitre_technique", "status",
    ]:
        assert expected_col in columns


def test_incident_table_has_expected_columns():
    columns = set(Base.metadata.tables["incidents"].columns.keys())
    for expected_col in ["incident_id", "title", "severity", "risk_score", "status",
                          "hosts", "users", "source_ips", "mitre_techniques"]:
        assert expected_col in columns


def test_alert_foreign_key_targets_incident():
    fk_targets = {
        fk.target_fullname for fk in Base.metadata.tables["alerts"].foreign_keys
    }
    assert "incidents.incident_id" in fk_targets
    assert "detection_rules.rule_id" in fk_targets


def test_models_are_importable_classes():
    assert DetectionRule.__tablename__ == "detection_rules"
    assert Incident.__tablename__ == "incidents"
    assert Alert.__tablename__ == "alerts"
    assert DlqEntry.__tablename__ == "dlq_entries"
    assert PipelineState.__tablename__ == "pipeline_state"
    assert BenchmarkRun.__tablename__ == "benchmark_runs"
