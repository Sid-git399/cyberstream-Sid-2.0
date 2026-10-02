"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-09-25

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_rules",
        sa.Column("rule_id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("mitre_technique", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("threshold_config", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(), primary_key=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="NEW"),
        sa.Column("hosts", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("users", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("source_ips", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_incidents_risk_score_range"),
    )

    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.String(), primary_key=True),
        sa.Column("incident_id", sa.String(), sa.ForeignKey("incidents.incident_id", ondelete="SET NULL"), nullable=True),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("source_ip", sa.String(), nullable=True),
        sa.Column("destination_ip", sa.String(), nullable=True),
        sa.Column("hostname", sa.String(), nullable=True),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("detection_rule_id", sa.String(), sa.ForeignKey("detection_rules.rule_id"), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("mitre_technique", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="NEW"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_alerts_risk_score_range"),
    )

    op.create_table(
        "dlq_entries",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("original_payload", postgresql.JSONB(), nullable=False),
        sa.Column("error_reason", sa.String(), nullable=False),
        sa.Column("source_topic", sa.String(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "pipeline_state",
        sa.Column("component", sa.String(), primary_key=True),
        sa.Column("status", sa.String(), nullable=False, server_default="UNKNOWN"),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
    )

    op.create_table(
        "benchmark_runs",
        sa.Column("run_id", sa.String(), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("target_rate", sa.Integer(), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("kafka_partitions", sa.Integer(), nullable=True),
        sa.Column("scenario", sa.String(), nullable=True),
        sa.Column("total_events", sa.BigInteger(), nullable=True),
        sa.Column("measured_throughput", sa.Numeric(), nullable=True),
        sa.Column("avg_latency_ms", sa.Numeric(), nullable=True),
        sa.Column("p95_latency_ms", sa.Numeric(), nullable=True),
        sa.Column("peak_kafka_lag", sa.BigInteger(), nullable=True),
        sa.Column("errors", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("alerts_generated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hardware_notes", sa.String(), nullable=True),
        sa.Column("raw_results", postgresql.JSONB(), nullable=True),
    )

    # Indexes per cahier des charges §60 - deliberately selective, not "index everything"
    op.create_index("idx_alerts_timestamp", "alerts", ["timestamp"])
    op.create_index("idx_alerts_severity", "alerts", ["severity"])
    op.create_index("idx_alerts_status", "alerts", ["status"])
    op.create_index("idx_alerts_source_ip", "alerts", ["source_ip"])
    op.create_index("idx_alerts_hostname", "alerts", ["hostname"])
    op.create_index("idx_alerts_username", "alerts", ["username"])
    op.create_index("idx_alerts_risk_score", "alerts", ["risk_score"])
    op.create_index("idx_alerts_incident_id", "alerts", ["incident_id"])
    op.create_index("idx_alerts_fingerprint", "alerts", ["fingerprint"])
    op.create_index("idx_incidents_severity", "incidents", ["severity"])
    op.create_index("idx_incidents_status", "incidents", ["status"])

    # Seed rows so /api/pipeline/status never 404s on a fresh database
    pipeline_state = sa.table(
        "pipeline_state",
        sa.column("component", sa.String),
        sa.column("status", sa.String),
    )
    op.bulk_insert(
        pipeline_state,
        [
            {"component": "generator", "status": "UNKNOWN"},
            {"component": "kafka", "status": "UNKNOWN"},
            {"component": "spark", "status": "UNKNOWN"},
            {"component": "postgres", "status": "RUNNING"},
            {"component": "backend", "status": "RUNNING"},
        ],
    )


def downgrade() -> None:
    op.drop_table("benchmark_runs")
    op.drop_table("pipeline_state")
    op.drop_table("dlq_entries")
    op.drop_index("idx_alerts_fingerprint", table_name="alerts")
    op.drop_index("idx_alerts_incident_id", table_name="alerts")
    op.drop_index("idx_alerts_risk_score", table_name="alerts")
    op.drop_index("idx_alerts_username", table_name="alerts")
    op.drop_index("idx_alerts_hostname", table_name="alerts")
    op.drop_index("idx_alerts_source_ip", table_name="alerts")
    op.drop_index("idx_alerts_status", table_name="alerts")
    op.drop_index("idx_alerts_severity", table_name="alerts")
    op.drop_index("idx_alerts_timestamp", table_name="alerts")
    op.drop_index("idx_incidents_status", table_name="incidents")
    op.drop_index("idx_incidents_severity", table_name="incidents")
    op.drop_table("alerts")
    op.drop_table("incidents")
    op.drop_table("detection_rules")
