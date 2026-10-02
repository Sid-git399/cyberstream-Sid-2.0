from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Integer, Numeric, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class DlqEntry(Base):
    __tablename__ = "dlq_entries"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    original_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    error_reason: Mapped[str] = mapped_column(String, nullable=False)
    source_topic: Mapped[str | None] = mapped_column(String, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PipelineState(Base):
    __tablename__ = "pipeline_state"

    component: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="UNKNOWN")
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"

    run_id: Mapped[str] = mapped_column(String, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    target_rate: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kafka_partitions: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scenario: Mapped[str | None] = mapped_column(String, nullable=True)
    total_events: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    measured_throughput: Mapped[float | None] = mapped_column(Numeric, nullable=True)
    avg_latency_ms: Mapped[float | None] = mapped_column(Numeric, nullable=True)
    p95_latency_ms: Mapped[float | None] = mapped_column(Numeric, nullable=True)
    peak_kafka_lag: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    errors: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alerts_generated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hardware_notes: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_results: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
