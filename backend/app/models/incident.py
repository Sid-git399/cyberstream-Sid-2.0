from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_incidents_risk_score_range"),
    )

    incident_id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="NEW")

    hosts: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    users: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    source_ips: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    mitre_techniques: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
