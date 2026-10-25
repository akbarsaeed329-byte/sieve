"""Core data model (see research doc, Section 10.2)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class QueueItem(Base):
    """Durable inbox: every raw alert lands here before any processing."""
    __tablename__ = "queue"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|done|failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    grouping_key: Mapped[str] = mapped_column(String(300), index=True)
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(24), default="new", index=True)
    score: Mapped[float] = mapped_column(Float, default=0)
    band: Mapped[str] = mapped_column(String(16), default="low", index=True)
    breakdown: Mapped[list] = mapped_column(JSON, default=list)
    overrides: Mapped[list] = mapped_column(JSON, default=list)
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    agent_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    srcip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(200), nullable=True)
    tripwire: Mapped[bool] = mapped_column(Boolean, default=False)
    tripwire_hits: Mapped[list] = mapped_column(JSON, default=list)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assignee: Mapped[str | None] = mapped_column(String(120), nullable=True)
    notified_band: Mapped[str | None] = mapped_column(String(16), nullable=True)
    notify_ref: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    playbook: Mapped[str | None] = mapped_column(String(40), nullable=True)
    alerts: Mapped[list[Alert]] = relationship(back_populates="incident", order_by="Alert.timestamp")
    explanations: Mapped[list[Explanation]] = relationship(back_populates="incident")


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    wazuh_id: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    level: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text, default="")
    agent_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    srcip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(200), nullable=True)
    groups: Mapped[list] = mapped_column(JSON, default=list)
    mitre_ids: Mapped[list] = mapped_column(JSON, default=list)
    mitre_tactics: Mapped[list] = mapped_column(JSON, default=list)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    untrusted: Mapped[dict] = mapped_column(JSON, default=dict)
    full_log: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict] = mapped_column(JSON)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    incident: Mapped[Incident | None] = relationship(back_populates="alerts")


class Suppression(Base):
    __tablename__ = "suppressions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    wazuh_id: Mapped[str] = mapped_column(String(120), index=True)
    rule_id: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sampled: Mapped[bool] = mapped_column(Boolean, default=False)
    review_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)  # noise|restored


class Explanation(Base):
    __tablename__ = "explanations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    provider: Mapped[str] = mapped_column(String(80))
    model: Mapped[str] = mapped_column(String(120))
    summary: Mapped[dict] = mapped_column(JSON)
    validation: Mapped[dict] = mapped_column(JSON)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    incident: Mapped[Incident] = relationship(back_populates="explanations")


class Baseline(Base):
    """First-seen memory: (entity, feature) pairs, e.g. ('user:deploy', 'srcip:203.0.113.45')."""
    __tablename__ = "baselines"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity: Mapped[str] = mapped_column(String(250), index=True)
    feature: Mapped[str] = mapped_column(String(250), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin|analyst|viewer
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    """Append-only: never update or delete rows."""
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(200), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
